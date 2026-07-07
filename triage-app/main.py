"""
AI-Driven Security Triage - Detect-Secrets Demo
=================================================
One Container App containing every logical component from the architecture,
separated into clearly labeled sections so the structure is visible in code
even though it's a single deployable unit.

Components in this file:
  1. Config / clients        - Key Vault, DefectDojo, Azure OpenAI, Service Bus
  2. Orchestrator             - reads test_type, routes to the right adapter
  3. Secrets adapter          - redacts the secret value, builds enriched finding
  4. Worker                  - dequeues the job, calls the model
  5. Policy Engine            - validates the model's JSON response
  6. Write-back               - patches the finding back into DefectDojo
"""

import os
import json
import logging
import threading
from pydantic import BaseModel
import uuid
from datetime import datetime

import requests
from fastapi import FastAPI, HTTPException
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.servicebus import ServiceBusClient, ServiceBusMessage
from openai import AzureOpenAI
from azure.search.documents import SearchClient
from azure.search.documents.models import VectorizedQuery
from azure.core.credentials import AzureKeyCredential

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("triage")

app = FastAPI(title="AI Triage Demo - Detect Secrets")

# ──────────────────────────────────────────────────────────────────────────
# 1. CONFIG / CLIENTS
# ──────────────────────────────────────────────────────────────────────────

KEY_VAULT_URI = os.environ["KEY_VAULT_URI"]              # e.g. https://kv-khan-triage-demo.vault.azure.net/
DD_BASE_URL = os.environ["DD_BASE_URL"]                  # e.g. http://YOUR_DEFECTDOJO_HOST:8080
SERVICE_BUS_NAMESPACE = os.environ["SERVICE_BUS_NAMESPACE"]  # e.g. sb-khan-triage-demo.servicebus.windows.net
AOAI_ENDPOINT = os.environ["AOAI_ENDPOINT"]               # e.g. https://aoai-khan-triage-demo.openai.azure.com/
AOAI_DEPLOYMENT = os.environ.get("AOAI_DEPLOYMENT", "gpt-4o-triage")

# Allow the browser-side progress-polling JavaScript (running on the
# DefectDojo page) to call this Container App directly. Every other call
# into this app so far has been server-to-server (curl, DD's Django backend),
# which is never subject to CORS - this is the first browser-originated call,
# so it needs this explicitly or the browser blocks it.
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[DD_BASE_URL],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

SECRETS_QUEUE_NAME = "secrets-triage"

# Managed Identity is used for everything - no keys stored anywhere in this app.
credential = DefaultAzureCredential()

# Key Vault client - used once at startup to fetch the DD token.
_kv_client = SecretClient(vault_url=KEY_VAULT_URI, credential=credential)


def get_dd_token() -> str:
    """Fetch the DefectDojo API token from Key Vault. Never hardcoded, never logged."""
    return _kv_client.get_secret("dd-api-token").value


DD_TOKEN = get_dd_token()
DD_HEADERS = {"Authorization": f"Token {DD_TOKEN}"}
DD_HEADERS_JSON = {**DD_HEADERS, "Content-Type": "application/json"}


def get_ado_pat() -> str:
    """
    Fetch the Azure DevOps Personal Access Token from Key Vault. This is the
    demo cloud repo's PAT (dev.azure.com/YOUR_ADO_ORG/YOUR_ADO_PROJECT) -
    read-only Code scope. When this moves to the real on-prem ADO Server
    repo, only ADO_ORG/ADO_PROJECT/ADO_REPO/ADO_BASE_URL below change; the
    PAT-fetch pattern and the fetch_code_from_repo() function stay the same.
    """
    return _kv_client.get_secret("ado-pat").value


ADO_PAT = get_ado_pat()
ADO_ORG = os.environ.get("ADO_ORG", "YOUR_ADO_ORG")
ADO_PROJECT = os.environ.get("ADO_PROJECT", "YOUR_ADO_PROJECT")
ADO_REPO = os.environ.get("ADO_REPO", "YOUR_ADO_REPO")
ADO_BRANCH = os.environ.get("ADO_BRANCH", "main")
ADO_BASE_URL = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/git/repositories/{ADO_REPO}"
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "https://YOUR_MCP_SERVER_INTERNAL_URL")


def get_aoai_token():
    return credential.get_token("https://cognitiveservices.azure.com/.default").token


aoai_client = AzureOpenAI(
    azure_endpoint=AOAI_ENDPOINT,
    azure_ad_token_provider=get_aoai_token,
    api_version="2024-10-21",
)
# ── RAG CONFIG ────────────────────────────────────────────────────────────────
SEARCH_ENDPOINT      = os.environ.get("SEARCH_ENDPOINT", "")
SEARCH_ADMIN_KEY     = os.environ.get("SEARCH_ADMIN_KEY", "")
SEARCH_INDEX         = "security-knowledge"
EMBEDDING_DEPLOYMENT = "text-embedding-ada-002"
RAG_TOP_K            = 3

_search_client = None

def get_search_client():
    global _search_client
    if _search_client is None and SEARCH_ENDPOINT and SEARCH_ADMIN_KEY:
        _search_client = SearchClient(
            endpoint=SEARCH_ENDPOINT,
            index_name=SEARCH_INDEX,
            credential=AzureKeyCredential(SEARCH_ADMIN_KEY),
        )
    return _search_client

def get_rag_context(query_text: str, cwe_id: str = "") -> str:
    """Query Azure AI Search with hybrid search. Returns formatted context for prompt injection."""
    client = get_search_client()
    if not client:
        log.warning("[RAG] Search client not available — skipping RAG enrichment")
        return ""
    try:
        embedding_resp = aoai_client.embeddings.create(
            model=EMBEDDING_DEPLOYMENT,
            input=query_text[:8000],
        )
        query_vector = embedding_resp.data[0].embedding
        vector_query = VectorizedQuery(
            vector=query_vector,
            k_nearest_neighbors=RAG_TOP_K,
            fields="embedding",
        )
        filter_expr = ("source_id eq '" + cwe_id + "'") if cwe_id else None
        results = client.search(
            search_text=query_text,
            vector_queries=[vector_query],
            filter=filter_expr,
            top=RAG_TOP_K,
            select=["source", "source_id", "title", "content", "mitigations"],
        )
        docs = list(results)
        if not docs:
            results = client.search(
                search_text=query_text,
                vector_queries=[vector_query],
                top=RAG_TOP_K,
                select=["source", "source_id", "title", "content", "mitigations"],
            )
            docs = list(results)
        if not docs:
            return ""
        parts = ["=== AUTHORITATIVE SECURITY KNOWLEDGE ==="]
        for doc in docs:
            src = doc["source"]
            src_id = doc["source_id"]
            title = doc["title"]
            definition = doc["content"]
            mitigations = doc["mitigations"]
            entry = "[" + src + " " + src_id + "] " + title + "\n" + "Definition: " + definition + "\n" + "Mitigations: " + mitigations
            parts.append(entry)
        parts.append("=== END SECURITY KNOWLEDGE ===")
        log.info(f"[RAG] Retrieved {len(docs)} docs for: {query_text[:60]}")
        return chr(10).join(parts)

    except Exception as e:
        log.warning(f"[RAG] Query failed: {e} — proceeding without RAG context")
        return ""

log.info("[CONFIG] RAG client configured — index: security-knowledge")

servicebus_client = ServiceBusClient(
    fully_qualified_namespace=SERVICE_BUS_NAMESPACE,
    credential=credential,
)


# ──────────────────────────────────────────────────────────────────────────
# 1b. REPO CONNECTOR (tool the agent calls - it decides when/how often)
# ──────────────────────────────────────────────────────────────────────────

import base64

_ado_auth_header = {
    "Authorization": "Basic " + base64.b64encode(f":{ADO_PAT}".encode()).decode()
}


def fetch_code_from_repo(file_path: str, line_number: int, context_lines: int = 10) -> dict:
    """
    Fetches a window of lines around the given line number from the repo.
    This is the ONE tool the agent has - it decides how many times to call
    it and with what context_lines value, but the fetch itself is a plain,
    deterministic REST call. The agent never gets raw repo browsing/search -
    only "give me lines around X in file Y", which keeps the attack surface
    and cost bounded even though the agent's calling pattern is autonomous.

    Returns a dict with the requested window AND the secret value itself
    redacted, so the agent never actually sees a real secret value even
    when it fetches the real surrounding code.
    """
    try:
        resp = requests.get(
            f"{ADO_BASE_URL}/items",
            headers=_ado_auth_header,
            params={
                "path": file_path,
                "versionDescriptor.version": ADO_BRANCH,
                "versionDescriptor.versionType": "branch",
                "includeContent": "true",
                "api-version": "7.1",
            },
            timeout=15,
        )
        resp.raise_for_status()
        full_content = resp.text
    except requests.RequestException as e:
        log.warning(f"[REPO CONNECTOR] failed to fetch {file_path}: {e}")
        return {"error": f"Could not fetch {file_path}: {e}"}

    lines = full_content.splitlines()
    start = max(0, line_number - 1 - context_lines)
    end = min(len(lines), line_number - 1 + context_lines + 1)
    window = lines[start:end]

    redacted_window = []
    for i, line_text in enumerate(window, start=start + 1):
        if i == line_number:
            redacted_window.append(redact_secret_value(line_text))
        else:
            redacted_window.append(line_text)

    log.info(f"[REPO CONNECTOR] fetched {file_path} lines {start+1}-{end} (target line {line_number} redacted)")
    return {
        "file_path": file_path,
        "target_line_number": line_number,
        "lines": "\n".join(f"{i}: {t}" for i, t in zip(range(start + 1, end + 1), redacted_window)),
    }


# ──────────────────────────────────────────────────────────────────────────
# 2. ORCHESTRATOR
# ──────────────────────────────────────────────────────────────────────────

def fetch_finding(finding_id: int) -> dict:
    """Ask DefectDojo for the full finding detail, including its test_type."""
    resp = requests.get(
        f"{DD_BASE_URL}/api/v2/findings/{finding_id}/",
        headers=DD_HEADERS,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def get_test_type_name(test_id: int) -> str:
    """Look up the human-readable test_type_name for a given test (e.g. 'Detect-secrets Scan')."""
    resp = requests.get(
        f"{DD_BASE_URL}/api/v2/tests/{test_id}/",
        headers=DD_HEADERS,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json().get("test_type_name", "")


def orchestrate(finding_id: int) -> dict:
    """
    The orchestrator's only job: read the finding, read its test_type,
    and decide which adapter handles it. For this demo, only the
    secrets adapter exists - anything else is rejected clearly.
    """
    finding = fetch_finding(finding_id)
    test_id = finding["test"]
    test_type_name = get_test_type_name(test_id)

    log.info(f"[ORCHESTRATOR] finding={finding_id} test_type_name='{test_type_name}'")

    if "detect-secrets" in test_type_name.lower():
        return secrets_adapter(finding)

    raise HTTPException(
        status_code=400,
        detail=f"No adapter configured for test_type '{test_type_name}' in this demo "
                "(only Detect-secrets Scan is wired up right now).",
    )


# ──────────────────────────────────────────────────────────────────────────
# 3. SECRETS ADAPTER
# ──────────────────────────────────────────────────────────────────────────

def redact_secret_value(code_line: str) -> str:
    """
    Best-effort redaction: if the line looks like KEY=VALUE or contains a long
    token-like string, mask the value portion. This is intentionally simple
    for the demo - the point is that the raw secret never reaches the model.
    """
    if not code_line:
        return ""
    if "=" in code_line:
        key_part, _, _ = code_line.partition("=")
        return f"{key_part.strip()}=[REDACTED]"
    if ":" in code_line:
        key_part, _, _ = code_line.partition(":")
        return f"{key_part.strip()}: [REDACTED]"
    return "[REDACTED LINE]"


def secrets_adapter(finding: dict) -> dict:
    """
    Builds the enriched-finding message for a detect-secrets finding.

    IMPORTANT: this no longer assumes the code line is present in DD's
    description. Real production findings (GHAS/detect-secrets via the
    actual scanner pipeline) carry only file_path + line_number, no code
    snippet - this matches what was confirmed directly: "DD has zero code
    context, only file+line, every time." If a description DOES happen to
    contain a code line (like this demo's test_data.py findings), it's
    intentionally ignored here, so the agentic path is exercised honestly
    and consistently rather than silently using a shortcut that won't exist
    in production.
    """
    enriched = {
        "finding_id": finding["id"],
        "adapter": "secrets",
        "rule_name": finding.get("vuln_id_from_tool") or finding.get("title", ""),
        "file_path": finding.get("file_path", ""),
        "line_number": finding.get("line"),
        "severity": finding.get("severity", ""),
    }
    log.info(f"[SECRETS ADAPTER] enriched finding ready (no code line - agent must fetch via tool): {enriched}")
    return publish_to_queue(enriched)


def publish_to_queue(enriched_finding: dict) -> dict:
    """Publishes the enriched finding onto the secrets-triage Service Bus queue."""
    with servicebus_client.get_queue_sender(queue_name=SECRETS_QUEUE_NAME) as sender:
        message = ServiceBusMessage(json.dumps(enriched_finding))
        sender.send_messages(message)
    log.info(f"[QUEUE] published finding {enriched_finding['finding_id']} to '{SECRETS_QUEUE_NAME}'")
    return {"status": "queued", "finding_id": enriched_finding["finding_id"]}


def sast_adapter(finding: dict) -> dict:
    """
    Builds enriched finding for SAST and routes to call_model_sast
    which uses the MCP server tools to fetch code and finding details.
    """
    enriched = {
        "finding_id": finding["id"],
        "adapter": "sast",
        "rule_name": finding.get("vuln_id_from_tool") or finding.get("title", ""),
        "file_path": finding.get("file_path", ""),
        "line_number": finding.get("line"),
        "severity": finding.get("severity", ""),
    }
    log.info(f"[SAST ADAPTER] enriched finding ready: {enriched}")
    result = call_model_sast(enriched)
    validated = policy_engine_validate(result)
    write_back_to_dd(enriched["finding_id"], validated)
    return {"status": "triaged", "finding_id": enriched["finding_id"], "result": validated}

# ──────────────────────────────────────────────────────────────────────────
# 4. WORKER
# ──────────────────────────────────────────────────────────────────────────

SECRETS_PROMPT_TEMPLATE = """You are a security triage assistant reviewing a detect-secrets finding.
The actual secret value has been redacted - you will never see it. You have no
internet access and must reason only from the metadata below, the same way an
experienced security reviewer would when looking at a single flagged line in
isolation.

Rule that fired: {rule_name}
File: {file_path}
Line: {line_number}
Severity reported by scanner: {severity}

{rag_context}

You do NOT have the code at this line yet. You have a tool, fetch_code,
that returns a window of lines from the file around a given line number -
the target line's actual secret value will always come back redacted, but
the surrounding code (variable names, imports, function context) will be
real. Call fetch_code with this file and line before making your decision -
you cannot reliably classify a hardcoded-credential finding without seeing
the key name and surrounding context. You may call it more than once with a
different context_lines value if the first window doesn't give you enough
to see the full assignment or surrounding logic, but most findings only
need one call.

IMPORTANT FRAMING: for hardcoded-credential findings (CWE-798), the
vulnerability is the act of hardcoding a credential-shaped value in source
code, regardless of how strong, weak, short, or guessable that value happens
to look. "This password looks weak/simple/guessable" is NEVER a reason to
classify something as false_positive - a weak hardcoded password is still a
real true_positive; if anything, an easily-guessable hardcoded credential is
a worse finding, not a more excusable one. The only valid grounds for
false_positive are that the value is verifiably NOT a functioning credential
at all, established only by the two categories in Step 1 below. The
rule_name field tells you what pattern matched, not how serious or real the
finding is - do not let rule_name alone influence your classification; the
same underlying value should be classified the same way regardless of which
rule happened to flag it.

Reason through this step by step before answering:

Step 1 - Non-functional value check (the ONLY valid basis for false_positive):
After fetching the code, check for exactly two kinds of evidence that the
value is not a real, functioning credential:
  (a) Vendor-documented placeholder pattern: many providers publish official
      example/test credentials as part of their own documentation, with
      recognizable markers in the key name's pattern (e.g. values containing
      the literal word "EXAMPLE", or key names indicating a vendor's own
      documented test-mode prefix convention such as "_test_" / "_TEST_"
      style markers that vendors use specifically to distinguish their
      official test-mode keys from live ones). If the visible portion of the
      line shows this kind of vendor-specific marker, this is genuine,
      verifiable evidence of a placeholder - not a guess.
  (b) Explicit human-readable placeholder phrase: the value itself (if any
      part is visible) reads as obviously non-functional placeholder text
      meant for a human to replace, such as "your_password_here",
      "changeme", "replace_this", "<insert_key_here>", or similarly explicit
      instructional phrasing - not just a short or simple-looking value, but
      text that is unambiguously an instruction rather than a credential.
If NEITHER (a) nor (b) clearly applies, do not classify as false_positive,
regardless of file path, key name informality, or how weak the value looks.

Step 2 - Context as a secondary signal only: file path (test/, tests/,
fixtures/, examples/ vs src/, app/, config/, lib/) can raise or lower
confidence, and can justify needs_review when combined with genuine
ambiguity, but a test-directory path alone, without Step 1 evidence, is NOT
sufficient grounds for false_positive - real credentials are frequently and
accidentally left in test code, which is itself a true_positive worth
flagging.

Step 3 - Default and confidence: if Step 1 found no clear non-functional
evidence, the default classification is true_positive, not false_positive,
because a hardcoded credential-shaped value is presumed real until shown
otherwise. Use needs_review only when the available metadata genuinely lacks
enough information to apply Step 1 either way (not merely because the value
"seems weak"). Confidence should be high (0.8-0.95) when Step 1 evidence is
clear in either direction, and below 0.6 with classification needs_review
only for genuine evidentiary gaps.

Once you have fetched the code and reasoned through the steps above,
respond with ONLY valid JSON, no other text, matching exactly this schema:
{{
  "classification": "true_positive" | "false_positive" | "needs_review",
  "confidence": <float between 0 and 1>,
  "reasoning": "<two to three sentences citing the specific Step 1 evidence found, or explicitly stating that no such evidence was found and the true_positive default applies>",
  "mitigation": "<one or two sentences of recommended action>",
  "cwe_reference": "<CWE id, e.g. CWE-798>",
  "references": "<one short reference to the relevant security guidance, e.g. 'OWASP Top 10 A07:2021 - Identification and Authentication Failures'>"
}}
"""

# ── Claude (Anthropic) tool schemas ─────────────────────────────────────────
FETCH_CODE_TOOL_SCHEMA_CLAUDE = {
    "name": "fetch_code",
    "description": (
        "Fetches a window of lines from a file in the repo around a given "
        "line number. The target line secret value comes back redacted; "
        "surrounding lines are real code, useful for seeing variable names, "
        "imports, and context."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "file_path": {"type": "string"},
            "line_number": {"type": "integer"},
            "context_lines": {
                "type": "integer",
                "description": "How many lines before/after the target line to include. Default 10.",
            },
        },
        "required": ["file_path", "line_number"],
    },
}

MCP_TOOL_SCHEMAS_CLAUDE = [
    {
        "name": "fetch_code",
        "description": "Fetch source file from ADO with context around the flagged line. The flagged line value is redacted.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "line_number": {"type": "integer"},
                "context_lines": {"type": "integer"}
            },
            "required": ["file_path", "line_number"]
        }
    },
    {
        "name": "fetch_finding",
        "description": "Fetch full finding from DefectDojo including severity, CWE, description, and SAST data flow.",
        "input_schema": {
            "type": "object",
            "properties": {"finding_id": {"type": "integer"}},
            "required": ["finding_id"]
        }
    },
    {
        "name": "fetch_related_file",
        "description": "Fetch any other file from ADO to verify sanitization logic or upstream validators.",
        "input_schema": {
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
            "required": ["file_path"]
        }
    },
]

FETCH_CODE_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "fetch_code",
        "description": (
            "Fetches a window of lines from a file in the repo around a given "
            "line number. The target line's secret value comes back redacted; "
            "surrounding lines are real code, useful for seeing variable names, "
            "imports, and context."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "line_number": {"type": "integer"},
                "context_lines": {
                    "type": "integer",
                    "description": "How many lines before/after the target line to include. Default 10.",
                },
            },
            "required": ["file_path", "line_number"],
        },
    },
}

MAX_AGENT_TOOL_CALLS = 4  # hard cap - bounds cost/latency even if the model loops

# ── SAST MCP tool schemas ────────────────────────────────────────────────────
MCP_TOOL_SCHEMAS = [
    {"type": "function", "function": {"name": "fetch_code", "description": "Fetch source file from ADO with context around the flagged line. The flagged line value is redacted.", "parameters": {"type": "object", "properties": {"file_path": {"type": "string"}, "line_number": {"type": "integer"}, "context_lines": {"type": "integer"}}, "required": ["file_path", "line_number"]}}},
    {"type": "function", "function": {"name": "fetch_finding", "description": "Fetch full finding from DefectDojo including severity, CWE, description, and SAST data flow.", "parameters": {"type": "object", "properties": {"finding_id": {"type": "integer"}}, "required": ["finding_id"]}}},
    {"type": "function", "function": {"name": "fetch_related_file", "description": "Fetch any other file from ADO to verify sanitization logic or upstream validators.", "parameters": {"type": "object", "properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}}},
    {"type": "function", "function": {"name": "fetch_epss", "description": "Fetch live EPSS score for a CVE ID from FIRST.org. Returns exploitation probability (0-1) for the next 30 days and a risk label. Call this when a CVE ID is known to get real-time exploitation likelihood.", "parameters": {"type": "object", "properties": {"cve_id": {"type": "string", "description": "CVE identifier e.g. CVE-2021-44228"}}, "required": ["cve_id"]}}},
    {"type": "function", "function": {"name": "analyze_reachability", "description": "Analyze if the vulnerable code at a given line is reachable from HTTP entry points using tree-sitter AST analysis. Call this after fetch_code to determine if the vulnerability is actually exploitable. Returns is_reachable (true/false/null), confidence, call_path, and analysis.", "parameters": {"type": "object", "properties": {"file_path": {"type": "string"}, "line_number": {"type": "integer"}, "language": {"type": "string", "description": "python, javascript, or java"}}, "required": ["file_path", "line_number"]}}},
]

SAST_PROMPT_TEMPLATE = """
You are a senior application security engineer triaging a SAST finding.
You have four tools available:
  fetch_code        — fetch the vulnerable file with context around the flagged line
  fetch_finding     — fetch the full finding record from DefectDojo (CWE, description, data flow)
  fetch_related_file — fetch any other file (e.g. validators, sanitizers, upstream callers)
  fetch_epss        — fetch live EPSS exploitation probability score for a CVE ID (0-1 scale, next 30 days)
  analyze_reachability — parse source code AST to determine if vulnerable code is reachable from HTTP entry points

Finding details:
  Rule   : {rule_name}
  File   : {file_path}
  Line   : {line_number}
  Severity: {severity}
  Finding ID: {finding_id}

{rag_context}

Step 1 — Call fetch_finding to get the full description and CWE.
Step 2 — Call fetch_code to see the vulnerable code and surrounding context.
Step 3 — If the code references a sanitizer, validator, or helper function that
          might neutralize the vulnerability, call fetch_related_file to verify.
Step 4 — If a CVE ID is present in the finding, call fetch_epss to get the
          live exploitation probability. A high EPSS score (>0.5) should
          increase your confidence in true_positive classification.
Step 5 — Call analyze_reachability with the file_path and line_number to
          determine if the vulnerable code is reachable from HTTP entry points.
          If is_reachable=False (dead code) → classify as false_positive with high confidence.
          If is_reachable=True → confirms true_positive.
          If is_reachable=None → use other evidence to decide.
Step 6 — Classify as one of: true_positive / false_positive / needs_review.

Respond ONLY with valid JSON:
{{"classification": "...", "confidence": 0.0-1.0, "reasoning": "...", "mitigation": "...", "cwe_reference": "CWE-XXX", "references": "...", "epss_score": null_or_float, "epss_percentile": null_or_float}}
If you called fetch_epss, populate epss_score and epss_percentile from the result. Otherwise set both to null.
"""

def call_mcp_tool(tool_name: str, args: dict) -> dict:
    """Call a tool on the MCP server."""
    import requests as req
    resp = req.post(f"{MCP_SERVER_URL}/tools/{tool_name}", json=args, timeout=30)
    resp.raise_for_status()
    return resp.json()

def call_model_sast(enriched_finding: dict) -> dict:
    """Agentic loop for SAST using MCP server tools — Claude Sonnet."""
    rag_query = f"{enriched_finding.get('rule_name', '')} SAST vulnerability {enriched_finding.get('severity', '')}"
    rag_context = get_rag_context(rag_query)
    prompt = SAST_PROMPT_TEMPLATE.format(
        rule_name=enriched_finding.get("rule_name", "unknown"),
        file_path=enriched_finding.get("file_path", "unknown"),
        line_number=enriched_finding.get("line_number", "unknown"),
        severity=enriched_finding.get("severity", "unknown"),
        finding_id=enriched_finding.get("finding_id", "unknown"),
        rag_context=rag_context,
    )
    messages = [{"role": "user", "content": prompt}]

    for call_count in range(MAX_AGENT_TOOL_CALLS + 1):
        force_final_answer = call_count == MAX_AGENT_TOOL_CALLS
        _tools = None if force_final_answer else MCP_TOOL_SCHEMAS
        _tool_choice = "auto" if not force_final_answer else None
        _response_format = {"type": "json_object"} if force_final_answer else None
        _kwargs = {"model": AOAI_DEPLOYMENT, "messages": messages, "temperature": 0}
        if _tools:
            _kwargs["tools"] = _tools
            _kwargs["tool_choice"] = _tool_choice
        if _response_format:
            _kwargs["response_format"] = _response_format
        response = aoai_client.chat.completions.create(**_kwargs)
        choice = response.choices[0]
        messages.append(choice.message.model_dump(exclude_none=True))
        if not choice.message.tool_calls:
            raw_content = choice.message.content or ""
            log.info(f"[SAST AGENT] final response after {call_count} tool call(s): {raw_content}")
            if not raw_content.strip():
                log.warning("[SAST AGENT] empty response from model, returning needs_review")
                return {"classification": "needs_review", "confidence": 0.5, "reasoning": "Model returned empty response.", "mitigation": "Review manually.", "cwe_reference": "CWE-unknown", "references": ""}
            try:
                return json.loads(raw_content)
            except json.JSONDecodeError:
                import re
                m = re.search(r'\{.*\}', raw_content, re.DOTALL)
                if m:
                    return json.loads(m.group())
                return {"classification": "needs_review", "confidence": 0.5, "reasoning": raw_content[:500], "mitigation": "Review manually.", "cwe_reference": "CWE-unknown", "references": ""}
        for tool_call in choice.message.tool_calls:
            args = json.loads(tool_call.function.arguments)
            tool_name = tool_call.function.name
            log.info(f"[SAST AGENT] calling MCP tool {tool_name} with args: {args}")
            try:
                tool_result = call_mcp_tool(tool_name, args)
            except Exception as e:
                tool_result = {"error": str(e)}
            messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": json.dumps(tool_result)})
    raise ValueError("SAST agent exceeded MAX_AGENT_TOOL_CALLS without producing a final answer")


def call_model(enriched_finding: dict) -> dict:
    """
    Agentic tool-calling loop: the model decides for itself whether and how
    many times to call fetch_code before producing a classification. This
    replaces the old fixed-prompt-only call, because real findings carry no
    code line - the model must fetch it. MAX_AGENT_TOOL_CALLS bounds the
    loop so a model that gets stuck calling the tool repeatedly cannot run
    away on cost/latency; if the cap is hit, the model is told to answer
    with whatever it has.
    """
    rag_query = f"hardcoded credential secret {enriched_finding.get('rule_name', '')} CWE-798"
    rag_context = get_rag_context(rag_query, cwe_id="CWE-798")
    prompt = SECRETS_PROMPT_TEMPLATE.format(
        rule_name=enriched_finding.get("rule_name", "unknown"),
        file_path=enriched_finding.get("file_path", "unknown"),
        line_number=enriched_finding.get("line_number", "unknown"),
        severity=enriched_finding.get("severity", "unknown"),
        rag_context=rag_context,
    )

    messages = [{"role": "user", "content": prompt}]

    for call_count in range(MAX_AGENT_TOOL_CALLS + 1):
        force_final_answer = call_count == MAX_AGENT_TOOL_CALLS
        _tools = None if force_final_answer else [FETCH_CODE_TOOL_SCHEMA]
        _response_format = {"type": "json_object"} if force_final_answer else None
        _kwargs = {"model": AOAI_DEPLOYMENT, "messages": messages, "temperature": 0}
        if _tools:
            _kwargs["tools"] = _tools
            _kwargs["tool_choice"] = "auto"
        if _response_format:
            _kwargs["response_format"] = _response_format
        response = aoai_client.chat.completions.create(**_kwargs)
        choice = response.choices[0]
        messages.append(choice.message.model_dump(exclude_none=True))
        if not choice.message.tool_calls:
            raw_content = choice.message.content or ""
            log.info(f"[AGENT] final response after {call_count} tool call(s): {raw_content}")
            if not raw_content.strip():
                log.warning("[AGENT] empty response from model, returning needs_review")
                return {"classification": "needs_review", "confidence": 0.5,
                        "reasoning": "Model returned empty response.",
                        "mitigation": "Review manually.", "cwe_reference": "CWE-unknown", "references": ""}
            try:
                return json.loads(raw_content)
            except json.JSONDecodeError:
                import re
                m = re.search(r'\{.*\}', raw_content, re.DOTALL)
                if m:
                    return json.loads(m.group())
                return {"classification": "needs_review", "confidence": 0.5,
                        "reasoning": raw_content[:500], "mitigation": "Review manually.",
                        "cwe_reference": "CWE-unknown", "references": ""}
        for tool_call in choice.message.tool_calls:
            args = json.loads(tool_call.function.arguments)
            log.info(f"[AGENT] calling fetch_code with args: {args}")
            tool_result = fetch_code_from_repo(
                file_path=args.get("file_path", enriched_finding.get("file_path", "")),
                line_number=args.get("line_number", enriched_finding.get("line_number", 0)),
                context_lines=args.get("context_lines", 10),
            )
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": json.dumps(tool_result),
            })
    raise HTTPException(status_code=502, detail="Agent did not produce a final classification within the tool-call budget.")


def process_one_message() -> dict:
    """
    Pulls exactly one message off the secrets-triage queue, calls the model,
    validates the result, and writes it back to DefectDojo. Built as a
    single synchronous call for the demo, so you can trigger it manually
    and see the whole chain happen in one request.

    NOTE: this is for the manual /triage/{id} + /worker/process-one demo
    flow only. The batch path (_run_batch_job) does NOT use this function -
    it calls process_finding_directly() instead, bypassing the queue
    entirely, because this function has no way to guarantee it dequeues the
    specific message that was just published (a real bug found in
    production testing: under a multi-finding batch, this could dequeue an
    unrelated or stale message, leaving the intended one stranded in the
    queue indefinitely).
    """
    with servicebus_client.get_queue_receiver(queue_name=SECRETS_QUEUE_NAME, max_wait_time=10) as receiver:
        messages = receiver.receive_messages(max_message_count=1, max_wait_time=10)
        if not messages:
            return {"status": "no_messages_in_queue"}

        msg = messages[0]
        raw_body = b"".join(msg.body) if hasattr(msg, "body") else str(msg).encode()
        log.info(f"[WORKER] DIAGNOSTIC raw_body repr: {raw_body!r}")
        log.info(f"[WORKER] DIAGNOSTIC str(msg) repr: {str(msg)!r}")
        enriched_finding = json.loads(raw_body.decode("utf-8"))
        log.info(f"[WORKER] dequeued finding {enriched_finding['finding_id']}")

        result = _process_enriched_finding(enriched_finding)
        receiver.complete_message(msg)
        return result


def _process_enriched_finding(enriched_finding: dict) -> dict:
    """
    The actual model-call -> policy-engine -> write-back chain, shared by
    both the queue-based path (process_one_message) and the direct,
    queue-free path (process_finding_directly) used by the batch job.
    """
    model_result = call_model(enriched_finding)
    validated_result = policy_engine_validate(model_result)
    write_back_to_dd(enriched_finding["finding_id"], validated_result)
    return {
        "status": "triaged",
        "finding_id": enriched_finding["finding_id"],
        "result": validated_result,
    }


def process_finding_directly(finding_id: int) -> dict:
    """
    Fetches a finding, builds the enriched version via the secrets adapter,
    and processes it immediately - no Service Bus involved. Used by the
    batch job specifically to avoid the dequeue-mismatch bug: each finding
    in a batch is fetched and triaged in one guaranteed step, with no
    chance of picking up a different finding's message.

    No longer assumes a code line is present in DD's description - real
    findings carry file_path + line_number only, so the enriched finding
    just passes those through and the agent fetches code itself via the
    repo connector tool.
    """
    if is_pending_analyst_review(finding_id):
        log.info(f"[DIRECT] skipping finding {finding_id} — pending analyst review")
        return {"status": "skipped", "reason": "pending_analyst_review", "finding_id": finding_id}
    finding = fetch_finding(finding_id)
    test_id = finding["test"]
    test_type_name = get_test_type_name(test_id)

    if "detect-secrets" in test_type_name.lower():
        enriched = {
            "finding_id": finding["id"],
            "adapter": "secrets",
            "rule_name": finding.get("vuln_id_from_tool") or finding.get("title", ""),
            "file_path": finding.get("file_path", ""),
            "line_number": finding.get("line"),
            "severity": finding.get("severity", ""),
        }
        log.info(f"[DIRECT] routing finding {finding_id} to secrets adapter")
        return _process_enriched_finding(enriched)
    elif any(x in test_type_name.lower() for x in ["sast", "semgrep", "sonarqube", "checkmarx", "bandit", "codeql", "sarif"]):
        log.info(f"[DIRECT] routing finding {finding_id} to sast_adapter")
        return sast_adapter(finding)
    else:
        raise HTTPException(
            status_code=400,
            detail=f"No adapter configured for test_type '{test_type_name}'.",
        )


# ──────────────────────────────────────────────────────────────────────────
# 5. POLICY ENGINE
# ──────────────────────────────────────────────────────────────────────────

VALID_CLASSIFICATIONS = {"true_positive", "false_positive", "needs_review"}
CONFIDENCE_THRESHOLD = 0.7


def policy_engine_validate(model_result: dict) -> dict:
    """
    Validates the model's JSON response before it's allowed anywhere near
    DefectDojo. If the shape is wrong, or a definitive (true_positive /
    false_positive) classification doesn't meet the confidence bar, downgrade
    to needs_review rather than trusting an uncertain or malformed answer.
    needs_review itself is never blocked by the confidence check, since a
    low-confidence "needs_review" from the model is already the safe outcome.
    """
    required_fields = {"classification", "confidence", "reasoning", "mitigation", "cwe_reference", "references"}
    missing = required_fields - model_result.keys()

    if missing:
        log.warning(f"[POLICY ENGINE] missing fields {missing}, forcing needs_review")
        return _needs_review_fallback(model_result, reason=f"missing fields: {missing}")

    if model_result["classification"] not in VALID_CLASSIFICATIONS:
        log.warning(f"[POLICY ENGINE] invalid classification '{model_result['classification']}'")
        return _needs_review_fallback(model_result, reason="invalid classification value")

    try:
        confidence = float(model_result["confidence"])
    except (TypeError, ValueError):
        log.warning("[POLICY ENGINE] confidence not numeric")
        return _needs_review_fallback(model_result, reason="confidence not numeric")

    if model_result["classification"] != "needs_review" and confidence < CONFIDENCE_THRESHOLD:
        log.warning(
            f"[POLICY ENGINE] {model_result['classification']} confidence {confidence} "
            f"below threshold {CONFIDENCE_THRESHOLD}, downgrading to needs_review"
        )
        return _needs_review_fallback(model_result, reason=f"confidence {confidence} below threshold for a definitive classification")

    log.info(f"[POLICY ENGINE] validated OK: {model_result['classification']} ({confidence})")
    return model_result


def _needs_review_fallback(original: dict, reason: str) -> dict:
    return {
        "classification": "needs_review",
        "confidence": original.get("confidence", 0),
        "reasoning": f"Policy Engine override: {reason}. Original model output: {original}",
        "mitigation": "Manual review required - automated triage did not meet confidence/schema requirements.",
        "cwe_reference": original.get("cwe_reference", "N/A"),
        "references": original.get("references", "N/A"),
    }


# ──────────────────────────────────────────────────────────────────────────
# 6. WRITE-BACK
# ──────────────────────────────────────────────────────────────────────────

# ANALYST REVIEW HELPERS
def should_flag_for_review(result: dict) -> bool:
    """Flag for analyst review if confidence below threshold or classification is needs_review."""
    return result.get("confidence", 1.0) < 0.7 or result.get("classification") == "needs_review"

def is_pending_analyst_review(finding_id: int) -> bool:
    """Returns True if finding is currently tagged ANALYST_REVIEW_NEEDED."""
    resp = requests.get(
        f"{DD_BASE_URL}/api/v2/findings/{finding_id}/",
        headers=DD_HEADERS_JSON,
        timeout=10,
    )
    if resp.status_code == 200:
        return "ANALYST_REVIEW_NEEDED" in resp.json().get("tags", [])
    return False

def swap_analyst_tags(finding_id: int) -> None:
    """Remove ANALYST_REVIEW_NEEDED, add ANALYST_REVIEWED. Preserves all other tags."""
    resp = requests.get(
        f"{DD_BASE_URL}/api/v2/findings/{finding_id}/",
        headers=DD_HEADERS_JSON,
        timeout=10,
    )
    existing = resp.json().get("tags", []) if resp.status_code == 200 else []
    updated = [t for t in existing if t != "ANALYST_REVIEW_NEEDED"]
    if "ANALYST_REVIEWED" not in updated:
        updated.append("ANALYST_REVIEWED")
    requests.patch(
        f"{DD_BASE_URL}/api/v2/findings/{finding_id}/",
        headers=DD_HEADERS_JSON,
        json={"tags": updated},
        timeout=10,
    )
    log.info(f"[ANALYST] finding {finding_id} tags updated → {updated}")

def write_back_to_dd(finding_id: int, result: dict) -> None:
    """
    Patches the finding in DefectDojo with the AI triage result:
      - Native 'mitigation' and 'references' fields, so they show in DD's
        own dedicated UI sections rather than only inside free-text notes.
      - A tag for quick visual scanning across finding lists.
      - A note attached specifically to this finding (via the finding-scoped
        notes endpoint), giving a timestamped audit trail of the triage event.
    """
    note_text = (
        f"**AI Triage Result** ({datetime.utcnow().isoformat()}Z)\n\n"
        f"- Classification: {result['classification']}\n"
        f"- Confidence: {result['confidence']}\n"
        f"- Reasoning: {result['reasoning']}\n"
        f"- Mitigation: {result['mitigation']}\n"
        f"- CWE: {result['cwe_reference']}\n"
        f"- References: {result.get('references', 'N/A')}\n"
    )

    tags = [f"ai-{result['classification']}"]
    if should_flag_for_review(result):
        tags.append("ANALYST_REVIEW_NEEDED")
        log.info(f"[WRITE-BACK] finding {finding_id} flagged for analyst review "
                 f"(confidence={result['confidence']}, classification={result['classification']})")
    patch_payload = {
        "tags": tags,
        "mitigation": result["mitigation"],
        "references": result.get("references", ""),
    }
    if result.get("epss_score") is not None:
        patch_payload["epss_score"] = result["epss_score"]
        log.info(f"[WRITE-BACK] writing EPSS score {result['epss_score']} to finding {finding_id}")
    if result.get("epss_percentile") is not None:
        patch_payload["epss_percentile"] = result["epss_percentile"]
    requests.patch(
        f"{DD_BASE_URL}/api/v2/findings/{finding_id}/",
        headers=DD_HEADERS_JSON,
        json=patch_payload,
        timeout=15,
    )

    requests.post(
        f"{DD_BASE_URL}/api/v2/findings/{finding_id}/notes/",
        headers=DD_HEADERS_JSON,
        json={"entry": note_text},
        timeout=15,
    )

    log.info(f"[WRITE-BACK] finding {finding_id} updated with classification={result['classification']}")


# ──────────────────────────────────────────────────────────────────────────
# HTTP ENDPOINTS
# ──────────────────────────────────────────────────────────────────────────

@app.get("/")
def health():
    return {"status": "ok", "service": "ai-triage-demo"}

# ──────────────────────────────────────────────────────────────────────────
# ANALYST REVIEW ENDPOINT
# ──────────────────────────────────────────────────────────────────────────
class AnalystReviewPayload(BaseModel):
    finding_id: int
    decision: str             # "approve" or "override"
    override_status: str = "" # "false_positive", "risk_accepted", "active"
    analyst_notes: str = ""
    analyst_user: str = "analyst"

@app.post("/analyst/review")
async def analyst_review(payload: AnalystReviewPayload):
    fid = payload.finding_id
    log.info(f"[ANALYST] review received for finding {fid}: decision={payload.decision}")

    # 1. Build and write decision note
    ts = datetime.utcnow().isoformat()
    if payload.decision == "approve":
        note_text = (
            f"**[APPROVED] Analyst Review** ({ts}Z)\n\n"
            f"- Reviewer: {payload.analyst_user}\n"
            f"- Decision: AI classification accepted as-is\n"
        )
        if payload.analyst_notes:
            note_text += f"- Notes: {payload.analyst_notes}\n"
    else:
        note_text = (
            f"**[OVERRIDDEN] Analyst Review** ({ts}Z)\n\n"
            f"- Reviewer: {payload.analyst_user}\n"
            f"- New status: {payload.override_status}\n"
        )
        if payload.analyst_notes:
            note_text += f"- Notes: {payload.analyst_notes}\n"

    note_resp = requests.post(
        f"{DD_BASE_URL}/api/v2/findings/{fid}/notes/",
        headers=DD_HEADERS_JSON,
        json={"entry": note_text},
        timeout=15,
    )
    if note_resp.status_code not in (200, 201):
        raise HTTPException(status_code=500, detail=f"Note write failed: {note_resp.text}")

    # 2. Update finding status if override
    if payload.decision == "override" and payload.override_status:
        status_map = {
            "false_positive": {"false_p": True,  "active": False, "risk_accepted": False},
            "risk_accepted":  {"false_p": False, "active": False, "risk_accepted": True},
            "active":         {"false_p": False, "active": True,  "risk_accepted": False},
        }
        status_payload = status_map.get(payload.override_status, {})
        if status_payload:
            requests.patch(
                f"{DD_BASE_URL}/api/v2/findings/{fid}/",
                headers=DD_HEADERS_JSON,
                json=status_payload,
                timeout=15,
            )

    # 3. Swap tags — automatic, no manual step required
    swap_analyst_tags(fid)
    log.info(f"[ANALYST] finding {fid} review complete: {payload.decision}")
    return {"status": "ok", "finding_id": fid, "decision": payload.decision}


# ──────────────────────────────────────────────────────────────────────────
# BATCH TRIAGE WITH PROGRESS TRACKING
#
# In-memory job store: job_id -> job dict. This is intentionally simple for
# the current single-replica preprod setup. KNOWN LIMITATION: this resets on
# every container restart, and would not work correctly if this Container
# App were ever scaled to more than one replica (each replica would have its
# own separate memory). Flagged for revisit before real production - the
# natural fix is a small persistent store (e.g. Azure Table Storage) shared
# across replicas, deliberately deferred for now.
# ──────────────────────────────────────────────────────────────────────────

_jobs = {}
_jobs_lock = threading.Lock()


def _run_batch_job(job_id: str, finding_ids: list[int]) -> None:
    with _jobs_lock:
        _jobs[job_id]["status"] = "running"

    for finding_id in finding_ids:
        try:
            process_finding_directly(finding_id)
            with _jobs_lock:
                _jobs[job_id]["completed"] += 1
                _jobs[job_id]["results"].append({"finding_id": finding_id, "status": "succeeded"})
        except Exception as e:
            err_str = str(e)
            if "content_filter" in err_str or "ResponsibleAIPolicyViolation" in err_str:
                log.warning(f"[BATCH {job_id}] finding {finding_id} blocked by content filter — flagging for analyst review")
                try:
                    import requests as _req
                    _note = "**AI Triage Result** — Content filter triggered\n\n- Classification: needs_review\n- Confidence: 0.0\n- Reasoning: Azure OpenAI content filter blocked this prompt. Manual analyst review required.\n- Mitigation: Review manually."
                    _req.post(f"{DD_BASE_URL}/api/v2/findings/{finding_id}/notes/", headers=DD_HEADERS_JSON, json={"entry": _note}, timeout=15)
                    _req.patch(f"{DD_BASE_URL}/api/v2/findings/{finding_id}/", headers=DD_HEADERS_JSON, json={"tags": ["ai-needs_review", "ANALYST_REVIEW_NEEDED"]}, timeout=15)
                except Exception:
                    pass
                with _jobs_lock:
                    _jobs[job_id]["completed"] += 1
                    _jobs[job_id]["results"].append({"finding_id": finding_id, "status": "succeeded", "note": "content_filter_flagged"})
            else:
                log.exception(f"[BATCH {job_id}] finding {finding_id} failed")
                with _jobs_lock:
                    _jobs[job_id]["completed"] += 1
                    _jobs[job_id]["failed"] += 1
                    _jobs[job_id]["results"].append({"finding_id": finding_id, "status": "failed", "error": err_str})

    with _jobs_lock:
        _jobs[job_id]["status"] = "done"


@app.post("/triage/batch")
def start_batch(finding_ids: list[int]):
    """
    Kicks off a batch triage job in a background thread and returns
    immediately with a job_id. The caller (DD's view) polls
    /triage/batch/{job_id}/status to show live progress.
    """
    job_id = str(uuid.uuid4())
    with _jobs_lock:
        _jobs[job_id] = {
            "status": "queued",
            "total": len(finding_ids),
            "completed": 0,
            "failed": 0,
            "results": [],
        }

    thread = threading.Thread(target=_run_batch_job, args=(job_id, finding_ids), daemon=True)
    thread.start()

    return {"job_id": job_id, "total": len(finding_ids)}


@app.get("/triage/batch/{job_id}/status")
@app.get("/batch/{job_id}/status")
def batch_status(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown job_id")
    return job


@app.post("/triage/{finding_id}")
@app.post("/{finding_id}")
def triage_finding(finding_id: int):
    """
    Step A: orchestrator reads the finding and the secrets adapter
    publishes it onto the queue.
    """
    return orchestrate(finding_id)


@app.post("/worker/process-one")
def worker_process_one():
    """
    Step B: the worker dequeues one message, calls the model, validates
    via the Policy Engine, and writes the result back to DefectDojo.
    Call this manually after calling /triage/{finding_id} to see the
    full chain complete.
    """
    return process_one_message()
