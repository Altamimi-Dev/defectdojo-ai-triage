"""
DefectDojo AI Triage — Container App (Triage Engine)
=====================================================
Agentic AI-powered security finding triage for DefectDojo.

Components:
  1. Config / clients        - Key Vault, DefectDojo, Azure OpenAI, Service Bus, AI Search
  2. RAG layer               - Azure AI Search query + context injection
  3. Orchestrator            - reads test_type, routes to the right adapter
  4. Secrets adapter         - detect-secrets findings via direct ADO fetch
  5. SAST adapter            - SAST findings via MCP server tools
  6. Policy Engine           - validates model JSON response + confidence threshold
  7. Write-back              - patches finding in DefectDojo + tags + notes
  8. Analyst Review          - approve/override endpoint with tag swap
  9. Batch engine            - bulk triage with live progress tracking

Environment Variables Required:
  DD_BASE_URL              - DefectDojo base URL
  KEY_VAULT_URI            - Azure Key Vault URI
  AOAI_ENDPOINT            - Azure OpenAI endpoint
  AOAI_DEPLOYMENT          - GPT-4o deployment name
  MCP_SERVER_URL           - Internal MCP server URL
  SEARCH_ENDPOINT          - Azure AI Search endpoint
  SEARCH_ADMIN_KEY         - Azure AI Search admin key (via Key Vault secret)
  SERVICE_BUS_NAMESPACE    - Service Bus namespace FQDN

Key Vault Secrets Required:
  dd-api-token             - DefectDojo API token
  ado-pat                  - Azure DevOps PAT (read-only, Code scope)
  srch-admin-key           - Azure AI Search admin key

ADO Configuration (update below):
  ADO_ORG                  - Azure DevOps organisation name
  ADO_PROJECT              - Azure DevOps project name
  ADO_REPO                 - Repository name
  ADO_BRANCH               - Branch to fetch code from
"""
import os
import json
import logging
import threading
import re
import uuid
import datetime
from datetime import datetime

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from openai import AzureOpenAI
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.servicebus import ServiceBusClient
from azure.search.documents import SearchClient
from azure.search.documents.models import VectorizedQuery
from azure.core.credentials import AzureKeyCredential

# ── LOGGING ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ── CONFIG ────────────────────────────────────────────────────────────────────
DD_BASE_URL           = os.environ["DD_BASE_URL"]
KEY_VAULT_URI         = os.environ["KEY_VAULT_URI"]
AOAI_ENDPOINT         = os.environ["AOAI_ENDPOINT"]
AOAI_DEPLOYMENT       = os.environ.get("AOAI_DEPLOYMENT", "gpt-4o-triage")
MCP_SERVER_URL        = os.environ.get("MCP_SERVER_URL", "")
SERVICE_BUS_NAMESPACE = os.environ.get("SERVICE_BUS_NAMESPACE", "")
SECRETS_QUEUE_NAME    = "secrets-triage"

# ── AZURE DEVOPS CONFIG — UPDATE THESE ────────────────────────────────────────
ADO_ORG     = os.environ.get("ADO_ORG",     "YOUR_ADO_ORG")
ADO_PROJECT = os.environ.get("ADO_PROJECT", "YOUR_ADO_PROJECT")
ADO_REPO    = os.environ.get("ADO_REPO",    "YOUR_ADO_REPO")
ADO_BRANCH  = os.environ.get("ADO_BRANCH",  "main")
ADO_BASE_URL = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/git/repositories/{ADO_REPO}"

# ── CLIENTS ───────────────────────────────────────────────────────────────────
credential = DefaultAzureCredential()
_kv_client = SecretClient(vault_url=KEY_VAULT_URI, credential=credential)


def get_dd_token() -> str:
    return _kv_client.get_secret("dd-api-token").value


def get_ado_pat() -> str:
    return _kv_client.get_secret("ado-pat").value


DD_TOKEN     = get_dd_token()
DD_HEADERS   = {"Authorization": f"Token {DD_TOKEN}"}
DD_HEADERS_JSON = {**DD_HEADERS, "Content-Type": "application/json"}
ADO_PAT      = get_ado_pat()


def get_aoai_token():
    return credential.get_token("https://cognitiveservices.azure.com/.default").token


aoai_client = AzureOpenAI(
    azure_endpoint=AOAI_ENDPOINT,
    azure_ad_token_provider=get_aoai_token,
    api_version="2024-10-21",
)

servicebus_client = ServiceBusClient(
    fully_qualified_namespace=SERVICE_BUS_NAMESPACE,
    credential=credential,
) if SERVICE_BUS_NAMESPACE else None

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
            src        = doc["source"]
            src_id     = doc["source_id"]
            title      = doc["title"]
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


log.info(f"[CONFIG] Azure OpenAI active — model: {AOAI_DEPLOYMENT}")
log.info("[CONFIG] RAG client configured — index: security-knowledge")

# ── FASTAPI APP ───────────────────────────────────────────────────────────────
app = FastAPI(title="DefectDojo AI Triage", version="1.0.0")

# ── TOOL SCHEMAS (OpenAI format) ──────────────────────────────────────────────
FETCH_CODE_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "fetch_code",
        "description": (
            "Fetches a window of lines from a file in the repo around a given line number. "
            "The target line's secret value comes back redacted; surrounding lines are real code."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "file_path":     {"type": "string"},
                "line_number":   {"type": "integer"},
                "context_lines": {"type": "integer", "description": "Lines before/after to include. Default 10."},
            },
            "required": ["file_path", "line_number"],
        },
    },
}

MAX_AGENT_TOOL_CALLS = 4

MCP_TOOL_SCHEMAS = [
    {"type": "function", "function": {"name": "fetch_code",         "description": "Fetch source file from ADO with context around the flagged line.", "parameters": {"type": "object", "properties": {"file_path": {"type": "string"}, "line_number": {"type": "integer"}, "context_lines": {"type": "integer"}}, "required": ["file_path", "line_number"]}}},
    {"type": "function", "function": {"name": "fetch_finding",      "description": "Fetch full finding from DefectDojo including severity, CWE, description, and SAST data flow.", "parameters": {"type": "object", "properties": {"finding_id": {"type": "integer"}}, "required": ["finding_id"]}}},
    {"type": "function", "function": {"name": "fetch_related_file", "description": "Fetch any other file from ADO to verify sanitization logic or upstream validators.", "parameters": {"type": "object", "properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}}},
]

# ── PROMPT TEMPLATES ──────────────────────────────────────────────────────────
SECRETS_PROMPT_TEMPLATE = """You are a security triage assistant reviewing a detect-secrets finding.
The actual secret value has been redacted - you will never see it. You have no
internet access and must reason only from the metadata below and the code context
you fetch, the same way an experienced security reviewer would.

Rule that fired: {rule_name}
File: {file_path}
Line: {line_number}
Severity reported by scanner: {severity}

{rag_context}

You do NOT have the code at this line yet. You have a tool, fetch_code, that returns
a window of lines from the file around a given line number. Call fetch_code before
making your decision - you cannot reliably classify a hardcoded-credential finding
without seeing the key name and surrounding context.

IMPORTANT: For hardcoded-credential findings (CWE-798), the vulnerability is the act
of hardcoding a credential-shaped value in source code regardless of how it looks.
The only valid grounds for false_positive are that the value is verifiably NOT a
functioning credential (e.g. a documentation example, a test fixture with explicit
placeholder comment, or a vendor-documented test key with 'EXAMPLE' in the name).

Classify as: true_positive / false_positive / needs_review

Respond ONLY with valid JSON:
{{"classification": "...", "confidence": 0.0-1.0, "reasoning": "...", "mitigation": "...", "cwe_reference": "CWE-XXX", "references": "..."}}
"""

SAST_PROMPT_TEMPLATE = """
You are a senior application security engineer triaging a SAST finding.
You have three tools available:
  fetch_code        — fetch the vulnerable file with context around the flagged line
  fetch_finding     — fetch the full finding record from DefectDojo (CWE, description, data flow)
  fetch_related_file — fetch any other file (e.g. validators, sanitizers, upstream callers)

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
Step 4 — Classify as one of: true_positive / false_positive / needs_review.

Respond ONLY with valid JSON:
{{"classification": "...", "confidence": 0.0-1.0, "reasoning": "...", "mitigation": "...", "cwe_reference": "CWE-XXX", "references": "..."}}
"""

# ── DEFECTDOJO HELPERS ────────────────────────────────────────────────────────
def fetch_finding(finding_id: int) -> dict:
    resp = __import__("requests").get(
        f"{DD_BASE_URL}/api/v2/findings/{finding_id}/",
        headers=DD_HEADERS_JSON,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def get_test_type_name(test_id: int) -> str:
    resp = __import__("requests").get(
        f"{DD_BASE_URL}/api/v2/tests/{test_id}/",
        headers=DD_HEADERS_JSON,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json().get("test_type_name", "")


# ── ADO CODE FETCH ────────────────────────────────────────────────────────────
def fetch_code_from_repo(file_path: str, line_number: int, context_lines: int = 10) -> dict:
    import requests as req
    import base64
    url = f"{ADO_BASE_URL}/items?path={file_path}&versionDescriptor.version={ADO_BRANCH}&api-version=7.1"
    credentials = base64.b64encode(f":{ADO_PAT}".encode()).decode()
    headers = {"Authorization": f"Basic {credentials}"}
    resp = req.get(url, headers=headers, timeout=15)
    if resp.status_code != 200:
        return {"error": f"ADO returned {resp.status_code}", "file_path": file_path}
    lines = resp.text.splitlines()
    start = max(0, line_number - context_lines - 1)
    end   = min(len(lines), line_number + context_lines)
    snippet = []
    for i, line in enumerate(lines[start:end], start=start + 1):
        if i == line_number:
            snippet.append(f"{i}: [REDACTED]")
        else:
            snippet.append(f"{i}: {line}")
    return {"file_path": file_path, "line_number": line_number, "snippet": "\n".join(snippet)}


# ── MCP TOOL CALLER ───────────────────────────────────────────────────────────
def call_mcp_tool(tool_name: str, args: dict) -> dict:
    import requests as req
    resp = req.post(f"{MCP_SERVER_URL}/tools/{tool_name}", json=args, timeout=30)
    resp.raise_for_status()
    return resp.json()


# ── ANALYST REVIEW HELPERS ────────────────────────────────────────────────────
def should_flag_for_review(result: dict) -> bool:
    return result.get("confidence", 1.0) < 0.7 or result.get("classification") == "needs_review"


def is_pending_analyst_review(finding_id: int) -> bool:
    import requests as req
    resp = req.get(f"{DD_BASE_URL}/api/v2/findings/{finding_id}/", headers=DD_HEADERS_JSON, timeout=10)
    if resp.status_code == 200:
        return "ANALYST_REVIEW_NEEDED" in resp.json().get("tags", [])
    return False


def swap_analyst_tags(finding_id: int) -> None:
    import requests as req
    resp = req.get(f"{DD_BASE_URL}/api/v2/findings/{finding_id}/", headers=DD_HEADERS_JSON, timeout=10)
    existing = resp.json().get("tags", []) if resp.status_code == 200 else []
    updated = [t for t in existing if t != "ANALYST_REVIEW_NEEDED"]
    if "ANALYST_REVIEWED" not in updated:
        updated.append("ANALYST_REVIEWED")
    req.patch(f"{DD_BASE_URL}/api/v2/findings/{finding_id}/", headers=DD_HEADERS_JSON, json={"tags": updated}, timeout=10)
    log.info(f"[ANALYST] finding {finding_id} tags updated → {updated}")


# ── WRITE-BACK ────────────────────────────────────────────────────────────────
def write_back_to_dd(finding_id: int, result: dict) -> None:
    import requests as req
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
        log.info(f"[WRITE-BACK] finding {finding_id} flagged for analyst review (confidence={result['confidence']})")
    req.patch(
        f"{DD_BASE_URL}/api/v2/findings/{finding_id}/",
        headers=DD_HEADERS_JSON,
        json={"tags": tags, "mitigation": result["mitigation"], "references": result.get("references", "")},
        timeout=15,
    )
    req.post(
        f"{DD_BASE_URL}/api/v2/findings/{finding_id}/notes/",
        headers=DD_HEADERS_JSON,
        json={"entry": note_text},
        timeout=15,
    )
    log.info(f"[WRITE-BACK] finding {finding_id} updated with classification={result['classification']}")


# ── POLICY ENGINE ─────────────────────────────────────────────────────────────
VALID_CLASSIFICATIONS = {"true_positive", "false_positive", "needs_review"}
CONFIDENCE_THRESHOLD  = 0.7


def policy_engine_validate(model_result: dict) -> dict:
    classification = model_result.get("classification", "needs_review")
    confidence     = float(model_result.get("confidence", 0.5))
    if classification not in VALID_CLASSIFICATIONS:
        model_result["classification"] = "needs_review"
    elif classification in ("true_positive", "false_positive") and confidence < CONFIDENCE_THRESHOLD:
        log.info(f"[POLICY ENGINE] downgrading {classification} (confidence={confidence}) to needs_review")
        model_result["classification"] = "needs_review"
    else:
        log.info(f"[POLICY ENGINE] validated OK: {classification} ({confidence})")
    return model_result


# ── SECRETS ADAPTER ───────────────────────────────────────────────────────────
def call_model(enriched_finding: dict) -> dict:
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
        response = aoai_client.chat.completions.create(
            model=AOAI_DEPLOYMENT,
            messages=messages,
            temperature=0,
            tools=None if force_final_answer else [FETCH_CODE_TOOL_SCHEMA],
            tool_choice="none" if force_final_answer else "auto",
            response_format={"type": "json_object"} if force_final_answer else None,
        )
        choice = response.choices[0]
        messages.append(choice.message.model_dump(exclude_none=True))
        if not choice.message.tool_calls:
            raw_content = choice.message.content or ""
            log.info(f"[AGENT] final response after {call_count} tool call(s): {raw_content}")
            if not raw_content.strip():
                return {"classification": "needs_review", "confidence": 0.5, "reasoning": "Model returned empty response.", "mitigation": "Review manually.", "cwe_reference": "CWE-unknown", "references": ""}
            try:
                return json.loads(raw_content)
            except json.JSONDecodeError:
                m = re.search(r'\{.*\}', raw_content, re.DOTALL)
                if m:
                    return json.loads(m.group())
                return {"classification": "needs_review", "confidence": 0.5, "reasoning": raw_content[:500], "mitigation": "Review manually.", "cwe_reference": "CWE-unknown", "references": ""}
        for tool_call in choice.message.tool_calls:
            args = json.loads(tool_call.function.arguments)
            log.info(f"[AGENT] calling fetch_code with args: {args}")
            tool_result = fetch_code_from_repo(
                file_path=args.get("file_path", enriched_finding.get("file_path", "")),
                line_number=args.get("line_number", enriched_finding.get("line_number", 0)),
                context_lines=args.get("context_lines", 10),
            )
            messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": json.dumps(tool_result)})
    raise HTTPException(status_code=502, detail="Agent did not produce a final classification within the tool-call budget.")


# ── SAST ADAPTER ──────────────────────────────────────────────────────────────
def call_model_sast(enriched_finding: dict) -> dict:
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
        response = aoai_client.chat.completions.create(
            model=AOAI_DEPLOYMENT, messages=messages, temperature=0,
            tools=None if force_final_answer else MCP_TOOL_SCHEMAS,
            tool_choice="none" if force_final_answer else "auto",
            response_format={"type": "json_object"} if force_final_answer else None,
        )
        choice = response.choices[0]
        messages.append(choice.message.model_dump(exclude_none=True))
        if not choice.message.tool_calls:
            raw_content = choice.message.content or ""
            log.info(f"[SAST AGENT] final response after {call_count} tool call(s): {raw_content}")
            if not raw_content.strip():
                return {"classification": "needs_review", "confidence": 0.5, "reasoning": "Model returned empty response.", "mitigation": "Review manually.", "cwe_reference": "CWE-unknown", "references": ""}
            try:
                return json.loads(raw_content)
            except json.JSONDecodeError:
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


def sast_adapter(finding: dict) -> dict:
    enriched = {
        "finding_id": finding["id"],
        "adapter":    "sast",
        "rule_name":  finding.get("vuln_id_from_tool") or finding.get("title", ""),
        "file_path":  finding.get("file_path", ""),
        "line_number": finding.get("line"),
        "severity":   finding.get("severity", ""),
    }
    result    = call_model_sast(enriched)
    validated = policy_engine_validate(result)
    write_back_to_dd(enriched["finding_id"], validated)
    return validated


def _process_enriched_finding(enriched: dict) -> dict:
    result    = call_model(enriched)
    validated = policy_engine_validate(result)
    write_back_to_dd(enriched["finding_id"], validated)
    return validated


# ── ROUTER ────────────────────────────────────────────────────────────────────
def process_finding_directly(finding_id: int) -> dict:
    if is_pending_analyst_review(finding_id):
        log.info(f"[DIRECT] skipping finding {finding_id} — pending analyst review")
        return {"status": "skipped", "reason": "pending_analyst_review", "finding_id": finding_id}
    finding        = fetch_finding(finding_id)
    test_id        = finding["test"]
    test_type_name = get_test_type_name(test_id)
    if "detect-secrets" in test_type_name.lower():
        enriched = {
            "finding_id": finding["id"],
            "adapter":    "secrets",
            "rule_name":  finding.get("vuln_id_from_tool") or finding.get("title", ""),
            "file_path":  finding.get("file_path", ""),
            "line_number": finding.get("line"),
            "severity":   finding.get("severity", ""),
        }
        log.info(f"[DIRECT] routing finding {finding_id} to secrets adapter")
        return _process_enriched_finding(enriched)
    elif any(x in test_type_name.lower() for x in ["sast", "semgrep", "sonarqube", "checkmarx", "bandit", "codeql", "sarif"]):
        log.info(f"[DIRECT] routing finding {finding_id} to sast_adapter")
        return sast_adapter(finding)
    else:
        raise HTTPException(status_code=400, detail=f"No adapter configured for test_type '{test_type_name}'.")


# ── HTTP ENDPOINTS ────────────────────────────────────────────────────────────
@app.get("/")
def health():
    return {"status": "ok", "service": "defectdojo-ai-triage", "version": "1.0.0"}


# ── ANALYST REVIEW ENDPOINT ───────────────────────────────────────────────────
class AnalystReviewPayload(BaseModel):
    finding_id:      int
    decision:        str
    override_status: str = ""
    analyst_notes:   str = ""
    analyst_user:    str = "analyst"


@app.post("/analyst/review")
async def analyst_review(payload: AnalystReviewPayload):
    import requests as req
    fid = payload.finding_id
    log.info(f"[ANALYST] review received for finding {fid}: decision={payload.decision}")
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
    note_resp = req.post(f"{DD_BASE_URL}/api/v2/findings/{fid}/notes/", headers=DD_HEADERS_JSON, json={"entry": note_text}, timeout=15)
    if note_resp.status_code not in (200, 201):
        raise HTTPException(status_code=500, detail=f"Note write failed: {note_resp.text}")
    if payload.decision == "override" and payload.override_status:
        status_map = {
            "false_positive": {"false_p": True,  "active": False, "risk_accepted": False},
            "risk_accepted":  {"false_p": False, "active": False, "risk_accepted": True},
            "active":         {"false_p": False, "active": True,  "risk_accepted": False},
        }
        if payload.override_status in status_map:
            req.patch(f"{DD_BASE_URL}/api/v2/findings/{fid}/", headers=DD_HEADERS_JSON, json=status_map[payload.override_status], timeout=15)
    swap_analyst_tags(fid)
    log.info(f"[ANALYST] finding {fid} review complete: {payload.decision}")
    return {"status": "ok", "finding_id": fid, "decision": payload.decision}


# ── BATCH TRIAGE ──────────────────────────────────────────────────────────────
_jobs: dict = {}


class BatchTriageRequest(BaseModel):
    finding_ids: list[int] = []
    test_id:     int = 0
    limit:       int = 25


def _run_batch_job(job_id: str, finding_ids: list):
    job = _jobs[job_id]
    job["total"]  = len(finding_ids)
    job["status"] = "running"
    for fid in finding_ids:
        try:
            process_finding_directly(fid)
            job["completed"] += 1
        except Exception as e:
            log.error(f"[BATCH {job_id}] finding {fid} failed\n{e}", exc_info=True)
            job["failed"] += 1
        job["results"].append({"finding_id": fid, "status": "succeeded" if job["failed"] == 0 else "failed"})
    job["status"] = "done"
    log.info(f"[BATCH {job_id}] done — completed={job['completed']} failed={job['failed']}")


@app.post("/triage/batch")
@app.post("/batch")
async def triage_batch(request: BatchTriageRequest):
    import requests as req
    finding_ids = request.finding_ids
    if not finding_ids and request.test_id:
        resp = req.get(f"{DD_BASE_URL}/api/v2/findings/?test={request.test_id}&active=true&limit={request.limit}", headers=DD_HEADERS_JSON, timeout=15)
        finding_ids = [f["id"] for f in resp.json().get("results", [])]
    job_id = str(uuid.uuid4())
    _jobs[job_id] = {"status": "queued", "total": 0, "completed": 0, "failed": 0, "results": []}
    threading.Thread(target=_run_batch_job, args=(job_id, finding_ids), daemon=True).start()
    return {"job_id": job_id, "finding_count": len(finding_ids)}


@app.get("/triage/batch/{job_id}/status")
@app.get("/batch/{job_id}/status")
def batch_status(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "status":    job["status"],
        "total":     job["total"],
        "completed": job["completed"],
        "failed":    job["failed"],
        "results":   job["results"],
    }


@app.post("/triage/{finding_id}")
@app.post("/{finding_id}")
def triage_finding(finding_id: int):
    return process_finding_directly(finding_id)
