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
from datetime import datetime

import requests
from fastapi import FastAPI, HTTPException
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.servicebus import ServiceBusClient, ServiceBusMessage
from openai import AzureOpenAI

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("triage")

app = FastAPI(title="AI Triage Demo - Detect Secrets")

# ──────────────────────────────────────────────────────────────────────────
# 1. CONFIG / CLIENTS
# ──────────────────────────────────────────────────────────────────────────

KEY_VAULT_URI = os.environ["KEY_VAULT_URI"]              # e.g. https://kv-khan-triage-demo.vault.azure.net/
DD_BASE_URL = os.environ["DD_BASE_URL"]                  # e.g. http://35.202.90.152:8080
SERVICE_BUS_NAMESPACE = os.environ["SERVICE_BUS_NAMESPACE"]  # e.g. sb-khan-triage-demo.servicebus.windows.net
AOAI_ENDPOINT = os.environ["AOAI_ENDPOINT"]               # e.g. https://aoai-khan-triage-demo.openai.azure.com/
AOAI_DEPLOYMENT = os.environ.get("AOAI_DEPLOYMENT", "gpt-4o-triage")

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
)


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
    This is the ONLY adapter in this demo, and it never calls the repo
    connector - the secret value is already in the finding's description,
    so there is nothing to fetch from a repository.
    """
    description = finding.get("description") or ""
    code_line = ""
    if "**Code Line:**" in description:
        try:
            code_block = description.split("**Code Line:**")[1]
            code_line = code_block.split("```")[1].strip()
        except IndexError:
            code_line = ""

    enriched = {
        "finding_id": finding["id"],
        "adapter": "secrets",
        "rule_name": finding.get("vuln_id_from_tool") or finding.get("title", ""),
        "file_path": finding.get("file_path", ""),
        "line_number": finding.get("line"),
        "redacted_code_line": redact_secret_value(code_line),
        "severity": finding.get("severity", ""),
    }
    log.info(f"[SECRETS ADAPTER] enriched finding ready, secret value redacted: {enriched}")
    return publish_to_queue(enriched)


def publish_to_queue(enriched_finding: dict) -> dict:
    """Publishes the enriched finding onto the secrets-triage Service Bus queue."""
    with servicebus_client.get_queue_sender(queue_name=SECRETS_QUEUE_NAME) as sender:
        message = ServiceBusMessage(json.dumps(enriched_finding))
        sender.send_messages(message)
    log.info(f"[QUEUE] published finding {enriched_finding['finding_id']} to '{SECRETS_QUEUE_NAME}'")
    return {"status": "queued", "finding_id": enriched_finding["finding_id"]}


# ──────────────────────────────────────────────────────────────────────────
# 4. WORKER
# ──────────────────────────────────────────────────────────────────────────

SECRETS_PROMPT_TEMPLATE = """You are a security triage assistant reviewing a detect-secrets finding.
The actual secret value has been redacted - you will never see it.

Rule that fired: {rule_name}
File: {file_path}
Line: {line_number}
Redacted code line: {redacted_code_line}
Severity reported by scanner: {severity}

Based only on this metadata, classify this finding. Respond with ONLY valid JSON,
no other text, matching exactly this schema:
{{
  "classification": "true_positive" | "false_positive" | "needs_review",
  "confidence": <float between 0 and 1>,
  "reasoning": "<one or two sentences>",
  "mitigation": "<one or two sentences of recommended action>",
  "cwe_reference": "<CWE id, e.g. CWE-798>"
}}
"""


def call_model(enriched_finding: dict) -> dict:
    """Calls Azure OpenAI with a fixed prompt template and temperature 0."""
    prompt = SECRETS_PROMPT_TEMPLATE.format(
        rule_name=enriched_finding.get("rule_name", "unknown"),
        file_path=enriched_finding.get("file_path", "unknown"),
        line_number=enriched_finding.get("line_number", "unknown"),
        redacted_code_line=enriched_finding.get("redacted_code_line", ""),
        severity=enriched_finding.get("severity", "unknown"),
    )

    response = aoai_client.chat.completions.create(
        model=AOAI_DEPLOYMENT,
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
        response_format={"type": "json_object"},
    )
    raw_content = response.choices[0].message.content
    log.info(f"[WORKER] model raw response: {raw_content}")
    return json.loads(raw_content)


def process_one_message() -> dict:
    """
    Pulls exactly one message off the secrets-triage queue, calls the model,
    validates the result, and writes it back to DefectDojo. Built as a
    single synchronous call for the demo, so you can trigger it manually
    and see the whole chain happen in one request.
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

        model_result = call_model(enriched_finding)
        validated_result = policy_engine_validate(model_result)

        write_back_to_dd(enriched_finding["finding_id"], validated_result)

        receiver.complete_message(msg)
        return {
            "status": "triaged",
            "finding_id": enriched_finding["finding_id"],
            "result": validated_result,
        }


# ──────────────────────────────────────────────────────────────────────────
# 5. POLICY ENGINE
# ──────────────────────────────────────────────────────────────────────────

VALID_CLASSIFICATIONS = {"true_positive", "false_positive", "needs_review"}
CONFIDENCE_THRESHOLD = 0.6


def policy_engine_validate(model_result: dict) -> dict:
    """
    Validates the model's JSON response before it's allowed anywhere near
    DefectDojo. If the shape is wrong or confidence is too low, downgrade
    to needs_review rather than trusting an uncertain or malformed answer.
    """
    required_fields = {"classification", "confidence", "reasoning", "mitigation", "cwe_reference"}
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

    if confidence < CONFIDENCE_THRESHOLD:
        log.warning(f"[POLICY ENGINE] confidence {confidence} below threshold {CONFIDENCE_THRESHOLD}")
        return _needs_review_fallback(model_result, reason=f"confidence {confidence} below threshold")

    log.info(f"[POLICY ENGINE] validated OK: {model_result['classification']} ({confidence})")
    return model_result


def _needs_review_fallback(original: dict, reason: str) -> dict:
    return {
        "classification": "needs_review",
        "confidence": original.get("confidence", 0),
        "reasoning": f"Policy Engine override: {reason}. Original model output: {original}",
        "mitigation": "Manual review required - automated triage did not meet confidence/schema requirements.",
        "cwe_reference": original.get("cwe_reference", "N/A"),
    }


# ──────────────────────────────────────────────────────────────────────────
# 6. WRITE-BACK
# ──────────────────────────────────────────────────────────────────────────

def write_back_to_dd(finding_id: int, result: dict) -> None:
    """Patches the finding in DefectDojo with the AI triage result."""
    note_text = (
        f"**AI Triage Result** ({datetime.utcnow().isoformat()}Z)\n\n"
        f"- Classification: {result['classification']}\n"
        f"- Confidence: {result['confidence']}\n"
        f"- Reasoning: {result['reasoning']}\n"
        f"- Mitigation: {result['mitigation']}\n"
        f"- CWE: {result['cwe_reference']}\n"
    )

    requests.patch(
        f"{DD_BASE_URL}/api/v2/findings/{finding_id}/",
        headers=DD_HEADERS_JSON,
        json={"tags": [f"ai-{result['classification']}"]},
        timeout=15,
    )

    requests.post(
        f"{DD_BASE_URL}/api/v2/notes/",
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


@app.post("/triage/{finding_id}")
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
