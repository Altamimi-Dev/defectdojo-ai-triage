"""
DefectDojo AI Triage — MCP Server
===================================
Internal-only Container App that exposes three tools to the SAST adapter:

  POST /tools/fetch_finding      - fetch full finding from DefectDojo
  POST /tools/fetch_code         - fetch source file from ADO with context
  POST /tools/fetch_related_file - fetch any related file from ADO

All credentials retrieved from Azure Key Vault via Managed Identity.
No credentials stored in this code.

Environment Variables Required:
  KEY_VAULT_URI   - Azure Key Vault URI
  DD_BASE_URL     - DefectDojo base URL

Key Vault Secrets Required:
  dd-api-token    - DefectDojo API token
  ado-pat         - Azure DevOps PAT (read-only, Code scope)

ADO Configuration (update below):
  ADO_ORG         - Azure DevOps organisation
  ADO_PROJECT     - Project name
  ADO_REPO        - Repository name
  ADO_BRANCH      - Branch to fetch from
"""
import os
import base64
import logging

import requests
from fastapi import FastAPI, HTTPException
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# ── LOGGING ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ── CONFIG ────────────────────────────────────────────────────────────────────
KEY_VAULT_URI = os.environ["KEY_VAULT_URI"]
DD_BASE_URL   = os.environ["DD_BASE_URL"]

# ── AZURE DEVOPS CONFIG — UPDATE THESE ────────────────────────────────────────
ADO_ORG     = os.environ.get("ADO_ORG",     "YOUR_ADO_ORG")
ADO_PROJECT = os.environ.get("ADO_PROJECT", "YOUR_ADO_PROJECT")
ADO_REPO    = os.environ.get("ADO_REPO",    "YOUR_ADO_REPO")
ADO_BRANCH  = os.environ.get("ADO_BRANCH",  "main")
ADO_BASE_URL = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/git/repositories/{ADO_REPO}"

# ── CLIENTS ───────────────────────────────────────────────────────────────────
credential = DefaultAzureCredential()
kv_client  = SecretClient(vault_url=KEY_VAULT_URI, credential=credential)

DD_TOKEN  = kv_client.get_secret("dd-api-token").value
ADO_PAT   = kv_client.get_secret("ado-pat").value

DD_HEADERS = {"Authorization": f"Token {DD_TOKEN}", "Content-Type": "application/json"}

# ── APP ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="AI Triage MCP Server", version="1.0.0")


@app.get("/")
def health():
    return {"status": "ok", "service": "mcp-server"}


@app.get("/tools")
def list_tools():
    return {
        "tools": [
            {
                "name": "fetch_finding",
                "description": "Fetch full finding from DefectDojo including CWE, severity, description, and SAST data flow.",
                "parameters": {"finding_id": "integer"},
            },
            {
                "name": "fetch_code",
                "description": "Fetch source file from ADO with context around the flagged line. Secret values are REDACTED.",
                "parameters": {"file_path": "string", "line_number": "integer", "context_lines": "integer (optional, default 10)"},
            },
            {
                "name": "fetch_related_file",
                "description": "Fetch any file from ADO — useful for checking sanitizers, validators, or upstream callers.",
                "parameters": {"file_path": "string"},
            },
        ]
    }


@app.post("/tools/fetch_finding")
def tool_fetch_finding(payload: dict):
    finding_id = payload.get("finding_id")
    if not finding_id:
        raise HTTPException(status_code=400, detail="finding_id required")
    resp = requests.get(f"{DD_BASE_URL}/api/v2/findings/{finding_id}/", headers=DD_HEADERS, timeout=15)
    if resp.status_code != 200:
        return {"error": f"DefectDojo returned {resp.status_code}", "finding_id": finding_id}
    data = resp.json()
    return {
        "finding_id":   finding_id,
        "title":        data.get("title", ""),
        "severity":     data.get("severity", ""),
        "cwe":          data.get("cwe", ""),
        "description":  data.get("description", ""),
        "mitigation":   data.get("mitigation", ""),
        "references":   data.get("references", ""),
        "file_path":    data.get("file_path", ""),
        "line":         data.get("line", ""),
        "vuln_id":      data.get("vuln_id_from_tool", ""),
    }


@app.post("/tools/fetch_code")
def tool_fetch_code(payload: dict):
    file_path     = payload.get("file_path", "")
    line_number   = int(payload.get("line_number", 0))
    context_lines = int(payload.get("context_lines", 10))
    if not file_path:
        raise HTTPException(status_code=400, detail="file_path required")
    url = f"{ADO_BASE_URL}/items?path={file_path}&versionDescriptor.version={ADO_BRANCH}&api-version=7.1"
    credentials = base64.b64encode(f":{ADO_PAT}".encode()).decode()
    headers = {"Authorization": f"Basic {credentials}"}
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code != 200:
        return {"error": f"ADO returned {resp.status_code}", "file_path": file_path}
    lines = resp.text.splitlines()
    start = max(0, line_number - context_lines - 1)
    end   = min(len(lines), line_number + context_lines)
    snippet = []
    for i, line in enumerate(lines[start:end], start=start + 1):
        if i == line_number:
            snippet.append(f"{i}: [REDACTED — secret value not shown]")
        else:
            snippet.append(f"{i}: {line}")
    return {
        "file_path":   file_path,
        "line_number": line_number,
        "snippet":     "\n".join(snippet),
        "total_lines": len(lines),
    }


@app.post("/tools/fetch_related_file")
def tool_fetch_related_file(payload: dict):
    file_path = payload.get("file_path", "")
    if not file_path:
        raise HTTPException(status_code=400, detail="file_path required")
    url = f"{ADO_BASE_URL}/items?path={file_path}&versionDescriptor.version={ADO_BRANCH}&api-version=7.1"
    credentials = base64.b64encode(f":{ADO_PAT}".encode()).decode()
    headers = {"Authorization": f"Basic {credentials}"}
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code != 200:
        return {"error": f"ADO returned {resp.status_code}", "file_path": file_path}
    content = resp.text
    # Limit response size to avoid token overflow
    if len(content) > 8000:
        content = content[:8000] + "\n... [truncated]"
    return {"file_path": file_path, "content": content}
