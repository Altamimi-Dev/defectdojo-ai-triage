import base64
import logging
import os
import re
import requests
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

app = FastAPI(title="AI Triage MCP Server", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

KEY_VAULT_URI = os.environ.get("KEY_VAULT_URI", "https://kv-khan-triage-demo.vault.azure.net/")
DD_BASE_URL   = os.environ.get("DD_BASE_URL", "http://YOUR_DEFECTDOJO_HOST:8080")
ADO_ORG       = os.environ.get("ADO_ORG", "YOUR_ADO_ORG")
ADO_PROJECT   = os.environ.get("ADO_PROJECT", "YOUR_ADO_PROJECT")
ADO_REPO      = os.environ.get("ADO_REPO", "YOUR_ADO_REPO")
ADO_BRANCH    = os.environ.get("ADO_BRANCH", "main")
CONTEXT_LINES = int(os.environ.get("CONTEXT_LINES", "15"))
DD_HEADERS    = {"Content-Type": "application/json"}

_secret_cache: dict = {}

def get_secret(name: str) -> str:
    if name not in _secret_cache:
        credential = ManagedIdentityCredential()
        client = SecretClient(vault_url=KEY_VAULT_URI, credential=credential)
        _secret_cache[name] = client.get_secret(name).value
        log.info(f"Fetched secret '{name}' from Key Vault")
    return _secret_cache[name]

def get_dd_token() -> str:
    return get_secret("dd-api-token")

def get_ado_pat() -> str:
    return get_secret("ado-pat")

def ado_auth_header() -> str:
    pat = get_ado_pat()
    encoded = base64.b64encode(f":{pat}".encode()).decode()
    return f"Basic {encoded}"

def redact_secret_value(line: str) -> str:
    return re.sub(r'(=|:)\s*["\']?([A-Za-z0-9+/=_\-]{8,})["\']?', r'\1 [REDACTED]', line)

def _fetch_ado_file(file_path: str, repo: str, branch: str) -> str:
    repo   = repo or ADO_REPO
    branch = branch or ADO_BRANCH
    url    = f"https://dev.azure.com/{ADO_ORG}/{ADO_PROJECT}/_apis/git/repositories/{repo}/items"
    params = {"path": file_path, "versionDescriptor.version": branch, "versionDescriptor.versionType": "branch", "includeContent": "true", "api-version": "7.1"}
    resp = requests.get(url, headers={"Authorization": ado_auth_header()}, params=params, timeout=30)
    resp.raise_for_status()
    return resp.text

class FetchCodeRequest(BaseModel):
    file_path: str
    line_number: int
    context_lines: int = CONTEXT_LINES
    repo: str = ""
    branch: str = ""

class FetchFindingRequest(BaseModel):
    finding_id: int

class FetchRelatedFileRequest(BaseModel):
    file_path: str
    repo: str = ""
    branch: str = ""

@app.get("/health")
def health():
    return {"status": "ok", "service": "mcp-server"}

@app.get("/tools")
def list_tools():
    return {"tools": [
        {"name": "fetch_code", "description": "Fetch source file from ADO repo with context around the flagged line. The flagged line value is redacted.", "inputSchema": {"type": "object", "properties": {"file_path": {"type": "string"}, "line_number": {"type": "integer"}, "context_lines": {"type": "integer", "default": 15}, "repo": {"type": "string"}, "branch": {"type": "string"}}, "required": ["file_path", "line_number"]}},
        {"name": "fetch_finding", "description": "Fetch full finding record from DefectDojo including severity, CWE, description, and SAST data flow.", "inputSchema": {"type": "object", "properties": {"finding_id": {"type": "integer"}}, "required": ["finding_id"]}},
        {"name": "fetch_related_file", "description": "Fetch any file from ADO repo to verify sanitization logic, validators, or configuration.", "inputSchema": {"type": "object", "properties": {"file_path": {"type": "string"}, "repo": {"type": "string"}, "branch": {"type": "string"}}, "required": ["file_path"]}},
    ]}

@app.post("/tools/fetch_code")
def tool_fetch_code(req: FetchCodeRequest):
    log.info(f"[fetch_code] {req.file_path}:{req.line_number}")
    try:
        full_content = _fetch_ado_file(req.file_path, req.repo, req.branch)
        lines = full_content.splitlines()
        start = max(0, req.line_number - 1 - req.context_lines)
        end   = min(len(lines), req.line_number + req.context_lines)
        result_lines = []
        for i, line in enumerate(lines[start:end], start=start + 1):
            if i == req.line_number:
                result_lines.append(f">>> {i}: {redact_secret_value(line)}")
            else:
                result_lines.append(f"    {i}: {line}")
        return {"tool": "fetch_code", "file_path": req.file_path, "line_number": req.line_number, "total_lines": len(lines), "content": "\n".join(result_lines)}
    except requests.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"ADO fetch failed: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tools/fetch_finding")
def tool_fetch_finding(req: FetchFindingRequest):
    log.info(f"[fetch_finding] finding_id={req.finding_id}")
    try:
        token = get_dd_token()
        resp = requests.get(f"{DD_BASE_URL}/api/v2/findings/{req.finding_id}/", headers={**DD_HEADERS, "Authorization": f"Token {token}"}, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        return {"tool": "fetch_finding", "finding_id": req.finding_id, "title": data.get("title"), "severity": data.get("severity"), "cwe": data.get("cwe"), "description": data.get("description"), "file_path": data.get("file_path"), "line": data.get("line"), "references": data.get("references")}
    except requests.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"DefectDojo fetch failed: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tools/fetch_related_file")
def tool_fetch_related_file(req: FetchRelatedFileRequest):
    log.info(f"[fetch_related_file] {req.file_path}")
    try:
        content = _fetch_ado_file(req.file_path, req.repo, req.branch)
        lines = content.splitlines()
        numbered = "\n".join(f"    {i+1}: {line}" for i, line in enumerate(lines))
        return {"tool": "fetch_related_file", "file_path": req.file_path, "total_lines": len(lines), "content": numbered}
    except requests.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"ADO fetch failed: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/fetch_epss")
def tool_fetch_epss(payload: dict):
    """Fetch live EPSS score for a CVE from FIRST.org API."""
    import requests as req
    cve_id = payload.get("cve_id", "")
    if not cve_id:
        return {"error": "cve_id required"}
    try:
        resp = req.get(
            "https://api.first.org/data/v1/epss?cve=" + cve_id,
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            if data:
                epss_score = float(data[0].get("epss", 0))
                percentile  = float(data[0].get("percentile", 0))
                date        = data[0].get("date", "")
                if epss_score >= 0.9:
                    risk_label = "CRITICAL — exploit imminent"
                elif epss_score >= 0.5:
                    risk_label = "HIGH — likely to be exploited"
                elif epss_score >= 0.1:
                    risk_label = "MEDIUM — possible exploitation"
                else:
                    risk_label = "LOW — unlikely to be exploited"
                pct_str = str(round(epss_score * 100, 1))
                top_str = str(round((1 - percentile) * 100, 1))
                return {
                    "cve_id":       cve_id,
                    "epss_score":   epss_score,
                    "percentile":   percentile,
                    "date":         date,
                    "risk_label":   risk_label,
                    "interpretation": "There is a " + pct_str + "% probability this CVE will be exploited in the next 30 days (top " + top_str + "% of all CVEs by exploitation likelihood)."
                }
            return {"cve_id": cve_id, "epss_score": None, "error": "CVE not found in EPSS database"}
        return {"error": "EPSS API returned " + str(resp.status_code), "cve_id": cve_id}
    except Exception as e:
        return {"error": str(e), "cve_id": cve_id}


@app.post("/tools/analyze_reachability")
def tool_analyze_reachability(payload: dict):
    """
    Analyze if the vulnerable code at a given line is reachable
    from HTTP entry points using tree-sitter AST analysis.
    Supports Python and JavaScript.
    """
    file_path    = payload.get("file_path", "")
    line_number  = int(payload.get("line_number", 0))
    language     = payload.get("language", "python").lower()

    if not file_path:
        return {"error": "file_path required"}

    # 1. Fetch the file from ADO
    try:
        source_code = _fetch_ado_file(file_path, ADO_REPO, ADO_BRANCH)
    except Exception as e:
        return {"error": f"Could not fetch file: {e}", "is_reachable": None}

    # 2. Parse with tree-sitter
    try:
        if language in ("python", "py"):
            import tree_sitter_python as ts_lang
        elif language in ("javascript", "js", "typescript", "ts"):
            import tree_sitter_javascript as ts_lang
        else:
            return {"error": f"Unsupported language: {language}", "is_reachable": None}

        from tree_sitter import Language, Parser
        LANG   = Language(ts_lang.language())
        parser = Parser(LANG)
        tree   = parser.parse(bytes(source_code, "utf-8"))
        root   = tree.root_node
    except Exception as e:
        return {"error": f"Parse error: {e}", "is_reachable": None}

    lines = source_code.splitlines()

    # 3. Find the function/method that contains the vulnerable line
    def find_containing_function(node, target_line):
        fn_types = {"function_definition", "method_definition",
                    "function_declaration", "arrow_function"}
        result = None
        if node.type in fn_types:
            start = node.start_point[0] + 1
            end   = node.end_point[0] + 1
            if start <= target_line <= end:
                for child in node.children:
                    if child.type in ("identifier", "property_identifier"):
                        result = {
                            "name":       child.text.decode("utf-8"),
                            "start_line": start,
                            "end_line":   end,
                            "node":       node,
                        }
                        break
        for child in node.children:
            found = find_containing_function(child, target_line)
            if found:
                result = found
        return result

    containing_fn = find_containing_function(root, line_number)
    if not containing_fn:
        return {
            "is_reachable":       None,
            "confidence":         0.3,
            "analysis":           "Could not identify containing function — may be module-level code.",
            "vulnerable_function": "unknown",
            "entry_points":       [],
            "call_path":          [],
        }

    fn_name = containing_fn["name"]

    # 4. Find all function calls in the file
    def collect_calls(node, calls=None):
        if calls is None:
            calls = []
        if node.type == "call":
            fn_node = node.child_by_field_name("function")
            if fn_node:
                calls.append({
                    "name": fn_node.text.decode("utf-8").split(".")[-1],
                    "line": node.start_point[0] + 1,
                })
        for child in node.children:
            collect_calls(child, calls)
        return calls

    all_calls = collect_calls(root)
    callers_of_fn = [c for c in all_calls
                     if c["name"] == fn_name
                     and not (containing_fn["start_line"] <= c["line"] <= containing_fn["end_line"])]

    # 5. Detect HTTP entry points (decorators for Flask, FastAPI, Django)
    ROUTE_MARKERS = [
        "@app.route", "@app.get", "@app.post", "@app.put",
        "@app.delete", "@app.patch", "@router.get", "@router.post",
        "@router.put", "@router.delete", "@router.patch",
        "urlpatterns", "path(", "re_path(", "url(",
        "app.add_url_rule", "router.add_api_route",
    ]

    entry_points = []
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if any(marker in stripped for marker in ROUTE_MARKERS):
            entry_points.append({"line": i, "code": stripped})

    # 6. Check if containing function or any of its callers is an entry point
    def is_near_entry_point(fn_start, fn_end, entry_pts):
        for ep in entry_pts:
            if fn_start - 5 <= ep["line"] <= fn_start:
                return ep
        return None

    # Check direct — is the vulnerable function itself a route handler?
    direct_ep = is_near_entry_point(
        containing_fn["start_line"],
        containing_fn["end_line"],
        entry_points
    )

    # Check indirect — is any caller a route handler?
    indirect_ep = None
    call_path   = []
    for caller in callers_of_fn:
        caller_fn = find_containing_function(root, caller["line"])
        if caller_fn:
            ep = is_near_entry_point(
                caller_fn["start_line"],
                caller_fn["end_line"],
                entry_points
            )
            if ep:
                indirect_ep = ep
                call_path   = [
                    ep["code"],
                    f"{caller_fn['name']}() at line {caller_fn['start_line']}",
                    f"{fn_name}() at line {containing_fn['start_line']} ← vulnerable",
                ]
                break

    # 7. Build result
    if direct_ep:
        return {
            "is_reachable":        True,
            "confidence":          0.92,
            "vulnerable_function": fn_name,
            "entry_points":        [direct_ep["code"]],
            "call_path":           [direct_ep["code"], f"{fn_name}() ← vulnerable"],
            "analysis": (
                f"The vulnerable function '{fn_name}' is directly registered as "
                f"an HTTP route handler: {direct_ep['code']}. "
                f"An attacker can reach this vulnerability via HTTP."
            ),
        }
    elif indirect_ep:
        return {
            "is_reachable":        True,
            "confidence":          0.85,
            "vulnerable_function": fn_name,
            "entry_points":        [indirect_ep["code"]],
            "call_path":           call_path,
            "analysis": (
                f"The vulnerable function '{fn_name}' is reachable via the call path: "
                + " → ".join(call_path)
            ),
        }
    elif callers_of_fn:
        return {
            "is_reachable":        None,
            "confidence":          0.5,
            "vulnerable_function": fn_name,
            "entry_points":        [ep["code"] for ep in entry_points[:3]],
            "call_path":           [f"{c['name']}() at line {c['line']}" for c in callers_of_fn],
            "analysis": (
                f"'{fn_name}' is called from {len(callers_of_fn)} location(s) "
                f"but no direct route handler found in this file. "
                f"May be reachable via cross-file calls — manual review recommended."
            ),
        }
    else:
        return {
            "is_reachable":        False,
            "confidence":          0.80,
            "vulnerable_function": fn_name,
            "entry_points":        [ep["code"] for ep in entry_points[:3]],
            "call_path":           [],
            "analysis": (
                f"'{fn_name}' has no callers in this file and is not registered "
                f"as a route handler. This appears to be dead code — "
                f"likely a false positive."
            ),
        }
