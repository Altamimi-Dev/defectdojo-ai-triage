"""
DefectDojo AI Triage — RAG Knowledge Base Ingestion Script
===========================================================
Ingests CWE, OWASP Top 10, and MITRE ATT&CK knowledge into Azure AI Search.
Run this once during setup, and again when you want to add new knowledge sources.

Usage:
    python3 ingest.py \\
        --search-endpoint https://srch-myorg.search.windows.net \\
        --search-key YOUR_SEARCH_KEY \\
        --aoai-endpoint https://aoai-myorg.openai.azure.com/ \\
        --aoai-key YOUR_AOAI_KEY

    # Or using Azure Managed Identity (recommended for CI/CD):
    python3 ingest.py \\
        --search-endpoint https://srch-myorg.search.windows.net \\
        --aoai-endpoint https://aoai-myorg.openai.azure.com/ \\
        --use-managed-identity
"""
import argparse
import time

from azure.search.documents import SearchClient
from azure.search.documents.indexes import SearchIndexClient
from azure.search.documents.indexes.models import (
    SearchIndex, SearchField, SearchFieldDataType,
    SimpleField, SearchableField,
    VectorSearch, HnswAlgorithmConfiguration, VectorSearchProfile,
    SemanticConfiguration, SemanticSearch,
    SemanticPrioritizedFields, SemanticField,
)
from azure.core.credentials import AzureKeyCredential
from openai import AzureOpenAI

# ── KNOWLEDGE BASE ────────────────────────────────────────────────────────────
DOCS = [
    # ── CWE ──────────────────────────────────────────────────────────────────
    {"id": "cwe-89",  "source": "CWE", "source_id": "CWE-89",  "severity_context": "Critical",
     "title": "CWE-89: SQL Injection",
     "content": "Improper neutralization of special elements used in an SQL command. User-controlled data is included in SQL queries without adequate sanitization, allowing attackers to manipulate database queries, bypass authentication, extract sensitive data, or execute administrative operations.",
     "mitigations": "Use parameterized queries or prepared statements. Apply input validation. Use stored procedures. Implement least privilege database accounts. Use ORM frameworks. Apply WAF rules for SQL injection patterns."},

    {"id": "cwe-79",  "source": "CWE", "source_id": "CWE-79",  "severity_context": "High",
     "title": "CWE-79: Cross-Site Scripting (XSS)",
     "content": "Improper neutralization of input during web page generation. Untrusted data sent to a web browser without proper validation or escaping, enabling attackers to execute scripts in the victim browser, hijack sessions, deface websites, or redirect users.",
     "mitigations": "Encode output data. Use Content Security Policy headers. Validate and sanitize all inputs. Use modern frameworks with built-in XSS protection. Apply HTTPOnly and Secure cookie flags."},

    {"id": "cwe-798", "source": "CWE", "source_id": "CWE-798", "severity_context": "Critical",
     "title": "CWE-798: Use of Hard-coded Credentials",
     "content": "The software contains hard-coded credentials such as passwords, API keys, tokens, or cryptographic keys. Attackers who gain access to source code or config files can extract these credentials and gain unauthorized access.",
     "mitigations": "Store credentials in secrets management systems like Azure Key Vault. Use managed identities. Rotate credentials regularly. Scan code for secrets. Use pre-commit hooks."},

    {"id": "cwe-22",  "source": "CWE", "source_id": "CWE-22",  "severity_context": "High",
     "title": "CWE-22: Path Traversal",
     "content": "Improper limitation of a pathname to a restricted directory. User-controlled input used to construct file paths without sanitization, allowing access to files outside intended locations.",
     "mitigations": "Validate and sanitize file paths. Use allowlists. Resolve canonical paths before validation. Avoid passing user-controlled data to file system APIs."},

    {"id": "cwe-78",  "source": "CWE", "source_id": "CWE-78",  "severity_context": "Critical",
     "title": "CWE-78: OS Command Injection",
     "content": "User-controlled data passed to system shell commands without sanitization, enabling execution of arbitrary commands on the host OS.",
     "mitigations": "Avoid OS command execution. Use language APIs instead of shell commands. Parameterize arguments. Apply strict input validation with allowlists. Run with minimal privileges."},

    {"id": "cwe-502", "source": "CWE", "source_id": "CWE-502", "severity_context": "Critical",
     "title": "CWE-502: Deserialization of Untrusted Data",
     "content": "Application deserializes untrusted data without verification. Malicious objects can execute arbitrary code, perform DoS, or manipulate application logic.",
     "mitigations": "Avoid deserializing from untrusted sources. Implement integrity checks. Use safe deserialization libraries. Apply type checking. Use allowlists for deserializable classes."},

    {"id": "cwe-611", "source": "CWE", "source_id": "CWE-611", "severity_context": "High",
     "title": "CWE-611: XML External Entity (XXE) Injection",
     "content": "XML input containing external entity references may expose confidential data, enable SSRF, or cause denial of service.",
     "mitigations": "Disable external entity processing in XML parsers. Use JSON instead. Validate and sanitize XML input. Update XML libraries."},

    {"id": "cwe-918", "source": "CWE", "source_id": "CWE-918", "severity_context": "High",
     "title": "CWE-918: Server-Side Request Forgery (SSRF)",
     "content": "Server fetches remote resource without validating user-supplied URL, allowing requests to internal services, cloud metadata endpoints, or external systems.",
     "mitigations": "Validate and sanitize URLs. Use allowlists for permitted hosts. Disable HTTP redirects. Block internal IP ranges. Use network segmentation."},

    {"id": "cwe-352", "source": "CWE", "source_id": "CWE-352", "severity_context": "Medium",
     "title": "CWE-352: Cross-Site Request Forgery (CSRF)",
     "content": "Application does not verify requests originate from legitimate sources, allowing attackers to trick authenticated users into submitting malicious requests.",
     "mitigations": "Implement CSRF tokens. Use SameSite cookie attribute. Verify Origin and Referer headers. Require re-authentication for sensitive actions."},

    {"id": "cwe-287", "source": "CWE", "source_id": "CWE-287", "severity_context": "High",
     "title": "CWE-287: Improper Authentication",
     "content": "Software does not correctly implement authentication, allowing attackers to assume identity of other users or gain unauthorized access.",
     "mitigations": "Implement MFA. Use strong password policies. Implement account lockout. Use secure session management. Validate authentication tokens."},

    {"id": "cwe-306", "source": "CWE", "source_id": "CWE-306", "severity_context": "Critical",
     "title": "CWE-306: Missing Authentication for Critical Function",
     "content": "Software does not perform authentication for functionality requiring a provable user identity or consuming significant resources.",
     "mitigations": "Require authentication for all sensitive operations. Implement proper access control checks. Use authentication middleware."},

    {"id": "cwe-200", "source": "CWE", "source_id": "CWE-200", "severity_context": "Medium",
     "title": "CWE-200: Exposure of Sensitive Information",
     "content": "Product exposes sensitive information to unauthorized actors including PII, credentials, internal system details, and business-sensitive data.",
     "mitigations": "Classify and protect sensitive data. Implement proper access controls. Avoid logging sensitive info. Use encryption at rest and in transit."},

    {"id": "cwe-327", "source": "CWE", "source_id": "CWE-327", "severity_context": "High",
     "title": "CWE-327: Use of Broken Cryptographic Algorithm",
     "content": "Using broken algorithms like MD5, SHA1, DES, RC4 introduces unnecessary risk and should not be used for security purposes.",
     "mitigations": "Use AES-256, SHA-256, RSA-2048+, ECDSA. Use established crypto libraries. Follow NIST guidelines."},

    {"id": "cwe-190", "source": "CWE", "source_id": "CWE-190", "severity_context": "Medium",
     "title": "CWE-190: Integer Overflow",
     "content": "A calculation can produce an integer overflow or wraparound leading to buffer overflows, memory corruption, or logic errors.",
     "mitigations": "Use safe integer libraries. Validate input ranges. Use languages with overflow protection. Apply bounds checking."},

    {"id": "cwe-476", "source": "CWE", "source_id": "CWE-476", "severity_context": "Medium",
     "title": "CWE-476: NULL Pointer Dereference",
     "content": "Dereferencing a pointer expected to be valid but is NULL, causing a crash or segmentation fault.",
     "mitigations": "Check pointer values before dereferencing. Use null-safe languages. Initialize pointers properly. Use static analysis tools."},

    # ── OWASP TOP 10 2021 ─────────────────────────────────────────────────────
    {"id": "owasp-a012021", "source": "OWASP", "source_id": "A01:2021", "severity_context": "High",
     "title": "OWASP A01:2021: Broken Access Control",
     "content": "Access control failures lead to unauthorized disclosure, modification, or destruction of data. Common issues include bypassing checks, elevation of privilege, CORS misconfiguration, force browsing.",
     "mitigations": "Implement deny by default. Use access control models consistently. Log failures. Rate limit API access. Invalidate session identifiers after logout."},

    {"id": "owasp-a022021", "source": "OWASP", "source_id": "A02:2021", "severity_context": "High",
     "title": "OWASP A02:2021: Cryptographic Failures",
     "content": "Failures related to cryptography leading to sensitive data exposure. Includes cleartext transmission, weak algorithms, improper key management, not enforcing encryption.",
     "mitigations": "Classify data by sensitivity. Encrypt sensitive data at rest. Use strong algorithms. Do not store sensitive data unnecessarily."},

    {"id": "owasp-a032021", "source": "OWASP", "source_id": "A03:2021", "severity_context": "Critical",
     "title": "OWASP A03:2021: Injection",
     "content": "Untrusted data sent to interpreter as part of command or query. Includes SQL, NoSQL, OS, LDAP injection, and XSS. Attacker data tricks interpreter into executing unintended commands.",
     "mitigations": "Use safe APIs. Use parameterized queries. Apply positive server-side input validation. Escape special characters."},

    {"id": "owasp-a042021", "source": "OWASP", "source_id": "A04:2021", "severity_context": "High",
     "title": "OWASP A04:2021: Insecure Design",
     "content": "Missing or ineffective control design. An insecure design cannot be fixed by a perfect implementation as security controls were never created to defend against specific attacks.",
     "mitigations": "Use secure development lifecycle. Apply threat modeling. Integrate security into user stories. Write unit and integration tests."},

    {"id": "owasp-a052021", "source": "OWASP", "source_id": "A05:2021", "severity_context": "High",
     "title": "OWASP A05:2021: Security Misconfiguration",
     "content": "Insecure default configurations, incomplete configurations, open cloud storage, misconfigured HTTP headers, verbose error messages.",
     "mitigations": "Implement repeatable hardening process. Review configurations. Remove unused features. Use automated verification."},

    {"id": "owasp-a062021", "source": "OWASP", "source_id": "A06:2021", "severity_context": "High",
     "title": "OWASP A06:2021: Vulnerable and Outdated Components",
     "content": "Components such as libraries and frameworks run with same privileges as the application. Exploiting a vulnerable component can cause serious data loss or server takeover.",
     "mitigations": "Remove unused dependencies. Continuously inventory component versions. Monitor for vulnerabilities. Use official sources over secure links."},

    {"id": "owasp-a072021", "source": "OWASP", "source_id": "A07:2021", "severity_context": "High",
     "title": "OWASP A07:2021: Identification and Authentication Failures",
     "content": "Weaknesses in authentication include automated attacks, weak passwords, weak credential recovery, storing passwords in plain text or with weak hashing, missing MFA.",
     "mitigations": "Implement MFA. Do not ship default credentials. Implement weak-password checks. Limit failed login attempts. Use high entropy session IDs."},

    {"id": "owasp-a082021", "source": "OWASP", "source_id": "A08:2021", "severity_context": "High",
     "title": "OWASP A08:2021: Software and Data Integrity Failures",
     "content": "Code and infrastructure not protecting against integrity violations. Relying on plugins from untrusted sources. Insecure CI/CD pipeline.",
     "mitigations": "Use digital signatures. Ensure libraries from trusted repositories. Proper CI/CD segregation and access control."},

    {"id": "owasp-a092021", "source": "OWASP", "source_id": "A09:2021", "severity_context": "Medium",
     "title": "OWASP A09:2021: Security Logging and Monitoring Failures",
     "content": "Without logging and monitoring, breaches cannot be detected. Insufficient logging of logins, failed logins, and high-value transactions.",
     "mitigations": "Log all login and access control failures. Generate logs in standard formats. Implement effective monitoring and alerting."},

    {"id": "owasp-a102021", "source": "OWASP", "source_id": "A10:2021", "severity_context": "High",
     "title": "OWASP A10:2021: Server-Side Request Forgery",
     "content": "Web application fetches remote resource without validating user-supplied URL, allowing coercion of requests to unexpected destinations.",
     "mitigations": "Sanitize and validate all client-supplied input. Enforce URL schema with positive allow list. Disable HTTP redirections."},

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    {"id": "mitre-t1190", "source": "MITRE_ATTCK", "source_id": "T1190", "severity_context": "Critical",
     "title": "MITRE ATT&CK T1190: Exploit Public-Facing Application",
     "content": "Adversaries exploit weaknesses in Internet-facing applications including websites, databases, network devices, and IoT devices.",
     "mitigations": "Update software regularly. Implement WAF. Use network segmentation. Perform regular vulnerability scanning."},

    {"id": "mitre-t1552", "source": "MITRE_ATTCK", "source_id": "T1552", "severity_context": "Critical",
     "title": "MITRE ATT&CK T1552: Unsecured Credentials",
     "content": "Adversaries search compromised systems for insecurely stored credentials in plaintext files, scripts, source code, environment variables, configuration files.",
     "mitigations": "Use secrets management solutions. Implement least privilege. Remove hardcoded credentials. Use managed identities."},

    {"id": "mitre-t1059", "source": "MITRE_ATTCK", "source_id": "T1059", "severity_context": "High",
     "title": "MITRE ATT&CK T1059: Command and Scripting Interpreter",
     "content": "Adversaries abuse command and script interpreters to execute commands, scripts, or binaries on target systems.",
     "mitigations": "Restrict script execution. Use application allowlisting. Monitor command execution. Disable scripting where not needed."},

    {"id": "mitre-t1078", "source": "MITRE_ATTCK", "source_id": "T1078", "severity_context": "High",
     "title": "MITRE ATT&CK T1078: Valid Accounts",
     "content": "Adversaries obtain and abuse credentials of existing accounts for Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
     "mitigations": "Implement MFA. Monitor for abnormal account activity. Implement account use policies. Audit account permissions."},

    {"id": "mitre-t1110", "source": "MITRE_ATTCK", "source_id": "T1110", "severity_context": "High",
     "title": "MITRE ATT&CK T1110: Brute Force",
     "content": "Adversaries use brute force techniques to gain access when passwords are unknown through repetitive guessing mechanisms.",
     "mitigations": "Implement account lockout policies. Use MFA. Monitor failed login attempts. Use CAPTCHA. Implement adaptive authentication."},

    {"id": "mitre-t1530", "source": "MITRE_ATTCK", "source_id": "T1530", "severity_context": "High",
     "title": "MITRE ATT&CK T1530: Data from Cloud Storage",
     "content": "Adversaries access data from cloud storage such as Azure Storage containing sensitive business information, customer data, or source code.",
     "mitigations": "Use appropriate permissions on cloud storage. Enable logging. Implement data classification. Use encryption. Monitor access patterns."},

    {"id": "mitre-t1071", "source": "MITRE_ATTCK", "source_id": "T1071", "severity_context": "Medium",
     "title": "MITRE ATT&CK T1071: Application Layer Protocol",
     "content": "Adversaries communicate using application layer protocols to avoid detection by blending in with existing traffic.",
     "mitigations": "Monitor network traffic. Use application-aware firewalls. Implement egress filtering. Monitor DNS and HTTP traffic."},
]


def create_index(index_client: SearchIndexClient, index_name: str):
    """Create the Azure AI Search index with vector search support."""
    fields = [
        SimpleField(name="id",               type=SearchFieldDataType.String, key=True, filterable=True),
        SimpleField(name="source",           type=SearchFieldDataType.String, filterable=True, facetable=True),
        SimpleField(name="source_id",        type=SearchFieldDataType.String, filterable=True),
        SearchableField(name="title",        type=SearchFieldDataType.String),
        SearchableField(name="content",      type=SearchFieldDataType.String),
        SearchableField(name="mitigations",  type=SearchFieldDataType.String),
        SimpleField(name="severity_context", type=SearchFieldDataType.String, filterable=True),
        SearchField(
            name="embedding",
            type=SearchFieldDataType.Collection(SearchFieldDataType.Single),
            searchable=True,
            vector_search_dimensions=1536,
            vector_search_profile_name="vector-profile",
        ),
    ]
    vector_search = VectorSearch(
        algorithms=[HnswAlgorithmConfiguration(name="hnsw-algo")],
        profiles=[VectorSearchProfile(name="vector-profile", algorithm_configuration_name="hnsw-algo")],
    )
    semantic_search = SemanticSearch(configurations=[
        SemanticConfiguration(
            name="semantic-config",
            prioritized_fields=SemanticPrioritizedFields(
                title_field=SemanticField(field_name="title"),
                content_fields=[SemanticField(field_name="content"), SemanticField(field_name="mitigations")],
            ),
        )
    ])
    index = SearchIndex(name=index_name, fields=fields, vector_search=vector_search, semantic_search=semantic_search)
    result = index_client.create_or_update_index(index)
    print(f"✓ Index created: {result.name}")


def embed(aoai: AzureOpenAI, text: str) -> list:
    return aoai.embeddings.create(model="text-embedding-ada-002", input=text[:8000]).data[0].embedding


def ingest(args):
    credential = AzureKeyCredential(args.search_key)

    index_client = SearchIndexClient(endpoint=args.search_endpoint, credential=credential)
    srch_client  = SearchClient(endpoint=args.search_endpoint, index_name="security-knowledge", credential=credential)

    if args.aoai_key:
        aoai = AzureOpenAI(azure_endpoint=args.aoai_endpoint, api_key=args.aoai_key, api_version="2024-10-21")
    else:
        from azure.identity import DefaultAzureCredential as _DAC
        _cred = _DAC()
        aoai = AzureOpenAI(
            azure_endpoint=args.aoai_endpoint,
            azure_ad_token_provider=lambda: _cred.get_token("https://cognitiveservices.azure.com/.default").token,
            api_version="2024-10-21",
        )

    print("Creating index...")
    create_index(index_client, "security-knowledge")

    print(f"\nEmbedding and uploading {len(DOCS)} documents...")
    for i, doc in enumerate(DOCS):
        text = f"{doc['title']} {doc['content']} {doc['mitigations']}"
        doc["embedding"] = embed(aoai, text)
        print(f"  [{i+1}/{len(DOCS)}] {doc['source_id']}")
        time.sleep(0.3)

    results   = srch_client.upload_documents(documents=DOCS)
    succeeded = sum(1 for r in results if r.succeeded)
    print(f"\n✅ {succeeded}/{len(DOCS)} documents indexed into 'security-knowledge'")
    print("Sources: CWE (15) · OWASP Top 10 (10) · MITRE ATT&CK (8)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest security knowledge into Azure AI Search")
    parser.add_argument("--search-endpoint", required=True)
    parser.add_argument("--search-key",      required=True)
    parser.add_argument("--aoai-endpoint",   required=True)
    parser.add_argument("--aoai-key",        default="")
    parser.add_argument("--use-managed-identity", action="store_true")
    args = parser.parse_args()
    ingest(args)
