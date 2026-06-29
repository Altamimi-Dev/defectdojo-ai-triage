# Contributing to DefectDojo AI Triage

Thank you for considering contributing. This project aims to make AI-powered security triage accessible to every organisation running DefectDojo.

## How to Contribute

### Reporting Bugs
Open an issue with:
- DefectDojo version
- Azure region
- Steps to reproduce
- Expected vs actual behaviour
- Relevant log output (redact any credentials)

### Adding a New Adapter
The highest-value contributions are new adapters for SCA, DAST, and IaC:

1. Fork the repo
2. Create a branch: `git checkout -b adapter/sca-dependabot`
3. Implement the adapter following the pattern in `triage-app/main.py`
4. Add a prompt template
5. Add routing in `process_finding_directly()`
6. Update the README adapter table
7. Open a PR with a description of the adapter and test findings used

### Adding RAG Knowledge
To add new knowledge sources (vendor-specific CWEs, NIST, PCI-DSS, etc.):

1. Add documents to `rag/ingest.py`
2. Keep the same schema: `id`, `source`, `source_id`, `title`, `content`, `mitigations`, `severity_context`
3. Open a PR

### Code Style
- Python 3.11+
- No hardcoded credentials anywhere
- Log at INFO level for normal flow, WARNING for degraded paths, ERROR for failures
- Keep adapter functions self-contained

## Ground Rules
- Never commit credentials, tokens, or API keys
- Never commit real finding data or customer information
- Redact any organisation-specific values before submitting PRs
