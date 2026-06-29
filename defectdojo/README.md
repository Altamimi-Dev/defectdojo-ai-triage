# DefectDojo Template Setup

This directory contains the patch to add the AI Triage button and Analyst Review modal to DefectDojo's test view.

## What It Adds

- **AI Triage button** in the test actions dropdown
- **Live progress overlay** with Completed / Failed / Remaining / Total counters
- **Analyst Review Queue** menu item
- **Inline Review button** on findings tagged `ANALYST_REVIEW_NEEDED`
- **Analyst Review modal** — Approve or Override with notes

## Applying the Patch

### Docker-based DefectDojo

```bash
# 1. Copy the patched template to the container
docker cp view_test.html django-defectdojo-uwsgi-1:/app/dojo/templates/dojo/view_test.html

# 2. Restart uwsgi to pick up the template change
docker restart django-defectdojo-uwsgi-1
```

### Manual install

```bash
cp view_test.html /path/to/django-DefectDojo/dojo/templates/dojo/view_test.html
# Restart your uwsgi/gunicorn process
```

## Configuration

Before applying, update these values in `view_test.html`:

| Placeholder | Replace with |
|---|---|
| `YOUR_APIM_ENDPOINT` | Your APIM URL e.g. `https://apim-myorg.azure-api.net` |
| `YOUR_SUBSCRIPTION_KEY` | Your APIM subscription key |

Search for `YOUR_APIM_ENDPOINT` and `YOUR_SUBSCRIPTION_KEY` in the file and replace with your values.

## DefectDojo Version Compatibility

Tested with DefectDojo 2.58.0. The template modifies `view_test.html` — if your version differs significantly, you may need to manually apply the changes described in `docs/defectdojo-changes.md`.
