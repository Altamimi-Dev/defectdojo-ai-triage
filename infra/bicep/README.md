# Infrastructure as Code — Bicep Deployment

This folder contains Azure Bicep templates to deploy the complete DefectDojo AI Triage infrastructure with a single command.

## What Gets Deployed

| Resource | Purpose |
|---|---|
| Azure Container Registry | Stores Docker images |
| Azure Key Vault | Stores secrets (DD token, ADO PAT) |
| Azure OpenAI | GPT-4o (triage) + text-embedding-ada-002 (RAG) |
| Azure AI Search | Vector store for CWE/OWASP/MITRE knowledge base |
| Azure Service Bus | Queue for async triage jobs |
| Container Apps Environment | Hosting environment |
| Container App: triage-app | Main triage engine |
| Container App: mcp-server | Internal tool server for SAST adapter |
| API Management | Secure gateway + CORS |
| Log Analytics | Centralised logging |

## Prerequisites

```bash
# Azure CLI
az --version   # needs 2.50+

# Bicep CLI (auto-installed with Azure CLI)
az bicep version

# Docker
docker --version
```

## Step 1 — Login to Azure

```bash
az login
az account set --subscription YOUR_SUBSCRIPTION_ID
```

## Step 2 — Create Resource Group

```bash
az group create \
  --name rg-ai-triage \
  --location eastus
```

## Step 3 — Configure Parameters

Edit `infra/bicep/main.bicepparam` and fill in all `REPLACE_WITH_...` values:

```bicep
param prefix         = 'myorg'       // 3-10 chars, no special chars
param location       = 'eastus'
param defectDojoUrl  = 'http://your-dojo:8080'
param adoOrg         = 'YourOrg'
param adoProject     = 'YourProject'
param adoRepo        = 'YourRepo'
param adoBranch      = 'main'
```

## Step 4 — Deploy Infrastructure

```bash
az deployment group create \
  --resource-group rg-ai-triage \
  --template-file infra/bicep/main.bicep \
  --parameters infra/bicep/main.bicepparam \
  --verbose
```

Deployment takes approximately 15-20 minutes (APIM is the slowest).

Outputs shown after completion:
- `triageAppUrl` — your triage app URL
- `apimUrl` — APIM gateway URL
- `apimSubscriptionKey` — save this securely
- `keyVaultUri` — Key Vault URI
- `acrLoginServer` — ACR URL

## Step 5 — Store Required Secrets in Key Vault

```bash
# Replace values with your actual credentials
KV_NAME="kv-myorg-triage"   # from deployment output

az keyvault secret set \
  --vault-name $KV_NAME \
  --name dd-api-token \
  --value "YOUR_DEFECTDOJO_API_TOKEN"

az keyvault secret set \
  --vault-name $KV_NAME \
  --name ado-pat \
  --value "YOUR_AZURE_DEVOPS_PAT"
```

## Step 6 — Build and Push Container Images

```bash
ACR="acrmyorgtriage"  # from deployment output (acrLoginServer without .azurecr.io)

az acr build --registry $ACR --image triage-app:latest ./triage-app
az acr build --registry $ACR --image mcp-server:latest ./mcp-server
```

## Step 7 — Ingest RAG Knowledge Base

```bash
# Get values from deployment outputs
SRCH_ENDPOINT="https://srch-myorg-triage.search.windows.net"
KV_NAME="kv-myorg-triage"
AOAI_ENDPOINT="https://aoai-myorg-triage.openai.azure.com/"

SRCH_KEY=$(az keyvault secret show --vault-name $KV_NAME --name srch-admin-key --query value -o tsv)

pip install -r rag/requirements.txt
python3 rag/ingest.py \
  --search-endpoint $SRCH_ENDPOINT \
  --search-key $SRCH_KEY \
  --aoai-endpoint $AOAI_ENDPOINT \
  --use-managed-identity
```

## Step 8 — Apply DefectDojo Template

See `defectdojo/README.md` for instructions.

## Cleanup

To delete all resources:

```bash
az group delete --name rg-ai-triage --yes
```

## Troubleshooting

**Deployment fails on APIM**
APIM Consumption tier sometimes takes 20-30 minutes. Re-run the deployment — it is idempotent.

**Container App shows unhealthy**
Images haven't been pushed yet. Complete Step 6 first.

**Key Vault access denied**
The Bicep template grants the Container Apps Managed Identity access automatically. Wait 2-3 minutes after deployment for RBAC to propagate.
