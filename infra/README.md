# Infrastructure Setup Guide

## APIM Operations

After running `deploy.sh`, register the API operations in APIM:

```bash
PREFIX="myorg"   # replace with your prefix
RG="rg-ai-triage"  # replace with your resource group

# Create the API
az apim api create \
  --resource-group $RG \
  --service-name apim-${PREFIX}-triage \
  --api-id triage-api \
  --path triage \
  --display-name "AI Triage API" \
  --protocols https \
  --service-url "https://ca-${PREFIX}-triage.YOUR_ENV.azurecontainerapps.io"

# Register operations
az apim api operation create \
  --resource-group $RG \
  --service-name apim-${PREFIX}-triage \
  --api-id triage-api \
  --url-template "/batch" \
  --method POST \
  --operation-id batch-triage \
  --display-name "Batch Triage"

az apim api operation create \
  --resource-group $RG \
  --service-name apim-${PREFIX}-triage \
  --api-id triage-api \
  --url-template "/batch/{jobId}/status" \
  --method GET \
  --operation-id batch-status \
  --display-name "Batch Status"

az apim api operation create \
  --resource-group $RG \
  --service-name apim-${PREFIX}-triage \
  --api-id triage-api \
  --url-template "/{finding_id}" \
  --method POST \
  --operation-id triage-finding \
  --display-name "Triage Finding"

az apim api operation create \
  --resource-group $RG \
  --service-name apim-${PREFIX}-triage \
  --api-id triage-api \
  --url-template "/analyst/review" \
  --method POST \
  --operation-id analyst-review \
  --display-name "Analyst Review"
```

## Apply CORS Policy

```bash
az rest \
  --method PUT \
  --uri "https://management.azure.com/subscriptions/YOUR_SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/apim-${PREFIX}-triage/apis/triage-api/policies/policy?api-version=2022-08-01" \
  --headers "Content-Type=application/json" \
  --body @apim-policy.xml
```

## Grant Managed Identity Access to Key Vault

```bash
# Get Container App principal IDs
TRIAGE_PRINCIPAL=$(az containerapp show \
  --name ca-${PREFIX}-triage \
  --resource-group $RG \
  --query "identity.principalId" -o tsv)

MCP_PRINCIPAL=$(az containerapp show \
  --name ca-${PREFIX}-mcp \
  --resource-group $RG \
  --query "identity.principalId" -o tsv)

KV_ID=$(az keyvault show --name kv-${PREFIX}-triage --resource-group $RG --query id -o tsv)

# Grant Key Vault Secrets User role
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee $TRIAGE_PRINCIPAL \
  --scope $KV_ID

az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee $MCP_PRINCIPAL \
  --scope $KV_ID
```

## Enable Sticky Sessions (required for batch progress polling)

```bash
az containerapp ingress sticky-sessions set \
  --name ca-${PREFIX}-triage \
  --resource-group $RG \
  --affinity sticky
```
