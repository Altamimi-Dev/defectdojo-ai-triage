#!/bin/bash
# =============================================================================
# DefectDojo AI Triage — Full Azure Deployment Script
# =============================================================================
# Usage:
#   ./deploy.sh --resource-group rg-ai-triage --location eastus --prefix myorg
#
# Prerequisites:
#   - Azure CLI installed and authenticated (az login)
#   - Docker installed
#   - Sufficient Azure permissions (Contributor on subscription)
# =============================================================================

set -e

# ── PARSE ARGUMENTS ───────────────────────────────────────────────────────────
RESOURCE_GROUP=""
LOCATION="eastus"
PREFIX=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --resource-group) RESOURCE_GROUP="$2"; shift ;;
        --location)       LOCATION="$2";       shift ;;
        --prefix)         PREFIX="$2";         shift ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

if [[ -z "$RESOURCE_GROUP" || -z "$PREFIX" ]]; then
    echo "Usage: ./deploy.sh --resource-group <rg> --location <location> --prefix <prefix>"
    exit 1
fi

# ── RESOURCE NAMES ────────────────────────────────────────────────────────────
ACR="acr${PREFIX}triage"
KV="kv-${PREFIX}-triage"
AOAI="aoai-${PREFIX}-triage"
SRCH="srch-${PREFIX}-triage"
SB="sb-${PREFIX}-triage"
CAE="cae-${PREFIX}-triage"
CA_TRIAGE="ca-${PREFIX}-triage"
CA_MCP="ca-${PREFIX}-mcp"
APIM="apim-${PREFIX}-triage"

echo "============================================================"
echo "  DefectDojo AI Triage — Deploying to Azure"
echo "  Resource Group: $RESOURCE_GROUP"
echo "  Location:       $LOCATION"
echo "  Prefix:         $PREFIX"
echo "============================================================"

# ── STEP 1: RESOURCE GROUP ────────────────────────────────────────────────────
echo ""
echo "[1/10] Creating resource group..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" -o none
echo "✓ Resource group: $RESOURCE_GROUP"

# ── STEP 2: CONTAINER REGISTRY ────────────────────────────────────────────────
echo ""
echo "[2/10] Creating Container Registry..."
az acr create \
    --name "$ACR" \
    --resource-group "$RESOURCE_GROUP" \
    --sku Basic \
    --admin-enabled true \
    -o none
echo "✓ ACR: $ACR.azurecr.io"

# ── STEP 3: KEY VAULT ─────────────────────────────────────────────────────────
echo ""
echo "[3/10] Creating Key Vault..."
az keyvault create \
    --name "$KV" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --sku standard \
    -o none
echo "✓ Key Vault: $KV"
echo "  → Store secrets: dd-api-token, ado-pat, srch-admin-key"

# ── STEP 4: AZURE OPENAI ──────────────────────────────────────────────────────
echo ""
echo "[4/10] Creating Azure OpenAI..."
az cognitiveservices account create \
    --name "$AOAI" \
    --resource-group "$RESOURCE_GROUP" \
    --kind OpenAI \
    --sku S0 \
    --location "$LOCATION" \
    --yes \
    -o none

echo "  Deploying gpt-4o..."
az cognitiveservices account deployment create \
    --name "$AOAI" \
    --resource-group "$RESOURCE_GROUP" \
    --deployment-name "gpt-4o-triage" \
    --model-name "gpt-4o" \
    --model-version "2024-08-06" \
    --model-format OpenAI \
    --sku-name Standard \
    --sku-capacity 10 \
    -o none

echo "  Deploying text-embedding-ada-002..."
az cognitiveservices account deployment create \
    --name "$AOAI" \
    --resource-group "$RESOURCE_GROUP" \
    --deployment-name "text-embedding-ada-002" \
    --model-name "text-embedding-ada-002" \
    --model-version "2" \
    --model-format OpenAI \
    --sku-name Standard \
    --sku-capacity 50 \
    -o none
echo "✓ Azure OpenAI: $AOAI"

# ── STEP 5: AZURE AI SEARCH ───────────────────────────────────────────────────
echo ""
echo "[5/10] Creating Azure AI Search..."
az search service create \
    --name "$SRCH" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --sku basic \
    --partition-count 1 \
    --replica-count 1 \
    -o none
echo "✓ AI Search: $SRCH.search.windows.net"

# Store search key in Key Vault
SRCH_KEY=$(az search admin-key show \
    --service-name "$SRCH" \
    --resource-group "$RESOURCE_GROUP" \
    --query "primaryKey" -o tsv)
az keyvault secret set \
    --vault-name "$KV" \
    --name "srch-admin-key" \
    --value "$SRCH_KEY" \
    -o none
echo "  → Search key stored in Key Vault"

# ── STEP 6: SERVICE BUS ───────────────────────────────────────────────────────
echo ""
echo "[6/10] Creating Service Bus..."
az servicebus namespace create \
    --name "$SB" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --sku Basic \
    -o none

az servicebus queue create \
    --name "secrets-triage" \
    --namespace-name "$SB" \
    --resource-group "$RESOURCE_GROUP" \
    -o none
echo "✓ Service Bus: $SB"

# ── STEP 7: CONTAINER APPS ENVIRONMENT ───────────────────────────────────────
echo ""
echo "[7/10] Creating Container Apps environment..."
az containerapp env create \
    --name "$CAE" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    -o none
echo "✓ Container Apps env: $CAE"

# ── STEP 8: API MANAGEMENT ────────────────────────────────────────────────────
echo ""
echo "[8/10] Creating API Management (this takes ~30 minutes)..."
az apim create \
    --name "$APIM" \
    --resource-group "$RESOURCE_GROUP" \
    --publisher-email "admin@example.com" \
    --publisher-name "AI Triage" \
    --sku-name Consumption \
    -o none
echo "✓ APIM: $APIM.azure-api.net"

# ── STEP 9: BUILD & PUSH IMAGES ───────────────────────────────────────────────
echo ""
echo "[9/10] Building and pushing container images..."
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

az acr build \
    --registry "$ACR" \
    --image "triage-app:latest" \
    "$REPO_ROOT/triage-app" \
    -o none
echo "  ✓ triage-app:latest"

az acr build \
    --registry "$ACR" \
    --image "mcp-server:latest" \
    "$REPO_ROOT/mcp-server" \
    -o none
echo "  ✓ mcp-server:latest"

# ── STEP 10: DEPLOY CONTAINER APPS ───────────────────────────────────────────
echo ""
echo "[10/10] Deploying Container Apps..."
AOAI_ENDPOINT=$(az cognitiveservices account show \
    --name "$AOAI" \
    --resource-group "$RESOURCE_GROUP" \
    --query "properties.endpoint" -o tsv)

KV_URI="https://${KV}.vault.azure.net/"

# MCP Server (internal ingress)
az containerapp create \
    --name "$CA_MCP" \
    --resource-group "$RESOURCE_GROUP" \
    --environment "$CAE" \
    --image "$ACR.azurecr.io/mcp-server:latest" \
    --registry-server "$ACR.azurecr.io" \
    --ingress internal \
    --target-port 8000 \
    --min-replicas 1 \
    --max-replicas 1 \
    --system-assigned \
    --env-vars \
        "KEY_VAULT_URI=${KV_URI}" \
        "DD_BASE_URL=PLACEHOLDER_REPLACE_ME" \
    -o none

MCP_FQDN=$(az containerapp show \
    --name "$CA_MCP" \
    --resource-group "$RESOURCE_GROUP" \
    --query "properties.configuration.ingress.fqdn" -o tsv)

# Triage App (external ingress)
az containerapp create \
    --name "$CA_TRIAGE" \
    --resource-group "$RESOURCE_GROUP" \
    --environment "$CAE" \
    --image "$ACR.azurecr.io/triage-app:latest" \
    --registry-server "$ACR.azurecr.io" \
    --ingress external \
    --target-port 8000 \
    --min-replicas 1 \
    --max-replicas 1 \
    --system-assigned \
    --env-vars \
        "KEY_VAULT_URI=${KV_URI}" \
        "DD_BASE_URL=PLACEHOLDER_REPLACE_ME" \
        "AOAI_ENDPOINT=${AOAI_ENDPOINT}" \
        "AOAI_DEPLOYMENT=gpt-4o-triage" \
        "MCP_SERVER_URL=https://${MCP_FQDN}" \
        "SEARCH_ENDPOINT=https://${SRCH}.search.windows.net" \
        "SERVICE_BUS_NAMESPACE=${SB}.servicebus.windows.net" \
    -o none

CA_FQDN=$(az containerapp show \
    --name "$CA_TRIAGE" \
    --resource-group "$RESOURCE_GROUP" \
    --query "properties.configuration.ingress.fqdn" -o tsv)

echo "✓ Triage App: https://$CA_FQDN"
echo "✓ MCP Server: https://$MCP_FQDN (internal)"

# ── SUMMARY ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  DEPLOYMENT COMPLETE"
echo "============================================================"
echo ""
echo "  Triage App:  https://$CA_FQDN"
echo "  APIM:        https://$APIM.azure-api.net"
echo "  Key Vault:   $KV_URI"
echo "  AI Search:   https://$SRCH.search.windows.net"
echo ""
echo "  NEXT STEPS:"
echo "  1. Store secrets in Key Vault:"
echo "     az keyvault secret set --vault-name $KV --name dd-api-token --value YOUR_TOKEN"
echo "     az keyvault secret set --vault-name $KV --name ado-pat --value YOUR_PAT"
echo ""
echo "  2. Update DD_BASE_URL in both Container Apps"
echo ""
echo "  3. Ingest RAG knowledge base:"
echo "     python3 rag/ingest.py --search-endpoint https://$SRCH.search.windows.net ..."
echo ""
echo "  4. Register APIM operations:"
echo "     See infra/README.md for APIM setup commands"
echo ""
echo "  5. Apply DefectDojo template patch:"
echo "     See defectdojo/README.md"
echo "============================================================"
