/*
  DefectDojo AI Triage — Bicep Parameters
  =========================================
  Copy this file and fill in your values.
  Then deploy with:

    az deployment group create \
      --resource-group YOUR_RESOURCE_GROUP \
      --template-file infra/bicep/main.bicep \
      --parameters infra/bicep/main.bicepparam
*/

using './main.bicep'

// ── REQUIRED — fill these in ──────────────────────────────────────────────────

// Short prefix for all resource names (3-10 chars, no special chars)
// Example: 'myorg', 'acme', 'dev'
param prefix = 'REPLACE_WITH_PREFIX'

// Azure region (run: az account list-locations -o table)
param location = 'eastus'

// Your DefectDojo instance URL
param defectDojoUrl = 'http://REPLACE_WITH_DEFECTDOJO_URL:8080'

// Azure DevOps configuration
param adoOrg     = 'REPLACE_WITH_ADO_ORG'
param adoProject = 'REPLACE_WITH_ADO_PROJECT'
param adoRepo    = 'REPLACE_WITH_ADO_REPO'
param adoBranch  = 'main'

// ── OPTIONAL — change if needed ───────────────────────────────────────────────
param aoaiDeploymentName = 'gpt-4o-triage'

param tags = {
  project: 'defectdojo-ai-triage'
  environment: 'production'
}
