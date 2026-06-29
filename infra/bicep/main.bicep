/*
  DefectDojo AI Triage — Main Bicep Template
  ============================================
  Deploys the complete Azure infrastructure for DefectDojo AI Triage.

  Resources deployed:
    - Azure Container Registry
    - Azure Key Vault
    - Azure OpenAI (gpt-4o + text-embedding-ada-002)
    - Azure AI Search
    - Azure Service Bus
    - Azure Container Apps Environment
    - Container App: Triage Engine
    - Container App: MCP Server (internal)
    - Azure API Management

  Usage:
    az deployment group create \
      --resource-group rg-ai-triage \
      --template-file main.bicep \
      --parameters main.bicepparam
*/

targetScope = 'resourceGroup'

// ── PARAMETERS ────────────────────────────────────────────────────────────────
@description('Short prefix for all resource names (e.g. myorg, acme, dev)')
@minLength(3)
@maxLength(10)
param prefix string

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('DefectDojo base URL (e.g. http://your-dojo:8080)')
param defectDojoUrl string

@description('Azure DevOps organisation name')
param adoOrg string

@description('Azure DevOps project name')
param adoProject string

@description('Azure DevOps repository name')
param adoRepo string

@description('Azure DevOps branch to fetch code from')
param adoBranch string = 'main'

@description('GPT-4o deployment name')
param aoaiDeploymentName string = 'gpt-4o-triage'

@description('Tags applied to all resources')
param tags object = {
  project: 'defectdojo-ai-triage'
  environment: 'production'
}

// ── VARIABLES ──────────────────────────────────────────────────────────────────
var acrName            = 'acr${replace(prefix, '-', '')}triage'
var kvName             = 'kv-${prefix}-triage'
var aoaiName           = 'aoai-${prefix}-triage'
var srchName           = 'srch-${prefix}-triage'
var sbName             = 'sb-${prefix}-triage'
var caeName            = 'cae-${prefix}-triage'
var caTriageName       = 'ca-${prefix}-triage'
var caMcpName          = 'ca-${prefix}-mcp'
var apimName           = 'apim-${prefix}-triage'
var sbQueueName        = 'secrets-triage'

// ── CONTAINER REGISTRY ────────────────────────────────────────────────────────
resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: acrName
  location: location
  tags: tags
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: true
  }
}

// ── KEY VAULT ─────────────────────────────────────────────────────────────────
resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: kvName
  location: location
  tags: tags
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
  }
}

// ── AZURE OPENAI ──────────────────────────────────────────────────────────────
resource aoai 'Microsoft.CognitiveServices/accounts@2023-05-01' = {
  name: aoaiName
  location: location
  tags: tags
  kind: 'OpenAI'
  sku: {
    name: 'S0'
  }
  properties: {
    publicNetworkAccess: 'Enabled'
    customSubDomainName: aoaiName
  }
}

resource gpt4oDeployment 'Microsoft.CognitiveServices/accounts/deployments@2023-05-01' = {
  parent: aoai
  name: aoaiDeploymentName
  sku: {
    name: 'Standard'
    capacity: 10
  }
  properties: {
    model: {
      format: 'OpenAI'
      name: 'gpt-4o'
      version: '2024-08-06'
    }
  }
}

resource embeddingDeployment 'Microsoft.CognitiveServices/accounts/deployments@2023-05-01' = {
  parent: aoai
  name: 'text-embedding-ada-002'
  dependsOn: [gpt4oDeployment]
  sku: {
    name: 'Standard'
    capacity: 50
  }
  properties: {
    model: {
      format: 'OpenAI'
      name: 'text-embedding-ada-002'
      version: '2'
    }
  }
}

// ── AZURE AI SEARCH ───────────────────────────────────────────────────────────
resource srch 'Microsoft.Search/searchServices@2023-11-01' = {
  name: srchName
  location: location
  tags: tags
  sku: {
    name: 'basic'
  }
  properties: {
    replicaCount: 1
    partitionCount: 1
    publicNetworkAccess: 'Enabled'
    semanticSearch: 'free'
  }
}

// ── SERVICE BUS ───────────────────────────────────────────────────────────────
resource sb 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' = {
  name: sbName
  location: location
  tags: tags
  sku: {
    name: 'Basic'
    tier: 'Basic'
  }
}

resource sbQueue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  parent: sb
  name: sbQueueName
  properties: {
    maxSizeInMegabytes: 1024
    defaultMessageTimeToLive: 'PT1H'
  }
}

// ── LOG ANALYTICS (for Container Apps) ───────────────────────────────────────
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'log-${prefix}-triage'
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

// ── CONTAINER APPS ENVIRONMENT ────────────────────────────────────────────────
resource cae 'Microsoft.App/managedEnvironments@2023-05-01' = {
  name: caeName
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
  }
}

// ── MCP SERVER (Internal Ingress) ─────────────────────────────────────────────
resource caMcp 'Microsoft.App/containerApps@2023-05-01' = {
  name: caMcpName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    managedEnvironmentId: cae.id
    configuration: {
      ingress: {
        external: false
        targetPort: 8000
        transport: 'Auto'
      }
      registries: [
        {
          server: acr.properties.loginServer
          username: acr.name
          passwordSecretRef: 'acr-password'
        }
      ]
      secrets: [
        {
          name: 'acr-password'
          value: acr.listCredentials().passwords[0].value
        }
      ]
    }
    template: {
      containers: [
        {
          name: caMcpName
          image: '${acr.properties.loginServer}/mcp-server:latest'
          env: [
            { name: 'KEY_VAULT_URI',  value: kv.properties.vaultUri }
            { name: 'DD_BASE_URL',    value: defectDojoUrl }
            { name: 'ADO_ORG',        value: adoOrg }
            { name: 'ADO_PROJECT',    value: adoProject }
            { name: 'ADO_REPO',       value: adoRepo }
            { name: 'ADO_BRANCH',     value: adoBranch }
          ]
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 1
      }
    }
  }
}

// ── TRIAGE APP (External Ingress) ─────────────────────────────────────────────
resource caTriage 'Microsoft.App/containerApps@2023-05-01' = {
  name: caTriageName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    managedEnvironmentId: cae.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8000
        transport: 'Auto'
        stickySessions: {
          affinity: 'sticky'
        }
      }
      registries: [
        {
          server: acr.properties.loginServer
          username: acr.name
          passwordSecretRef: 'acr-password'
        }
      ]
      secrets: [
        {
          name: 'acr-password'
          value: acr.listCredentials().passwords[0].value
        }
        {
          name: 'srch-admin-key'
          keyVaultUrl: '${kv.properties.vaultUri}secrets/srch-admin-key'
          identity: 'system'
        }
      ]
    }
    template: {
      containers: [
        {
          name: caTriageName
          image: '${acr.properties.loginServer}/triage-app:latest'
          env: [
            { name: 'KEY_VAULT_URI',           value: kv.properties.vaultUri }
            { name: 'DD_BASE_URL',             value: defectDojoUrl }
            { name: 'AOAI_ENDPOINT',           value: aoai.properties.endpoint }
            { name: 'AOAI_DEPLOYMENT',         value: aoaiDeploymentName }
            { name: 'MCP_SERVER_URL',          value: 'https://${caMcp.properties.configuration.ingress.fqdn}' }
            { name: 'SEARCH_ENDPOINT',         value: 'https://${srch.properties.endpoint}' }
            { name: 'SEARCH_ADMIN_KEY',        secretRef: 'srch-admin-key' }
            { name: 'SERVICE_BUS_NAMESPACE',   value: '${sbName}.servicebus.windows.net' }
            { name: 'ADO_ORG',                 value: adoOrg }
            { name: 'ADO_PROJECT',             value: adoProject }
            { name: 'ADO_REPO',                value: adoRepo }
            { name: 'ADO_BRANCH',              value: adoBranch }
          ]
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 1
      }
    }
  }
}

// ── KEY VAULT RBAC — grant Container Apps access ──────────────────────────────
resource kvRoleTriage 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, caTriage.id, 'Key Vault Secrets User')
  scope: kv
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: caTriage.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource kvRoleMcp 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, caMcp.id, 'Key Vault Secrets User')
  scope: kv
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: caMcp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ── STORE SEARCH KEY IN KEY VAULT ─────────────────────────────────────────────
resource srchKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: kv
  name: 'srch-admin-key'
  properties: {
    value: srch.listAdminKeys().primaryKey
  }
}

// ── API MANAGEMENT ────────────────────────────────────────────────────────────
resource apim 'Microsoft.ApiManagement/service@2023-05-01-preview' = {
  name: apimName
  location: location
  tags: tags
  sku: {
    name: 'Consumption'
    capacity: 0
  }
  properties: {
    publisherEmail: 'admin@example.com'
    publisherName: 'AI Triage'
  }
}

resource apimApi 'Microsoft.ApiManagement/service/apis@2023-05-01-preview' = {
  parent: apim
  name: 'triage-api'
  properties: {
    displayName: 'AI Triage API'
    path: 'triage'
    protocols: ['https']
    serviceUrl: 'https://${caTriage.properties.configuration.ingress.fqdn}'
  }
}

resource apimOpBatch 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  parent: apimApi
  name: 'batch-triage'
  properties: {
    displayName: 'Batch Triage'
    method: 'POST'
    urlTemplate: '/batch'
  }
}

resource apimOpBatchStatus 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  parent: apimApi
  name: 'batch-status'
  properties: {
    displayName: 'Batch Status'
    method: 'GET'
    urlTemplate: '/batch/{jobId}/status'
    templateParameters: [
      {
        name: 'jobId'
        required: true
        type: 'string'
      }
    ]
  }
}

resource apimOpFinding 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  parent: apimApi
  name: 'triage-finding'
  properties: {
    displayName: 'Triage Finding'
    method: 'POST'
    urlTemplate: '/{finding_id}'
    templateParameters: [
      {
        name: 'finding_id'
        required: true
        type: 'integer'
      }
    ]
  }
}

resource apimOpAnalyst 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  parent: apimApi
  name: 'analyst-review'
  properties: {
    displayName: 'Analyst Review'
    method: 'POST'
    urlTemplate: '/analyst/review'
  }
}

// ── OUTPUTS ────────────────────────────────────────────────────────────────────
@description('Triage App FQDN')
output triageAppUrl string = 'https://${caTriage.properties.configuration.ingress.fqdn}'

@description('APIM Gateway URL')
output apimUrl string = 'https://${apim.properties.gatewayUrl}'

@description('Key Vault URI')
output keyVaultUri string = kv.properties.vaultUri

@description('Azure AI Search endpoint')
output searchEndpoint string = 'https://${srch.properties.endpoint}'

@description('Azure OpenAI endpoint')
output aoaiEndpoint string = aoai.properties.endpoint

@description('Container Registry login server')
output acrLoginServer string = acr.properties.loginServer

@description('MCP Server internal FQDN')
output mcpServerUrl string = 'https://${caMcp.properties.configuration.ingress.fqdn}'

@description('APIM subscription key — store securely')
output apimSubscriptionKey string = apim.listSubscriptionSecrets('master').primaryKey
