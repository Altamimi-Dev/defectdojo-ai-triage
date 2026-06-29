# GitHub Setup Guide

This guide walks you through publishing this project to GitHub from scratch.
No prior Git experience needed — follow each step in order.

---

## Part 1 — Create a GitHub Account (skip if you have one)

1. Go to [github.com](https://github.com)
2. Click **Sign up**
3. Enter your email, create a password, choose a username
4. Verify your email

---

## Part 2 — Create the Repository on GitHub

1. Log in to [github.com](https://github.com)
2. Click the **+** icon in the top-right corner → **New repository**
3. Fill in:
   - **Repository name**: `defectdojo-ai-triage`
   - **Description**: `Agentic AI-powered security finding triage for DefectDojo`
   - **Visibility**: Public (so the community can use it)
   - **Do NOT** tick "Add a README file" — we already have one
4. Click **Create repository**
5. GitHub will show you a page with setup instructions — keep this tab open

---

## Part 3 — Install Git on Your Machine

### Windows
Download from [git-scm.com](https://git-scm.com/download/win) and install.

### Mac
```bash
brew install git
```

### Linux
```bash
sudo apt install git    # Ubuntu/Debian
sudo yum install git    # RHEL/CentOS
```

Verify installation:
```bash
git --version
# Should print: git version 2.x.x
```

---

## Part 4 — Configure Git (one-time setup)

```bash
git config --global user.name "Your Name"
git config --global user.email "your-email@example.com"
```

---

## Part 5 — Prepare the Project Files

1. Download `defectdojo-ai-triage.zip` from the project releases
2. Unzip it:
   ```bash
   unzip defectdojo-ai-triage.zip
   cd defectdojo-ai-triage
   ```

3. Add your DefectDojo template file:
   ```bash
   # Copy your modified view_test.html into the defectdojo folder
   cp /path/to/your/view_test.html defectdojo/view_test.html
   ```

4. Remove your specific APIM details from the template:
   ```bash
   # Replace with placeholder values before committing
   sed -i 's/YOUR_ACTUAL_APIM_URL/YOUR_APIM_ENDPOINT/g' defectdojo/view_test.html
   sed -i 's/YOUR_ACTUAL_SUBSCRIPTION_KEY/YOUR_SUBSCRIPTION_KEY/g' defectdojo/view_test.html
   ```

5. Update `infra/bicep/main.bicepparam` with your placeholder values
   (do NOT put real credentials — use REPLACE_WITH_... placeholders)

---

## Part 6 — Push to GitHub

```bash
# Step 1 — Initialise git in the project folder
git init

# Step 2 — Add all files
git add .

# Step 3 — Create the first commit
git commit -m "Initial release — DefectDojo AI Triage v1.0.0"

# Step 4 — Connect to your GitHub repository
# Replace YOUR_USERNAME with your GitHub username
git remote add origin https://github.com/YOUR_USERNAME/defectdojo-ai-triage.git

# Step 5 — Push to GitHub
git branch -M main
git push -u origin main
```

GitHub will ask for your username and password.
For password, use a **Personal Access Token** (not your account password):
1. GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Generate new token → tick **repo** → Generate
3. Copy the token and use it as your password

---

## Part 7 — Set Up GitHub Actions (CI/CD)

This lets GitHub automatically rebuild and redeploy whenever you push code changes.

### Create an Azure Service Principal

```bash
az ad sp create-for-rbac \
  --name "sp-defectdojo-ai-triage" \
  --role Contributor \
  --scopes /subscriptions/YOUR_SUBSCRIPTION_ID/resourceGroups/YOUR_RESOURCE_GROUP \
  --sdk-auth
```

Copy the entire JSON output — you'll need it in the next step.

### Add GitHub Secrets

Go to your GitHub repo → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

Add these secrets:

| Secret Name | Value |
|---|---|
| `AZURE_CREDENTIALS` | The full JSON from the service principal command above |
| `AZURE_RESOURCE_GROUP` | Your resource group name e.g. `rg-ai-triage` |
| `ACR_LOGIN_SERVER` | Your ACR URL e.g. `acrmyorgtriage.azurecr.io` |
| `TRIAGE_APP_NAME` | Your triage Container App name e.g. `ca-myorg-triage` |
| `MCP_APP_NAME` | Your MCP Container App name e.g. `ca-myorg-mcp` |

### Test the workflow

```bash
git add .
git commit -m "Test CI/CD pipeline"
git push
```

Go to your GitHub repo → **Actions** tab — you should see the workflow running.

---

## Part 8 — Add a GitHub Topic (helps discoverability)

1. Go to your repo on GitHub
2. Click the gear icon next to **About**
3. Add topics: `defectdojo`, `security`, `ai-triage`, `ssdlc`, `azure`, `appsec`, `devsecops`
4. Click **Save changes**

---

## Making Updates

Every time you change the code:

```bash
git add .
git commit -m "Description of what you changed"
git push
```

GitHub Actions will automatically rebuild and redeploy. That's it.

---

## Useful Git Commands

| Command | What it does |
|---|---|
| `git status` | Shows what files have changed |
| `git log --oneline` | Shows commit history |
| `git diff` | Shows exactly what changed |
| `git pull` | Gets latest changes from GitHub |
