# Publish to GitHub

This project is safe to publish as a standalone repository. It contains no tenant IDs, client IDs, client secrets, local machine paths, or company-specific configuration.

## Before Publishing

Review the files:

```bash
find . -maxdepth 3 -type f | sort
```

Confirm there are no local secrets:

```bash
grep -RniE 'tenant-id|client-secret|absolute-local-path|company-name' .
```

The placeholders in `.env.example`, `README.md`, and `INSTALL.md` are intentional.

## Create the Repository Locally

Use a neutral or public identity for the first commit if you do not want your work Git identity attached to the repository history.

```bash
git init
git config user.name "<public-name-or-org>"
git config user.email "<public-email-or-noreply-email>"
git add .
git commit -m "Initial Defender Graph Security MCP server"
```

## Push to GitHub

Create an empty GitHub repository named `defender-graph-security-mcp-server`, then run:

```bash
git branch -M main
git remote add origin https://github.com/<your-org-or-user>/defender-graph-security-mcp-server.git
git push -u origin main
```

## Install After Publishing

Users can install from the repository with:

```bash
git clone https://github.com/<your-org-or-user>/defender-graph-security-mcp-server.git
cd defender-graph-security-mcp-server
npm install
npm run smoke
```
