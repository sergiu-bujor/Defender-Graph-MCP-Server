# Defender Graph Security MCP Server

Local MCP server for Microsoft Defender XDR and Microsoft Graph Security incidents and alerts.

The server uses Microsoft Graph application authentication with the client credentials flow. It exposes read tools for incidents and alerts, plus guarded write tools for updating or closing incidents and alerts.

## Quick Start

```bash
git clone https://github.com/<your-org-or-user>/defender-graph-security-mcp-server.git
cd defender-graph-security-mcp-server
npm install
npm run smoke
```

Then configure your MCP client to run:

```bash
node /path/to/defender-graph-security-mcp-server/src/index.js
```

## Authentication

Create or use a Microsoft Entra ID app registration with client credentials and Microsoft Graph application permissions.

Recommended application permissions:

- `SecurityIncident.Read.All`
- `SecurityIncident.ReadWrite.All`
- `SecurityAlert.Read.All`
- `SecurityAlert.ReadWrite.All`

Set these environment variables in your MCP client:

- `MSGRAPH_TENANT_ID`: Microsoft Entra tenant ID.
- `MSGRAPH_CLIENT_ID`: app registration client/application ID.
- `MSGRAPH_CLIENT_SECRET`: app registration client secret.
- `MSGRAPH_HUMAN_APPROVAL_TOKEN`: required before write actions can run.

Accepted aliases:

- `AZURE_TENANT_ID` or `TENANT_ID`
- `AZURE_CLIENT_ID` or `CLIENT_ID`
- `AZURE_CLIENT_SECRET` or `CLIENT_SECRET`

Optional:

- `MSGRAPH_AUTH_BASE_URL`: defaults to `https://login.microsoftonline.com`.
- `MSGRAPH_API_BASE_URL`: defaults to `https://graph.microsoft.com/v1.0`.
- `MSGRAPH_TIMEOUT_SECONDS`: defaults to `30`.

## Tools

Configuration:

- `config_status`: shows whether credentials, endpoints, and guardrails are configured without revealing secrets.

Incidents:

- `list_security_incidents`: `GET /security/incidents`
- `get_security_incident`: `GET /security/incidents/{incident_id}`
- `list_incident_alerts`: `GET /security/incidents/{incident_id}/alerts`
- `update_security_incident`: `PATCH /security/incidents/{incident_id}` with human approval
- `close_security_incident`: resolves an incident with human approval

Alerts:

- `list_alerts_v2`: `GET /security/alerts_v2`
- `get_alert_v2`: `GET /security/alerts_v2/{alert_id}`
- `update_alert_v2`: `PATCH /security/alerts_v2/{alert_id}` with human approval
- `create_alert_comment`: `POST /security/alerts_v2/{alert_id}/comments` with human approval

Advanced:

- `graph_security_request`: escape hatch for Graph Security API calls not covered by a dedicated tool. Non-GET calls require human approval.

## Human Approval Guardrails

Read-only tools can run normally. Write tools require a `human_approval` object with:

- `approved: true`
- `phrase`: exact action-specific approval phrase
- `approved_by`: human approver name or identifier
- `reason`: why the action is approved
- `approval_token`: value matching `MSGRAPH_HUMAN_APPROVAL_TOKEN`

If `MSGRAPH_HUMAN_APPROVAL_TOKEN` is not configured, protected write tools are blocked. `config_status` only reports whether the token exists; it never reveals the value.

Protected tools:

- `close_security_incident`
- `update_security_incident`
- `update_alert_v2`
- `create_alert_comment`
- non-GET `graph_security_request` calls

Approval phrase examples:

- Close incident: `APPROVE DEFENDER GRAPH CLOSE INCIDENT <incident_id>`
- Update incident: `APPROVE DEFENDER GRAPH UPDATE INCIDENT <incident_id>`
- Update alert: `APPROVE DEFENDER GRAPH UPDATE ALERT <alert_id>`
- Comment on alert: `APPROVE DEFENDER GRAPH COMMENT ON ALERT <alert_id>`
- Sensitive raw API request: `APPROVE DEFENDER GRAPH API REQUEST <METHOD> <PATH>`

## MCP Client Example

JSON-style clients:

```json
{
  "mcpServers": {
    "defender-graph-security": {
      "command": "node",
      "args": [
        "/path/to/defender-graph-security-mcp-server/src/index.js"
      ],
      "env": {
        "MSGRAPH_TENANT_ID": "<tenant-id>",
        "MSGRAPH_CLIENT_ID": "<application-client-id>",
        "MSGRAPH_CLIENT_SECRET": "<client-secret>",
        "MSGRAPH_HUMAN_APPROVAL_TOKEN": "a-human-held-approval-token"
      }
    }
  }
}
```

TOML-style clients:

```toml
[mcp_servers.defender-graph-security]
command = "node"
args = ["/path/to/defender-graph-security-mcp-server/src/index.js"]

[mcp_servers.defender-graph-security.env]
MSGRAPH_TENANT_ID = "<tenant-id>"
MSGRAPH_CLIENT_ID = "<application-client-id>"
MSGRAPH_CLIENT_SECRET = "<client-secret>"
MSGRAPH_HUMAN_APPROVAL_TOKEN = "a-human-held-approval-token"
```

## Example Tool Arguments

List active incidents:

```json
{
  "filter": "status eq 'active'",
  "orderby": "createdDateTime desc",
  "top": 25
}
```

Get one incident with alerts:

```json
{
  "incident_id": "12345",
  "expand": "alerts"
}
```

Close an incident:

```json
{
  "incident_id": "12345",
  "classification": "truePositive",
  "determination": "malware",
  "resolving_comment": "Resolved after containment and remediation.",
  "human_approval": {
    "approved": true,
    "phrase": "APPROVE DEFENDER GRAPH CLOSE INCIDENT 12345",
    "approved_by": "Jane Analyst",
    "reason": "Confirmed malicious incident has been remediated.",
    "approval_token": "a-human-held-approval-token"
  }
}
```

## Manual Smoke Test

From this folder after `npm install`:

```bash
npm run smoke
```

With credentials configured, use `config_status` first, then try `list_security_incidents` with a small `top` value.
