# Install Defender Graph Security MCP Server

## 1. Install Dependencies

```bash
git clone https://github.com/<your-org-or-user>/defender-graph-security-mcp-server.git
cd defender-graph-security-mcp-server
npm install
npm run smoke
```

## 2. Configure Microsoft Graph Access

Create an Entra ID app registration and grant the Microsoft Graph application permissions required by the tools you plan to use.

Read-only usage:

- `SecurityIncident.Read.All`
- `SecurityAlert.Read.All`
- `Machine.ReadWrite.All`
- `User.Read.All`

Write/closure usage:

- `SecurityIncident.ReadWrite.All`
- `SecurityAlert.ReadWrite.All`
- `Machine.Isolate`
- `Machine.Scan`
- `Machine.StopAndQuarantine`
- `Machine.RestrictExecution`
- `Machine.CollectForensics`
- `Machine.Offboard`
- `Machine.LiveResponse`
- `User.RevokeSessions.All`
- `IdentityRiskyUser.ReadWrite.All`
- `SecurityIdentitiesAccount.Read.All`
- `SecurityIdentitiesActions.ReadWrite.All`
- `ThreatHunting.Read.All`
- `Ti.ReadWrite.All`
- `File.Read.All`

Admin consent is required for application permissions.

## 3. Configure Your MCP Client

Point the client at:

```bash
node /path/to/defender-graph-security-mcp-server/src/index.js
```

Use these environment variables:

```bash
MSGRAPH_TENANT_ID=<tenant-id>
MSGRAPH_CLIENT_ID=<application-client-id>
MSGRAPH_CLIENT_SECRET=<client-secret>
MSGRAPH_HUMAN_APPROVAL_TOKEN=choose-a-human-held-approval-token
```

## 4. Validate

Run `config_status` from your MCP client. It should show configured credentials and the Graph base URL without exposing secret values.

Then run:

```json
{
  "top": 5,
  "orderby": "createdDateTime desc"
}
```

against `list_security_incidents`.

You can also test tool discovery with `context_discover` and `graph_entity_schema` before making live Graph API calls.
