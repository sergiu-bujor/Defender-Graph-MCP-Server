# Defender Graph Security MCP Server

Local MCP server for Microsoft Defender XDR and Microsoft Graph Security incidents and alerts.

The server uses Microsoft Graph application authentication with the client credentials flow. It exposes read tools for incidents and alerts, universal entity tools with intent-based field selection, plus guarded write tools for updating or closing incidents and alerts.

## Quick Start

```bash
git clone https://github.com/sergiu-bujor/defender-graph-security-mcp-server.git
cd defender-graph-security-mcp-server
poetry install
poetry run smoke
```

Then configure your MCP client to run:

```bash
poetry --directory /path/to/defender-graph-security-mcp-server run defender-graph-security-mcp
```

## Authentication

Create or use a Microsoft Entra ID app registration with client credentials and Microsoft Graph application permissions.

Recommended application permissions:

- `SecurityIncident.Read.All`
- `SecurityIncident.ReadWrite.All`
- `SecurityAlert.Read.All`
- `SecurityAlert.ReadWrite.All`
- `Machine.ReadWrite.All`
- `Machine.Isolate`
- `Machine.Scan`
- `Machine.StopAndQuarantine`
- `Machine.RestrictExecution`
- `Machine.CollectForensics`
- `Machine.Offboard`
- `Machine.LiveResponse`
- `User.Read.All`
- `User.RevokeSessions.All`
- `IdentityRiskyUser.ReadWrite.All`
- `SecurityIdentitiesAccount.Read.All`
- `SecurityIdentitiesActions.ReadWrite.All`
- `ThreatHunting.Read.All`
- `Ti.ReadWrite.All`
- `File.Read.All`

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
- `DEFENDER_API_BASE_URL`: defaults to `https://api.securitycenter.microsoft.com`.
- `MSGRAPH_TIMEOUT_SECONDS`: defaults to `30`.

## Tools

Configuration:

- `config_status`: shows whether credentials, endpoints, and guardrails are configured without revealing secrets.
- `run_hunting_query`: run Microsoft Graph Security Advanced Hunting KQL via `/security/runHuntingQuery`.

Universal entity tools:

- `graph_entity_list`: list `alert` or `incident` entities with optional filters and intent-based `$select`.
- `graph_entity_get`: get a single `alert` or `incident`.
- `graph_entity_update`: update a single `alert` or `incident` with human approval.
- `graph_entity_comment`: add a comment to an `alert` or `incident` with human approval.
- `graph_entity_navigate`: navigate between incidents and related alerts.
- `graph_entity_list_next`: fetch the next page from an `@odata.nextLink`.
- `graph_entity_schema`: return supported fields, filters, updateable fields, and relationships.

Context helper tools:

- `context_discover`: discover entity capabilities and recommended tools.
- `context_stats`: show lightweight tool usage/context stats for the current server process.
- `context_configure`: configure or reset lightweight context behavior.

Defender for Endpoint device response tools:

- `list_machines`: list endpoint machines with OData filters.
- `get_machine`: get a machine by Defender machine ID.
- `get_machine_by_name`: find a machine/device by hostname.
- `get_machine_actions`: list recent machine response actions.
- `list_endpoint_alerts`: list Defender for Endpoint alerts.
- `get_endpoint_alert`: get one Defender for Endpoint alert.
- `get_endpoint_alert_files`: get files related to an endpoint alert.
- `get_file_info`: get file profile data by SHA1 or SHA256.
- `get_file_related_machines`: find machines related to a file SHA1.
- `get_file_stats`: get file prevalence/statistics.
- `isolate_device`: isolate a device with human approval.
- `release_device`: release a device from isolation with human approval.
- `set_machine_tag`: add or remove a device tag with human approval.
- `run_antivirus_scan`: run a quick or full antivirus scan with human approval.
- `offboard_device`: offboard a Windows device from Defender for Endpoint with human approval.
- `run_live_response`: run Defender Live Response commands with human approval.
- `stop_and_quarantine`: stop a process and quarantine a file by SHA1 with human approval.
- `restrict_code_execution`: restrict code execution on a device with human approval.
- `remove_code_restriction`: remove code execution restrictions with human approval.
- `collect_investigation_package`: collect a forensic package with human approval.
- `get_investigation_package_uri`: get the download URI for a completed package action.
- `isolate_multiple`: bulk isolate multiple devices with human approval.
- `list_indicators`: list Defender for Endpoint indicators.
- `submit_indicator`: submit or update an IOC indicator with human approval.
- `delete_indicator`: delete an IOC indicator with human approval.

Identity response tools:

- `revoke_entra_sessions`: revoke all Entra ID sessions and refresh tokens with human approval.
- `confirm_user_compromised`: mark a user as compromised in Identity Protection with human approval.
- `confirm_user_safe`: dismiss user risk in Identity Protection with human approval.
- `invoke_identity_account_action`: invoke a Microsoft Defender for Identity account action through Graph beta with human approval.
- `disable_ad_account`: convenience wrapper for the MDI Active Directory disable action.
- `enable_ad_account`: convenience wrapper for the MDI Active Directory enable action.
- `force_ad_password_reset`: convenience wrapper for the MDI Active Directory force password reset action.

Incident convenience tools:

- `update_incident_status`: update incident status with human approval.
- `assign_incident`: assign or unassign an incident with human approval.
- `classify_incident`: set classification and determination with human approval.
- `add_incident_tags`: preserve existing tags and add new custom tags with human approval.
- `add_incident_comment`: add an incident comment with human approval.

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
- `defender_endpoint_request`: escape hatch for Defender for Endpoint API calls not covered by a dedicated tool. Non-GET calls require human approval.

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
- `graph_entity_update`
- `graph_entity_comment`
- Defender for Endpoint response tools such as `isolate_device`, `run_antivirus_scan`, `stop_and_quarantine`, and `collect_investigation_package`
- Live Response and lifecycle tools such as `run_live_response`, `set_machine_tag`, and `offboard_device`
- IOC tools such as `submit_indicator` and `delete_indicator`
- Identity response tools such as `revoke_entra_sessions`, `confirm_user_compromised`, and `disable_ad_account`
- Incident convenience tools such as `assign_incident`, `classify_incident`, and `add_incident_comment`
- non-GET `defender_endpoint_request` calls
- non-GET `graph_security_request` calls

Approval phrase examples:

- Close incident: `APPROVE DEFENDER GRAPH CLOSE INCIDENT <incident_id>`
- Update incident: `APPROVE DEFENDER GRAPH UPDATE INCIDENT <incident_id>`
- Update alert: `APPROVE DEFENDER GRAPH UPDATE ALERT <alert_id>`
- Comment on alert: `APPROVE DEFENDER GRAPH COMMENT ON ALERT <alert_id>`
- Universal entity update: `APPROVE DEFENDER GRAPH UPDATE ENTITY <entityType> <entityId>`
- Universal entity comment: `APPROVE DEFENDER GRAPH COMMENT ON ENTITY <entityType> <entityId>`
- Isolate device: `APPROVE DEFENDER GRAPH ISOLATE DEVICE <device-name>`
- Release device: `APPROVE DEFENDER GRAPH RELEASE DEVICE <device-name>`
- Run antivirus scan: `APPROVE DEFENDER GRAPH RUN ANTIVIRUS SCAN <device-name> <Quick|Full>`
- Stop and quarantine: `APPROVE DEFENDER GRAPH STOP AND QUARANTINE <device-name> <sha1>`
- Set machine tag: `APPROVE DEFENDER GRAPH SET MACHINE TAG <Add|Remove> <tag> <device-name>`
- Offboard device: `APPROVE DEFENDER GRAPH OFFBOARD DEVICE <device-name>`
- Run Live Response: `APPROVE DEFENDER GRAPH RUN LIVE RESPONSE <device-name> <count> COMMANDS`
- Submit indicator: `APPROVE DEFENDER GRAPH SUBMIT INDICATOR <indicatorType> <indicatorValue> <action>`
- Delete indicator: `APPROVE DEFENDER GRAPH DELETE INDICATOR <indicator_id>`
- Revoke Entra sessions: `APPROVE DEFENDER GRAPH REVOKE ENTRA SESSIONS <user-principal-name>`
- Disable AD account: `APPROVE DEFENDER GRAPH DISABLE AD ACCOUNT <user-principal-name>`
- Defender Endpoint raw request: `APPROVE DEFENDER GRAPH DEFENDER ENDPOINT API REQUEST <METHOD> <PATH>`
- Sensitive raw API request: `APPROVE DEFENDER GRAPH API REQUEST <METHOD> <PATH>`

## MCP Client Example

JSON-style clients:

```json
{
  "mcpServers": {
    "defender-graph-security": {
      "command": "poetry",
      "args": [
        "--directory",
        "/path/to/defender-graph-security-mcp-server",
        "run",
        "defender-graph-security-mcp"
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
command = "poetry"
args = ["--directory", "/path/to/defender-graph-security-mcp-server", "run", "defender-graph-security-mcp"]

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

Use the universal entity list tool with overview fields:

```json
{
  "entityType": "alert",
  "filter": "severity eq 'high' and status eq 'new'",
  "intent": "overview",
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

Navigate from an incident to alerts:

```json
{
  "sourceEntityType": "incident",
  "sourceEntityId": "12345",
  "targetEntityType": "alert",
  "intent": "standard"
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

From this folder after `poetry install`:

```bash
poetry run smoke
```

With credentials configured, use `config_status` first, then try `list_security_incidents` with a small `top` value.
