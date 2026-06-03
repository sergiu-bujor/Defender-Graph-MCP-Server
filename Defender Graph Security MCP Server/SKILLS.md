# Defender Graph Security MCP Skill Notes

Use this MCP server for Microsoft Defender XDR and Microsoft Graph Security incident and alert work.

## Safe Defaults

- Start with `config_status`.
- Prefer read-only tools before using the raw `graph_security_request`.
- Use `list_security_incidents` or `get_security_incident` for incident triage.
- Use `list_incident_alerts`, `list_alerts_v2`, or `get_alert_v2` for alert details.

## Write Actions

Write actions require explicit human approval and a configured `MSGRAPH_HUMAN_APPROVAL_TOKEN`.

Use `close_security_incident` only when the incident closure classification and determination are known. Use `update_security_incident` for assignment, tags, or other incident patch operations.

Approval phrases must match exactly:

- `APPROVE DEFENDER GRAPH CLOSE INCIDENT <incident_id>`
- `APPROVE DEFENDER GRAPH UPDATE INCIDENT <incident_id>`
- `APPROVE DEFENDER GRAPH UPDATE ALERT <alert_id>`
- `APPROVE DEFENDER GRAPH COMMENT ON ALERT <alert_id>`
- `APPROVE DEFENDER GRAPH API REQUEST <METHOD> <PATH>`

## Classification Guidance

Common Microsoft Defender incident classifications:

- `truePositive`
- `falsePositive`
- `informationalExpectedActivity`
- `unknown`

Common determinations:

- `malware`
- `phishing`
- `compromisedAccount`
- `securityTesting`
- `confirmedUserActivity`
- `lineOfBusinessApplication`
- `other`

When unsure, avoid closing the incident and gather more context first.
