# Defender Graph Security MCP Skill Notes

Use this MCP server for Microsoft Defender XDR and Microsoft Graph Security incident and alert work.

## Safe Defaults

- Start with `config_status`.
- Prefer read-only tools before using the raw `graph_security_request`.
- Use `list_security_incidents` or `get_security_incident` for incident triage.
- Use `list_incident_alerts`, `list_alerts_v2`, or `get_alert_v2` for alert details.
- Use universal tools when the workflow should apply to either supported entity type: `graph_entity_list`, `graph_entity_get`, `graph_entity_update`, `graph_entity_comment`, `graph_entity_navigate`, `graph_entity_list_next`, and `graph_entity_schema`.
- Use `context_discover` when you need field, filter, relationship, or update guidance before forming a query.
- Use device response tools only after validating the impacted device and expected business impact: `isolate_device`, `release_device`, `run_antivirus_scan`, `stop_and_quarantine`, `restrict_code_execution`, `remove_code_restriction`, and `collect_investigation_package`.
- Use `run_hunting_query`, file pivots, machine inventory, endpoint alerts, and indicator listing for investigation before taking response actions.
- Use `submit_indicator` for IOC blocking or alerting when an indicator is confirmed and scoped correctly.
- Use `run_live_response` only for deliberate CSIRT workflows because it can run scripts and collect files from devices.
- Treat `offboard_device` as a lifecycle/decommission action, not normal containment.
- Use identity response tools only after confirming the account and action target: `revoke_entra_sessions`, `confirm_user_compromised`, `confirm_user_safe`, `disable_ad_account`, `enable_ad_account`, and `force_ad_password_reset`.

## Write Actions

Write actions require explicit human approval and a configured `MSGRAPH_HUMAN_APPROVAL_TOKEN`.

Use `close_security_incident` only when the incident closure classification and determination are known. Use `update_security_incident` for assignment, tags, or other incident patch operations.

Approval phrases must match exactly:

- `APPROVE DEFENDER GRAPH CLOSE INCIDENT <incident_id>`
- `APPROVE DEFENDER GRAPH UPDATE INCIDENT <incident_id>`
- `APPROVE DEFENDER GRAPH UPDATE ALERT <alert_id>`
- `APPROVE DEFENDER GRAPH COMMENT ON ALERT <alert_id>`
- `APPROVE DEFENDER GRAPH UPDATE ENTITY <entityType> <entityId>`
- `APPROVE DEFENDER GRAPH COMMENT ON ENTITY <entityType> <entityId>`
- `APPROVE DEFENDER GRAPH ISOLATE DEVICE <device-name>`
- `APPROVE DEFENDER GRAPH RELEASE DEVICE <device-name>`
- `APPROVE DEFENDER GRAPH RUN ANTIVIRUS SCAN <device-name> <Quick|Full>`
- `APPROVE DEFENDER GRAPH STOP AND QUARANTINE <device-name> <sha1>`
- `APPROVE DEFENDER GRAPH SET MACHINE TAG <Add|Remove> <tag> <device-name>`
- `APPROVE DEFENDER GRAPH OFFBOARD DEVICE <device-name>`
- `APPROVE DEFENDER GRAPH RUN LIVE RESPONSE <device-name> <count> COMMANDS`
- `APPROVE DEFENDER GRAPH SUBMIT INDICATOR <indicatorType> <indicatorValue> <action>`
- `APPROVE DEFENDER GRAPH DELETE INDICATOR <indicator_id>`
- `APPROVE DEFENDER GRAPH REVOKE ENTRA SESSIONS <user-principal-name>`
- `APPROVE DEFENDER GRAPH DISABLE AD ACCOUNT <user-principal-name>`
- `APPROVE DEFENDER GRAPH DEFENDER ENDPOINT API REQUEST <METHOD> <PATH>`
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
