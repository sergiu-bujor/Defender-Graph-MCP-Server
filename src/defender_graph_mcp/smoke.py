from __future__ import annotations

import json
import subprocess
import sys


REQUIRED_TOOLS = [
    "config_status",
    "run_hunting_query",
    "list_machines",
    "get_machine",
    "list_security_incidents",
    "close_security_incident",
    "create_alert_comment",
    "graph_entity_list",
    "graph_entity_get",
    "graph_entity_update",
    "graph_entity_comment",
    "graph_entity_navigate",
    "graph_entity_list_next",
    "graph_entity_schema",
    "context_discover",
    "context_stats",
    "context_configure",
    "get_machine_by_name",
    "get_machine_actions",
    "list_endpoint_alerts",
    "get_endpoint_alert",
    "get_endpoint_alert_files",
    "get_file_info",
    "get_file_related_machines",
    "get_file_stats",
    "isolate_device",
    "release_device",
    "set_machine_tag",
    "run_antivirus_scan",
    "offboard_device",
    "run_live_response",
    "stop_and_quarantine",
    "restrict_code_execution",
    "remove_code_restriction",
    "collect_investigation_package",
    "get_investigation_package_uri",
    "isolate_multiple",
    "list_indicators",
    "submit_indicator",
    "delete_indicator",
    "revoke_entra_sessions",
    "confirm_user_compromised",
    "confirm_user_safe",
    "invoke_identity_account_action",
    "disable_ad_account",
    "enable_ad_account",
    "force_ad_password_reset",
    "assign_incident",
    "update_incident_status",
    "classify_incident",
    "add_incident_tags",
    "add_incident_comment",
    "graph_security_request",
    "defender_endpoint_request",
]


def main() -> None:
    child = subprocess.Popen(
        [sys.executable, "-m", "defender_graph_mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "smoke", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "config_status", "arguments": {}}},
    ]

    assert child.stdin is not None
    assert child.stdout is not None
    for request in requests:
        child.stdin.write(json.dumps(request) + "\n")
    child.stdin.flush()

    responses = []
    while len([response for response in responses if "id" in response]) < 3:
        line = child.stdout.readline()
        if not line:
            break
        responses.append(json.loads(line))

    child.terminate()
    _, stderr = child.communicate(timeout=5)
    if stderr:
        print(stderr, file=sys.stderr)

    tool_list = next((response for response in responses if response.get("id") == 2), {})
    tools = tool_list.get("result", {}).get("tools", [])
    missing = [tool_name for tool_name in REQUIRED_TOOLS if not any(tool.get("name") == tool_name for tool in tools)]

    if missing:
        raise SystemExit(f"Smoke test failed. Missing tools: {', '.join(missing)}")

    print(json.dumps({"ok": True, "tools": len(tools)}, indent=2))


if __name__ == "__main__":
    main()
