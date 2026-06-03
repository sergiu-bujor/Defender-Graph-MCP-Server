#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const child = spawn(process.execPath, ["./src/index.js"], {
  cwd: new URL("..", import.meta.url),
  stdio: ["pipe", "pipe", "inherit"]
});

const rl = createInterface({ input: child.stdout });
const responses = [];

rl.on("line", (line) => {
  responses.push(JSON.parse(line));
  if (responses.length === 3) {
    child.kill();
  }
});

const requests = [
  {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "smoke", version: "0" }
    }
  },
  { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
  {
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "config_status", arguments: {} }
  }
];

for (const request of requests) {
  child.stdin.write(`${JSON.stringify(request)}\n`);
}

child.on("exit", () => {
  const toolList = responses.find((response) => response.id === 2);
  const tools = toolList?.result?.tools ?? [];
  const requiredTools = [
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
    "defender_endpoint_request"
  ];
  const missingTools = requiredTools.filter((toolName) => !tools.some((tool) => tool.name === toolName));

  if (missingTools.length) {
    console.error(`Smoke test failed. Missing tools: ${missingTools.join(", ")}`);
    process.exit(1);
  }

  console.log(JSON.stringify({ ok: true, tools: tools.length }, null, 2));
});
