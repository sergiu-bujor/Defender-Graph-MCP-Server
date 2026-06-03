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
  const requiredTools = ["config_status", "list_security_incidents", "close_security_incident", "create_alert_comment", "graph_security_request"];
  const missingTools = requiredTools.filter((toolName) => !tools.some((tool) => tool.name === toolName));

  if (missingTools.length) {
    console.error(`Smoke test failed. Missing tools: ${missingTools.join(", ")}`);
    process.exit(1);
  }

  console.log(JSON.stringify({ ok: true, tools: tools.length }, null, 2));
});
