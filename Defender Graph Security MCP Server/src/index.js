#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const SERVER_NAME = "defender-graph-security-mcp-server";
const SERVER_VERSION = "0.1.0";
const DEFAULT_AUTH_BASE_URL = "https://login.microsoftonline.com";
const DEFAULT_API_BASE_URL = "https://graph.microsoft.com/v1.0";
const GRAPH_SCOPE = "https://graph.microsoft.com/.default";
const HUMAN_APPROVAL_NOTE =
  "This action can change Microsoft Defender or Graph Security state. A human must explicitly approve it by providing the exact approval phrase, their name, a reason, and the configured approval token in human_approval.";

const tokenCache = {
  accessToken: null,
  expiresAt: 0
};

const jsonObject = z.record(z.string(), z.unknown());
const humanApprovalSchema = z.object({
  approved: z.boolean(),
  phrase: z.string(),
  approved_by: z.string(),
  reason: z.string(),
  approval_token: z.string()
});

const incidentClassificationSchema = z.enum([
  "unknown",
  "falsePositive",
  "truePositive",
  "informationalExpectedActivity"
]);

const incidentDeterminationSchema = z.enum([
  "unknown",
  "apt",
  "malware",
  "securityPersonnel",
  "securityTesting",
  "unwantedSoftware",
  "other",
  "multiStagedAttack",
  "compromisedUser",
  "phishing",
  "maliciousUserActivity",
  "clean",
  "insufficientData",
  "confirmedUserActivity",
  "lineOfBusinessApplication",
  "compromisedAccount",
  "networkIntrusion",
  "exfiltration",
  "manuallyDefined"
]);

const alertClassificationSchema = z.enum(["unknown", "falsePositive", "truePositive", "informationalExpectedActivity"]);
const alertDeterminationSchema = z.enum([
  "unknown",
  "apt",
  "malware",
  "securityPersonnel",
  "securityTesting",
  "unwantedSoftware",
  "other",
  "multiStagedAttack",
  "compromisedUser",
  "phishing",
  "maliciousUserActivity",
  "clean",
  "insufficientData",
  "confirmedUserActivity",
  "lineOfBusinessApplication"
]);

function textResult(data) {
  const text = typeof data === "string" ? data : JSON.stringify(data, null, 2);
  return { content: [{ type: "text", text }] };
}

function errorResult(error) {
  const message = error instanceof Error ? error.message : String(error);
  return { content: [{ type: "text", text: message }], isError: true };
}

function readConfig() {
  const timeoutRaw = process.env.MSGRAPH_TIMEOUT_SECONDS ?? "30";
  const timeoutSeconds = Number.parseFloat(timeoutRaw);

  return {
    tenantId:
      process.env.MSGRAPH_TENANT_ID ??
      process.env.AZURE_TENANT_ID ??
      process.env.TENANT_ID,
    clientId:
      process.env.MSGRAPH_CLIENT_ID ??
      process.env.AZURE_CLIENT_ID ??
      process.env.CLIENT_ID,
    clientSecret:
      process.env.MSGRAPH_CLIENT_SECRET ??
      process.env.AZURE_CLIENT_SECRET ??
      process.env.CLIENT_SECRET,
    authBaseUrl: (process.env.MSGRAPH_AUTH_BASE_URL ?? DEFAULT_AUTH_BASE_URL).replace(/\/+$/, ""),
    apiBaseUrl: (process.env.MSGRAPH_API_BASE_URL ?? DEFAULT_API_BASE_URL).replace(/\/+$/, ""),
    timeoutSeconds: Number.isFinite(timeoutSeconds) ? timeoutSeconds : 30,
    approvalToken: process.env.MSGRAPH_HUMAN_APPROVAL_TOKEN
  };
}

function requireCredentials(config) {
  if (!config.tenantId || !config.clientId || !config.clientSecret) {
    throw new Error(
      "Missing Microsoft Graph credentials. Set MSGRAPH_TENANT_ID, MSGRAPH_CLIENT_ID, and MSGRAPH_CLIENT_SECRET."
    );
  }
}

function approvalPhrase(action, subject) {
  return `APPROVE DEFENDER GRAPH ${action.toUpperCase()}${subject ? ` ${subject}` : ""}`;
}

function requireHumanApproval(args, action, expectedPhrase) {
  const config = readConfig();
  if (!config.approvalToken) {
    throw new Error(
      `Sensitive Defender/Graph Security actions are disabled until MSGRAPH_HUMAN_APPROVAL_TOKEN is configured. Required approval phrase: ${expectedPhrase}`
    );
  }

  const approval = args.human_approval;
  if (!approval || typeof approval !== "object") {
    throw new Error(`${HUMAN_APPROVAL_NOTE} Required approval phrase: ${expectedPhrase}`);
  }

  if (
    approval.approved !== true ||
    approval.phrase !== expectedPhrase ||
    approval.approval_token !== config.approvalToken ||
    typeof approval.approved_by !== "string" ||
    approval.approved_by.trim() === "" ||
    typeof approval.reason !== "string" ||
    approval.reason.trim() === ""
  ) {
    throw new Error(`${action} requires explicit human approval. Required approval phrase: ${expectedPhrase}`);
  }
}

function encodePathId(value, name) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`Missing or invalid ${name}`);
  }
  return encodeURIComponent(value.trim());
}

function graphQuery(args) {
  const query = {};
  const mappings = {
    filter: "$filter",
    select: "$select",
    expand: "$expand",
    orderby: "$orderby",
    search: "$search",
    top: "$top",
    skip: "$skip",
    skiptoken: "$skiptoken"
  };

  for (const [argName, queryName] of Object.entries(mappings)) {
    if (args[argName] !== undefined && args[argName] !== null && args[argName] !== "") {
      query[queryName] = args[argName];
    }
  }

  return Object.keys(query).length ? query : undefined;
}

function isSensitiveGraphRequest(method, path) {
  const upperMethod = method.toUpperCase();
  if (upperMethod === "GET") {
    return false;
  }

  const normalized = `/${path.replace(/^\/+/, "").split("?", 1)[0]}`.toLowerCase();
  return normalized.startsWith("/security/");
}

async function fetchWithTimeout(url, options, timeoutSeconds) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutSeconds * 1000);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

async function parseResponse(response) {
  const contentType = response.headers.get("content-type") ?? "";
  const rawBody = await response.arrayBuffer();
  const bytes = Buffer.from(rawBody);

  if (bytes.length === 0) {
    return null;
  }

  if (contentType.toLowerCase().includes("application/json")) {
    return JSON.parse(bytes.toString("utf8"));
  }

  const text = bytes.toString("utf8");
  if (text.includes("\uFFFD")) {
    return {
      content_type: contentType || "application/octet-stream",
      body_base64: bytes.toString("base64")
    };
  }

  return {
    content_type: contentType || "unknown",
    text
  };
}

async function graphRequestError(response, url) {
  let body = null;
  try {
    body = await parseResponse(response);
  } catch {
    body = await response.text().catch(() => null);
  }

  return new Error(
    `Microsoft Graph returned an error: ${JSON.stringify({
      status: response.status,
      reason: response.statusText,
      url,
      body
    })}`
  );
}

async function getAccessToken(forceRefresh = false) {
  const now = Date.now();
  if (tokenCache.accessToken && !forceRefresh && tokenCache.expiresAt > now + 60_000) {
    return tokenCache.accessToken;
  }

  const config = readConfig();
  requireCredentials(config);

  const tokenUrl = `${config.authBaseUrl}/${encodeURIComponent(config.tenantId)}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: config.clientId,
    client_secret: config.clientSecret,
    scope: GRAPH_SCOPE
  });

  const response = await fetchWithTimeout(
    tokenUrl,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        "User-Agent": `${SERVER_NAME}/${SERVER_VERSION}`
      },
      body
    },
    config.timeoutSeconds
  );

  if (!response.ok) {
    throw await graphRequestError(response, tokenUrl);
  }

  const tokenResponse = await response.json();
  if (!tokenResponse.access_token) {
    throw new Error("Microsoft identity platform response did not include access_token");
  }

  const expiresIn = Number.parseInt(tokenResponse.expires_in ?? "3600", 10);
  tokenCache.accessToken = tokenResponse.access_token;
  tokenCache.expiresAt = now + (Number.isFinite(expiresIn) ? expiresIn : 3600) * 1000;
  return tokenCache.accessToken;
}

async function graphRequest(method, path, body, query, forceTokenRefresh = false) {
  const config = readConfig();
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  const url = new URL(`${config.apiBaseUrl}${cleanPath}`);

  if (query && typeof query === "object") {
    for (const [key, value] of Object.entries(query)) {
      if (Array.isArray(value)) {
        for (const item of value) {
          url.searchParams.append(key, String(item));
        }
      } else if (value !== undefined && value !== null) {
        url.searchParams.set(key, String(value));
      }
    }
  }

  const headers = {
    Accept: "application/json, */*",
    Authorization: `Bearer ${await getAccessToken(forceTokenRefresh)}`,
    "User-Agent": `${SERVER_NAME}/${SERVER_VERSION}`
  };

  const options = { method: method.toUpperCase(), headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }

  const response = await fetchWithTimeout(url, options, config.timeoutSeconds);
  if (response.status === 401 && !forceTokenRefresh) {
    tokenCache.accessToken = null;
    tokenCache.expiresAt = 0;
    return graphRequest(method, path, body, query, true);
  }

  if (!response.ok) {
    throw await graphRequestError(response, url.toString());
  }

  return parseResponse(response);
}

async function withErrors(handler) {
  try {
    return await handler();
  } catch (error) {
    return errorResult(error);
  }
}

const server = new McpServer({
  name: SERVER_NAME,
  version: SERVER_VERSION
});

server.registerTool(
  "config_status",
  {
    title: "Configuration Status",
    description: "Show whether Microsoft Graph credentials, endpoints, and guardrails are configured without revealing secret values.",
    inputSchema: {}
  },
  async () =>
    withErrors(async () => {
      const config = readConfig();
      return textResult({
        tenant_id_configured: Boolean(config.tenantId),
        client_id_configured: Boolean(config.clientId),
        client_secret_configured: Boolean(config.clientSecret),
        human_approval_token_configured: Boolean(config.approvalToken),
        auth_base_url: config.authBaseUrl,
        api_base_url: config.apiBaseUrl,
        timeout_seconds: config.timeoutSeconds,
        token_cached: Boolean(tokenCache.accessToken),
        token_expires_at_epoch: tokenCache.expiresAt ? Math.floor(tokenCache.expiresAt / 1000) : null,
        recommended_application_permissions: [
          "SecurityIncident.Read.All",
          "SecurityIncident.ReadWrite.All",
          "SecurityAlert.Read.All",
          "SecurityAlert.ReadWrite.All"
        ],
        human_approval_required_for: [
          "close_security_incident",
          "update_security_incident",
          "update_alert_v2",
          "create_alert_comment",
          "non-GET graph_security_request calls"
        ]
      });
    })
);

server.registerTool(
  "list_security_incidents",
  {
    title: "List Security Incidents",
    description: "List Microsoft Graph Security incidents with optional OData query parameters.",
    inputSchema: {
      filter: z.string().optional(),
      select: z.string().optional(),
      expand: z.string().optional(),
      orderby: z.string().optional(),
      top: z.number().int().min(1).max(999).optional(),
      skip: z.number().int().min(0).optional(),
      skiptoken: z.string().optional()
    }
  },
  async (args) => withErrors(async () => textResult(await graphRequest("GET", "/security/incidents", undefined, graphQuery(args))))
);

server.registerTool(
  "get_security_incident",
  {
    title: "Get Security Incident",
    description: "Get a Microsoft Graph Security incident by ID.",
    inputSchema: {
      incident_id: z.string().min(1),
      select: z.string().optional(),
      expand: z.string().optional()
    }
  },
  async ({ incident_id, select, expand }) =>
    withErrors(async () =>
      textResult(
        await graphRequest("GET", `/security/incidents/${encodePathId(incident_id, "incident_id")}`, undefined, graphQuery({ select, expand }))
      )
    )
);

server.registerTool(
  "list_incident_alerts",
  {
    title: "List Incident Alerts",
    description: "List alerts related to a Microsoft Graph Security incident.",
    inputSchema: {
      incident_id: z.string().min(1),
      filter: z.string().optional(),
      select: z.string().optional(),
      orderby: z.string().optional(),
      top: z.number().int().min(1).max(999).optional(),
      skip: z.number().int().min(0).optional()
    }
  },
  async ({ incident_id, ...queryArgs }) =>
    withErrors(async () =>
      textResult(await graphRequest("GET", `/security/incidents/${encodePathId(incident_id, "incident_id")}/alerts`, undefined, graphQuery(queryArgs)))
    )
);

server.registerTool(
  "list_alerts_v2",
  {
    title: "List Alerts V2",
    description: "List Microsoft Graph Security alerts_v2 with optional OData query parameters.",
    inputSchema: {
      filter: z.string().optional(),
      select: z.string().optional(),
      expand: z.string().optional(),
      orderby: z.string().optional(),
      top: z.number().int().min(1).max(999).optional(),
      skip: z.number().int().min(0).optional(),
      skiptoken: z.string().optional()
    }
  },
  async (args) => withErrors(async () => textResult(await graphRequest("GET", "/security/alerts_v2", undefined, graphQuery(args))))
);

server.registerTool(
  "get_alert_v2",
  {
    title: "Get Alert V2",
    description: "Get a Microsoft Graph Security alert_v2 by ID.",
    inputSchema: {
      alert_id: z.string().min(1),
      select: z.string().optional(),
      expand: z.string().optional()
    }
  },
  async ({ alert_id, select, expand }) =>
    withErrors(async () =>
      textResult(await graphRequest("GET", `/security/alerts_v2/${encodePathId(alert_id, "alert_id")}`, undefined, graphQuery({ select, expand })))
    )
);

server.registerTool(
  "update_security_incident",
  {
    title: "Update Security Incident",
    description: "Patch selected Microsoft Graph Security incident fields. Requires explicit human approval.",
    inputSchema: {
      incident_id: z.string().min(1),
      status: z.enum(["active", "resolved", "inProgress", "redirected", "unknownFutureValue"]).optional(),
      classification: incidentClassificationSchema.optional(),
      determination: incidentDeterminationSchema.optional(),
      custom_tags: z.array(z.string()).optional(),
      assigned_to: z.string().optional(),
      resolving_comment: z.string().optional(),
      request_body: jsonObject.optional(),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      const incidentId = args.incident_id.trim();
      requireHumanApproval(args, "update_security_incident", approvalPhrase("UPDATE INCIDENT", incidentId));

      const body = args.request_body ?? {
        ...(args.status ? { status: args.status } : {}),
        ...(args.classification ? { classification: args.classification } : {}),
        ...(args.determination ? { determination: args.determination } : {}),
        ...(args.custom_tags ? { customTags: args.custom_tags } : {}),
        ...(args.assigned_to ? { assignedTo: args.assigned_to } : {}),
        ...(args.resolving_comment ? { resolvingComment: args.resolving_comment } : {})
      };

      if (Object.keys(body).length === 0) {
        throw new Error("Provide at least one incident field or request_body to update");
      }

      return textResult(await graphRequest("PATCH", `/security/incidents/${encodePathId(incidentId, "incident_id")}`, body));
    })
);

server.registerTool(
  "close_security_incident",
  {
    title: "Close Security Incident",
    description: "Resolve a Microsoft Graph Security incident with classification, determination, and optional resolving comment. Requires explicit human approval.",
    inputSchema: {
      incident_id: z.string().min(1),
      classification: incidentClassificationSchema,
      determination: incidentDeterminationSchema.default("other"),
      resolving_comment: z.string().optional(),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      const incidentId = args.incident_id.trim();
      requireHumanApproval(args, "close_security_incident", approvalPhrase("CLOSE INCIDENT", incidentId));

      const body = {
        status: "resolved",
        classification: args.classification,
        determination: args.determination
      };

      if (args.resolving_comment) {
        body.resolvingComment = args.resolving_comment;
      }

      return textResult(await graphRequest("PATCH", `/security/incidents/${encodePathId(incidentId, "incident_id")}`, body));
    })
);

server.registerTool(
  "update_alert_v2",
  {
    title: "Update Alert V2",
    description: "Patch selected Microsoft Graph Security alert_v2 fields. Requires explicit human approval.",
    inputSchema: {
      alert_id: z.string().min(1),
      status: z.enum(["new", "inProgress", "resolved", "unknownFutureValue"]).optional(),
      classification: alertClassificationSchema.optional(),
      determination: alertDeterminationSchema.optional(),
      assigned_to: z.string().optional(),
      custom_details: jsonObject.optional(),
      request_body: jsonObject.optional(),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      const alertId = args.alert_id.trim();
      requireHumanApproval(args, "update_alert_v2", approvalPhrase("UPDATE ALERT", alertId));

      const body = args.request_body ?? {
        ...(args.status ? { status: args.status } : {}),
        ...(args.classification ? { classification: args.classification } : {}),
        ...(args.determination ? { determination: args.determination } : {}),
        ...(args.assigned_to ? { assignedTo: args.assigned_to } : {}),
        ...(args.custom_details ? { customDetails: args.custom_details } : {})
      };

      if (Object.keys(body).length === 0) {
        throw new Error("Provide at least one alert field or request_body to update");
      }

      return textResult(await graphRequest("PATCH", `/security/alerts_v2/${encodePathId(alertId, "alert_id")}`, body));
    })
);

server.registerTool(
  "create_alert_comment",
  {
    title: "Create Alert Comment",
    description: "Create a comment on a Microsoft Graph Security alert_v2. Requires explicit human approval.",
    inputSchema: {
      alert_id: z.string().min(1),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      const alertId = args.alert_id.trim();
      requireHumanApproval(args, "create_alert_comment", approvalPhrase("COMMENT ON ALERT", alertId));

      return textResult(
        await graphRequest("POST", `/security/alerts_v2/${encodePathId(alertId, "alert_id")}/comments`, {
          "@odata.type": "microsoft.graph.security.alertComment",
          comment: args.comment
        })
      );
    })
);

server.registerTool(
  "graph_security_request",
  {
    title: "Graph Security Request",
    description: "Advanced escape hatch for Microsoft Graph Security API calls not covered by a dedicated tool. Non-GET calls require explicit human approval.",
    inputSchema: {
      method: z.enum(["GET", "POST", "PATCH", "PUT", "DELETE"]),
      path: z.string().min(1),
      query: jsonObject.optional(),
      body: jsonObject.optional(),
      human_approval: humanApprovalSchema.optional()
    }
  },
  async (args) =>
    withErrors(async () => {
      if (isSensitiveGraphRequest(args.method, args.path)) {
        const normalized = `/${args.path.replace(/^\/+/, "").split("?", 1)[0]}`;
        requireHumanApproval(args, "graph_security_request", approvalPhrase("API REQUEST", `${args.method} ${normalized}`));
      }

      return textResult(await graphRequest(args.method, args.path, args.body, args.query));
    })
);

const transport = new StdioServerTransport();
await server.connect(transport);
