#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const SERVER_NAME = "defender-graph-security-mcp-server";
const SERVER_VERSION = "0.1.0";
const DEFAULT_AUTH_BASE_URL = "https://login.microsoftonline.com";
const DEFAULT_API_BASE_URL = "https://graph.microsoft.com/v1.0";
const DEFAULT_DEFENDER_API_BASE_URL = "https://api.securitycenter.microsoft.com";
const GRAPH_SCOPE = "https://graph.microsoft.com/.default";
const DEFENDER_SCOPE = "https://api.securitycenter.microsoft.com/.default";
const HUMAN_APPROVAL_NOTE =
  "This action can change Microsoft Defender or Graph Security state. A human must explicitly approve it by providing the exact approval phrase, their name, a reason, and the configured approval token in human_approval.";

const tokenCache = {
  graph: {
    accessToken: null,
    expiresAt: 0
  },
  defender: {
    accessToken: null,
    expiresAt: 0
  }
};

const contextState = {
  level: "standard",
  ttlSeconds: 3600,
  configuredAt: new Date().toISOString(),
  toolCalls: {}
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

const entityTypeSchema = z.enum(["alert", "incident"]);
const queryIntentSchema = z.enum(["overview", "standard", "complete"]);
const machineActionTypeSchema = z.enum([
  "Isolate",
  "Unisolate",
  "RunAntiVirusScan",
  "StopAndQuarantineFile",
  "RestrictCodeExecution",
  "UnrestrictCodeExecution",
  "CollectInvestigationPackage"
]);
const indicatorTypeSchema = z.enum(["FileSha1", "FileSha256", "FileMd5", "CertificateThumbprint", "IpAddress", "DomainName", "Url"]);
const indicatorActionSchema = z.enum(["Warn", "Block", "Audit", "Alert", "AlertAndBlock", "BlockAndRemediate", "Allowed"]);
const indicatorSeveritySchema = z.enum(["Informational", "Low", "Medium", "High"]);
const liveResponseCommandSchema = z.object({
  type: z.enum(["PutFile", "RunScript", "GetFile"]),
  params: z.array(
    z.object({
      key: z.string().min(1),
      value: z.string()
    })
  ).default([])
});

const entityDefinitions = {
  alert: {
    singular: "alert",
    plural: "alerts",
    collectionPath: "/security/alerts_v2",
    itemPath: "/security/alerts_v2",
    commentPath: "/security/alerts_v2",
    idField: "id",
    defaultOrderBy: "createdDateTime desc",
    overviewFields: [
      "id",
      "title",
      "severity",
      "status",
      "classification",
      "determination",
      "serviceSource",
      "incidentId",
      "createdDateTime"
    ],
    standardFields: [
      "id",
      "title",
      "description",
      "severity",
      "status",
      "classification",
      "determination",
      "assignedTo",
      "category",
      "serviceSource",
      "detectionSource",
      "incidentId",
      "createdDateTime",
      "lastUpdateDateTime"
    ],
    filterableFields: [
      "assignedTo",
      "classification",
      "determination",
      "createdDateTime",
      "lastUpdateDateTime",
      "severity",
      "serviceSource",
      "status"
    ],
    updateableFields: ["status", "classification", "determination", "assignedTo", "customDetails"],
    relationships: {
      incident: "Use incidentId on the alert, then graph_entity_get with entityType='incident'."
    }
  },
  incident: {
    singular: "incident",
    plural: "incidents",
    collectionPath: "/security/incidents",
    itemPath: "/security/incidents",
    commentPath: "/security/incidents",
    idField: "id",
    defaultOrderBy: "createdDateTime desc",
    overviewFields: [
      "id",
      "displayName",
      "severity",
      "status",
      "classification",
      "determination",
      "assignedTo",
      "createdDateTime"
    ],
    standardFields: [
      "id",
      "displayName",
      "description",
      "severity",
      "status",
      "classification",
      "determination",
      "assignedTo",
      "customTags",
      "createdDateTime",
      "lastUpdateDateTime",
      "incidentWebUrl"
    ],
    filterableFields: [
      "assignedTo",
      "classification",
      "createdDateTime",
      "determination",
      "lastUpdateDateTime",
      "severity",
      "status"
    ],
    updateableFields: ["status", "classification", "determination", "assignedTo", "customTags", "resolvingComment"],
    relationships: {
      alert: "Use graph_entity_navigate with targetEntityType='alert' to list alerts under the incident."
    }
  }
};

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
    defenderApiBaseUrl: (process.env.DEFENDER_API_BASE_URL ?? DEFAULT_DEFENDER_API_BASE_URL).replace(/\/+$/, ""),
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

function getEntityDefinition(entityType) {
  const definition = entityDefinitions[entityType];
  if (!definition) {
    throw new Error(`Unsupported entityType '${entityType}'. Supported values: ${Object.keys(entityDefinitions).join(", ")}`);
  }
  return definition;
}

function fieldsForIntent(entityType, intent = "standard") {
  const definition = getEntityDefinition(entityType);
  if (intent === "complete") {
    return undefined;
  }
  return (intent === "overview" ? definition.overviewFields : definition.standardFields).join(",");
}

function recordToolCall(toolName) {
  const current = contextState.toolCalls[toolName] ?? { count: 0, lastCalledAt: null };
  contextState.toolCalls[toolName] = {
    count: current.count + 1,
    lastCalledAt: new Date().toISOString()
  };
}

function entityQuery(args) {
  const select = args.select || fieldsForIntent(args.entityType, args.intent);
  const orderby = args.orderby || args.orderBy || getEntityDefinition(args.entityType).defaultOrderBy;
  return graphQuery({
    filter: args.filter,
    select,
    expand: args.expand,
    orderby,
    search: args.search,
    top: args.top,
    skip: args.skip,
    skiptoken: args.skiptoken,
    count: args.count
  });
}

function graphQuery(args) {
  const query = {};
  const mappings = {
    filter: "$filter",
    select: "$select",
    expand: "$expand",
    orderby: "$orderby",
    orderBy: "$orderby",
    search: "$search",
    top: "$top",
    skip: "$skip",
    skiptoken: "$skiptoken",
    count: "$count"
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

function machineLookupFilter(deviceName) {
  return `computerDnsName eq '${String(deviceName).replaceAll("'", "''")}'`;
}

async function resolveMachineId({ device_id, device_name }) {
  if (device_id) {
    const machine = await defenderRequest("GET", `/api/machines/${encodePathId(device_id, "device_id")}`);
    return {
      id: machine.id,
      name: machine.computerDnsName || device_name || machine.id,
      machine
    };
  }

  if (device_name) {
    const result = await defenderRequest("GET", "/api/machines", undefined, { "$filter": machineLookupFilter(device_name) });
    const machine = result?.value?.[0];
    if (!machine) {
      throw new Error(`No Defender for Endpoint machine found with name '${device_name}'`);
    }
    return {
      id: machine.id,
      name: machine.computerDnsName || device_name,
      machine
    };
  }

  throw new Error("Provide device_id or device_name");
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

async function getAccessToken(scope = GRAPH_SCOPE, forceRefresh = false) {
  const cacheKey = scope === DEFENDER_SCOPE ? "defender" : "graph";
  const cache = tokenCache[cacheKey];
  const now = Date.now();
  if (cache.accessToken && !forceRefresh && cache.expiresAt > now + 60_000) {
    return cache.accessToken;
  }

  const config = readConfig();
  requireCredentials(config);

  const tokenUrl = `${config.authBaseUrl}/${encodeURIComponent(config.tenantId)}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: config.clientId,
    client_secret: config.clientSecret,
    scope
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
  cache.accessToken = tokenResponse.access_token;
  cache.expiresAt = now + (Number.isFinite(expiresIn) ? expiresIn : 3600) * 1000;
  return cache.accessToken;
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
    Authorization: `Bearer ${await getAccessToken(GRAPH_SCOPE, forceTokenRefresh)}`,
    "User-Agent": `${SERVER_NAME}/${SERVER_VERSION}`
  };

  const options = { method: method.toUpperCase(), headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }

  const response = await fetchWithTimeout(url, options, config.timeoutSeconds);
  if (response.status === 401 && !forceTokenRefresh) {
    tokenCache.graph.accessToken = null;
    tokenCache.graph.expiresAt = 0;
    return graphRequest(method, path, body, query, true);
  }

  if (!response.ok) {
    throw await graphRequestError(response, url.toString());
  }

  return parseResponse(response);
}

async function graphRequestNextLink(nextLink, forceTokenRefresh = false) {
  const config = readConfig();
  const url = new URL(nextLink);
  const allowedBase = new URL(config.apiBaseUrl);

  if (url.origin !== allowedBase.origin) {
    throw new Error(`nextLink origin '${url.origin}' does not match configured Microsoft Graph origin '${allowedBase.origin}'`);
  }

  const headers = {
    Accept: "application/json, */*",
    Authorization: `Bearer ${await getAccessToken(GRAPH_SCOPE, forceTokenRefresh)}`,
    "User-Agent": `${SERVER_NAME}/${SERVER_VERSION}`
  };

  const response = await fetchWithTimeout(url, { method: "GET", headers }, config.timeoutSeconds);
  if (response.status === 401 && !forceTokenRefresh) {
    tokenCache.graph.accessToken = null;
    tokenCache.graph.expiresAt = 0;
    return graphRequestNextLink(nextLink, true);
  }

  if (!response.ok) {
    throw await graphRequestError(response, url.toString());
  }

  return parseResponse(response);
}

function betaApiBaseUrl() {
  const config = readConfig();
  return config.apiBaseUrl.replace(/\/v1\.0$/i, "/beta");
}

async function graphBetaRequest(method, path, body, query, forceTokenRefresh = false) {
  const config = readConfig();
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  const url = new URL(`${betaApiBaseUrl()}${cleanPath}`);

  if (query && typeof query === "object") {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    }
  }

  const headers = {
    Accept: "application/json, */*",
    Authorization: `Bearer ${await getAccessToken(GRAPH_SCOPE, forceTokenRefresh)}`,
    "User-Agent": `${SERVER_NAME}/${SERVER_VERSION}`
  };

  const options = { method: method.toUpperCase(), headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }

  const response = await fetchWithTimeout(url, options, config.timeoutSeconds);
  if (response.status === 401 && !forceTokenRefresh) {
    tokenCache.graph.accessToken = null;
    tokenCache.graph.expiresAt = 0;
    return graphBetaRequest(method, path, body, query, true);
  }

  if (!response.ok) {
    throw await graphRequestError(response, url.toString());
  }

  return parseResponse(response);
}

async function defenderRequest(method, path, body, query, forceTokenRefresh = false) {
  const config = readConfig();
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  const url = new URL(`${config.defenderApiBaseUrl}${cleanPath}`);

  if (query && typeof query === "object") {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    }
  }

  const headers = {
    Accept: "application/json, */*",
    Authorization: `Bearer ${await getAccessToken(DEFENDER_SCOPE, forceTokenRefresh)}`,
    "User-Agent": `${SERVER_NAME}/${SERVER_VERSION}`
  };

  const options = { method: method.toUpperCase(), headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }

  const response = await fetchWithTimeout(url, options, config.timeoutSeconds);
  if (response.status === 401 && !forceTokenRefresh) {
    tokenCache.defender.accessToken = null;
    tokenCache.defender.expiresAt = 0;
    return defenderRequest(method, path, body, query, true);
  }

  if (!response.ok) {
    throw await graphRequestError(response, url.toString());
  }

  return parseResponse(response);
}

async function getUserIdByUpn(userPrincipalName) {
  const user = await graphRequest("GET", `/users/${encodePathId(userPrincipalName, "user_principal_name")}`, undefined, {
    "$select": "id,userPrincipalName"
  });
  if (!user?.id) {
    throw new Error(`Could not resolve user ID for ${userPrincipalName}`);
  }
  return user.id;
}

async function getIdentityAccountIdByUpn(userPrincipalName) {
  const result = await graphBetaRequest("GET", "/security/identities/identityAccounts", undefined, {
    "$filter": `userPrincipalName eq '${String(userPrincipalName).replaceAll("'", "''")}'`
  });
  const account = result?.value?.[0];
  if (!account?.id) {
    throw new Error(`No Microsoft Defender for Identity account found for UPN ${userPrincipalName}`);
  }
  return account.id;
}

async function invokeIdentityActionForUser(args, action) {
  const identityAccountId = await getIdentityAccountIdByUpn(args.user_principal_name);
  const result = await graphBetaRequest("POST", `/security/identities/identityAccounts/${encodePathId(identityAccountId, "identity_account_id")}/invokeAction`, {
    accountId: args.account_id,
    action,
    identityProvider: args.identity_provider ?? "activeDirectory"
  });
  return {
    user_principal_name: args.user_principal_name,
    identity_account_id: identityAccountId,
    account_id: args.account_id,
    identity_action: action,
    identity_provider: args.identity_provider ?? "activeDirectory",
    comment: args.comment,
    result
  };
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
        defender_api_base_url: config.defenderApiBaseUrl,
        timeout_seconds: config.timeoutSeconds,
        graph_token_cached: Boolean(tokenCache.graph.accessToken),
        graph_token_expires_at_epoch: tokenCache.graph.expiresAt ? Math.floor(tokenCache.graph.expiresAt / 1000) : null,
        defender_token_cached: Boolean(tokenCache.defender.accessToken),
        defender_token_expires_at_epoch: tokenCache.defender.expiresAt ? Math.floor(tokenCache.defender.expiresAt / 1000) : null,
        recommended_application_permissions: [
          "SecurityIncident.Read.All",
          "SecurityIncident.ReadWrite.All",
          "SecurityAlert.Read.All",
          "SecurityAlert.ReadWrite.All",
          "Machine.ReadWrite.All",
          "Machine.Isolate",
          "Machine.Scan",
          "Machine.StopAndQuarantine",
          "Machine.RestrictExecution",
          "Machine.CollectForensics",
          "Machine.Offboard",
          "Machine.LiveResponse",
          "User.Read.All",
          "User.RevokeSessions.All",
          "IdentityRiskyUser.ReadWrite.All",
          "SecurityIdentitiesAccount.Read.All",
          "SecurityIdentitiesActions.ReadWrite.All",
          "ThreatHunting.Read.All",
          "Ti.ReadWrite.All",
          "File.Read.All"
        ],
        human_approval_required_for: [
          "close_security_incident",
          "update_security_incident",
          "update_alert_v2",
          "create_alert_comment",
          "graph_entity_update",
          "graph_entity_comment",
          "isolate_device",
          "release_device",
          "run_antivirus_scan",
          "stop_and_quarantine",
          "restrict_code_execution",
          "remove_code_restriction",
          "collect_investigation_package",
          "offboard_device",
          "run_live_response",
          "isolate_multiple",
          "set_machine_tag",
          "submit_indicator",
          "delete_indicator",
          "identity response tools",
          "non-GET defender_endpoint_request calls",
          "non-GET graph_security_request calls"
        ]
      });
    })
);

server.registerTool(
  "run_hunting_query",
  {
    title: "Run Hunting Query",
    description: "Run a Microsoft Graph Security advanced hunting KQL query.",
    inputSchema: {
      query: z.string().min(1)
    }
  },
  async ({ query }) =>
    withErrors(async () => {
      recordToolCall("run_hunting_query");
      return textResult(await graphRequest("POST", "/security/runHuntingQuery", { Query: query }));
    })
);

server.registerTool(
  "list_machines",
  {
    title: "List Machines",
    description: "List Defender for Endpoint machines with optional OData filter and paging.",
    inputSchema: {
      filter: z.string().optional(),
      top: z.number().int().min(1).max(10000).optional(),
      skip: z.number().int().min(0).optional()
    }
  },
  async ({ filter, top, skip }) =>
    withErrors(async () => {
      recordToolCall("list_machines");
      return textResult(await defenderRequest("GET", "/api/machines", undefined, graphQuery({ filter, top, skip })));
    })
);

server.registerTool(
  "get_machine",
  {
    title: "Get Machine",
    description: "Get a Defender for Endpoint machine by machine ID.",
    inputSchema: {
      device_id: z.string().min(1)
    }
  },
  async ({ device_id }) =>
    withErrors(async () => {
      recordToolCall("get_machine");
      return textResult(await defenderRequest("GET", `/api/machines/${encodePathId(device_id, "device_id")}`));
    })
);

server.registerTool(
  "get_machine_by_name",
  {
    title: "Get Machine By Name",
    description: "Find a Microsoft Defender for Endpoint machine by hostname.",
    inputSchema: {
      device_name: z.string().min(1)
    }
  },
  async ({ device_name }) =>
    withErrors(async () => {
      recordToolCall("get_machine_by_name");
      const result = await defenderRequest("GET", "/api/machines", undefined, { "$filter": machineLookupFilter(device_name) });
      return textResult({
        device_name,
        machine: result?.value?.[0] ?? null,
        matches: result?.value ?? []
      });
    })
);

server.registerTool(
  "get_machine_actions",
  {
    title: "Get Machine Actions",
    description: "List Defender for Endpoint machine response actions, optionally filtered by device, action type, or status.",
    inputSchema: {
      device_id: z.string().optional(),
      device_name: z.string().optional(),
      action_type: machineActionTypeSchema.optional(),
      status: z.string().optional(),
      top: z.number().int().min(1).max(100).default(10)
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("get_machine_actions");
      let machineId = args.device_id;
      if (!machineId && args.device_name) {
        machineId = (await resolveMachineId({ device_name: args.device_name })).id;
      }

      const filters = [];
      if (machineId) {
        filters.push(`machineId eq '${machineId.replaceAll("'", "''")}'`);
      }
      if (args.action_type) {
        filters.push(`type eq '${args.action_type}'`);
      }
      if (args.status) {
        filters.push(`status eq '${args.status.replaceAll("'", "''")}'`);
      }

      return textResult(
        await defenderRequest("GET", "/api/machineactions", undefined, {
          "$top": args.top,
          ...(filters.length ? { "$filter": filters.join(" and ") } : {})
        })
      );
    })
);

server.registerTool(
  "list_endpoint_alerts",
  {
    title: "List Endpoint Alerts",
    description: "List Defender for Endpoint alerts with optional OData filter, expand, and paging.",
    inputSchema: {
      filter: z.string().optional(),
      expand: z.string().optional(),
      top: z.number().int().min(1).max(10000).optional(),
      skip: z.number().int().min(0).optional()
    }
  },
  async ({ filter, expand, top, skip }) =>
    withErrors(async () => {
      recordToolCall("list_endpoint_alerts");
      return textResult(await defenderRequest("GET", "/api/alerts", undefined, graphQuery({ filter, expand, top, skip })));
    })
);

server.registerTool(
  "get_endpoint_alert",
  {
    title: "Get Endpoint Alert",
    description: "Get a Defender for Endpoint alert by ID.",
    inputSchema: {
      alert_id: z.string().min(1),
      expand: z.string().optional()
    }
  },
  async ({ alert_id, expand }) =>
    withErrors(async () => {
      recordToolCall("get_endpoint_alert");
      return textResult(await defenderRequest("GET", `/api/alerts/${encodePathId(alert_id, "alert_id")}`, undefined, graphQuery({ expand })));
    })
);

server.registerTool(
  "get_endpoint_alert_files",
  {
    title: "Get Endpoint Alert Files",
    description: "Get files related to a Defender for Endpoint alert.",
    inputSchema: {
      alert_id: z.string().min(1)
    }
  },
  async ({ alert_id }) =>
    withErrors(async () => {
      recordToolCall("get_endpoint_alert_files");
      return textResult(await defenderRequest("GET", `/api/alerts/${encodePathId(alert_id, "alert_id")}/files`));
    })
);

server.registerTool(
  "get_file_info",
  {
    title: "Get File Info",
    description: "Get Defender for Endpoint file profile information by SHA1 or SHA256.",
    inputSchema: {
      file_hash: z.string().min(1)
    }
  },
  async ({ file_hash }) =>
    withErrors(async () => {
      recordToolCall("get_file_info");
      return textResult(await defenderRequest("GET", `/api/files/${encodePathId(file_hash, "file_hash")}`));
    })
);

server.registerTool(
  "get_file_related_machines",
  {
    title: "Get File Related Machines",
    description: "Get Defender for Endpoint machines related to a file SHA1.",
    inputSchema: {
      sha1: z.string().min(1)
    }
  },
  async ({ sha1 }) =>
    withErrors(async () => {
      recordToolCall("get_file_related_machines");
      return textResult(await defenderRequest("GET", `/api/files/${encodePathId(sha1, "sha1")}/machines`));
    })
);

server.registerTool(
  "get_file_stats",
  {
    title: "Get File Stats",
    description: "Get Defender for Endpoint file statistics by SHA1 or SHA256.",
    inputSchema: {
      file_hash: z.string().min(1)
    }
  },
  async ({ file_hash }) =>
    withErrors(async () => {
      recordToolCall("get_file_stats");
      return textResult(await defenderRequest("GET", `/api/files/${encodePathId(file_hash, "file_hash")}/stats`));
    })
);

server.registerTool(
  "isolate_device",
  {
    title: "Isolate Device",
    description: "Isolate a Defender for Endpoint device from the network. Requires explicit human approval.",
    inputSchema: {
      device_id: z.string().optional(),
      device_name: z.string().optional(),
      isolation_type: z.enum(["Full", "Selective"]).default("Full"),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("isolate_device");
      const machine = await resolveMachineId(args);
      requireHumanApproval(args, "isolate_device", approvalPhrase("ISOLATE DEVICE", machine.name));
      const result = await defenderRequest("POST", `/api/machines/${encodePathId(machine.id, "device_id")}/isolate`, {
        Comment: args.comment,
        IsolationType: args.isolation_type
      });
      return textResult({ action: "isolate_device", device_id: machine.id, device_name: machine.name, result });
    })
);

server.registerTool(
  "release_device",
  {
    title: "Release Device",
    description: "Release a Defender for Endpoint device from isolation. Requires explicit human approval.",
    inputSchema: {
      device_id: z.string().optional(),
      device_name: z.string().optional(),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("release_device");
      const machine = await resolveMachineId(args);
      requireHumanApproval(args, "release_device", approvalPhrase("RELEASE DEVICE", machine.name));
      const result = await defenderRequest("POST", `/api/machines/${encodePathId(machine.id, "device_id")}/unisolate`, {
        Comment: args.comment
      });
      return textResult({ action: "release_device", device_id: machine.id, device_name: machine.name, result });
    })
);

server.registerTool(
  "set_machine_tag",
  {
    title: "Set Machine Tag",
    description: "Add or remove a Defender for Endpoint machine tag. Requires explicit human approval.",
    inputSchema: {
      device_id: z.string().optional(),
      device_name: z.string().optional(),
      tag: z.string().min(1),
      action: z.enum(["Add", "Remove"]),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("set_machine_tag");
      const machine = await resolveMachineId(args);
      requireHumanApproval(args, "set_machine_tag", approvalPhrase("SET MACHINE TAG", `${args.action} ${args.tag} ${machine.name}`));
      const result = await defenderRequest("POST", `/api/machines/${encodePathId(machine.id, "device_id")}/tags`, {
        Value: args.tag,
        Action: args.action
      });
      return textResult({ action: "set_machine_tag", device_id: machine.id, device_name: machine.name, tag: args.tag, tag_action: args.action, result });
    })
);

server.registerTool(
  "run_antivirus_scan",
  {
    title: "Run Antivirus Scan",
    description: "Run a Defender for Endpoint antivirus scan on a device. Requires explicit human approval.",
    inputSchema: {
      device_id: z.string().optional(),
      device_name: z.string().optional(),
      scan_type: z.enum(["Quick", "Full"]).default("Quick"),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("run_antivirus_scan");
      const machine = await resolveMachineId(args);
      requireHumanApproval(args, "run_antivirus_scan", approvalPhrase("RUN ANTIVIRUS SCAN", `${machine.name} ${args.scan_type}`));
      const result = await defenderRequest("POST", `/api/machines/${encodePathId(machine.id, "device_id")}/runAntiVirusScan`, {
        Comment: args.comment,
        ScanType: args.scan_type
      });
      return textResult({ action: "run_antivirus_scan", device_id: machine.id, device_name: machine.name, scan_type: args.scan_type, result });
    })
);

server.registerTool(
  "offboard_device",
  {
    title: "Offboard Device",
    description: "Offboard a Windows device from Defender for Endpoint. This is high impact and requires explicit human approval.",
    inputSchema: {
      device_id: z.string().optional(),
      device_name: z.string().optional(),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("offboard_device");
      const machine = await resolveMachineId(args);
      requireHumanApproval(args, "offboard_device", approvalPhrase("OFFBOARD DEVICE", machine.name));
      const result = await defenderRequest("POST", `/api/machines/${encodePathId(machine.id, "device_id")}/offboard`, {
        Comment: args.comment
      });
      return textResult({ action: "offboard_device", device_id: machine.id, device_name: machine.name, result });
    })
);

server.registerTool(
  "run_live_response",
  {
    title: "Run Live Response",
    description: "Run Defender for Endpoint Live Response commands on a device. Requires explicit human approval.",
    inputSchema: {
      device_id: z.string().optional(),
      device_name: z.string().optional(),
      comment: z.string().min(1),
      commands: z.array(liveResponseCommandSchema).min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("run_live_response");
      const machine = await resolveMachineId(args);
      requireHumanApproval(args, "run_live_response", approvalPhrase("RUN LIVE RESPONSE", `${machine.name} ${args.commands.length} COMMANDS`));
      const result = await defenderRequest("POST", `/api/machines/${encodePathId(machine.id, "device_id")}/runliveresponse`, {
        Comment: args.comment,
        Commands: args.commands
      });
      return textResult({ action: "run_live_response", device_id: machine.id, device_name: machine.name, command_count: args.commands.length, result });
    })
);

server.registerTool(
  "stop_and_quarantine",
  {
    title: "Stop And Quarantine",
    description: "Stop a running process and quarantine the associated file by SHA1. Requires explicit human approval.",
    inputSchema: {
      device_id: z.string().optional(),
      device_name: z.string().optional(),
      sha1: z.string().min(1),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("stop_and_quarantine");
      const machine = await resolveMachineId(args);
      requireHumanApproval(args, "stop_and_quarantine", approvalPhrase("STOP AND QUARANTINE", `${machine.name} ${args.sha1}`));
      const result = await defenderRequest("POST", `/api/machines/${encodePathId(machine.id, "device_id")}/StopAndQuarantineFile`, {
        Comment: args.comment,
        Sha1: args.sha1
      });
      return textResult({ action: "stop_and_quarantine", device_id: machine.id, device_name: machine.name, sha1: args.sha1, result });
    })
);

server.registerTool(
  "restrict_code_execution",
  {
    title: "Restrict Code Execution",
    description: "Restrict code execution on a Defender for Endpoint device. Requires explicit human approval.",
    inputSchema: {
      device_id: z.string().optional(),
      device_name: z.string().optional(),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("restrict_code_execution");
      const machine = await resolveMachineId(args);
      requireHumanApproval(args, "restrict_code_execution", approvalPhrase("RESTRICT CODE EXECUTION", machine.name));
      const result = await defenderRequest("POST", `/api/machines/${encodePathId(machine.id, "device_id")}/restrictCodeExecution`, {
        Comment: args.comment
      });
      return textResult({ action: "restrict_code_execution", device_id: machine.id, device_name: machine.name, result });
    })
);

server.registerTool(
  "remove_code_restriction",
  {
    title: "Remove Code Restriction",
    description: "Remove code execution restrictions from a Defender for Endpoint device. Requires explicit human approval.",
    inputSchema: {
      device_id: z.string().optional(),
      device_name: z.string().optional(),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("remove_code_restriction");
      const machine = await resolveMachineId(args);
      requireHumanApproval(args, "remove_code_restriction", approvalPhrase("REMOVE CODE RESTRICTION", machine.name));
      const result = await defenderRequest("POST", `/api/machines/${encodePathId(machine.id, "device_id")}/unrestrictCodeExecution`, {
        Comment: args.comment
      });
      return textResult({ action: "remove_code_restriction", device_id: machine.id, device_name: machine.name, result });
    })
);

server.registerTool(
  "collect_investigation_package",
  {
    title: "Collect Investigation Package",
    description: "Collect a forensic investigation package from a Defender for Endpoint device. Requires explicit human approval.",
    inputSchema: {
      device_id: z.string().optional(),
      device_name: z.string().optional(),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("collect_investigation_package");
      const machine = await resolveMachineId(args);
      requireHumanApproval(args, "collect_investigation_package", approvalPhrase("COLLECT INVESTIGATION PACKAGE", machine.name));
      const result = await defenderRequest("POST", `/api/machines/${encodePathId(machine.id, "device_id")}/collectInvestigationPackage`, {
        Comment: args.comment
      });
      return textResult({ action: "collect_investigation_package", device_id: machine.id, device_name: machine.name, result });
    })
);

server.registerTool(
  "get_investigation_package_uri",
  {
    title: "Get Investigation Package URI",
    description: "Get a temporary download URI for a completed Defender for Endpoint investigation package action.",
    inputSchema: {
      action_id: z.string().min(1)
    }
  },
  async ({ action_id }) =>
    withErrors(async () => {
      recordToolCall("get_investigation_package_uri");
      return textResult(await defenderRequest("GET", `/api/machineactions/${encodePathId(action_id, "action_id")}/GetPackageUri`));
    })
);

server.registerTool(
  "isolate_multiple",
  {
    title: "Isolate Multiple Devices",
    description: "Bulk isolate multiple Defender for Endpoint devices by hostname. Requires explicit human approval.",
    inputSchema: {
      device_names: z.array(z.string().min(1)).min(1).max(100),
      isolation_type: z.enum(["Full", "Selective"]).default("Full"),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("isolate_multiple");
      requireHumanApproval(args, "isolate_multiple", approvalPhrase("ISOLATE MULTIPLE DEVICES", `${args.device_names.length} DEVICES`));
      const results = [];
      for (const deviceName of args.device_names) {
        const machine = await resolveMachineId({ device_name: deviceName });
        const result = await defenderRequest("POST", `/api/machines/${encodePathId(machine.id, "device_id")}/isolate`, {
          Comment: args.comment,
          IsolationType: args.isolation_type
        });
        results.push({ device_name: machine.name, device_id: machine.id, result });
      }
      return textResult({ action: "isolate_multiple", count: results.length, results });
    })
);

server.registerTool(
  "list_indicators",
  {
    title: "List Indicators",
    description: "List active Defender for Endpoint indicators with optional OData filter and paging.",
    inputSchema: {
      filter: z.string().optional(),
      top: z.number().int().min(1).max(10000).optional(),
      skip: z.number().int().min(0).optional()
    }
  },
  async ({ filter, top, skip }) =>
    withErrors(async () => {
      recordToolCall("list_indicators");
      return textResult(await defenderRequest("GET", "/api/indicators", undefined, graphQuery({ filter, top, skip })));
    })
);

server.registerTool(
  "submit_indicator",
  {
    title: "Submit Indicator",
    description: "Submit or update a Defender for Endpoint indicator. Requires explicit human approval.",
    inputSchema: {
      indicator_value: z.string().min(1).optional(),
      indicator_type: indicatorTypeSchema.optional(),
      action: indicatorActionSchema.optional(),
      title: z.string().optional(),
      description: z.string().optional(),
      expiration_time: z.string().optional(),
      severity: indicatorSeveritySchema.optional(),
      generate_alert: z.boolean().optional(),
      recommended_actions: z.string().optional(),
      request_body: jsonObject.optional(),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("submit_indicator");
      const body = args.request_body ?? {
        indicatorValue: args.indicator_value,
        indicatorType: args.indicator_type,
        action: args.action,
        title: args.title,
        description: args.description,
        expirationTime: args.expiration_time,
        severity: args.severity,
        generateAlert: args.generate_alert,
        recommendedActions: args.recommended_actions
      };

      for (const [key, value] of Object.entries(body)) {
        if (value === undefined) {
          delete body[key];
        }
      }

      if (!body.indicatorValue || !body.indicatorType || !body.action) {
        throw new Error("Provide indicator_value, indicator_type, and action, or request_body with indicatorValue, indicatorType, and action");
      }

      requireHumanApproval(args, "submit_indicator", approvalPhrase("SUBMIT INDICATOR", `${body.indicatorType} ${body.indicatorValue} ${body.action}`));
      return textResult(await defenderRequest("POST", "/api/indicators", body));
    })
);

server.registerTool(
  "delete_indicator",
  {
    title: "Delete Indicator",
    description: "Delete a Defender for Endpoint indicator by ID. Requires explicit human approval.",
    inputSchema: {
      indicator_id: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("delete_indicator");
      requireHumanApproval(args, "delete_indicator", approvalPhrase("DELETE INDICATOR", args.indicator_id));
      return textResult(await defenderRequest("DELETE", `/api/indicators/${encodePathId(args.indicator_id, "indicator_id")}`));
    })
);

server.registerTool(
  "revoke_entra_sessions",
  {
    title: "Revoke Entra Sessions",
    description: "Revoke all Entra ID sign-in sessions and refresh tokens for a user. Requires explicit human approval.",
    inputSchema: {
      user_principal_name: z.string().min(1),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("revoke_entra_sessions");
      requireHumanApproval(args, "revoke_entra_sessions", approvalPhrase("REVOKE ENTRA SESSIONS", args.user_principal_name));
      const result = await graphRequest("POST", `/users/${encodePathId(args.user_principal_name, "user_principal_name")}/revokeSignInSessions`);
      return textResult({ action: "revoke_entra_sessions", user_principal_name: args.user_principal_name, comment: args.comment, result });
    })
);

server.registerTool(
  "confirm_user_compromised",
  {
    title: "Confirm User Compromised",
    description: "Mark a user as compromised in Microsoft Entra Identity Protection. Requires explicit human approval.",
    inputSchema: {
      user_principal_name: z.string().min(1),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("confirm_user_compromised");
      requireHumanApproval(args, "confirm_user_compromised", approvalPhrase("CONFIRM USER COMPROMISED", args.user_principal_name));
      const userId = await getUserIdByUpn(args.user_principal_name);
      const result = await graphRequest("POST", "/identityProtection/riskyUsers/confirmCompromised", { userIds: [userId] });
      return textResult({ action: "confirm_user_compromised", user_principal_name: args.user_principal_name, user_id: userId, comment: args.comment, result });
    })
);

server.registerTool(
  "confirm_user_safe",
  {
    title: "Confirm User Safe",
    description: "Dismiss user risk in Microsoft Entra Identity Protection. Requires explicit human approval.",
    inputSchema: {
      user_principal_name: z.string().min(1),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("confirm_user_safe");
      requireHumanApproval(args, "confirm_user_safe", approvalPhrase("CONFIRM USER SAFE", args.user_principal_name));
      const userId = await getUserIdByUpn(args.user_principal_name);
      const result = await graphRequest("POST", "/identityProtection/riskyUsers/confirmSafe", { userIds: [userId] });
      return textResult({ action: "confirm_user_safe", user_principal_name: args.user_principal_name, user_id: userId, comment: args.comment, result });
    })
);

server.registerTool(
  "invoke_identity_account_action",
  {
    title: "Invoke Identity Account Action",
    description: "Invoke a Microsoft Defender for Identity account action through Graph beta. Requires explicit human approval.",
    inputSchema: {
      user_principal_name: z.string().min(1),
      account_id: z.string().min(1),
      action: z.enum(["disable", "enable", "forcePasswordReset", "revokeAllSessions"]),
      identity_provider: z.enum(["activeDirectory", "entraID", "okta"]).default("activeDirectory"),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("invoke_identity_account_action");
      requireHumanApproval(args, "invoke_identity_account_action", approvalPhrase("INVOKE IDENTITY ACTION", `${args.action} ${args.user_principal_name}`));
      return textResult({ action: "invoke_identity_account_action", ...(await invokeIdentityActionForUser(args, args.action)) });
    })
);

server.registerTool(
  "disable_ad_account",
  {
    title: "Disable AD Account",
    description: "Disable an Active Directory account through Microsoft Defender for Identity. Requires explicit human approval.",
    inputSchema: {
      user_principal_name: z.string().min(1),
      account_id: z.string().min(1),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("disable_ad_account");
      requireHumanApproval(args, "disable_ad_account", approvalPhrase("DISABLE AD ACCOUNT", args.user_principal_name));
      return textResult({ action: "disable_ad_account", ...(await invokeIdentityActionForUser(args, "disable")) });
    })
);

server.registerTool(
  "enable_ad_account",
  {
    title: "Enable AD Account",
    description: "Re-enable an Active Directory account through Microsoft Defender for Identity. Requires explicit human approval.",
    inputSchema: {
      user_principal_name: z.string().min(1),
      account_id: z.string().min(1),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("enable_ad_account");
      requireHumanApproval(args, "enable_ad_account", approvalPhrase("ENABLE AD ACCOUNT", args.user_principal_name));
      return textResult({ action: "enable_ad_account", ...(await invokeIdentityActionForUser(args, "enable")) });
    })
);

server.registerTool(
  "force_ad_password_reset",
  {
    title: "Force AD Password Reset",
    description: "Force an Active Directory user to change password at next logon through Microsoft Defender for Identity. Requires explicit human approval.",
    inputSchema: {
      user_principal_name: z.string().min(1),
      account_id: z.string().min(1),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("force_ad_password_reset");
      requireHumanApproval(args, "force_ad_password_reset", approvalPhrase("FORCE AD PASSWORD RESET", args.user_principal_name));
      return textResult({ action: "force_ad_password_reset", ...(await invokeIdentityActionForUser(args, "forcePasswordReset")) });
    })
);

server.registerTool(
  "assign_incident",
  {
    title: "Assign Incident",
    description: "Assign or unassign a Microsoft Graph Security incident. Requires explicit human approval.",
    inputSchema: {
      incident_id: z.string().min(1),
      assigned_to: z.string(),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("assign_incident");
      requireHumanApproval(args, "assign_incident", approvalPhrase("ASSIGN INCIDENT", args.incident_id));
      return textResult(await graphRequest("PATCH", `/security/incidents/${encodePathId(args.incident_id, "incident_id")}`, { assignedTo: args.assigned_to }));
    })
);

server.registerTool(
  "update_incident_status",
  {
    title: "Update Incident Status",
    description: "Update a Microsoft Graph Security incident status. Requires explicit human approval.",
    inputSchema: {
      incident_id: z.string().min(1),
      status: z.enum(["active", "resolved", "inProgress", "redirected", "unknownFutureValue"]),
      resolving_comment: z.string().optional(),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("update_incident_status");
      requireHumanApproval(args, "update_incident_status", approvalPhrase("UPDATE INCIDENT STATUS", `${args.incident_id} ${args.status}`));
      return textResult(
        await graphRequest("PATCH", `/security/incidents/${encodePathId(args.incident_id, "incident_id")}`, {
          status: args.status,
          ...(args.resolving_comment ? { resolvingComment: args.resolving_comment } : {})
        })
      );
    })
);

server.registerTool(
  "classify_incident",
  {
    title: "Classify Incident",
    description: "Set classification and determination on a Microsoft Graph Security incident. Requires explicit human approval.",
    inputSchema: {
      incident_id: z.string().min(1),
      classification: incidentClassificationSchema,
      determination: incidentDeterminationSchema.default("other"),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("classify_incident");
      requireHumanApproval(args, "classify_incident", approvalPhrase("CLASSIFY INCIDENT", `${args.incident_id} ${args.classification}`));
      return textResult(
        await graphRequest("PATCH", `/security/incidents/${encodePathId(args.incident_id, "incident_id")}`, {
          classification: args.classification,
          determination: args.determination
        })
      );
    })
);

server.registerTool(
  "add_incident_tags",
  {
    title: "Add Incident Tags",
    description: "Add custom tags to a Microsoft Graph Security incident while preserving existing tags. Requires explicit human approval.",
    inputSchema: {
      incident_id: z.string().min(1),
      tags: z.array(z.string().min(1)).min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("add_incident_tags");
      requireHumanApproval(args, "add_incident_tags", approvalPhrase("ADD INCIDENT TAGS", args.incident_id));
      const incident = await graphRequest("GET", `/security/incidents/${encodePathId(args.incident_id, "incident_id")}`, undefined, {
        "$select": "id,customTags"
      });
      const currentTags = Array.isArray(incident?.customTags) ? incident.customTags : [];
      const customTags = [...new Set([...currentTags, ...args.tags])];
      return textResult(await graphRequest("PATCH", `/security/incidents/${encodePathId(args.incident_id, "incident_id")}`, { customTags }));
    })
);

server.registerTool(
  "add_incident_comment",
  {
    title: "Add Incident Comment",
    description: "Add a comment to a Microsoft Graph Security incident. Requires explicit human approval.",
    inputSchema: {
      incident_id: z.string().min(1),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("add_incident_comment");
      requireHumanApproval(args, "add_incident_comment", approvalPhrase("COMMENT ON INCIDENT", args.incident_id));
      return textResult(
        await graphRequest("POST", `/security/incidents/${encodePathId(args.incident_id, "incident_id")}/comments`, {
          "@odata.type": "microsoft.graph.security.alertComment",
          comment: args.comment
        })
      );
    })
);

server.registerTool(
  "graph_entity_list",
  {
    title: "Graph Entity List",
    description: "List Microsoft Graph Security alerts or incidents with intent-based field selection.",
    inputSchema: {
      entityType: entityTypeSchema,
      filter: z.string().optional(),
      top: z.number().int().min(1).max(999).optional(),
      orderBy: z.string().optional(),
      orderby: z.string().optional(),
      select: z.string().optional(),
      expand: z.string().optional(),
      search: z.string().optional(),
      skip: z.number().int().min(0).optional(),
      skiptoken: z.string().optional(),
      count: z.boolean().optional(),
      intent: queryIntentSchema.default("standard")
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("graph_entity_list");
      const definition = getEntityDefinition(args.entityType);
      return textResult(await graphRequest("GET", definition.collectionPath, undefined, entityQuery(args)));
    })
);

server.registerTool(
  "graph_entity_get",
  {
    title: "Graph Entity Get",
    description: "Get a Microsoft Graph Security alert or incident by ID with optional field selection and expansion.",
    inputSchema: {
      entityType: entityTypeSchema,
      entityId: z.string().min(1),
      select: z.string().optional(),
      expand: z.string().optional(),
      intent: queryIntentSchema.default("complete")
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("graph_entity_get");
      const definition = getEntityDefinition(args.entityType);
      const select = args.select || fieldsForIntent(args.entityType, args.intent);
      return textResult(
        await graphRequest(
          "GET",
          `${definition.itemPath}/${encodePathId(args.entityId, "entityId")}`,
          undefined,
          graphQuery({ select, expand: args.expand })
        )
      );
    })
);

server.registerTool(
  "graph_entity_update",
  {
    title: "Graph Entity Update",
    description: "Update a Microsoft Graph Security alert or incident. Requires explicit human approval.",
    inputSchema: {
      entityType: entityTypeSchema,
      entityId: z.string().min(1),
      properties: jsonObject,
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("graph_entity_update");
      const definition = getEntityDefinition(args.entityType);
      const entityId = args.entityId.trim();
      requireHumanApproval(args, "graph_entity_update", approvalPhrase("UPDATE ENTITY", `${args.entityType} ${entityId}`));

      if (!args.properties || Object.keys(args.properties).length === 0) {
        throw new Error("properties must include at least one field to update");
      }

      return textResult(await graphRequest("PATCH", `${definition.itemPath}/${encodePathId(entityId, "entityId")}`, args.properties));
    })
);

server.registerTool(
  "graph_entity_comment",
  {
    title: "Graph Entity Comment",
    description: "Add a comment to a Microsoft Graph Security alert or incident. Requires explicit human approval.",
    inputSchema: {
      entityType: entityTypeSchema,
      entityId: z.string().min(1),
      comment: z.string().min(1),
      human_approval: humanApprovalSchema
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("graph_entity_comment");
      const definition = getEntityDefinition(args.entityType);
      const entityId = args.entityId.trim();
      requireHumanApproval(args, "graph_entity_comment", approvalPhrase("COMMENT ON ENTITY", `${args.entityType} ${entityId}`));

      return textResult(
        await graphRequest("POST", `${definition.commentPath}/${encodePathId(entityId, "entityId")}/comments`, {
          "@odata.type": "microsoft.graph.security.alertComment",
          comment: args.comment
        })
      );
    })
);

server.registerTool(
  "graph_entity_navigate",
  {
    title: "Graph Entity Navigate",
    description: "Navigate supported Graph Security relationships between alerts and incidents.",
    inputSchema: {
      sourceEntityType: entityTypeSchema,
      sourceEntityId: z.string().min(1),
      targetEntityType: entityTypeSchema,
      intent: queryIntentSchema.default("standard")
    }
  },
  async (args) =>
    withErrors(async () => {
      recordToolCall("graph_entity_navigate");

      if (args.sourceEntityType === "incident" && args.targetEntityType === "alert") {
        const select = fieldsForIntent("alert", args.intent);
        return textResult(
          await graphRequest(
            "GET",
            `/security/incidents/${encodePathId(args.sourceEntityId, "sourceEntityId")}/alerts`,
            undefined,
            graphQuery({ select })
          )
        );
      }

      if (args.sourceEntityType === "alert" && args.targetEntityType === "incident") {
        const alert = await graphRequest(
          "GET",
          `/security/alerts_v2/${encodePathId(args.sourceEntityId, "sourceEntityId")}`,
          undefined,
          graphQuery({ select: "id,incidentId" })
        );

        if (!alert?.incidentId) {
          return textResult({
            message: "Alert does not include an incidentId relationship.",
            alertId: args.sourceEntityId
          });
        }

        return textResult(
          await graphRequest(
            "GET",
            `/security/incidents/${encodePathId(alert.incidentId, "incidentId")}`,
            undefined,
            graphQuery({ select: fieldsForIntent("incident", args.intent) })
          )
        );
      }

      throw new Error(`Unsupported navigation: ${args.sourceEntityType} to ${args.targetEntityType}`);
    })
);

server.registerTool(
  "graph_entity_list_next",
  {
    title: "Graph Entity List Next",
    description: "Fetch the next page from an @odata.nextLink returned by Microsoft Graph.",
    inputSchema: {
      nextLink: z.string().url()
    }
  },
  async ({ nextLink }) =>
    withErrors(async () => {
      recordToolCall("graph_entity_list_next");
      return textResult(await graphRequestNextLink(nextLink));
    })
);

server.registerTool(
  "graph_entity_schema",
  {
    title: "Graph Entity Schema",
    description: "Return schema, field priority, filter, update, and relationship guidance for alerts or incidents.",
    inputSchema: {
      entityType: entityTypeSchema,
      operation: z.enum(["list", "get", "update", "comment", "navigate", "all"]).default("all")
    }
  },
  async ({ entityType, operation }) =>
    withErrors(async () => {
      recordToolCall("graph_entity_schema");
      const definition = getEntityDefinition(entityType);
      return textResult({
        entityType,
        operation,
        collectionPath: definition.collectionPath,
        itemPath: definition.itemPath,
        idField: definition.idField,
        fieldSelection: {
          overview: definition.overviewFields,
          standard: definition.standardFields,
          complete: "No $select is sent; Microsoft Graph returns its default complete representation for the endpoint."
        },
        filterableFields: definition.filterableFields,
        updateableFields: definition.updateableFields,
        relationships: definition.relationships,
        recommendedTools: [
          "graph_entity_list",
          "graph_entity_get",
          "graph_entity_update",
          "graph_entity_comment",
          "graph_entity_navigate",
          "graph_entity_list_next"
        ]
      });
    })
);

server.registerTool(
  "context_discover",
  {
    title: "Context Discover",
    description: "Discover Graph Security entity capabilities, recommended tools, and field-selection behavior.",
    inputSchema: {
      entityType: entityTypeSchema.optional(),
      focusArea: z.enum(["fields", "filters", "updates", "relationships", "tools", "all"]).default("all")
    }
  },
  async ({ entityType, focusArea }) =>
    withErrors(async () => {
      recordToolCall("context_discover");
      const entityTypes = entityType ? [entityType] : Object.keys(entityDefinitions);
      return textResult({
        focusArea,
        contextLevel: contextState.level,
        ttlSeconds: contextState.ttlSeconds,
        entities: Object.fromEntries(
          entityTypes.map((type) => {
            const definition = getEntityDefinition(type);
            return [
              type,
              {
                overviewFields: definition.overviewFields,
                standardFields: definition.standardFields,
                filterableFields: definition.filterableFields,
                updateableFields: definition.updateableFields,
                relationships: definition.relationships
              }
            ];
          })
        ),
        universalTools: [
          "graph_entity_list",
          "graph_entity_get",
          "graph_entity_update",
          "graph_entity_comment",
          "graph_entity_navigate",
          "graph_entity_list_next",
          "graph_entity_schema"
        ]
      });
    })
);

server.registerTool(
  "context_stats",
  {
    title: "Context Stats",
    description: "Return lightweight context and tool usage statistics for this MCP server process.",
    inputSchema: {}
  },
  async () =>
    withErrors(async () => {
      recordToolCall("context_stats");
      return textResult({
        level: contextState.level,
        ttlSeconds: contextState.ttlSeconds,
        configuredAt: contextState.configuredAt,
        toolCalls: contextState.toolCalls
      });
    })
);

server.registerTool(
  "context_configure",
  {
    title: "Context Configure",
    description: "Configure lightweight context behavior for this MCP server process.",
    inputSchema: {
      action: z.enum(["set", "reset"]),
      level: z.enum(["none", "minimal", "standard", "complete"]).optional(),
      seconds: z.number().int().min(0).optional(),
      toolName: z.string().optional()
    }
  },
  async ({ action, level, seconds, toolName }) =>
    withErrors(async () => {
      recordToolCall("context_configure");

      if (action === "reset") {
        contextState.level = "standard";
        contextState.ttlSeconds = 3600;
        contextState.configuredAt = new Date().toISOString();
        if (toolName) {
          delete contextState.toolCalls[toolName];
        } else {
          contextState.toolCalls = {};
        }
      } else {
        if (level) {
          contextState.level = level;
        }
        if (seconds !== undefined) {
          contextState.ttlSeconds = seconds;
        }
        contextState.configuredAt = new Date().toISOString();
      }

      return textResult({
        level: contextState.level,
        ttlSeconds: contextState.ttlSeconds,
        configuredAt: contextState.configuredAt,
        toolCalls: contextState.toolCalls
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

server.registerTool(
  "defender_endpoint_request",
  {
    title: "Defender Endpoint Request",
    description: "Advanced escape hatch for Microsoft Defender for Endpoint API calls not covered by a dedicated tool. Non-GET calls require explicit human approval.",
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
      recordToolCall("defender_endpoint_request");
      if (args.method.toUpperCase() !== "GET") {
        const normalized = `/${args.path.replace(/^\/+/, "").split("?", 1)[0]}`;
        requireHumanApproval(args, "defender_endpoint_request", approvalPhrase("DEFENDER ENDPOINT API REQUEST", `${args.method} ${normalized}`));
      }

      return textResult(await defenderRequest(args.method, args.path, args.body, args.query));
    })
);

const transport = new StdioServerTransport();
await server.connect(transport);
