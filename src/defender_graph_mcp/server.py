from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import quote, urlencode, urlparse

import httpx
from fastmcp.server.server import FastMCP
from pydantic import BaseModel, Field, HttpUrl


SERVER_NAME = "defender-graph-security-mcp-server"
SERVER_VERSION = "0.1.0"
DEFAULT_AUTH_BASE_URL = "https://login.microsoftonline.com"
DEFAULT_API_BASE_URL = "https://graph.microsoft.com/v1.0"
DEFAULT_DEFENDER_API_BASE_URL = "https://api.securitycenter.microsoft.com"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
DEFENDER_SCOPE = "https://api.securitycenter.microsoft.com/.default"
HUMAN_APPROVAL_NOTE = (
    "This action can change Microsoft Defender or Graph Security state. A human must explicitly approve it by "
    "providing the exact approval phrase, their name, a reason, and the configured approval token in human_approval."
)

IncidentClassification = Literal["unknown", "falsePositive", "truePositive", "informationalExpectedActivity"]
IncidentDetermination = Literal[
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
    "manuallyDefined",
]
AlertClassification = Literal["unknown", "falsePositive", "truePositive", "informationalExpectedActivity"]
AlertDetermination = Literal[
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
]
EntityType = Literal["alert", "incident"]
QueryIntent = Literal["overview", "standard", "complete"]
MachineActionType = Literal[
    "Isolate",
    "Unisolate",
    "RunAntiVirusScan",
    "StopAndQuarantineFile",
    "RestrictCodeExecution",
    "UnrestrictCodeExecution",
    "CollectInvestigationPackage",
]
IndicatorType = Literal["FileSha1", "FileSha256", "FileMd5", "CertificateThumbprint", "IpAddress", "DomainName", "Url"]
IndicatorAction = Literal["Warn", "Block", "Audit", "Alert", "AlertAndBlock", "BlockAndRemediate", "Allowed"]
IndicatorSeverity = Literal["Informational", "Low", "Medium", "High"]


class HumanApproval(BaseModel):
    approved: bool
    phrase: str
    approved_by: str
    reason: str
    approval_token: str


class LiveResponseParam(BaseModel):
    key: str = Field(min_length=1)
    value: str


class LiveResponseCommand(BaseModel):
    type: Literal["PutFile", "RunScript", "GetFile"]
    params: list[LiveResponseParam] = Field(default_factory=list)


@dataclass
class Config:
    tenant_id: str | None
    client_id: str | None
    client_secret: str | None
    auth_base_url: str
    api_base_url: str
    defender_api_base_url: str
    timeout_seconds: float
    approval_token: str | None


TOKEN_CACHE: dict[str, dict[str, Any]] = {
    "graph": {"access_token": None, "expires_at": 0.0},
    "defender": {"access_token": None, "expires_at": 0.0},
}

CONTEXT_STATE: dict[str, Any] = {
    "level": "standard",
    "ttlSeconds": 3600,
    "configuredAt": datetime.now(timezone.utc).isoformat(),
    "toolCalls": {},
}

ENTITY_DEFINITIONS: dict[str, dict[str, Any]] = {
    "alert": {
        "singular": "alert",
        "plural": "alerts",
        "collectionPath": "/security/alerts_v2",
        "itemPath": "/security/alerts_v2",
        "commentPath": "/security/alerts_v2",
        "idField": "id",
        "defaultOrderBy": "createdDateTime desc",
        "overviewFields": [
            "id",
            "title",
            "severity",
            "status",
            "classification",
            "determination",
            "serviceSource",
            "incidentId",
            "createdDateTime",
        ],
        "standardFields": [
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
            "lastUpdateDateTime",
        ],
        "filterableFields": [
            "assignedTo",
            "classification",
            "determination",
            "createdDateTime",
            "lastUpdateDateTime",
            "severity",
            "serviceSource",
            "status",
        ],
        "updateableFields": ["status", "classification", "determination", "assignedTo", "customDetails"],
        "relationships": {
            "incident": "Use incidentId on the alert, then graph_entity_get with entityType='incident'."
        },
    },
    "incident": {
        "singular": "incident",
        "plural": "incidents",
        "collectionPath": "/security/incidents",
        "itemPath": "/security/incidents",
        "commentPath": "/security/incidents",
        "idField": "id",
        "defaultOrderBy": "createdDateTime desc",
        "overviewFields": [
            "id",
            "displayName",
            "severity",
            "status",
            "classification",
            "determination",
            "assignedTo",
            "createdDateTime",
        ],
        "standardFields": [
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
            "incidentWebUrl",
        ],
        "filterableFields": [
            "assignedTo",
            "classification",
            "createdDateTime",
            "determination",
            "lastUpdateDateTime",
            "severity",
            "status",
        ],
        "updateableFields": ["status", "classification", "determination", "assignedTo", "customTags", "resolvingComment"],
        "relationships": {
            "alert": "Use graph_entity_navigate with targetEntityType='alert' to list alerts under the incident."
        },
    },
}

mcp = FastMCP(SERVER_NAME, version=SERVER_VERSION)


def as_text(data: Any) -> str:
    if isinstance(data, str):
        return data
    return json.dumps(data, indent=2, ensure_ascii=False)


def read_config() -> Config:
    try:
        timeout_seconds = float(os.getenv("MSGRAPH_TIMEOUT_SECONDS", "30"))
    except ValueError:
        timeout_seconds = 30.0

    return Config(
        tenant_id=os.getenv("MSGRAPH_TENANT_ID") or os.getenv("AZURE_TENANT_ID") or os.getenv("TENANT_ID"),
        client_id=os.getenv("MSGRAPH_CLIENT_ID") or os.getenv("AZURE_CLIENT_ID") or os.getenv("CLIENT_ID"),
        client_secret=os.getenv("MSGRAPH_CLIENT_SECRET") or os.getenv("AZURE_CLIENT_SECRET") or os.getenv("CLIENT_SECRET"),
        auth_base_url=os.getenv("MSGRAPH_AUTH_BASE_URL", DEFAULT_AUTH_BASE_URL).rstrip("/"),
        api_base_url=os.getenv("MSGRAPH_API_BASE_URL", DEFAULT_API_BASE_URL).rstrip("/"),
        defender_api_base_url=os.getenv("DEFENDER_API_BASE_URL", DEFAULT_DEFENDER_API_BASE_URL).rstrip("/"),
        timeout_seconds=timeout_seconds if timeout_seconds == timeout_seconds else 30.0,
        approval_token=os.getenv("MSGRAPH_HUMAN_APPROVAL_TOKEN"),
    )


def require_credentials(config: Config) -> None:
    if not config.tenant_id or not config.client_id or not config.client_secret:
        raise ValueError(
            "Missing Microsoft Graph credentials. Set MSGRAPH_TENANT_ID, MSGRAPH_CLIENT_ID, and MSGRAPH_CLIENT_SECRET."
        )


def approval_phrase(action: str, subject: str | None = None) -> str:
    suffix = f" {subject}" if subject else ""
    return f"APPROVE DEFENDER GRAPH {action.upper()}{suffix}"


def require_human_approval(args: dict[str, Any], action: str, expected_phrase: str) -> None:
    config = read_config()
    if not config.approval_token:
        raise PermissionError(
            "Sensitive Defender/Graph Security actions are disabled until MSGRAPH_HUMAN_APPROVAL_TOKEN is configured. "
            f"Required approval phrase: {expected_phrase}"
        )

    approval = args.get("human_approval")
    if isinstance(approval, BaseModel):
        approval = approval.model_dump()

    if not isinstance(approval, dict):
        raise PermissionError(f"{HUMAN_APPROVAL_NOTE} Required approval phrase: {expected_phrase}")

    if (
        approval.get("approved") is not True
        or approval.get("phrase") != expected_phrase
        or approval.get("approval_token") != config.approval_token
        or not isinstance(approval.get("approved_by"), str)
        or not approval["approved_by"].strip()
        or not isinstance(approval.get("reason"), str)
        or not approval["reason"].strip()
    ):
        raise PermissionError(f"{action} requires explicit human approval. Required approval phrase: {expected_phrase}")


def encode_path_id(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing or invalid {name}")
    return quote(value.strip(), safe="")


def get_entity_definition(entity_type: str) -> dict[str, Any]:
    definition = ENTITY_DEFINITIONS.get(entity_type)
    if not definition:
        supported = ", ".join(ENTITY_DEFINITIONS)
        raise ValueError(f"Unsupported entityType '{entity_type}'. Supported values: {supported}")
    return definition


def fields_for_intent(entity_type: str, intent: str = "standard") -> str | None:
    definition = get_entity_definition(entity_type)
    if intent == "complete":
        return None
    return ",".join(definition["overviewFields"] if intent == "overview" else definition["standardFields"])


def record_tool_call(tool_name: str) -> None:
    current = CONTEXT_STATE["toolCalls"].get(tool_name, {"count": 0, "lastCalledAt": None})
    CONTEXT_STATE["toolCalls"][tool_name] = {
        "count": current["count"] + 1,
        "lastCalledAt": datetime.now(timezone.utc).isoformat(),
    }


def graph_query(**kwargs: Any) -> dict[str, Any] | None:
    mappings = {
        "filter": "$filter",
        "select": "$select",
        "expand": "$expand",
        "orderby": "$orderby",
        "orderBy": "$orderby",
        "top": "$top",
        "skip": "$skip",
        "skiptoken": "$skiptoken",
        "count": "$count",
        "search": "$search",
    }
    query: dict[str, Any] = {}
    for arg_name, query_name in mappings.items():
        value = kwargs.get(arg_name)
        if value is not None and value != "":
            query[query_name] = value
    return query or None


def entity_query(args: dict[str, Any]) -> dict[str, Any] | None:
    select = args.get("select") or fields_for_intent(args["entityType"], args.get("intent", "standard"))
    orderby = args.get("orderby") or args.get("orderBy") or get_entity_definition(args["entityType"])["defaultOrderBy"]
    return graph_query(
        filter=args.get("filter"),
        select=select,
        expand=args.get("expand"),
        orderby=orderby,
        search=args.get("search"),
        top=args.get("top"),
        skip=args.get("skip"),
        skiptoken=args.get("skiptoken"),
        count=args.get("count"),
    )


def is_sensitive_graph_request(method: str, path: str) -> bool:
    if method.upper() == "GET":
        return False
    normalized = f"/{path.lstrip('/').split('?', 1)[0]}".lower()
    return normalized.startswith("/security/")


def machine_lookup_filter(device_name: str) -> str:
    return f"computerDnsName eq '{str(device_name).replace(chr(39), chr(39) * 2)}'"


async def parse_response(response: httpx.Response) -> Any:
    raw = response.content
    if not raw:
        return None

    content_type = response.headers.get("content-type", "")
    if "application/json" in content_type.lower():
        return response.json()

    text = raw.decode("utf-8", errors="replace")
    if "\ufffd" in text:
        return {
            "content_type": content_type or "application/octet-stream",
            "body_base64": base64.b64encode(raw).decode("ascii"),
        }
    return {"content_type": content_type or "unknown", "text": text}


async def request_error(response: httpx.Response, url: str) -> RuntimeError:
    try:
        body = await parse_response(response)
    except Exception:
        body = response.text
    return RuntimeError(
        "Microsoft Graph returned an error: "
        + json.dumps({"status": response.status_code, "reason": response.reason_phrase, "url": url, "body": body}, ensure_ascii=False)
    )


async def get_access_token(scope: str = GRAPH_SCOPE, force_refresh: bool = False) -> str:
    cache_key = "defender" if scope == DEFENDER_SCOPE else "graph"
    cache = TOKEN_CACHE[cache_key]
    now = time.time()
    if cache["access_token"] and not force_refresh and cache["expires_at"] > now + 60:
        return str(cache["access_token"])

    config = read_config()
    require_credentials(config)

    token_url = f"{config.auth_base_url}/{quote(config.tenant_id or '', safe='')}/oauth2/v2.0/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": f"{SERVER_NAME}/{SERVER_VERSION}",
    }
    data = {
        "grant_type": "client_credentials",
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "scope": scope,
    }

    async with httpx.AsyncClient(timeout=config.timeout_seconds) as client:
        response = await client.post(token_url, headers=headers, data=data)

    if response.status_code < 200 or response.status_code >= 300:
        raise await request_error(response, token_url)

    token_response = response.json()
    access_token = token_response.get("access_token")
    if not access_token:
        raise RuntimeError("Microsoft identity platform response did not include access_token")

    try:
        expires_in = int(token_response.get("expires_in", 3600))
    except (TypeError, ValueError):
        expires_in = 3600

    cache["access_token"] = access_token
    cache["expires_at"] = now + expires_in
    return str(access_token)


async def api_request(
    base_url: str,
    scope: str,
    cache_key: str,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    query: dict[str, Any] | None = None,
    force_token_refresh: bool = False,
) -> Any:
    config = read_config()
    clean_path = path if path.startswith("/") else f"/{path}"
    url = f"{base_url}{clean_path}"
    if query:
        query_items: list[tuple[str, str]] = []
        for key, value in query.items():
            if value is None or value == "":
                continue
            if isinstance(value, list):
                query_items.extend((key, str(item)) for item in value)
            else:
                query_items.append((key, str(value)))
        if query_items:
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}{urlencode(query_items)}"

    headers = {
        "Accept": "application/json, */*",
        "Authorization": f"Bearer {await get_access_token(scope, force_token_refresh)}",
        "User-Agent": f"{SERVER_NAME}/{SERVER_VERSION}",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"

    async with httpx.AsyncClient(timeout=config.timeout_seconds) as client:
        response = await client.request(method.upper(), url, headers=headers, json=body if body is not None else None)

    if response.status_code == 401 and not force_token_refresh:
        TOKEN_CACHE[cache_key]["access_token"] = None
        TOKEN_CACHE[cache_key]["expires_at"] = 0.0
        return await api_request(base_url, scope, cache_key, method, path, body, query, True)

    if response.status_code < 200 or response.status_code >= 300:
        raise await request_error(response, url)

    return await parse_response(response)


async def graph_request(method: str, path: str, body: dict[str, Any] | None = None, query: dict[str, Any] | None = None) -> Any:
    return await api_request(read_config().api_base_url, GRAPH_SCOPE, "graph", method, path, body, query)


async def graph_beta_request(
    method: str, path: str, body: dict[str, Any] | None = None, query: dict[str, Any] | None = None
) -> Any:
    config = read_config()
    beta_base_url = config.api_base_url[:-5] + "/beta" if config.api_base_url.lower().endswith("/v1.0") else config.api_base_url
    return await api_request(beta_base_url, GRAPH_SCOPE, "graph", method, path, body, query)


async def defender_request(method: str, path: str, body: dict[str, Any] | None = None, query: dict[str, Any] | None = None) -> Any:
    return await api_request(read_config().defender_api_base_url, DEFENDER_SCOPE, "defender", method, path, body, query)


async def graph_request_next_link(next_link: str, force_token_refresh: bool = False) -> Any:
    config = read_config()
    parsed = urlparse(str(next_link))
    allowed = urlparse(config.api_base_url)
    if (parsed.scheme, parsed.netloc) != (allowed.scheme, allowed.netloc):
        raise ValueError(
            f"nextLink origin '{parsed.scheme}://{parsed.netloc}' does not match configured Microsoft Graph origin "
            f"'{allowed.scheme}://{allowed.netloc}'"
        )

    headers = {
        "Accept": "application/json, */*",
        "Authorization": f"Bearer {await get_access_token(GRAPH_SCOPE, force_token_refresh)}",
        "User-Agent": f"{SERVER_NAME}/{SERVER_VERSION}",
    }
    async with httpx.AsyncClient(timeout=config.timeout_seconds) as client:
        response = await client.get(str(next_link), headers=headers)

    if response.status_code == 401 and not force_token_refresh:
        TOKEN_CACHE["graph"]["access_token"] = None
        TOKEN_CACHE["graph"]["expires_at"] = 0.0
        return await graph_request_next_link(next_link, True)

    if response.status_code < 200 or response.status_code >= 300:
        raise await request_error(response, str(next_link))

    return await parse_response(response)


async def resolve_machine_id(device_id: str | None = None, device_name: str | None = None) -> dict[str, Any]:
    if device_id:
        machine = await defender_request("GET", f"/api/machines/{encode_path_id(device_id, 'device_id')}")
        return {"id": machine["id"], "name": machine.get("computerDnsName") or device_name or machine["id"], "machine": machine}

    if device_name:
        result = await defender_request("GET", "/api/machines", query={"$filter": machine_lookup_filter(device_name)})
        machine = (result or {}).get("value", [None])[0]
        if not machine:
            raise ValueError(f"No Defender for Endpoint machine found with name '{device_name}'")
        return {"id": machine["id"], "name": machine.get("computerDnsName") or device_name, "machine": machine}

    raise ValueError("Provide device_id or device_name")


async def get_user_id_by_upn(user_principal_name: str) -> str:
    user = await graph_request(
        "GET",
        f"/users/{encode_path_id(user_principal_name, 'user_principal_name')}",
        query={"$select": "id,userPrincipalName"},
    )
    if not user or not user.get("id"):
        raise ValueError(f"Could not resolve user ID for {user_principal_name}")
    return str(user["id"])


async def get_identity_account_id_by_upn(user_principal_name: str) -> str:
    result = await graph_beta_request(
        "GET",
        "/security/identities/identityAccounts",
        query={"$filter": f"userPrincipalName eq '{str(user_principal_name).replace(chr(39), chr(39) * 2)}'"},
    )
    account = (result or {}).get("value", [None])[0]
    if not account or not account.get("id"):
        raise ValueError(f"No Microsoft Defender for Identity account found for UPN {user_principal_name}")
    return str(account["id"])


async def invoke_identity_action_for_user(
    user_principal_name: str,
    account_id: str,
    action: str,
    identity_provider: str = "activeDirectory",
    comment: str | None = None,
) -> dict[str, Any]:
    identity_account_id = await get_identity_account_id_by_upn(user_principal_name)
    result = await graph_beta_request(
        "POST",
        f"/security/identities/identityAccounts/{encode_path_id(identity_account_id, 'identity_account_id')}/invokeAction",
        body={"accountId": account_id, "action": action, "identityProvider": identity_provider},
    )
    return {
        "user_principal_name": user_principal_name,
        "identity_account_id": identity_account_id,
        "account_id": account_id,
        "identity_action": action,
        "identity_provider": identity_provider,
        "comment": comment,
        "result": result,
    }


def approval_dict(human_approval: HumanApproval | None) -> dict[str, Any]:
    return {"human_approval": human_approval.model_dump() if isinstance(human_approval, HumanApproval) else human_approval}


@mcp.tool
async def config_status() -> str:
    """Show whether Microsoft Graph credentials, endpoints, and guardrails are configured without revealing secret values."""
    config = read_config()
    return as_text(
        {
            "tenant_id_configured": bool(config.tenant_id),
            "client_id_configured": bool(config.client_id),
            "client_secret_configured": bool(config.client_secret),
            "human_approval_token_configured": bool(config.approval_token),
            "auth_base_url": config.auth_base_url,
            "api_base_url": config.api_base_url,
            "defender_api_base_url": config.defender_api_base_url,
            "timeout_seconds": config.timeout_seconds,
            "graph_token_cached": bool(TOKEN_CACHE["graph"]["access_token"]),
            "graph_token_expires_at_epoch": int(TOKEN_CACHE["graph"]["expires_at"]) if TOKEN_CACHE["graph"]["expires_at"] else None,
            "defender_token_cached": bool(TOKEN_CACHE["defender"]["access_token"]),
            "defender_token_expires_at_epoch": int(TOKEN_CACHE["defender"]["expires_at"]) if TOKEN_CACHE["defender"]["expires_at"] else None,
            "recommended_application_permissions": [
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
                "File.Read.All",
            ],
            "human_approval_required_for": [
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
                "non-GET graph_security_request calls",
            ],
        }
    )


@mcp.tool
async def run_hunting_query(query: str = Field(min_length=1)) -> str:
    """Run a Microsoft Graph Security advanced hunting KQL query."""
    record_tool_call("run_hunting_query")
    return as_text(await graph_request("POST", "/security/runHuntingQuery", body={"Query": query}))


@mcp.tool
async def list_machines(filter: str | None = None, top: int | None = Field(default=None, ge=1, le=10000), skip: int | None = Field(default=None, ge=0)) -> str:
    """List Defender for Endpoint machines with optional OData filter and paging."""
    record_tool_call("list_machines")
    return as_text(await defender_request("GET", "/api/machines", query=graph_query(filter=filter, top=top, skip=skip)))


@mcp.tool
async def get_machine(device_id: str = Field(min_length=1)) -> str:
    """Get a Defender for Endpoint machine by machine ID."""
    record_tool_call("get_machine")
    return as_text(await defender_request("GET", f"/api/machines/{encode_path_id(device_id, 'device_id')}"))


@mcp.tool
async def get_machine_by_name(device_name: str = Field(min_length=1)) -> str:
    """Find a Microsoft Defender for Endpoint machine by hostname."""
    record_tool_call("get_machine_by_name")
    result = await defender_request("GET", "/api/machines", query={"$filter": machine_lookup_filter(device_name)})
    return as_text({"device_name": device_name, "machine": (result or {}).get("value", [None])[0], "matches": (result or {}).get("value", [])})


@mcp.tool
async def get_machine_actions(
    device_id: str | None = None,
    device_name: str | None = None,
    action_type: MachineActionType | None = None,
    status: str | None = None,
    top: int = Field(default=10, ge=1, le=100),
) -> str:
    """List Defender for Endpoint machine response actions, optionally filtered by device, action type, or status."""
    record_tool_call("get_machine_actions")
    machine_id = device_id
    if not machine_id and device_name:
        machine_id = (await resolve_machine_id(device_name=device_name))["id"]
    filters = []
    if machine_id:
        filters.append(f"machineId eq '{machine_id.replace(chr(39), chr(39) * 2)}'")
    if action_type:
        filters.append(f"type eq '{action_type}'")
    if status:
        filters.append(f"status eq '{status.replace(chr(39), chr(39) * 2)}'")
    query = {"$top": top}
    if filters:
        query["$filter"] = " and ".join(filters)
    return as_text(await defender_request("GET", "/api/machineactions", query=query))


@mcp.tool
async def list_endpoint_alerts(
    filter: str | None = None,
    expand: str | None = None,
    top: int | None = Field(default=None, ge=1, le=10000),
    skip: int | None = Field(default=None, ge=0),
) -> str:
    """List Defender for Endpoint alerts with optional OData filter, expand, and paging."""
    record_tool_call("list_endpoint_alerts")
    return as_text(await defender_request("GET", "/api/alerts", query=graph_query(filter=filter, expand=expand, top=top, skip=skip)))


@mcp.tool
async def get_endpoint_alert(alert_id: str = Field(min_length=1), expand: str | None = None) -> str:
    """Get a Defender for Endpoint alert by ID."""
    record_tool_call("get_endpoint_alert")
    return as_text(await defender_request("GET", f"/api/alerts/{encode_path_id(alert_id, 'alert_id')}", query=graph_query(expand=expand)))


@mcp.tool
async def get_endpoint_alert_files(alert_id: str = Field(min_length=1)) -> str:
    """Get files related to a Defender for Endpoint alert."""
    record_tool_call("get_endpoint_alert_files")
    return as_text(await defender_request("GET", f"/api/alerts/{encode_path_id(alert_id, 'alert_id')}/files"))


@mcp.tool
async def get_file_info(file_hash: str = Field(min_length=1)) -> str:
    """Get Defender for Endpoint file profile information by SHA1 or SHA256."""
    record_tool_call("get_file_info")
    return as_text(await defender_request("GET", f"/api/files/{encode_path_id(file_hash, 'file_hash')}"))


@mcp.tool
async def get_file_related_machines(sha1: str = Field(min_length=1)) -> str:
    """Get Defender for Endpoint machines related to a file SHA1."""
    record_tool_call("get_file_related_machines")
    return as_text(await defender_request("GET", f"/api/files/{encode_path_id(sha1, 'sha1')}/machines"))


@mcp.tool
async def get_file_stats(file_hash: str = Field(min_length=1)) -> str:
    """Get Defender for Endpoint file statistics by SHA1 or SHA256."""
    record_tool_call("get_file_stats")
    return as_text(await defender_request("GET", f"/api/files/{encode_path_id(file_hash, 'file_hash')}/stats"))


@mcp.tool
async def isolate_device(
    comment: str = Field(min_length=1),
    human_approval: HumanApproval = Field(),
    device_id: str | None = None,
    device_name: str | None = None,
    isolation_type: Literal["Full", "Selective"] = "Full",
) -> str:
    """Isolate a Defender for Endpoint device from the network. Requires explicit human approval."""
    record_tool_call("isolate_device")
    machine = await resolve_machine_id(device_id, device_name)
    require_human_approval(approval_dict(human_approval), "isolate_device", approval_phrase("ISOLATE DEVICE", machine["name"]))
    result = await defender_request(
        "POST",
        f"/api/machines/{encode_path_id(machine['id'], 'device_id')}/isolate",
        body={"Comment": comment, "IsolationType": isolation_type},
    )
    return as_text({"action": "isolate_device", "device_id": machine["id"], "device_name": machine["name"], "result": result})


@mcp.tool
async def release_device(
    comment: str = Field(min_length=1),
    human_approval: HumanApproval = Field(),
    device_id: str | None = None,
    device_name: str | None = None,
) -> str:
    """Release a Defender for Endpoint device from isolation. Requires explicit human approval."""
    record_tool_call("release_device")
    machine = await resolve_machine_id(device_id, device_name)
    require_human_approval(approval_dict(human_approval), "release_device", approval_phrase("RELEASE DEVICE", machine["name"]))
    result = await defender_request("POST", f"/api/machines/{encode_path_id(machine['id'], 'device_id')}/unisolate", body={"Comment": comment})
    return as_text({"action": "release_device", "device_id": machine["id"], "device_name": machine["name"], "result": result})


@mcp.tool
async def set_machine_tag(
    tag: str = Field(min_length=1),
    action: Literal["Add", "Remove"] = Field(),
    human_approval: HumanApproval = Field(),
    device_id: str | None = None,
    device_name: str | None = None,
) -> str:
    """Add or remove a Defender for Endpoint machine tag. Requires explicit human approval."""
    record_tool_call("set_machine_tag")
    machine = await resolve_machine_id(device_id, device_name)
    require_human_approval(approval_dict(human_approval), "set_machine_tag", approval_phrase("SET MACHINE TAG", f"{action} {tag} {machine['name']}"))
    result = await defender_request("POST", f"/api/machines/{encode_path_id(machine['id'], 'device_id')}/tags", body={"Value": tag, "Action": action})
    return as_text({"action": "set_machine_tag", "device_id": machine["id"], "device_name": machine["name"], "tag": tag, "tag_action": action, "result": result})


@mcp.tool
async def run_antivirus_scan(
    comment: str = Field(min_length=1),
    human_approval: HumanApproval = Field(),
    device_id: str | None = None,
    device_name: str | None = None,
    scan_type: Literal["Quick", "Full"] = "Quick",
) -> str:
    """Run a Defender for Endpoint antivirus scan on a device. Requires explicit human approval."""
    record_tool_call("run_antivirus_scan")
    machine = await resolve_machine_id(device_id, device_name)
    require_human_approval(approval_dict(human_approval), "run_antivirus_scan", approval_phrase("RUN ANTIVIRUS SCAN", f"{machine['name']} {scan_type}"))
    result = await defender_request(
        "POST",
        f"/api/machines/{encode_path_id(machine['id'], 'device_id')}/runAntiVirusScan",
        body={"Comment": comment, "ScanType": scan_type},
    )
    return as_text({"action": "run_antivirus_scan", "device_id": machine["id"], "device_name": machine["name"], "scan_type": scan_type, "result": result})


@mcp.tool
async def offboard_device(
    comment: str = Field(min_length=1),
    human_approval: HumanApproval = Field(),
    device_id: str | None = None,
    device_name: str | None = None,
) -> str:
    """Offboard a Windows device from Defender for Endpoint. This is high impact and requires explicit human approval."""
    record_tool_call("offboard_device")
    machine = await resolve_machine_id(device_id, device_name)
    require_human_approval(approval_dict(human_approval), "offboard_device", approval_phrase("OFFBOARD DEVICE", machine["name"]))
    result = await defender_request("POST", f"/api/machines/{encode_path_id(machine['id'], 'device_id')}/offboard", body={"Comment": comment})
    return as_text({"action": "offboard_device", "device_id": machine["id"], "device_name": machine["name"], "result": result})


@mcp.tool
async def run_live_response(
    comment: str = Field(min_length=1),
    commands: list[LiveResponseCommand] = Field(min_length=1),
    human_approval: HumanApproval = Field(),
    device_id: str | None = None,
    device_name: str | None = None,
) -> str:
    """Run Defender for Endpoint Live Response commands on a device. Requires explicit human approval."""
    record_tool_call("run_live_response")
    machine = await resolve_machine_id(device_id, device_name)
    require_human_approval(approval_dict(human_approval), "run_live_response", approval_phrase("RUN LIVE RESPONSE", f"{machine['name']} {len(commands)} COMMANDS"))
    result = await defender_request(
        "POST",
        f"/api/machines/{encode_path_id(machine['id'], 'device_id')}/runliveresponse",
        body={"Comment": comment, "Commands": [command.model_dump() for command in commands]},
    )
    return as_text({"action": "run_live_response", "device_id": machine["id"], "device_name": machine["name"], "command_count": len(commands), "result": result})


@mcp.tool
async def stop_and_quarantine(
    sha1: str = Field(min_length=1),
    comment: str = Field(min_length=1),
    human_approval: HumanApproval = Field(),
    device_id: str | None = None,
    device_name: str | None = None,
) -> str:
    """Stop a running process and quarantine the associated file by SHA1. Requires explicit human approval."""
    record_tool_call("stop_and_quarantine")
    machine = await resolve_machine_id(device_id, device_name)
    require_human_approval(approval_dict(human_approval), "stop_and_quarantine", approval_phrase("STOP AND QUARANTINE", f"{machine['name']} {sha1}"))
    result = await defender_request(
        "POST",
        f"/api/machines/{encode_path_id(machine['id'], 'device_id')}/StopAndQuarantineFile",
        body={"Comment": comment, "Sha1": sha1},
    )
    return as_text({"action": "stop_and_quarantine", "device_id": machine["id"], "device_name": machine["name"], "sha1": sha1, "result": result})


@mcp.tool
async def restrict_code_execution(
    comment: str = Field(min_length=1),
    human_approval: HumanApproval = Field(),
    device_id: str | None = None,
    device_name: str | None = None,
) -> str:
    """Restrict code execution on a Defender for Endpoint device. Requires explicit human approval."""
    record_tool_call("restrict_code_execution")
    machine = await resolve_machine_id(device_id, device_name)
    require_human_approval(approval_dict(human_approval), "restrict_code_execution", approval_phrase("RESTRICT CODE EXECUTION", machine["name"]))
    result = await defender_request("POST", f"/api/machines/{encode_path_id(machine['id'], 'device_id')}/restrictCodeExecution", body={"Comment": comment})
    return as_text({"action": "restrict_code_execution", "device_id": machine["id"], "device_name": machine["name"], "result": result})


@mcp.tool
async def remove_code_restriction(
    comment: str = Field(min_length=1),
    human_approval: HumanApproval = Field(),
    device_id: str | None = None,
    device_name: str | None = None,
) -> str:
    """Remove code execution restrictions from a Defender for Endpoint device. Requires explicit human approval."""
    record_tool_call("remove_code_restriction")
    machine = await resolve_machine_id(device_id, device_name)
    require_human_approval(approval_dict(human_approval), "remove_code_restriction", approval_phrase("REMOVE CODE RESTRICTION", machine["name"]))
    result = await defender_request("POST", f"/api/machines/{encode_path_id(machine['id'], 'device_id')}/unrestrictCodeExecution", body={"Comment": comment})
    return as_text({"action": "remove_code_restriction", "device_id": machine["id"], "device_name": machine["name"], "result": result})


@mcp.tool
async def collect_investigation_package(
    comment: str = Field(min_length=1),
    human_approval: HumanApproval = Field(),
    device_id: str | None = None,
    device_name: str | None = None,
) -> str:
    """Collect a forensic investigation package from a Defender for Endpoint device. Requires explicit human approval."""
    record_tool_call("collect_investigation_package")
    machine = await resolve_machine_id(device_id, device_name)
    require_human_approval(approval_dict(human_approval), "collect_investigation_package", approval_phrase("COLLECT INVESTIGATION PACKAGE", machine["name"]))
    result = await defender_request("POST", f"/api/machines/{encode_path_id(machine['id'], 'device_id')}/collectInvestigationPackage", body={"Comment": comment})
    return as_text({"action": "collect_investigation_package", "device_id": machine["id"], "device_name": machine["name"], "result": result})


@mcp.tool
async def get_investigation_package_uri(action_id: str = Field(min_length=1)) -> str:
    """Get a temporary download URI for a completed Defender for Endpoint investigation package action."""
    record_tool_call("get_investigation_package_uri")
    return as_text(await defender_request("GET", f"/api/machineactions/{encode_path_id(action_id, 'action_id')}/GetPackageUri"))


@mcp.tool
async def isolate_multiple(
    device_names: list[str] = Field(min_length=1, max_length=100),
    comment: str = Field(min_length=1),
    human_approval: HumanApproval = Field(),
    isolation_type: Literal["Full", "Selective"] = "Full",
) -> str:
    """Bulk isolate multiple Defender for Endpoint devices by hostname. Requires explicit human approval."""
    record_tool_call("isolate_multiple")
    require_human_approval(approval_dict(human_approval), "isolate_multiple", approval_phrase("ISOLATE MULTIPLE DEVICES", f"{len(device_names)} DEVICES"))
    results = []
    for device_name in device_names:
        machine = await resolve_machine_id(device_name=device_name)
        result = await defender_request(
            "POST",
            f"/api/machines/{encode_path_id(machine['id'], 'device_id')}/isolate",
            body={"Comment": comment, "IsolationType": isolation_type},
        )
        results.append({"device_name": machine["name"], "device_id": machine["id"], "result": result})
    return as_text({"action": "isolate_multiple", "count": len(results), "results": results})


@mcp.tool
async def list_indicators(filter: str | None = None, top: int | None = Field(default=None, ge=1, le=10000), skip: int | None = Field(default=None, ge=0)) -> str:
    """List active Defender for Endpoint indicators with optional OData filter and paging."""
    record_tool_call("list_indicators")
    return as_text(await defender_request("GET", "/api/indicators", query=graph_query(filter=filter, top=top, skip=skip)))


@mcp.tool
async def submit_indicator(
    human_approval: HumanApproval = Field(),
    indicator_value: str | None = None,
    indicator_type: IndicatorType | None = None,
    action: IndicatorAction | None = None,
    title: str | None = None,
    description: str | None = None,
    expiration_time: str | None = None,
    severity: IndicatorSeverity | None = None,
    generate_alert: bool | None = None,
    recommended_actions: str | None = None,
    request_body: dict[str, Any] | None = None,
) -> str:
    """Submit or update a Defender for Endpoint indicator. Requires explicit human approval."""
    record_tool_call("submit_indicator")
    body = request_body or {
        "indicatorValue": indicator_value,
        "indicatorType": indicator_type,
        "action": action,
        "title": title,
        "description": description,
        "expirationTime": expiration_time,
        "severity": severity,
        "generateAlert": generate_alert,
        "recommendedActions": recommended_actions,
    }
    body = {key: value for key, value in body.items() if value is not None}
    if not body.get("indicatorValue") or not body.get("indicatorType") or not body.get("action"):
        raise ValueError("Provide indicator_value, indicator_type, and action, or request_body with indicatorValue, indicatorType, and action")
    require_human_approval(
        approval_dict(human_approval),
        "submit_indicator",
        approval_phrase("SUBMIT INDICATOR", f"{body['indicatorType']} {body['indicatorValue']} {body['action']}"),
    )
    return as_text(await defender_request("POST", "/api/indicators", body=body))


@mcp.tool
async def delete_indicator(indicator_id: str = Field(min_length=1), human_approval: HumanApproval = Field()) -> str:
    """Delete a Defender for Endpoint indicator by ID. Requires explicit human approval."""
    record_tool_call("delete_indicator")
    require_human_approval(approval_dict(human_approval), "delete_indicator", approval_phrase("DELETE INDICATOR", indicator_id))
    return as_text(await defender_request("DELETE", f"/api/indicators/{encode_path_id(indicator_id, 'indicator_id')}"))


@mcp.tool
async def revoke_entra_sessions(user_principal_name: str = Field(min_length=1), comment: str = Field(min_length=1), human_approval: HumanApproval = Field()) -> str:
    """Revoke all Entra ID sign-in sessions and refresh tokens for a user. Requires explicit human approval."""
    record_tool_call("revoke_entra_sessions")
    require_human_approval(approval_dict(human_approval), "revoke_entra_sessions", approval_phrase("REVOKE ENTRA SESSIONS", user_principal_name))
    result = await graph_request("POST", f"/users/{encode_path_id(user_principal_name, 'user_principal_name')}/revokeSignInSessions")
    return as_text({"action": "revoke_entra_sessions", "user_principal_name": user_principal_name, "comment": comment, "result": result})


@mcp.tool
async def confirm_user_compromised(user_principal_name: str = Field(min_length=1), comment: str = Field(min_length=1), human_approval: HumanApproval = Field()) -> str:
    """Mark a user as compromised in Microsoft Entra Identity Protection. Requires explicit human approval."""
    record_tool_call("confirm_user_compromised")
    require_human_approval(approval_dict(human_approval), "confirm_user_compromised", approval_phrase("CONFIRM USER COMPROMISED", user_principal_name))
    user_id = await get_user_id_by_upn(user_principal_name)
    result = await graph_request("POST", "/identityProtection/riskyUsers/confirmCompromised", body={"userIds": [user_id]})
    return as_text({"action": "confirm_user_compromised", "user_principal_name": user_principal_name, "user_id": user_id, "comment": comment, "result": result})


@mcp.tool
async def confirm_user_safe(user_principal_name: str = Field(min_length=1), comment: str = Field(min_length=1), human_approval: HumanApproval = Field()) -> str:
    """Dismiss user risk in Microsoft Entra Identity Protection. Requires explicit human approval."""
    record_tool_call("confirm_user_safe")
    require_human_approval(approval_dict(human_approval), "confirm_user_safe", approval_phrase("CONFIRM USER SAFE", user_principal_name))
    user_id = await get_user_id_by_upn(user_principal_name)
    result = await graph_request("POST", "/identityProtection/riskyUsers/confirmSafe", body={"userIds": [user_id]})
    return as_text({"action": "confirm_user_safe", "user_principal_name": user_principal_name, "user_id": user_id, "comment": comment, "result": result})


@mcp.tool
async def invoke_identity_account_action(
    user_principal_name: str = Field(min_length=1),
    account_id: str = Field(min_length=1),
    action: Literal["disable", "enable", "forcePasswordReset", "revokeAllSessions"] = Field(),
    comment: str = Field(min_length=1),
    human_approval: HumanApproval = Field(),
    identity_provider: Literal["activeDirectory", "entraID", "okta"] = "activeDirectory",
) -> str:
    """Invoke a Microsoft Defender for Identity account action through Graph beta. Requires explicit human approval."""
    record_tool_call("invoke_identity_account_action")
    require_human_approval(approval_dict(human_approval), "invoke_identity_account_action", approval_phrase("INVOKE IDENTITY ACTION", f"{action} {user_principal_name}"))
    result = await invoke_identity_action_for_user(user_principal_name, account_id, action, identity_provider, comment)
    return as_text({"action": "invoke_identity_account_action", **result})


@mcp.tool
async def disable_ad_account(user_principal_name: str = Field(min_length=1), account_id: str = Field(min_length=1), comment: str = Field(min_length=1), human_approval: HumanApproval = Field()) -> str:
    """Disable an Active Directory account through Microsoft Defender for Identity. Requires explicit human approval."""
    record_tool_call("disable_ad_account")
    require_human_approval(approval_dict(human_approval), "disable_ad_account", approval_phrase("DISABLE AD ACCOUNT", user_principal_name))
    return as_text({"action": "disable_ad_account", **(await invoke_identity_action_for_user(user_principal_name, account_id, "disable", comment=comment))})


@mcp.tool
async def enable_ad_account(user_principal_name: str = Field(min_length=1), account_id: str = Field(min_length=1), comment: str = Field(min_length=1), human_approval: HumanApproval = Field()) -> str:
    """Re-enable an Active Directory account through Microsoft Defender for Identity. Requires explicit human approval."""
    record_tool_call("enable_ad_account")
    require_human_approval(approval_dict(human_approval), "enable_ad_account", approval_phrase("ENABLE AD ACCOUNT", user_principal_name))
    return as_text({"action": "enable_ad_account", **(await invoke_identity_action_for_user(user_principal_name, account_id, "enable", comment=comment))})


@mcp.tool
async def force_ad_password_reset(user_principal_name: str = Field(min_length=1), account_id: str = Field(min_length=1), comment: str = Field(min_length=1), human_approval: HumanApproval = Field()) -> str:
    """Force an Active Directory user to change password at next logon through Microsoft Defender for Identity. Requires explicit human approval."""
    record_tool_call("force_ad_password_reset")
    require_human_approval(approval_dict(human_approval), "force_ad_password_reset", approval_phrase("FORCE AD PASSWORD RESET", user_principal_name))
    return as_text({"action": "force_ad_password_reset", **(await invoke_identity_action_for_user(user_principal_name, account_id, "forcePasswordReset", comment=comment))})


@mcp.tool
async def assign_incident(incident_id: str = Field(min_length=1), assigned_to: str = Field(), human_approval: HumanApproval = Field()) -> str:
    """Assign or unassign a Microsoft Graph Security incident. Requires explicit human approval."""
    record_tool_call("assign_incident")
    require_human_approval(approval_dict(human_approval), "assign_incident", approval_phrase("ASSIGN INCIDENT", incident_id))
    return as_text(await graph_request("PATCH", f"/security/incidents/{encode_path_id(incident_id, 'incident_id')}", body={"assignedTo": assigned_to}))


@mcp.tool
async def update_incident_status(
    incident_id: str = Field(min_length=1),
    status: Literal["active", "resolved", "inProgress", "redirected", "unknownFutureValue"] = Field(),
    human_approval: HumanApproval = Field(),
    resolving_comment: str | None = None,
) -> str:
    """Update a Microsoft Graph Security incident status. Requires explicit human approval."""
    record_tool_call("update_incident_status")
    require_human_approval(approval_dict(human_approval), "update_incident_status", approval_phrase("UPDATE INCIDENT STATUS", f"{incident_id} {status}"))
    body = {"status": status}
    if resolving_comment:
        body["resolvingComment"] = resolving_comment
    return as_text(await graph_request("PATCH", f"/security/incidents/{encode_path_id(incident_id, 'incident_id')}", body=body))


@mcp.tool
async def classify_incident(
    incident_id: str = Field(min_length=1),
    classification: IncidentClassification = Field(),
    human_approval: HumanApproval = Field(),
    determination: IncidentDetermination = "other",
) -> str:
    """Set classification and determination on a Microsoft Graph Security incident. Requires explicit human approval."""
    record_tool_call("classify_incident")
    require_human_approval(approval_dict(human_approval), "classify_incident", approval_phrase("CLASSIFY INCIDENT", f"{incident_id} {classification}"))
    return as_text(
        await graph_request(
            "PATCH",
            f"/security/incidents/{encode_path_id(incident_id, 'incident_id')}",
            body={"classification": classification, "determination": determination},
        )
    )


@mcp.tool
async def add_incident_tags(incident_id: str = Field(min_length=1), tags: list[str] = Field(min_length=1), human_approval: HumanApproval = Field()) -> str:
    """Add custom tags to a Microsoft Graph Security incident while preserving existing tags. Requires explicit human approval."""
    record_tool_call("add_incident_tags")
    require_human_approval(approval_dict(human_approval), "add_incident_tags", approval_phrase("ADD INCIDENT TAGS", incident_id))
    incident = await graph_request("GET", f"/security/incidents/{encode_path_id(incident_id, 'incident_id')}", query={"$select": "id,customTags"})
    current_tags = incident.get("customTags", []) if isinstance(incident, dict) and isinstance(incident.get("customTags"), list) else []
    custom_tags = list(dict.fromkeys([*current_tags, *tags]))
    return as_text(await graph_request("PATCH", f"/security/incidents/{encode_path_id(incident_id, 'incident_id')}", body={"customTags": custom_tags}))


@mcp.tool
async def add_incident_comment(incident_id: str = Field(min_length=1), comment: str = Field(min_length=1), human_approval: HumanApproval = Field()) -> str:
    """Add a comment to a Microsoft Graph Security incident. Requires explicit human approval."""
    record_tool_call("add_incident_comment")
    require_human_approval(approval_dict(human_approval), "add_incident_comment", approval_phrase("COMMENT ON INCIDENT", incident_id))
    return as_text(
        await graph_request(
            "POST",
            f"/security/incidents/{encode_path_id(incident_id, 'incident_id')}/comments",
            body={"@odata.type": "microsoft.graph.security.alertComment", "comment": comment},
        )
    )


@mcp.tool
async def graph_entity_list(
    entityType: EntityType,
    filter: str | None = None,
    top: int | None = Field(default=None, ge=1, le=999),
    orderBy: str | None = None,
    orderby: str | None = None,
    select: str | None = None,
    expand: str | None = None,
    search: str | None = None,
    skip: int | None = Field(default=None, ge=0),
    skiptoken: str | None = None,
    count: bool | None = None,
    intent: QueryIntent = "standard",
) -> str:
    """List Microsoft Graph Security alerts or incidents with intent-based field selection."""
    record_tool_call("graph_entity_list")
    definition = get_entity_definition(entityType)
    return as_text(await graph_request("GET", definition["collectionPath"], query=entity_query(locals())))


@mcp.tool
async def graph_entity_get(
    entityType: EntityType,
    entityId: str = Field(min_length=1),
    select: str | None = None,
    expand: str | None = None,
    intent: QueryIntent = "complete",
) -> str:
    """Get a Microsoft Graph Security alert or incident by ID with optional field selection and expansion."""
    record_tool_call("graph_entity_get")
    definition = get_entity_definition(entityType)
    select_value = select or fields_for_intent(entityType, intent)
    return as_text(await graph_request("GET", f"{definition['itemPath']}/{encode_path_id(entityId, 'entityId')}", query=graph_query(select=select_value, expand=expand)))


@mcp.tool
async def graph_entity_update(entityType: EntityType, entityId: str = Field(min_length=1), properties: dict[str, Any] = Field(), human_approval: HumanApproval = Field()) -> str:
    """Update a Microsoft Graph Security alert or incident. Requires explicit human approval."""
    record_tool_call("graph_entity_update")
    definition = get_entity_definition(entityType)
    entity_id = entityId.strip()
    require_human_approval(approval_dict(human_approval), "graph_entity_update", approval_phrase("UPDATE ENTITY", f"{entityType} {entity_id}"))
    if not properties:
        raise ValueError("properties must include at least one field to update")
    return as_text(await graph_request("PATCH", f"{definition['itemPath']}/{encode_path_id(entity_id, 'entityId')}", body=properties))


@mcp.tool
async def graph_entity_comment(entityType: EntityType, entityId: str = Field(min_length=1), comment: str = Field(min_length=1), human_approval: HumanApproval = Field()) -> str:
    """Add a comment to a Microsoft Graph Security alert or incident. Requires explicit human approval."""
    record_tool_call("graph_entity_comment")
    definition = get_entity_definition(entityType)
    entity_id = entityId.strip()
    require_human_approval(approval_dict(human_approval), "graph_entity_comment", approval_phrase("COMMENT ON ENTITY", f"{entityType} {entity_id}"))
    return as_text(
        await graph_request(
            "POST",
            f"{definition['commentPath']}/{encode_path_id(entity_id, 'entityId')}/comments",
            body={"@odata.type": "microsoft.graph.security.alertComment", "comment": comment},
        )
    )


@mcp.tool
async def graph_entity_navigate(
    sourceEntityType: EntityType,
    sourceEntityId: str = Field(min_length=1),
    targetEntityType: EntityType = Field(),
    intent: QueryIntent = "standard",
) -> str:
    """Navigate supported Graph Security relationships between alerts and incidents."""
    record_tool_call("graph_entity_navigate")
    if sourceEntityType == "incident" and targetEntityType == "alert":
        return as_text(
            await graph_request(
                "GET",
                f"/security/incidents/{encode_path_id(sourceEntityId, 'sourceEntityId')}/alerts",
                query=graph_query(select=fields_for_intent("alert", intent)),
            )
        )
    if sourceEntityType == "alert" and targetEntityType == "incident":
        alert = await graph_request(
            "GET",
            f"/security/alerts_v2/{encode_path_id(sourceEntityId, 'sourceEntityId')}",
            query=graph_query(select="id,incidentId"),
        )
        if not alert or not alert.get("incidentId"):
            return as_text({"message": "Alert does not include an incidentId relationship.", "alertId": sourceEntityId})
        return as_text(
            await graph_request(
                "GET",
                f"/security/incidents/{encode_path_id(alert['incidentId'], 'incidentId')}",
                query=graph_query(select=fields_for_intent("incident", intent)),
            )
        )
    raise ValueError(f"Unsupported navigation: {sourceEntityType} to {targetEntityType}")


@mcp.tool
async def graph_entity_list_next(nextLink: HttpUrl) -> str:
    """Fetch the next page from an @odata.nextLink returned by Microsoft Graph."""
    record_tool_call("graph_entity_list_next")
    return as_text(await graph_request_next_link(str(nextLink)))


@mcp.tool
async def graph_entity_schema(entityType: EntityType, operation: Literal["list", "get", "update", "comment", "navigate", "all"] = "all") -> str:
    """Return schema, field priority, filter, update, and relationship guidance for alerts or incidents."""
    record_tool_call("graph_entity_schema")
    definition = get_entity_definition(entityType)
    return as_text(
        {
            "entityType": entityType,
            "operation": operation,
            "collectionPath": definition["collectionPath"],
            "itemPath": definition["itemPath"],
            "idField": definition["idField"],
            "fieldSelection": {
                "overview": definition["overviewFields"],
                "standard": definition["standardFields"],
                "complete": "No $select is sent; Microsoft Graph returns its default complete representation for the endpoint.",
            },
            "filterableFields": definition["filterableFields"],
            "updateableFields": definition["updateableFields"],
            "relationships": definition["relationships"],
            "recommendedTools": [
                "graph_entity_list",
                "graph_entity_get",
                "graph_entity_update",
                "graph_entity_comment",
                "graph_entity_navigate",
                "graph_entity_list_next",
            ],
        }
    )


@mcp.tool
async def context_discover(entityType: EntityType | None = None, focusArea: Literal["fields", "filters", "updates", "relationships", "tools", "all"] = "all") -> str:
    """Discover Graph Security entity capabilities, recommended tools, and field-selection behavior."""
    record_tool_call("context_discover")
    entity_types = [entityType] if entityType else list(ENTITY_DEFINITIONS)
    return as_text(
        {
            "focusArea": focusArea,
            "contextLevel": CONTEXT_STATE["level"],
            "ttlSeconds": CONTEXT_STATE["ttlSeconds"],
            "entities": {
                entity_type: {
                    "overviewFields": get_entity_definition(entity_type)["overviewFields"],
                    "standardFields": get_entity_definition(entity_type)["standardFields"],
                    "filterableFields": get_entity_definition(entity_type)["filterableFields"],
                    "updateableFields": get_entity_definition(entity_type)["updateableFields"],
                    "relationships": get_entity_definition(entity_type)["relationships"],
                }
                for entity_type in entity_types
            },
            "universalTools": [
                "graph_entity_list",
                "graph_entity_get",
                "graph_entity_update",
                "graph_entity_comment",
                "graph_entity_navigate",
                "graph_entity_list_next",
                "graph_entity_schema",
            ],
        }
    )


@mcp.tool
async def context_stats() -> str:
    """Return lightweight context and tool usage statistics for this MCP server process."""
    record_tool_call("context_stats")
    return as_text(CONTEXT_STATE)


@mcp.tool
async def context_configure(
    action: Literal["set", "reset"],
    level: Literal["none", "minimal", "standard", "complete"] | None = None,
    seconds: int | None = Field(default=None, ge=0),
    toolName: str | None = None,
) -> str:
    """Configure lightweight context behavior for this MCP server process."""
    record_tool_call("context_configure")
    if action == "reset":
        CONTEXT_STATE["level"] = "standard"
        CONTEXT_STATE["ttlSeconds"] = 3600
        CONTEXT_STATE["configuredAt"] = datetime.now(timezone.utc).isoformat()
        if toolName:
            CONTEXT_STATE["toolCalls"].pop(toolName, None)
        else:
            CONTEXT_STATE["toolCalls"] = {}
    else:
        if level:
            CONTEXT_STATE["level"] = level
        if seconds is not None:
            CONTEXT_STATE["ttlSeconds"] = seconds
        CONTEXT_STATE["configuredAt"] = datetime.now(timezone.utc).isoformat()
    return as_text(CONTEXT_STATE)


@mcp.tool
async def list_security_incidents(
    filter: str | None = None,
    select: str | None = None,
    expand: str | None = None,
    orderby: str | None = None,
    top: int | None = Field(default=None, ge=1, le=999),
    skip: int | None = Field(default=None, ge=0),
    skiptoken: str | None = None,
) -> str:
    """List Microsoft Graph Security incidents with optional OData query parameters."""
    return as_text(await graph_request("GET", "/security/incidents", query=graph_query(**locals())))


@mcp.tool
async def get_security_incident(incident_id: str = Field(min_length=1), select: str | None = None, expand: str | None = None) -> str:
    """Get a Microsoft Graph Security incident by ID."""
    return as_text(await graph_request("GET", f"/security/incidents/{encode_path_id(incident_id, 'incident_id')}", query=graph_query(select=select, expand=expand)))


@mcp.tool
async def list_incident_alerts(
    incident_id: str = Field(min_length=1),
    filter: str | None = None,
    select: str | None = None,
    orderby: str | None = None,
    top: int | None = Field(default=None, ge=1, le=999),
    skip: int | None = Field(default=None, ge=0),
) -> str:
    """List alerts related to a Microsoft Graph Security incident."""
    return as_text(
        await graph_request(
            "GET",
            f"/security/incidents/{encode_path_id(incident_id, 'incident_id')}/alerts",
            query=graph_query(filter=filter, select=select, orderby=orderby, top=top, skip=skip),
        )
    )


@mcp.tool
async def list_alerts_v2(
    filter: str | None = None,
    select: str | None = None,
    expand: str | None = None,
    orderby: str | None = None,
    top: int | None = Field(default=None, ge=1, le=999),
    skip: int | None = Field(default=None, ge=0),
    skiptoken: str | None = None,
) -> str:
    """List Microsoft Graph Security alerts_v2 with optional OData query parameters."""
    return as_text(await graph_request("GET", "/security/alerts_v2", query=graph_query(**locals())))


@mcp.tool
async def get_alert_v2(alert_id: str = Field(min_length=1), select: str | None = None, expand: str | None = None) -> str:
    """Get a Microsoft Graph Security alert_v2 by ID."""
    return as_text(await graph_request("GET", f"/security/alerts_v2/{encode_path_id(alert_id, 'alert_id')}", query=graph_query(select=select, expand=expand)))


@mcp.tool
async def update_security_incident(
    incident_id: str = Field(min_length=1),
    human_approval: HumanApproval = Field(),
    status: Literal["active", "resolved", "inProgress", "redirected", "unknownFutureValue"] | None = None,
    classification: IncidentClassification | None = None,
    determination: IncidentDetermination | None = None,
    custom_tags: list[str] | None = None,
    assigned_to: str | None = None,
    resolving_comment: str | None = None,
    request_body: dict[str, Any] | None = None,
) -> str:
    """Patch selected Microsoft Graph Security incident fields. Requires explicit human approval."""
    incident_id = incident_id.strip()
    require_human_approval(approval_dict(human_approval), "update_security_incident", approval_phrase("UPDATE INCIDENT", incident_id))
    body = request_body or {
        **({"status": status} if status else {}),
        **({"classification": classification} if classification else {}),
        **({"determination": determination} if determination else {}),
        **({"customTags": custom_tags} if custom_tags else {}),
        **({"assignedTo": assigned_to} if assigned_to else {}),
        **({"resolvingComment": resolving_comment} if resolving_comment else {}),
    }
    if not body:
        raise ValueError("Provide at least one incident field or request_body to update")
    return as_text(await graph_request("PATCH", f"/security/incidents/{encode_path_id(incident_id, 'incident_id')}", body=body))


@mcp.tool
async def close_security_incident(
    incident_id: str = Field(min_length=1),
    classification: IncidentClassification = Field(),
    human_approval: HumanApproval = Field(),
    determination: IncidentDetermination = "other",
    resolving_comment: str | None = None,
) -> str:
    """Resolve a Microsoft Graph Security incident with classification, determination, and optional resolving comment. Requires explicit human approval."""
    incident_id = incident_id.strip()
    require_human_approval(approval_dict(human_approval), "close_security_incident", approval_phrase("CLOSE INCIDENT", incident_id))
    body = {"status": "resolved", "classification": classification, "determination": determination}
    if resolving_comment:
        body["resolvingComment"] = resolving_comment
    return as_text(await graph_request("PATCH", f"/security/incidents/{encode_path_id(incident_id, 'incident_id')}", body=body))


@mcp.tool
async def update_alert_v2(
    alert_id: str = Field(min_length=1),
    human_approval: HumanApproval = Field(),
    status: Literal["new", "inProgress", "resolved", "unknownFutureValue"] | None = None,
    classification: AlertClassification | None = None,
    determination: AlertDetermination | None = None,
    assigned_to: str | None = None,
    custom_details: dict[str, Any] | None = None,
    request_body: dict[str, Any] | None = None,
) -> str:
    """Patch selected Microsoft Graph Security alert_v2 fields. Requires explicit human approval."""
    alert_id = alert_id.strip()
    require_human_approval(approval_dict(human_approval), "update_alert_v2", approval_phrase("UPDATE ALERT", alert_id))
    body = request_body or {
        **({"status": status} if status else {}),
        **({"classification": classification} if classification else {}),
        **({"determination": determination} if determination else {}),
        **({"assignedTo": assigned_to} if assigned_to else {}),
        **({"customDetails": custom_details} if custom_details else {}),
    }
    if not body:
        raise ValueError("Provide at least one alert field or request_body to update")
    return as_text(await graph_request("PATCH", f"/security/alerts_v2/{encode_path_id(alert_id, 'alert_id')}", body=body))


@mcp.tool
async def create_alert_comment(alert_id: str = Field(min_length=1), comment: str = Field(min_length=1), human_approval: HumanApproval = Field()) -> str:
    """Create a comment on a Microsoft Graph Security alert_v2. Requires explicit human approval."""
    alert_id = alert_id.strip()
    require_human_approval(approval_dict(human_approval), "create_alert_comment", approval_phrase("COMMENT ON ALERT", alert_id))
    return as_text(
        await graph_request(
            "POST",
            f"/security/alerts_v2/{encode_path_id(alert_id, 'alert_id')}/comments",
            body={"@odata.type": "microsoft.graph.security.alertComment", "comment": comment},
        )
    )


@mcp.tool
async def graph_security_request(
    method: Literal["GET", "POST", "PATCH", "PUT", "DELETE"],
    path: str = Field(min_length=1),
    query: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
    human_approval: HumanApproval | None = None,
) -> str:
    """Advanced escape hatch for Microsoft Graph Security API calls not covered by a dedicated tool. Non-GET calls require explicit human approval."""
    if is_sensitive_graph_request(method, path):
        normalized = f"/{path.lstrip('/').split('?', 1)[0]}"
        require_human_approval(approval_dict(human_approval), "graph_security_request", approval_phrase("API REQUEST", f"{method} {normalized}"))
    return as_text(await graph_request(method, path, body=body, query=query))


@mcp.tool
async def defender_endpoint_request(
    method: Literal["GET", "POST", "PATCH", "PUT", "DELETE"],
    path: str = Field(min_length=1),
    query: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
    human_approval: HumanApproval | None = None,
) -> str:
    """Advanced escape hatch for Microsoft Defender for Endpoint API calls not covered by a dedicated tool. Non-GET calls require explicit human approval."""
    record_tool_call("defender_endpoint_request")
    if method.upper() != "GET":
        normalized = f"/{path.lstrip('/').split('?', 1)[0]}"
        require_human_approval(approval_dict(human_approval), "defender_endpoint_request", approval_phrase("DEFENDER ENDPOINT API REQUEST", f"{method} {normalized}"))
    return as_text(await defender_request(method, path, body=body, query=query))


def main() -> None:
    mcp.run(show_banner=False)


if __name__ == "__main__":
    main()
