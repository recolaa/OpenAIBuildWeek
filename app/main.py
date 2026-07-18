from __future__ import annotations

# FastAPI's documented dependency-injection form evaluates Depends at definition time.
# ruff: noqa: B008
import asyncio
import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request, status

from app.chat import ChatDispatcher
from app.database import ContextConflict, Database
from app.firewall import DryRunIptablesFirewall, InMemoryFirewall, IptablesFirewall
from app.normalizers import NormalizationError
from app.policy import PolicyLoader
from app.reasoners import create_mock_reasoner, create_openai_reasoner
from app.schemas import (
    ApproverIdentity,
    ChatContextResponse,
    ChatDecision,
    ContextRequest,
    EnforcementResult,
    ExternalNetworkEvent,
    FirewallDropEvent,
    FlowScope,
    GenericNetworkEventIn,
    IncidentListResponse,
    IncidentResponse,
    IncidentTimelineResponse,
    NetworkEventIn,
    ZeekEventIn,
)
from app.services import DecisionService, ExpiryService, NetworkAgentService
from app.settings import Settings, SettingsError


@dataclass(slots=True)
class Container:
    settings: Settings
    database: Database
    network_agent: NetworkAgentService
    decisions: DecisionService
    expiry: ExpiryService
    firewall: Any


def build_container(settings: Settings) -> Container:
    if (
        (settings.chat_integration_token or settings.integration_api_token)
        and settings.trusted_chat_agent_role not in settings.allowed_approver_roles
    ):
        raise SettingsError(
            "Trusted chat-agent role must be included in the allowed approver roles"
        )
    database = Database(settings.database_path)
    policies = PolicyLoader(settings.project_root / "config")
    if settings.reasoner_mode == "openai":
        if not settings.openai_api_key:
            raise SettingsError("OpenAI mode requires the project-local API key")
        reasoner = create_openai_reasoner(
            api_key=settings.openai_api_key,
            model=settings.openai_model,
            max_output_tokens=settings.llm_max_output_tokens,
        )
    else:
        reasoner = create_mock_reasoner()

    if settings.firewall_mode == "in_memory":
        firewall = InMemoryFirewall()
    elif settings.firewall_mode == "dry_run_iptables":
        firewall = DryRunIptablesFirewall()
    else:
        if not settings.firewall_enabled or not settings.allow_host_firewall:
            raise SettingsError(
                "Real iptables requires FIREWALL_ENABLED=true and ALLOW_HOST_FIREWALL=true"
            )
        if (
            settings.demo_mode
            or not settings.network_ingest_token
            or not settings.chat_integration_token
            or settings.network_ingest_token == settings.chat_integration_token
        ):
            raise SettingsError(
                "Real iptables requires DEMO_MODE=false plus distinct "
                "NETWORK_INGEST_TOKEN and CHAT_INTEGRATION_TOKEN values in .env"
            )
        firewall = IptablesFirewall(enabled=True)

    chat = ChatDispatcher(
        database,
        mode=settings.chat_mode,
        url=settings.chat_agent_url,
        token=settings.chat_agent_token,
    )
    network_agent = NetworkAgentService(settings, database, policies, reasoner, chat)
    decisions = DecisionService(settings, database, firewall, policies)
    expiry = ExpiryService(settings, database, firewall, policies)
    return Container(settings, database, network_agent, decisions, expiry, firewall)


def create_app(settings: Settings | None = None) -> FastAPI:
    selected = settings or Settings.load()
    container = build_container(selected)
    stop_event = asyncio.Event()
    expiry_task: asyncio.Task[None] | None = None

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        nonlocal expiry_task
        container.database.initialize()
        topology_verifier = getattr(
            container.firewall, "verify_parent_chain_topology", None
        )
        if topology_verifier is not None:
            await topology_verifier()
        await container.expiry.restore_active_rules()
        await container.expiry.expire_once()
        expiry_task = asyncio.create_task(
            container.expiry.run(stop_event), name="intentbridge-expiry"
        )
        application.state.container = container
        try:
            yield
        finally:
            stop_event.set()
            if expiry_task is not None:
                await expiry_task

    application = FastAPI(
        title="IntentBridge Network Agent",
        version="0.1.0",
        description=(
            "Analyzes network evidence, requests missing organizational context, "
            "and applies only deterministically validated temporary exact-service rules."
        ),
        lifespan=lifespan,
    )
    application.state.container = container

    async def integration_principal(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
        x_intentbridge_token: Annotated[str | None, Header()] = None,
    ) -> ApproverIdentity | None:
        """Authenticate integration calls when a project-local token is configured."""

        expected = selected.chat_integration_token or selected.integration_api_token
        if expected is None:
            client_host = request.client.host if request.client is not None else None
            if client_host not in {"127.0.0.1", "::1", "localhost", "testclient"}:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="unauthenticated integration access is loopback-only",
                )
            return None
        supplied = x_intentbridge_token
        if authorization and authorization.startswith("Bearer "):
            supplied = authorization.removeprefix("Bearer ").strip()
        if supplied is None or not secrets.compare_digest(supplied, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing or invalid integration credential",
            )
        return ApproverIdentity(
            id=selected.trusted_chat_agent_id,
            role=selected.trusted_chat_agent_role,
            display_name="Authenticated chat-agent integration",
        )

    async def network_principal(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
        x_intentbridge_token: Annotated[str | None, Header()] = None,
    ) -> str | None:
        """Authenticate network ingestion separately from chat authorization."""

        expected = selected.network_ingest_token or selected.integration_api_token
        if expected is None:
            client_host = request.client.host if request.client is not None else None
            if client_host not in {"127.0.0.1", "::1", "localhost", "testclient"}:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="unauthenticated network ingestion is loopback-only",
                )
            return None
        supplied = x_intentbridge_token
        if authorization and authorization.startswith("Bearer "):
            supplied = authorization.removeprefix("Bearer ").strip()
        if supplied is None or not secrets.compare_digest(supplied, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing or invalid network-ingest credential",
            )
        return "authenticated-network-source"

    async def process_event(payload: Any) -> IncidentResponse:
        try:
            return await container.network_agent.process(payload)
        except NormalizationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    def require_local_demo(request: Request) -> None:
        client_host = request.client.host if request.client is not None else None
        local_hosts = {"127.0.0.1", "::1", "localhost", "testclient"}
        if (
            selected.chat_integration_token is None
            and selected.integration_api_token is None
            and client_host not in local_hosts
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="unauthenticated demo endpoints are loopback-only",
            )

    @application.get("/", tags=["system"])
    async def root() -> dict[str, Any]:
        return {
            "service": "intentbridge-network-agent",
            "version": "0.1.0",
            "reasoner_mode": selected.reasoner_mode,
            "model": selected.openai_model if selected.reasoner_mode == "openai" else "mock",
            "chat_mode": selected.chat_mode,
            "firewall_mode": selected.firewall_mode,
            "docs": "/docs",
        }

    @application.get("/healthz", tags=["system"])
    async def health() -> dict[str, Any]:
        return {
            "status": "ok" if container.database.healthcheck() else "degraded",
            "reasoner_mode": selected.reasoner_mode,
            "chat_mode": selected.chat_mode,
            "firewall_mode": selected.firewall_mode,
            "firewall_enabled": selected.firewall_enabled,
            "reasoner_status": container.network_agent.last_reasoner_status,
            "expiry_status": "ok" if container.expiry.healthy else "degraded",
            "expiry_error_code": container.expiry.last_error_code,
        }

    @application.get("/readyz", tags=["system"])
    async def ready() -> dict[str, str | None]:
        if not container.database.healthcheck():
            raise HTTPException(status_code=503, detail="database unavailable")
        if container.network_agent.last_reasoner_status in {"failed", "overloaded"}:
            raise HTTPException(status_code=503, detail="reasoner is degraded")
        if not container.expiry.healthy:
            raise HTTPException(
                status_code=503,
                detail=container.expiry.last_error_code or "expiry worker is degraded",
            )
        topology_verifier = getattr(
            container.firewall, "verify_parent_chain_topology", None
        )
        if topology_verifier is not None:
            try:
                await topology_verifier()
            except Exception as exc:
                raise HTTPException(
                    status_code=503, detail="real firewall topology is unsafe"
                ) from exc
        return {
            "status": "ready",
            "reasoner_status": container.network_agent.last_reasoner_status,
            "expiry_status": "ok",
        }

    @application.post(
        "/events/drop",
        response_model=IncidentResponse,
        status_code=status.HTTP_200_OK,
        tags=["network input"],
    )
    async def receive_drop(
        payload: FirewallDropEvent,
        _source: str | None = Depends(network_principal),
    ) -> IncidentResponse:
        return await process_event(payload)

    @application.post(
        "/events/zeek",
        response_model=IncidentResponse,
        status_code=status.HTTP_200_OK,
        tags=["network input"],
    )
    async def receive_zeek(
        payload: ZeekEventIn,
        _source: str | None = Depends(network_principal),
    ) -> IncidentResponse:
        return await process_event(payload)

    @application.post(
        "/events/network",
        response_model=IncidentResponse,
        status_code=status.HTTP_200_OK,
        tags=["network input"],
    )
    async def receive_network(
        payload: Annotated[
            GenericNetworkEventIn | NetworkEventIn,
            Body(discriminator="schema_version"),
        ],
        _source: str | None = Depends(network_principal),
    ) -> IncidentResponse:
        return await process_event(payload)

    @application.post(
        "/events",
        response_model=IncidentResponse,
        status_code=status.HTTP_200_OK,
        tags=["network input"],
    )
    async def receive_any(
        payload: Annotated[ExternalNetworkEvent, Body(discriminator="schema_version")],
        _source: str | None = Depends(network_principal),
    ) -> IncidentResponse:
        return await process_event(payload)

    @application.get(
        "/context-requests", response_model=list[ContextRequest], tags=["chat integration"]
    )
    async def list_context_requests(
        request_status: str | None = Query(default=None, alias="status"),
        limit: int = Query(default=100, ge=1, le=500),
        _principal: ApproverIdentity | None = Depends(integration_principal),
    ) -> list[ContextRequest]:
        rows = container.database.list_context_requests(request_status, limit)
        return [ContextRequest.model_validate(row["payload_json"]) for row in rows]

    @application.get(
        "/context-requests/{request_id}",
        response_model=ContextRequest,
        tags=["chat integration"],
    )
    async def get_context_request(
        request_id: str,
        _principal: ApproverIdentity | None = Depends(integration_principal),
    ) -> ContextRequest:
        row = container.database.get_context_request(request_id)
        if row is None:
            raise HTTPException(status_code=404, detail="context request not found")
        return ContextRequest.model_validate(row["payload_json"])

    @application.post(
        "/context-responses",
        response_model=IncidentResponse,
        tags=["chat integration"],
    )
    async def receive_context_response(
        response: ChatContextResponse,
        principal: ApproverIdentity | None = Depends(integration_principal),
    ) -> IncidentResponse:
        try:
            return await container.network_agent.process_context_response(
                response, verified_provider=principal
            )
        except ContextConflict as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"reason_code": exc.reason_code, "message": str(exc)},
            ) from exc

    @application.get(
        "/context-responses/{response_id}",
        response_model=ChatContextResponse,
        tags=["chat integration"],
    )
    async def get_context_response(
        response_id: str,
        _principal: ApproverIdentity | None = Depends(integration_principal),
    ) -> ChatContextResponse:
        row = container.database.get_context_response(response_id)
        if row is None:
            raise HTTPException(status_code=404, detail="context response not found")
        return ChatContextResponse.model_validate(row["payload_json"])

    @application.post(
        "/decisions", response_model=EnforcementResult, tags=["chat integration"]
    )
    async def receive_decision(
        decision: ChatDecision,
        principal: ApproverIdentity | None = Depends(integration_principal),
    ) -> EnforcementResult:
        return await container.decisions.handle(decision, verified_approver=principal)

    @application.get(
        "/incidents", response_model=IncidentListResponse, tags=["observability"]
    )
    async def list_incidents(
        limit: int = Query(default=100, ge=1, le=500),
        _principal: ApproverIdentity | None = Depends(integration_principal),
    ) -> IncidentListResponse:
        rows = container.database.list_incidents(limit)
        incidents = [container.network_agent.incident_response(row["incident_id"]) for row in rows]
        return IncidentListResponse(incidents=incidents, total=len(incidents))

    @application.get(
        "/incidents/{incident_id}",
        response_model=IncidentResponse,
        tags=["observability"],
    )
    async def get_incident(
        incident_id: str,
        _principal: ApproverIdentity | None = Depends(integration_principal),
    ) -> IncidentResponse:
        try:
            return container.network_agent.incident_response(incident_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="incident not found") from exc

    @application.get(
        "/incidents/{incident_id}/timeline",
        response_model=IncidentTimelineResponse,
        tags=["observability"],
    )
    async def get_timeline(
        incident_id: str,
        _principal: ApproverIdentity | None = Depends(integration_principal),
    ) -> IncidentTimelineResponse:
        try:
            return container.network_agent.timeline(incident_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="incident not found") from exc

    @application.post("/demo/check-flow", tags=["demo"])
    async def check_flow(
        scope: FlowScope,
        request: Request,
        _principal: ApproverIdentity | None = Depends(integration_principal),
    ) -> dict[str, Any]:
        if not selected.demo_mode:
            raise HTTPException(status_code=404, detail="demo endpoints are disabled")
        require_local_demo(request)
        check = getattr(container.firewall, "check_flow", None)
        if check is None:
            raise HTTPException(
                status_code=409,
                detail="the configured firewall adapter cannot simulate connectivity",
            )
        return {"allowed": await check(scope), "scope": scope.model_dump(mode="json")}

    @application.post("/demo/expire", tags=["demo"])
    async def run_expiry(
        request: Request,
        _principal: ApproverIdentity | None = Depends(integration_principal),
    ) -> dict[str, int]:
        if not selected.demo_mode:
            raise HTTPException(status_code=404, detail="demo endpoints are disabled")
        require_local_demo(request)
        return {"rules_revoked": await container.expiry.expire_once()}

    return application


app = create_app()
