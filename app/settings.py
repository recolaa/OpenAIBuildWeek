from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import dotenv_values


class SettingsError(RuntimeError):
    """Raised when project-local configuration is missing or unsafe."""


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise SettingsError(f"Expected a boolean value, received {value!r}")


def _as_int(value: str | None, default: int, *, minimum: int, maximum: int) -> int:
    if value is None or not value.strip():
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise SettingsError(f"Expected an integer value, received {value!r}") from exc
    if not minimum <= parsed <= maximum:
        raise SettingsError(f"Integer must be between {minimum} and {maximum}")
    return parsed


def _as_float(value: str | None, default: float, *, minimum: float, maximum: float) -> float:
    if value is None or not value.strip():
        return default
    try:
        parsed = float(value)
    except ValueError as exc:
        raise SettingsError(f"Expected a numeric value, received {value!r}") from exc
    if not minimum <= parsed <= maximum:
        raise SettingsError(f"Number must be between {minimum} and {maximum}")
    return parsed


@dataclass(slots=True)
class Settings:
    project_root: Path
    env_path: Path
    openai_api_key: str | None = field(default=None, repr=False)
    reasoner_mode: str = "mock"
    openai_model: str = "gpt-4.1-mini"
    allow_non_budget_model: bool = False
    llm_max_output_tokens: int = 800
    max_concurrent_analyses: int = 2
    analysis_queue_timeout_seconds: float = 2.0
    chat_mode: str = "outbox"
    chat_agent_url: str | None = None
    chat_agent_token: str | None = field(default=None, repr=False)
    integration_api_token: str | None = field(default=None, repr=False)
    network_ingest_token: str | None = field(default=None, repr=False)
    chat_integration_token: str | None = field(default=None, repr=False)
    trusted_chat_agent_id: str = "chat-agent"
    trusted_chat_agent_role: str = "network-manager"
    firewall_mode: str = "in_memory"
    firewall_enabled: bool = False
    allow_host_firewall: bool = False
    demo_mode: bool = True
    database_path: Path | None = None
    max_ttl_seconds: int = 600
    default_ttl_seconds: int = 60
    context_request_timeout_seconds: int = 120
    max_context_rounds: int = 3
    decision_clock_skew_seconds: int = 30
    dedup_window_seconds: int = 30
    expiry_poll_seconds: float = 1.0
    allowed_approver_roles: tuple[str, ...] = ("network-manager", "security-operator")

    @classmethod
    def load(cls, env_path: Path | None = None) -> Settings:
        project_root = Path(__file__).resolve().parents[1]
        selected_env = (env_path or project_root / ".env").resolve()
        values: Mapping[str, str | None] = (
            dotenv_values(selected_env, interpolate=False) if selected_env.exists() else {}
        )

        # Deliberately do not consult os.environ. This project is required to use only
        # OPENAI_API_KEY from its own .env file.
        api_key = (values.get("OPENAI_API_KEY") or "").strip() or None
        if api_key and "${" in api_key:
            raise SettingsError(
                "OPENAI_API_KEY interpolation is disabled; place the project key directly in .env"
            )
        configured_mode = (values.get("REASONER_MODE") or "").strip().lower()
        reasoner_mode = configured_mode or ("openai" if api_key else "mock")
        if reasoner_mode not in {"mock", "openai"}:
            raise SettingsError("REASONER_MODE must be 'mock' or 'openai'")
        if reasoner_mode == "openai" and not api_key:
            raise SettingsError(
                f"REASONER_MODE=openai requires OPENAI_API_KEY in the project file {selected_env}"
            )

        chat_mode = (values.get("CHAT_MODE") or "outbox").strip().lower()
        if chat_mode not in {"outbox", "http"}:
            raise SettingsError("CHAT_MODE must be 'outbox' or 'http'")
        chat_url = (values.get("CHAT_AGENT_URL") or "").strip() or None
        if chat_mode == "http" and not chat_url:
            raise SettingsError("CHAT_MODE=http requires CHAT_AGENT_URL in the project .env")

        firewall_mode = (values.get("FIREWALL_MODE") or "in_memory").strip().lower()
        if firewall_mode not in {"in_memory", "dry_run_iptables", "iptables"}:
            raise SettingsError(
                "FIREWALL_MODE must be 'in_memory', 'dry_run_iptables', or 'iptables'"
            )

        database_value = (values.get("DATABASE_PATH") or "data/network_agent.db").strip()
        database_path = Path(database_value)
        if not database_path.is_absolute():
            database_path = project_root / database_path

        roles_raw = values.get("ALLOWED_APPROVER_ROLES") or "network-manager,security-operator"
        roles = tuple(role.strip() for role in roles_raw.split(",") if role.strip())
        if not roles:
            raise SettingsError("At least one approver role must be configured")
        integration_api_token = (
            values.get("INTEGRATION_API_TOKEN") or ""
        ).strip() or None
        if integration_api_token is not None and len(integration_api_token) < 16:
            raise SettingsError("INTEGRATION_API_TOKEN must contain at least 16 characters")
        network_ingest_token = (
            values.get("NETWORK_INGEST_TOKEN") or ""
        ).strip() or None
        chat_integration_token = (
            values.get("CHAT_INTEGRATION_TOKEN") or ""
        ).strip() or None
        for token_name, token_value in (
            ("NETWORK_INGEST_TOKEN", network_ingest_token),
            ("CHAT_INTEGRATION_TOKEN", chat_integration_token),
        ):
            if token_value is not None and len(token_value) < 16:
                raise SettingsError(f"{token_name} must contain at least 16 characters")
        if (
            network_ingest_token
            and chat_integration_token
            and network_ingest_token == chat_integration_token
        ):
            raise SettingsError("Network and chat integration tokens must be distinct")
        trusted_chat_agent_id = (
            values.get("TRUSTED_CHAT_AGENT_ID") or "chat-agent"
        ).strip()
        trusted_chat_agent_role = (
            values.get("TRUSTED_CHAT_AGENT_ROLE") or "network-manager"
        ).strip()
        if not trusted_chat_agent_id or not trusted_chat_agent_role:
            raise SettingsError("Trusted chat-agent identity fields must not be empty")
        if integration_api_token and trusted_chat_agent_role not in roles:
            raise SettingsError(
                "TRUSTED_CHAT_AGENT_ROLE must be present in ALLOWED_APPROVER_ROLES"
            )
        openai_model = (values.get("OPENAI_MODEL") or "gpt-4.1-mini").strip()
        allow_non_budget_model = _as_bool(
            values.get("ALLOW_NON_BUDGET_MODEL"), False
        )
        budget_model_prefixes = ("gpt-4.1-mini", "gpt-4.1-nano")
        if (
            reasoner_mode == "openai"
            and not allow_non_budget_model
            and not openai_model.startswith(budget_model_prefixes)
        ):
            raise SettingsError(
                "OPENAI_MODEL must be a GPT-4.1 mini/nano model unless "
                "ALLOW_NON_BUDGET_MODEL=true is explicitly set"
            )

        return cls(
            project_root=project_root,
            env_path=selected_env,
            openai_api_key=api_key,
            reasoner_mode=reasoner_mode,
            openai_model=openai_model,
            allow_non_budget_model=allow_non_budget_model,
            llm_max_output_tokens=_as_int(
                values.get("LLM_MAX_OUTPUT_TOKENS"), 800, minimum=128, maximum=4096
            ),
            max_concurrent_analyses=_as_int(
                values.get("MAX_CONCURRENT_ANALYSES"), 2, minimum=1, maximum=32
            ),
            analysis_queue_timeout_seconds=_as_float(
                values.get("ANALYSIS_QUEUE_TIMEOUT_SECONDS"),
                2.0,
                minimum=0.1,
                maximum=60.0,
            ),
            chat_mode=chat_mode,
            chat_agent_url=chat_url,
            chat_agent_token=(values.get("CHAT_AGENT_TOKEN") or "").strip() or None,
            integration_api_token=integration_api_token,
            network_ingest_token=network_ingest_token,
            chat_integration_token=chat_integration_token,
            trusted_chat_agent_id=trusted_chat_agent_id,
            trusted_chat_agent_role=trusted_chat_agent_role,
            firewall_mode=firewall_mode,
            firewall_enabled=_as_bool(values.get("FIREWALL_ENABLED"), False),
            allow_host_firewall=_as_bool(values.get("ALLOW_HOST_FIREWALL"), False),
            demo_mode=_as_bool(values.get("DEMO_MODE"), True),
            database_path=database_path.resolve(),
            max_ttl_seconds=_as_int(
                values.get("MAX_TTL_SECONDS"), 600, minimum=1, maximum=3600
            ),
            default_ttl_seconds=_as_int(
                values.get("DEFAULT_TTL_SECONDS"), 60, minimum=1, maximum=3600
            ),
            context_request_timeout_seconds=_as_int(
                values.get("CONTEXT_REQUEST_TIMEOUT_SECONDS"),
                120,
                minimum=10,
                maximum=3600,
            ),
            max_context_rounds=_as_int(
                values.get("MAX_CONTEXT_ROUNDS"), 3, minimum=1, maximum=10
            ),
            decision_clock_skew_seconds=_as_int(
                values.get("DECISION_CLOCK_SKEW_SECONDS"),
                30,
                minimum=0,
                maximum=300,
            ),
            dedup_window_seconds=_as_int(
                values.get("DEDUP_WINDOW_SECONDS"), 30, minimum=1, maximum=600
            ),
            expiry_poll_seconds=_as_float(
                values.get("EXPIRY_POLL_SECONDS"), 1.0, minimum=0.1, maximum=60.0
            ),
            allowed_approver_roles=roles,
        )
