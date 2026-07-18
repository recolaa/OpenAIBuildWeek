from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app.database import DatabaseError
from app.firewall import ValidatedFlowGrant
from app.main import build_container
from app.schemas import FlowScope, IncidentState, RuleAction
from app.settings import Settings
from app.time_utils import utc_now
from tests.helpers import decision_for, drop_payload


def test_post_install_bookkeeping_failure_revokes_and_untracks_rule(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    incident = client.post(
        "/events/drop", json=drop_payload("drop-bookkeeping-failure")
    ).json()
    decision = decision_for(incident, decision_id="decision-bookkeeping-failure")
    container = client.app.state.container
    original_transition = container.database.transition_incident

    def fail_enforced_transition(
        incident_id: str, allowed_states, new_state: str, **fields
    ):  # type: ignore[no-untyped-def]
        if new_state == IncidentState.ENFORCED.value:
            raise DatabaseError("simulated post-install persistence failure")
        return original_transition(incident_id, allowed_states, new_state, **fields)

    monkeypatch.setattr(
        container.database, "transition_incident", fail_enforced_transition
    )

    result = client.post("/decisions", json=decision).json()

    assert result["status"] == "FAILED"
    scope = incident["context_request"]["permitted_grant_scope"]
    assert client.post("/demo/check-flow", json=scope).json()["allowed"] is False
    assert container.database.list_desired_rules() == []
    assert container.database.list_rules_requiring_cleanup() == []
    assert (
        client.get(f"/incidents/{incident['incident_id']}").json()["state"]
        == "ENFORCEMENT_FAILED"
    )


@pytest.mark.asyncio
async def test_startup_reconciliation_revokes_adapter_orphan(
    app_settings: Settings,
) -> None:
    container = build_container(app_settings)
    container.database.initialize()
    scope = FlowScope(
        source_ip="10.0.2.1",
        destination_ip="10.0.3.10",
        destination_port=443,
        protocol="tcp",
        direction="forward",
        interface_in="eth0",
        interface_out="eth1",
    )
    await container.firewall.install_exact_grant(
        ValidatedFlowGrant(
            scope=scope,
            action=RuleAction.ALLOW,
            expires_at=utc_now() + timedelta(minutes=1),
        )
    )

    await container.expiry.restore_active_rules()

    assert await container.firewall.list_managed_grants() == []
    assert container.expiry.healthy is True

