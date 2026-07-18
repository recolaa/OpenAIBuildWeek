from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas import (
    AdvisoryTrust,
    ChatContextResponse,
    ContextRequest,
    FlowScope,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_chat_context_response_is_strict_and_explicitly_advisory() -> None:
    payload = _fixture("chat_context_response_vpn_https.json")
    response = ChatContextResponse.model_validate(payload)

    assert response.trust is AdvisoryTrust.UNTRUSTED_ADVISORY
    assert response.context_round == 1
    with pytest.raises(ValidationError):
        ChatContextResponse.model_validate({**payload, "command": "allow all"})
    with pytest.raises(ValidationError):
        ChatContextResponse.model_validate({**payload, "trust": "VALIDATED_AUTHORIZATION"})


def test_context_request_round_chain_is_strict_but_round_one_is_compatible() -> None:
    first_payload = _fixture("context_request_vpn_https.json")
    first_payload.pop("context_round")
    first_payload.pop("previous_request_id")
    first = ContextRequest.model_validate(first_payload)
    assert first.context_round == 1
    assert first.previous_request_id is None

    second_payload = _fixture("context_request_vpn_https_round_2.json")
    second = ContextRequest.model_validate(second_payload)
    assert second.context_round == 2
    assert second.previous_request_id == "ctx-drop-1042"

    with pytest.raises(ValidationError):
        ContextRequest.model_validate({**second_payload, "previous_request_id": None})
    with pytest.raises(ValidationError):
        ContextRequest.model_validate({**first_payload, "previous_request_id": "ctx-unexpected"})


def test_flow_scope_defaults_to_forward_and_accepts_bounded_interfaces() -> None:
    legacy = FlowScope.model_validate(
        {
            "source_ip": "10.0.2.1",
            "destination_ip": "10.0.3.10",
            "destination_port": 443,
            "protocol": "tcp",
        }
    )
    assert legacy.direction == "forward"
    assert legacy.interface_in is None

    bound = legacy.model_copy(update={"interface_in": "eth0", "interface_out": "eth1"})
    assert bound.interface_out == "eth1"
    with pytest.raises(ValidationError):
        FlowScope.model_validate(
            {
                **legacy.model_dump(mode="json"),
                "direction": "input",
            }
        )
    with pytest.raises(ValidationError):
        FlowScope.model_validate(
            {
                **legacy.model_dump(mode="json"),
                "interface_in": "-j ACCEPT",
            }
        )
    with pytest.raises(ValidationError):
        FlowScope.model_validate(
            {
                **legacy.model_dump(mode="json"),
                "interface_in": "eth0",
            }
        )
