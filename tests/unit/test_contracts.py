"""Shared wire-model base semantics."""

from pydantic import ValidationError
import pytest

from policyops_contracts import CONTRACTS_SCHEMA_VERSION, WireModel


class Probe(WireModel):
    count: int
    label: str


def test_valid_message_round_trips() -> None:
    message = Probe.model_validate_json('{"count": 2, "label": "a"}')
    assert Probe.model_validate_json(message.model_dump_json()) == message
    assert CONTRACTS_SCHEMA_VERSION == "0.2.0"


@pytest.mark.parametrize(
    "payload",
    ['{"count": "2", "label": "a"}', '{"count": 2, "label": "a", "role": "admin"}', '{"count": 2}'],
)
def test_coercion_unknown_fields_and_missing_fields_are_rejected(payload: str) -> None:
    with pytest.raises(ValidationError):
        Probe.model_validate_json(payload)


def test_messages_are_immutable() -> None:
    message = Probe(count=1, label="a")
    with pytest.raises(ValidationError):
        message.count = 3  # type: ignore[misc]
