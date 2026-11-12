from typing import Any
from uuid import uuid4

from pydantic import ValidationError
import pytest

from policyops.orchestration.state import CheckpointStateVersionError, InvestigationState, state_from_json


def value() -> dict[str, Any]:
    return {"state_version": 1, "workspace_id": str(uuid4()), "case_id": str(uuid4()), "run_id": str(uuid4()),
            "graph_sha256": "1" * 64, "prompt_sha256": "2" * 64, "config_sha256": "3" * 64}


def test_state_roundtrip() -> None:
    state = state_from_json(value())
    assert state_from_json(state.model_dump(mode="json")) == state
    assert state.model_config["frozen"] and state.model_config["extra"] == "forbid"


@pytest.mark.parametrize("version", [None, False, True, "1", 0, 2, -1])
def test_state_version_has_no_implicit_upgrader(version: Any) -> None:
    data = value()
    if version is None:
        del data["state_version"]
    else:
        data["state_version"] = version
    with pytest.raises(CheckpointStateVersionError):
        state_from_json(data)


@pytest.mark.parametrize("change", [{"step_count": 65}, {"model_calls": -1}, {"max_steps": 0},
                                   {"extra": "no"}, {"terminal": {"kind": "success"}},
                                   {"input_message_ids": [str(uuid4())] * 257}])
def test_state_bounds(change: dict[str, Any]) -> None:
    from policyops.persistence.checkpoint_json import CheckpointUnsafeTypeError

    with pytest.raises((ValidationError, CheckpointUnsafeTypeError)):
        state_from_json(value() | change)


def test_constructed_dto_is_not_a_serialization_escape() -> None:
    from policyops.persistence.checkpoint_json import CheckpointUnsafeTypeError, state

    with pytest.raises(CheckpointUnsafeTypeError):
        state(InvestigationState.model_construct(**value(), step_count=10000))
