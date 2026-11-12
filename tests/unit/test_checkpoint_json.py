import asyncio
import json
from typing import Any

from langgraph.checkpoint.serde.types import ERROR
import pytest

from policyops.persistence import checkpoint_json as codec
from policyops.persistence.checkpoints import pending_writes
from policyops.persistence.runs import Fenced
from policyops_testing.checkpoint_cases import META, checkpoint
from tests.unit.test_investigation_state import value


class Attack:
    def __reduce__(self) -> Any:
        raise AssertionError("must never be invoked")

    def __str__(self) -> str:
        raise AssertionError("must never be invoked")

    def model_dump(self, **kwargs: Any) -> Any:
        raise AssertionError("must never be invoked")


def test_checkpoint_and_bootstrap_roundtrip() -> None:
    original = checkpoint(value())
    assert codec.decode_checkpoint(codec.encode_checkpoint(original)) == original
    original["channel_values"] = {"__start__": {"state": value()}, "branch:to:investigate": None}
    assert codec.decode_checkpoint(codec.encode_checkpoint(original)) == original
    original["channel_values"] = {}
    assert codec.decode_checkpoint(codec.encode_checkpoint(original)) == original
    assert codec.metadata(META) == META


@pytest.mark.parametrize("bad", [Attack(), b"bytes", 1.0, float("nan"), float("inf"), {1: "bad"}, (1,),
                                {"__start__": Attack()}, "\ud800", "nul\x00", 2**100, [None] * 257])
def test_attack_objects_and_non_json_types_fail_before_hooks(bad: Any) -> None:
    with pytest.raises(codec.CheckpointUnsafeTypeError):
        codec.CheckpointJsonSerializer().dumps_typed(bad)


def test_cycles_depth_work_and_byte_bounds() -> None:
    recursive: list[Any] = []
    recursive.append(recursive)
    for bad in (recursive, "x" * (codec.MAX_CHECKPOINT_BYTES + 1), [[None] * 256] * 256):
        with pytest.raises(codec.CheckpointUnsafeTypeError):
            codec.json_bytes(bad)
    with pytest.raises(codec.CheckpointUnsafeTypeError):
        codec.json_bytes({"x": "a" * 20}, limit=20)


@pytest.mark.parametrize("field, version", [("codec_version", 0), ("codec_version", True),
                                          ("framework_version", 3), ("framework_version", None)])
def test_versions_fail_closed(field: str, version: Any) -> None:
    data = codec.encode_checkpoint(checkpoint(value()))
    data[field] = version
    with pytest.raises(codec.CheckpointCompatibilityError):
        codec.decode_checkpoint(data)


@pytest.mark.parametrize("change", [{"channel_values": {"arbitrary": None}}, {"channel_versions": {"state": "1"}},
                                   {"versions_seen": {"arbitrary": {}}}, {"updated_channels": ["arbitrary"]},
                                   {"channel_values": {"branch:to:read": "Send"}}, {"pending_sends": []},
                                   {"ts": "2026-01-01T01:00:00+01:00"}])
def test_envelope_is_closed(change: dict[str, Any]) -> None:
    data = codec.encode_checkpoint(checkpoint(value())) | change
    with pytest.raises(codec.CheckpointUnsafeTypeError):
        codec.decode_checkpoint(data)


@pytest.mark.parametrize("bad", [META | {"trace": "secret"}, META | {"step": True}, META | {"parents": {"x": "1"}},
                                META | {"source": "fork"}, META | {"step": 67}])
def test_metadata_is_closed(bad: Any) -> None:
    with pytest.raises(codec.CheckpointUnsafeTypeError):
        codec.metadata(bad)


def test_error_projection_is_fixed_and_does_not_recreate_exceptions() -> None:
    assert codec.channel_value(ERROR, asyncio.CancelledError("secret"), pending=True) == {"diagnostic": "cancelled"}
    assert codec.channel_value(ERROR, Fenced("secret"), pending=True) == {"diagnostic": "fenced"}
    with pytest.raises(codec.CheckpointUnsafeTypeError):
        codec.channel_value(ERROR, RuntimeError("secret"), pending=True)
    with pytest.raises(codec.CheckpointUnsafeTypeError):
        codec.channel_value("state", asyncio.CancelledError("secret"), pending=True)
    with pytest.raises(codec.CheckpointUnsafeTypeError):
        codec.channel_value(Attack(), None, pending=True)  # type: ignore[arg-type]


def test_fixed_serializer_tag_and_bounds() -> None:
    serde = codec.CheckpointJsonSerializer()
    obj = {"x": "世界"}
    assert serde.loads_typed(serde.dumps_typed(obj)) == obj
    for tag in ("pickle", "msgpack", "json"):
        with pytest.raises(codec.CheckpointCompatibilityError):
            serde.loads_typed((tag, b"{}"))
    with pytest.raises(codec.CheckpointUnsafeTypeError):
        serde.loads_typed((Attack(), b"{}"))  # type: ignore[arg-type]
    for raw in (b"{", b"[" * 10000, b"null" * codec.MAX_CHECKPOINT_BYTES, json.dumps(float("nan")).encode()):
        with pytest.raises(codec.CheckpointUnsafeTypeError):
            serde.loads_typed((codec.TAG, raw))


def test_pending_writes_use_task_path_then_id_then_index_and_validate_slots() -> None:
    rows = [{"task_path": path, "task_id": task, "idx": idx, "channel": channel, "value": val}
            for path, task, idx, channel, val in (
                ("z", "a", 0, "branch:to:read", None),
                ("a", "z", 0, "state", value()),
                ("a", "a", 1, "branch:to:read", None),
                ("a", "a", -1, ERROR, {"diagnostic": "cancelled"}))]
    result = pending_writes(rows)
    assert [(task, channel) for task, channel, _ in result] == [
        ("a", ERROR), ("a", "branch:to:read"), ("z", "state"), ("a", "branch:to:read")]
    with pytest.raises(codec.CheckpointUnsafeTypeError):
        pending_writes([rows[-1] | {"idx": 0}])


@pytest.mark.parametrize("fault", ["none", "checkpoint", "node"])
def test_installed_framework_emits_the_closed_protocol(fault: str) -> None:
    """Offline protocol check only; the real-PG tests exercise the production saver."""
    from collections.abc import Sequence

    from langchain_core.runnables import RunnableConfig, RunnableLambda
    from langgraph.checkpoint.base import (
        BaseCheckpointSaver,
        ChannelVersions,
        Checkpoint,
        CheckpointMetadata,
        CheckpointTuple,
    )
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.graph import END, START, StateGraph

    from tests.integration.test_checkpoints import GraphEnvelope, GraphInput

    calls: list[int] = []
    entered = asyncio.Event()

    class Recording(BaseCheckpointSaver[int]):
        def __init__(self) -> None:
            super().__init__(serde=codec.CheckpointJsonSerializer())
            self.memory = InMemorySaver(serde=self.serde)
            self.interrupted = fault == "checkpoint"

        async def aget_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
            return await self.memory.aget_tuple(config)

        async def aput(self, config: RunnableConfig, checkpoint: Checkpoint, metadata: CheckpointMetadata,
                       new_versions: ChannelVersions) -> RunnableConfig:
            codec.encode_checkpoint(checkpoint)
            codec.metadata(metadata)
            codec.versions(new_versions)
            if self.interrupted and metadata["step"] == 1:
                self.interrupted = False
                raise asyncio.CancelledError("synthetic lost checkpoint acknowledgement")
            return await self.memory.aput(config, checkpoint, metadata, new_versions)

        async def aput_writes(self, config: RunnableConfig, writes: Sequence[tuple[str, Any]], task_id: str,
                              task_path: str = "") -> None:
            checked = [(channel, codec.channel_value(channel, value, pending=True)) for channel, value in writes]
            await self.memory.aput_writes(config, checked, task_id, task_path)

    async def advance(data: GraphEnvelope) -> dict[str, Any]:
        calls.append(data.state.step_count)
        if fault == "node" and calls == [0, 1]:
            entered.set()
            await asyncio.Event().wait()
        updated = data.state.model_copy(update={"step_count": data.state.step_count + 1})
        return {"state": updated.model_dump(mode="json")}

    graph = StateGraph(GraphEnvelope, input_schema=GraphInput)
    graph.add_node("investigate", RunnableLambda(advance))
    graph.add_node("finalize", RunnableLambda(advance))
    graph.add_edge(START, "investigate")
    graph.add_edge("investigate", "finalize")
    graph.add_edge("finalize", END)

    async def run() -> None:
        saver = Recording()
        compiled = graph.compile(checkpointer=saver)
        config: RunnableConfig = {"configurable": {"thread_id": "test"}}
        if fault != "none":
            if fault == "node":
                task = asyncio.create_task(compiled.ainvoke({"state": value()}, config, durability="sync"))
                try:
                    await asyncio.wait_for(entered.wait(), 5)
                finally:
                    task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await task
            else:
                with pytest.raises(asyncio.CancelledError):
                    await compiled.ainvoke({"state": value()}, config, durability="sync")
            saved = await saver.aget_tuple(config)
            assert saved is not None
            if fault == "checkpoint":
                assert saved.pending_writes
            else:
                assert saved.checkpoint["channel_values"]["state"]["step_count"] == 1
            first = await graph.compile(checkpointer=saver).ainvoke(None, config, durability="sync")
        else:
            first = await compiled.ainvoke({"state": value()}, config, durability="sync")
        assert first["state"]["step_count"] == 2
        assert calls == ([0, 1, 1] if fault == "node" else [0, 1])
        assert await graph.compile(checkpointer=saver).ainvoke(None, config, durability="sync") == first

    asyncio.run(run())
