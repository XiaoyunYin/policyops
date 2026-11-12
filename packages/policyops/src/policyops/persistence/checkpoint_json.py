"""Closed JSON checkpoint protocol for the sequential investigation graph.

Only built-in JSON containers/scalars enter validation: no object hooks, DTO dumps,
exception text, pickle, msgpack or import-based reconstruction. Bounds are checked
iteratively before Pydantic or JSON encoding visits the payload recursively.
"""

import asyncio
from datetime import datetime
import json
from typing import Annotated, Any, Literal, cast

from langgraph.checkpoint.base import ChannelVersions, Checkpoint, CheckpointMetadata
from langgraph.checkpoint.serde.types import ERROR
from pydantic import Field, ValidationError

from policyops.orchestration.state import CheckpointStateVersionError as CheckpointStateVersionError
from policyops.orchestration.state import InvestigationState, state_from_json
from policyops.persistence.runs import Fenced
from policyops_contracts.base import WireModel


MAX_STATE_BYTES = 262144
MAX_CHECKPOINT_BYTES = 524288
MAX_METADATA_BYTES = 8192
NODES = frozenset({"investigate", "retrieve", "read", "propose", "finalize"})
CHANNELS = frozenset({"state", "__start__"} | {f"branch:to:{node}" for node in NODES})
# The runtime records its resume watermark under __interrupt__ even without
# application interrupt()/Command support. It is a versions_seen key only.
NODE_IDS = NODES | {"__start__", "__input__", "__interrupt__"}
TAG = "policyops-checkpoint-json-v1"


class CheckpointUnsafeTypeError(ValueError):
    """A payload is unsafe, malformed, too large, or outside the closed schema."""


class CheckpointCompatibilityError(ValueError):
    """An unsupported codec or framework checkpoint version (never start from empty)."""


def json_bytes(value: object, *, limit: int = MAX_CHECKPOINT_BYTES) -> bytes:
    """Validate exact built-ins, depth, aggregate work and UTF-8 size before encoding."""
    stack = [(value, 0)]
    count = size = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if depth > 24 or count > 32768:
            raise CheckpointUnsafeTypeError("checkpoint structural bound exceeded")
        if type(item) is dict:
            if len(item) > 256:
                raise CheckpointUnsafeTypeError("checkpoint mapping bound exceeded")
            for key, child in item.items():
                if type(key) is not str:
                    raise CheckpointUnsafeTypeError("checkpoint keys must be strings")
                stack.extend(((key, depth + 1), (child, depth + 1)))
        elif type(item) is list:
            if len(item) > 256:
                raise CheckpointUnsafeTypeError("checkpoint sequence bound exceeded")
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            if len(item) > limit or "\x00" in item:
                raise CheckpointUnsafeTypeError("invalid or oversized checkpoint text")
            try:
                size += len(item.encode("utf-8"))
            except UnicodeEncodeError:
                raise CheckpointUnsafeTypeError("invalid checkpoint text") from None
        elif type(item) is int:
            if not -(2**63) <= item < 2**63:
                raise CheckpointUnsafeTypeError("checkpoint integer bound exceeded")
        elif item is not None and type(item) is not bool:
            raise CheckpointUnsafeTypeError("non-JSON checkpoint type")
        if size > limit:
            raise CheckpointUnsafeTypeError("checkpoint byte bound exceeded")
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True).encode()
    if len(encoded) > limit:
        raise CheckpointUnsafeTypeError("checkpoint byte bound exceeded")
    return encoded


def state(value: object) -> InvestigationState:
    json_bytes(value, limit=MAX_STATE_BYTES)
    try:
        return state_from_json(value)
    except ValidationError:
        raise CheckpointUnsafeTypeError("invalid investigation state") from None


def channel_value(channel: str, value: object, *, pending: bool = False) -> Any:
    if type(channel) is not str or not 1 <= len(channel) <= 128:
        raise CheckpointUnsafeTypeError("invalid checkpoint channel name")
    if pending and channel == ERROR:
        # Exact known exceptions only; never inspect args/text/locals or reconstruct classes.
        if type(value) is asyncio.CancelledError:
            return {"diagnostic": "cancelled"}
        if type(value) is Fenced:
            return {"diagnostic": "fenced"}
        json_bytes(value)
        if value in ({"diagnostic": "cancelled"}, {"diagnostic": "fenced"}):
            return value
        raise CheckpointUnsafeTypeError("unsupported checkpoint error")
    json_bytes(value)
    if channel == "state":
        state(value)
    elif channel == "__start__":
        if type(value) is not dict or set(value) != {"state"}:
            raise CheckpointUnsafeTypeError("invalid checkpoint input")
        state(value["state"])
    elif channel in CHANNELS:
        if value is not None:
            raise CheckpointUnsafeTypeError("invalid branch control value")
    else:
        raise CheckpointUnsafeTypeError("unsupported checkpoint channel")
    return value


Identifier = Annotated[str, Field(min_length=1, max_length=128)]
Version = Annotated[int, Field(ge=0, le=2**63 - 1)]


class Envelope(WireModel):
    codec_version: Literal[1]
    framework_version: Literal[4]
    id: Identifier
    ts: Annotated[str, Field(max_length=64)]
    channel_values: dict[str, Any]
    channel_versions: dict[str, Version]
    versions_seen: dict[str, dict[str, Version]]
    updated_channels: list[str] | None = None


class Metadata(WireModel):
    source: Literal["input", "loop", "update"]
    step: Annotated[int, Field(ge=-1, le=66)]
    parents: dict[str, Identifier]


def versions(value: ChannelVersions) -> None:
    json_bytes(value)
    if type(value) is not dict:
        raise CheckpointUnsafeTypeError("invalid checkpoint channel versions")
    if any(key not in CHANNELS or type(v) is not int or not 0 <= v < 2**63 for key, v in value.items()):
        raise CheckpointUnsafeTypeError("invalid checkpoint channel versions")


def envelope(value: object) -> Envelope:
    raw = json_bytes(value)
    if type(value) is not dict:
        raise CheckpointUnsafeTypeError("invalid checkpoint envelope")
    if type(value.get("codec_version")) is not int or value["codec_version"] != 1:
        raise CheckpointCompatibilityError("unsupported checkpoint codec version")
    if type(value.get("framework_version")) is not int or value["framework_version"] != 4:
        raise CheckpointCompatibilityError("unsupported framework checkpoint version")
    try:
        result = Envelope.model_validate_json(raw)
        timestamp = datetime.fromisoformat(result.ts)
        offset = timestamp.utcoffset()
        if offset is None or offset.total_seconds() != 0:
            raise ValueError
        versions(cast(ChannelVersions, result.channel_versions))
        for node, seen in result.versions_seen.items():
            if node not in NODE_IDS:
                raise ValueError
            versions(cast(ChannelVersions, seen))
        if result.updated_channels is not None and any(c not in CHANNELS for c in result.updated_channels):
            raise ValueError
        for channel, val in result.channel_values.items():
            channel_value(channel, val)
    except (ValidationError, ValueError) as exc:
        if isinstance(exc, CheckpointStateVersionError | CheckpointCompatibilityError | CheckpointUnsafeTypeError):
            raise
        raise CheckpointUnsafeTypeError("invalid checkpoint envelope") from None
    return result


def encode_checkpoint(checkpoint: Checkpoint) -> dict[str, Any]:
    json_bytes(checkpoint)
    if set(checkpoint) - {"v", "id", "ts", "channel_values", "channel_versions", "versions_seen", "updated_channels"}:
        raise CheckpointUnsafeTypeError("unsupported framework checkpoint fields")
    value = {key: val for key, val in checkpoint.items() if key != "v"}
    value.update(codec_version=1, framework_version=checkpoint.get("v"))
    return envelope(value).model_dump(mode="json")


def decode_checkpoint(value: object) -> Checkpoint:
    data = envelope(value).model_dump(mode="json")
    data["v"] = data.pop("framework_version")
    del data["codec_version"]
    return cast(Checkpoint, data)


def metadata(value: object) -> CheckpointMetadata:
    raw = json_bytes(value, limit=MAX_METADATA_BYTES)
    try:
        checked = Metadata.model_validate_json(raw)
        if checked.parents:  # subgraphs are deliberately unsupported
            raise ValueError
    except (ValidationError, ValueError):
        raise CheckpointUnsafeTypeError("invalid checkpoint metadata") from None
    return cast(CheckpointMetadata, checked.model_dump(mode="json"))


class CheckpointJsonSerializer:
    """Fixed-tag JSON only. The saver additionally validates context-specific schemas."""

    def dumps_typed(self, obj: Any) -> tuple[str, bytes]:
        return TAG, json_bytes(obj)

    def loads_typed(self, data: tuple[str, bytes]) -> Any:
        if type(data) is not tuple or len(data) != 2 or type(data[0]) is not str:
            raise CheckpointUnsafeTypeError("invalid checkpoint serializer input")
        tag, raw = data
        if tag != TAG:
            raise CheckpointCompatibilityError("unsupported checkpoint serializer tag")
        if type(raw) is not bytes or len(raw) > MAX_CHECKPOINT_BYTES:
            raise CheckpointUnsafeTypeError("invalid checkpoint bytes")
        try:
            value = json.loads(raw)
        except (ValueError, RecursionError, UnicodeError):
            raise CheckpointUnsafeTypeError("invalid checkpoint JSON") from None
        json_bytes(value)
        return value
