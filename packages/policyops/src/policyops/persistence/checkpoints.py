"""Async LangGraph saver, bound to a trusted run and T09 worker claim.

SQL uses the existing short synchronous workspace transactions. It can block the
event loop; this interface makes no hard cancellation/deadline guarantee for SQL.
No runtime DDL, unscoped listing, forks, subgraphs, deletion or arbitrary serde.
"""

from collections.abc import AsyncIterator, Mapping, Sequence
from typing import Any
from uuid import UUID, uuid5

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import (
    WRITES_IDX_MAP,
    BaseCheckpointSaver,
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    CheckpointTuple,
    writes_sort_key,
)
from langgraph.checkpoint.serde.types import ERROR
from sqlalchemy import Connection, Engine, text

from policyops.orchestration.state import STATE_VERSION
from policyops.persistence import checkpoint_json as codec
from policyops.persistence import runs
from policyops.persistence.database import (
    IdempotencyConflict,
    NotFound,
    verify_runtime_role,
    workspace_transaction,
)
from policyops.persistence.roles import APP_RUNTIME
from policyops.runtime.clock import LeaseClock
from policyops_contracts.scalars import RunScope


THREAD_NAMESPACE = UUID("bc28bdbc-c80d-55c1-b377-a19d8398ce69")


def thread_id_for(workspace_id: UUID, run_id: UUID) -> UUID:
    return uuid5(THREAD_NAMESPACE, f"{workspace_id}:{run_id}")


def pending_writes(rows: Sequence[Mapping[str, Any]]) -> list[tuple[str, str, Any]]:
    """Validate and restore the framework's task-path/id/index order, not SQL row order."""
    if len(rows) > 256:
        raise codec.CheckpointUnsafeTypeError("pending write count exceeded")
    codec.json_bytes([row["value"] for row in rows])
    result = []
    for row in sorted(rows, key=lambda w: writes_sort_key(w["task_path"], w["task_id"], w["idx"])):
        if row["idx"] != WRITES_IDX_MAP.get(row["channel"], row["idx"]) or (
                row["idx"] < 0 and row["channel"] != ERROR):
            raise codec.CheckpointUnsafeTypeError("invalid pending write slot")
        result.append((row["task_id"], row["channel"],
                       codec.channel_value(row["channel"], row["value"], pending=True)))
    return result


class InvestigationSaver(BaseCheckpointSaver[int]):
    def __init__(self, *, engine: Engine, scope: RunScope, token: runs.ClaimToken,
                 graph_sha256: str, prompt_sha256: str, config_sha256: str, clock: LeaseClock) -> None:
        if (token.workspace_id, token.run_id) != (scope.workspace_id, scope.run_id):
            raise ValueError("checkpoint claim does not match scope")
        verify_runtime_role(engine, APP_RUNTIME)
        super().__init__(serde=codec.CheckpointJsonSerializer())
        self.engine, self.scope, self.token, self.clock = engine, scope, token, clock
        self.thread_id = thread_id_for(scope.workspace_id, scope.run_id)
        self.digests = (graph_sha256, prompt_sha256, config_sha256)

    def config(self, checkpoint_id: str | None = None) -> RunnableConfig:
        selected: dict[str, Any] = {"thread_id": str(self.thread_id), "checkpoint_ns": ""}
        if checkpoint_id is not None:
            selected["checkpoint_id"] = checkpoint_id
        return {"configurable": selected}

    def _config_id(self, config: RunnableConfig | None) -> str | None:
        if config is None:
            raise ValueError("a bound checkpoint config is required")
        selected = config.get("configurable", {})
        if selected.get("thread_id") != str(self.thread_id) or selected.get("checkpoint_ns", "") != "":
            raise ValueError("foreign checkpoint thread or namespace")
        checkpoint_id = selected.get("checkpoint_id")
        if checkpoint_id is not None and (type(checkpoint_id) is not str or not 1 <= len(checkpoint_id) <= 128):
            raise ValueError("invalid checkpoint id")
        return checkpoint_id

    def _keys(self, checkpoint_id: str | None = None) -> dict[str, Any]:
        return {"w": self.scope.workspace_id, "t": self.thread_id, "id": checkpoint_id}

    def _binding(self, connection: Connection, *, mutate: bool = False) -> None:
        run: runs.Run | None
        if mutate:
            run, job, _ = runs.check_fence(connection, self.token, self.clock)
            if job.run_id != run.id:
                raise ValueError("checkpoint job does not belong to run")
        else:
            run = runs.get_run(connection, self.scope.run_id)
        if run is None or run.scope != self.scope or (
                run.graph_sha256, run.prompt_sha256, run.config_sha256) != self.digests:
            raise ValueError("checkpoint run binding changed")
        row = connection.execute(text("SELECT case_id, run_id, graph_sha256, prompt_sha256, config_sha256 "
                                      "FROM checkpoints.threads WHERE workspace_id = :w AND thread_id = :t"),
                                 self._keys()).first()
        if row is not None and tuple(row) != (self.scope.case_id, self.scope.run_id, *self.digests):
            raise ValueError("checkpoint thread binding changed")

    def _state_binding(self, payload: dict[str, Any]) -> None:
        channels = payload["channel_values"]
        for val in ([channels["state"]] if "state" in channels else []) + (
                [channels["__start__"]["state"]] if "__start__" in channels else []):
            self._one_state_binding(val)

    def _one_state_binding(self, value: object) -> None:
        state = codec.state(value)
        if (state.workspace_id, state.case_id, state.run_id) != (
                self.scope.workspace_id, self.scope.case_id, self.scope.run_id) or (
                state.graph_sha256, state.prompt_sha256, state.config_sha256) != self.digests:
            raise ValueError("checkpoint application binding changed")

    def _tuple(self, connection: Connection, row: Any) -> CheckpointTuple:
        checkpoint = codec.decode_checkpoint(row["payload"])
        if row["codec_version"] != 1:
            raise codec.CheckpointCompatibilityError("unsupported stored codec version")
        if row["state_version"] != STATE_VERSION:
            raise codec.CheckpointStateVersionError("unsupported stored state version")
        if row["checkpoint_id"] != checkpoint["id"] or row["checkpoint_ns"] != "":
            raise codec.CheckpointUnsafeTypeError("checkpoint row disagrees with envelope")
        self._state_binding(row["payload"])
        writes = connection.execute(text(
            "SELECT task_id, task_path, idx, channel, value FROM checkpoints.writes "
            "WHERE workspace_id = :w AND thread_id = :t AND checkpoint_ns = '' AND checkpoint_id = :id LIMIT 257"),
            self._keys(checkpoint["id"])).mappings().all()
        pending = pending_writes([dict(write) for write in writes])
        for _, channel, value in pending:
            self._write_binding(channel, value)
        parent = row["parent_checkpoint_id"]
        return CheckpointTuple(self.config(checkpoint["id"]), checkpoint, codec.metadata(row["metadata"]),
                               self.config(parent) if parent else None, pending)

    def _write_binding(self, channel: str, value: Any) -> None:
        if channel == "state":
            self._one_state_binding(value)
        elif channel == "__start__":
            self._one_state_binding(value["state"])

    async def aget_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        checkpoint_id = self._config_id(config)
        with workspace_transaction(self.engine, self.scope.workspace_id) as connection:
            self._binding(connection)
            row = connection.execute(text(
                "SELECT * FROM checkpoints.snapshots WHERE workspace_id = :w AND thread_id = :t "
                "AND checkpoint_ns = '' AND (CAST(:id AS text) IS NULL OR checkpoint_id = :id) "
                "ORDER BY checkpoint_id DESC LIMIT 1"), self._keys(checkpoint_id)).mappings().first()
            if row is None and checkpoint_id is not None:
                raise NotFound("checkpoint does not exist in this thread")
            return self._tuple(connection, row) if row is not None else None

    async def alist(self, config: RunnableConfig | None, *, filter: dict[str, Any] | None = None,
                    before: RunnableConfig | None = None, limit: int | None = None) -> AsyncIterator[CheckpointTuple]:
        checkpoint_id = self._config_id(config)
        cursor = self._config_id(before) if before is not None else None
        count = 20 if limit is None else limit
        if type(count) is not int or not 1 <= count <= 100:
            raise ValueError("checkpoint history limit must be 1..100")
        selected = {} if filter is None else filter
        codec.json_bytes(selected, limit=codec.MAX_METADATA_BYTES)
        if set(selected) - {"source", "step"} or any(
                (key == "source" and value not in ("input", "loop", "update")) or
                (key == "step" and (type(value) is not int or not -1 <= value <= 66))
                for key, value in selected.items()):
            raise ValueError("unsupported checkpoint history filter")
        with workspace_transaction(self.engine, self.scope.workspace_id) as connection:
            self._binding(connection)
            rows = connection.execute(text(
                "SELECT * FROM checkpoints.snapshots WHERE workspace_id = :w AND thread_id = :t "
                "AND checkpoint_ns = '' AND (CAST(:id AS text) IS NULL OR checkpoint_id = :id) "
                "AND (CAST(:cursor AS text) IS NULL OR checkpoint_id < :cursor) "
                "AND metadata @> CAST(:filter AS jsonb) "
                "ORDER BY checkpoint_id DESC LIMIT :limit"),
                {**self._keys(checkpoint_id), "cursor": cursor, "filter": codec.json_bytes(selected).decode(),
                 "limit": count}).mappings().all()
            result = [self._tuple(connection, row) for row in rows]
        for item in result:  # never hold a connection while the caller is suspended
            yield item

    async def aput(self, config: RunnableConfig, checkpoint: Checkpoint, metadata: CheckpointMetadata,
                   new_versions: ChannelVersions) -> RunnableConfig:
        parent = self._config_id(config)
        payload, meta = codec.encode_checkpoint(checkpoint), codec.metadata(metadata)
        if parent is not None and parent >= checkpoint["id"]:
            raise ValueError("checkpoint parent must precede child")
        codec.versions(new_versions)
        self._state_binding(payload)
        with workspace_transaction(self.engine, self.scope.workspace_id) as connection:
            self._binding(connection, mutate=True)
            connection.execute(text(
                "INSERT INTO checkpoints.threads (workspace_id, thread_id, case_id, run_id, graph_sha256, "
                "prompt_sha256, config_sha256) VALUES (:w, :t, :c, :r, :g, :p, :cfg) ON CONFLICT DO NOTHING"),
                {**self._keys(), "c": self.scope.case_id, "r": self.scope.run_id,
                 "g": self.digests[0], "p": self.digests[1], "cfg": self.digests[2]})
            self._binding(connection)
            keys = self._keys(checkpoint["id"])
            connection.execute(text(
                "INSERT INTO checkpoints.snapshots (workspace_id, thread_id, checkpoint_ns, checkpoint_id, "
                "parent_checkpoint_id, generation, codec_version, state_version, payload, metadata) "
                "VALUES (:w, :t, '', :id, :parent, :generation, 1, :sv, CAST(:payload AS jsonb), CAST(:meta AS jsonb)) "
                "ON CONFLICT DO NOTHING"), {**keys, "parent": parent, "generation": self.token.generation,
                                           "sv": STATE_VERSION, "payload": codec.json_bytes(payload).decode(),
                                           "meta": codec.json_bytes(meta).decode()})
            row = connection.execute(text(
                "SELECT parent_checkpoint_id, payload, metadata, codec_version, state_version "
                "FROM checkpoints.snapshots "
                "WHERE workspace_id = :w AND thread_id = :t AND checkpoint_ns = '' AND checkpoint_id = :id"),
                keys).one()
            if row[3] != 1:
                raise codec.CheckpointCompatibilityError("unsupported stored codec version")
            if row[4] != STATE_VERSION:
                raise codec.CheckpointStateVersionError("unsupported stored state version")
            if tuple(row[:3]) != (parent, payload, meta):
                raise IdempotencyConflict("checkpoint replay changed content")
        return self.config(checkpoint["id"])

    async def aput_writes(self, config: RunnableConfig, writes: Sequence[tuple[str, Any]], task_id: str,
                          task_path: str = "") -> None:
        checkpoint_id = self._config_id(config)
        if checkpoint_id is None or type(task_id) is not str or not 1 <= len(task_id) <= 128 or (
                type(task_path) is not str or len(task_path) > 1024) or len(writes) > 256:
            raise codec.CheckpointUnsafeTypeError("invalid pending write bounds")
        codec.json_bytes([task_id, task_path], limit=8192)
        prepared = []
        for index, (channel, value) in enumerate(writes):
            checked = codec.channel_value(channel, value, pending=True)
            self._write_binding(channel, checked)
            prepared.append((WRITES_IDX_MAP.get(channel, index), channel, checked))
        codec.json_bytes([value for _, _, value in prepared])
        with workspace_transaction(self.engine, self.scope.workspace_id) as connection:
            self._binding(connection, mutate=True)
            for index, channel, value in prepared:
                keys = {**self._keys(checkpoint_id), "task": task_id, "idx": index}
                connection.execute(text(
                    "INSERT INTO checkpoints.writes (workspace_id, thread_id, checkpoint_ns, checkpoint_id, "
                    "task_id, idx, task_path, channel, value) VALUES (:w, :t, '', :id, :task, :idx, :path, :channel, "
                    "CAST(:value AS jsonb)) ON CONFLICT DO NOTHING"),
                    {**keys, "path": task_path, "channel": channel, "value": codec.json_bytes(value).decode()})
                row = connection.execute(text(
                    "SELECT task_path, channel, value FROM checkpoints.writes WHERE workspace_id = :w "
                    "AND thread_id = :t AND checkpoint_ns = '' AND checkpoint_id = :id "
                    "AND task_id = :task AND idx = :idx"), keys).one()
                if row[0] != task_path or row[1] != channel:
                    raise IdempotencyConflict("pending write replay changed slot")
                if row[2] != value:
                    if channel != ERROR:
                        raise IdempotencyConflict("pending write replay changed content")
                    connection.execute(text(
                        "UPDATE checkpoints.writes SET value = CAST(:value AS jsonb) WHERE workspace_id = :w "
                        "AND thread_id = :t AND checkpoint_ns = '' AND checkpoint_id = :id "
                        "AND task_id = :task AND idx = :idx"), {**keys, "value": codec.json_bytes(value).decode()})
            count, size = connection.execute(text(
                "SELECT count(*), COALESCE(sum(octet_length(value::text)), 0) FROM checkpoints.writes "
                "WHERE workspace_id = :w AND thread_id = :t "
                "AND checkpoint_ns = '' AND checkpoint_id = :id"), self._keys(checkpoint_id)).one()
            if count > 256 or size > codec.MAX_CHECKPOINT_BYTES:
                raise codec.CheckpointUnsafeTypeError("pending write count exceeded")
