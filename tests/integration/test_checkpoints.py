"""T21 saver contract against the installed LangGraph and actual runtime-role PostgreSQL."""

import asyncio
from dataclasses import replace
from typing import Any, TypedDict
from uuid import uuid4

from langchain_core.runnables import RunnableLambda
from langgraph.checkpoint.base import ChannelVersions, Checkpoint, CheckpointMetadata
from langgraph.checkpoint.serde.types import ERROR
from langgraph.graph import END, START, StateGraph
from pydantic import field_validator
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from policyops.orchestration.state import InvestigationState, state_from_json
from policyops.persistence import checkpoint_json as codec
from policyops.persistence.checkpoints import InvestigationSaver
from policyops.persistence.database import IdempotencyConflict, NotFound, RuntimeRoleError, workspace_transaction
from policyops.persistence.roles import APP_MIGRATOR, APP_RUNTIME
from policyops.persistence.runs import Fenced
from policyops_contracts.base import WireModel
from policyops_testing.app_database import AppDatabase
from policyops_testing.checkpoint_cases import DIGESTS, META, Claimed, checkpoint, claimed


pytestmark = pytest.mark.postgres


class GraphEnvelope(WireModel):
    state: InvestigationState

    @field_validator("state", mode="before")
    @classmethod
    def json_state(cls, value: Any) -> InvestigationState:
        # LangGraph coerces channel dictionaries with Python validation, whereas
        # the wire contract uses JSON UUIDs. Keep that conversion explicit/strict.
        return state_from_json(value)


class GraphInput(TypedDict):
    state: dict[str, Any]


def test_compiled_graph_bootstrap_end_and_restart(shared_db: AppDatabase) -> None:
    owner = claimed(shared_db)
    calls: list[str] = []

    def advance(data: GraphEnvelope) -> dict[str, Any]:
        calls.append("node")
        updated = data.state.model_copy(update={"step_count": data.state.step_count + 1})
        return {"state": updated.model_dump(mode="json")}

    graph = StateGraph(GraphEnvelope, input_schema=GraphInput)
    graph.add_node("investigate", RunnableLambda(advance))
    graph.add_node("finalize", RunnableLambda(advance))
    graph.add_edge(START, "investigate")
    graph.add_edge("investigate", "finalize")
    graph.add_edge("finalize", END)

    async def run() -> None:
        saver = owner.saver()
        compiled = graph.compile(checkpointer=saver)
        first = await compiled.ainvoke({"state": owner.state()}, saver.config(), durability="sync")
        assert first["state"]["step_count"] == 2
        assert calls == ["node", "node"]
        latest = await saver.aget_tuple(saver.config())
        assert latest is not None and latest.checkpoint["v"] == 4
        # Fresh saver and compiled graph, SAME server-derived thread; no new input.
        restarted = owner.saver()
        second = await graph.compile(checkpointer=restarted).ainvoke(None, restarted.config(), durability="sync")
        assert second == first and calls == ["node", "node"]
        history = [item async for item in restarted.alist(restarted.config())]
        assert len(history) == 4
        assert history[-1].metadata["source"] == "input"
        assert "__start__" in history[-1].checkpoint["channel_values"]
        assert [item.metadata["step"] for item in history] == [2, 1, 0, -1]
        assert len([item async for item in restarted.alist(restarted.config(), filter={"step": 1})]) == 1
        assert len([item async for item in restarted.alist(restarted.config(), before=history[1].config)]) == 2

    asyncio.run(run())


@pytest.mark.parametrize("fault", ["checkpoint", "node"])
def test_compiled_graph_replays_interrupted_pending_writes(shared_db: AppDatabase, fault: str) -> None:
    from langchain_core.runnables import RunnableConfig

    owner = claimed(shared_db)
    calls: list[str] = []
    entered = asyncio.Event()

    class Interrupted(InvestigationSaver):
        async def aput(self, config: RunnableConfig, checkpoint: Checkpoint, metadata: CheckpointMetadata,
                       new_versions: ChannelVersions) -> RunnableConfig:
            if fault == "checkpoint" and metadata["step"] == 1:
                raise asyncio.CancelledError("simulated process loss after node writes")
            return await super().aput(config, checkpoint, metadata, new_versions)

    def first(data: GraphEnvelope) -> dict[str, Any]:
        calls.append("first")
        return {"state": data.state.model_copy(update={"step_count": 1}).model_dump(mode="json")}

    async def last(data: GraphEnvelope) -> dict[str, Any]:
        calls.append("last")
        if fault == "node" and calls.count("last") == 1:
            entered.set()
            await asyncio.Event().wait()
        return {"state": data.state.model_copy(update={"step_count": 2}).model_dump(mode="json")}

    graph = StateGraph(GraphEnvelope, input_schema=GraphInput)
    graph.add_node("investigate", RunnableLambda(first))
    graph.add_node("finalize", RunnableLambda(last))
    graph.add_edge(START, "investigate")
    graph.add_edge("investigate", "finalize")
    graph.add_edge("finalize", END)

    async def run() -> None:
        saver = Interrupted(engine=shared_db.engine(APP_RUNTIME), scope=owner.scope.run, token=owner.token,
                            graph_sha256=DIGESTS[0], prompt_sha256=DIGESTS[1], config_sha256=DIGESTS[2],
                            clock=owner.saver().clock)
        compiled = graph.compile(checkpointer=saver)
        if fault == "node":
            task = asyncio.create_task(compiled.ainvoke({"state": owner.state()}, saver.config(), durability="sync"))
            try:
                await asyncio.wait_for(entered.wait(), 5)
            finally:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
        else:
            with pytest.raises(asyncio.CancelledError):
                await compiled.ainvoke({"state": owner.state()}, saver.config(), durability="sync")
        restarted = owner.saver()
        latest = await restarted.aget_tuple(restarted.config())
        assert latest is not None
        if fault == "checkpoint":
            assert latest.pending_writes
            assert any(channel == "state" for _, channel, _ in latest.pending_writes)
        else:
            assert latest.checkpoint["channel_values"]["state"]["step_count"] == 1
        owner.reclaim()
        restarted = owner.saver()
        result = await graph.compile(checkpointer=restarted).ainvoke(None, restarted.config(), durability="sync")
        assert result["state"]["step_count"] == 2
        assert calls == (["first", "last"] if fault == "checkpoint" else ["first", "last", "last"])

    asyncio.run(run())


def test_insert_equal_conflicts_ordering_reserved_updates_and_fence(shared_db: AppDatabase) -> None:
    owner = claimed(shared_db)

    async def run() -> None:
        saver, value = owner.saver(), checkpoint(owner.state())
        config = await saver.aput(saver.config(), value, META, {"state": 1})
        assert await saver.aput(saver.config(), value, META, {}) == config
        with pytest.raises(IdempotencyConflict):
            await saver.aput(saver.config(), value, META | {"step": 1}, {})
        await saver.aput_writes(config, [("state", owner.state())], "z", "a")
        for bad_id, bad_path, bad_writes in (("x" * 129, "", []), ("task", "x" * 1025, []),
                                            ("task", "nul\x00", []), ("task", "", [("state", owner.state())] * 257)):
            with pytest.raises(codec.CheckpointUnsafeTypeError):
                await saver.aput_writes(config, bad_writes, bad_id, bad_path)
        await saver.aput_writes(config, [("branch:to:read", None)], "a", "z")
        await saver.aput_writes(config, [("state", owner.state())], "z", "a")
        with pytest.raises(IdempotencyConflict):
            await saver.aput_writes(config, [("state", owner.state() | {"step_count": 2})], "z", "a")
        with pytest.raises(IdempotencyConflict):
            await saver.aput_writes(config, [("state", owner.state())], "z", "changed")
        await saver.aput_writes(config, [(ERROR, asyncio.CancelledError("secret"))], "error", "a")
        await saver.aput_writes(config, [(ERROR, Fenced("secret"))], "error", "a")
        loaded = await saver.aget_tuple(config)
        assert loaded is not None and loaded.pending_writes is not None
        assert [task for task, _, _ in loaded.pending_writes] == ["error", "z", "a"]
        assert loaded.pending_writes[0][2] == {"diagnostic": "fenced"}
        with pytest.raises(NotFound):
            await saver.aget_tuple(saver.config("foreign"))
        with pytest.raises(ValueError):
            await saver.aget_tuple({"configurable": {"thread_id": str(uuid4())}})
        with pytest.raises(ValueError):
            _ = [item async for item in saver.alist(None)]
        with pytest.raises(ValueError):
            _ = [item async for item in saver.alist(saver.config(), limit=101)]
        owner.reclaim()
        for mutation in (saver.aput(config, checkpoint(owner.state(), "0002"), META, {}),
                         saver.aput_writes(config, [(ERROR, Fenced("late"))], "error", "a")):
            with pytest.raises(Fenced):
                await mutation
        assert (await owner.saver().aget_tuple(config)) == loaded

    asyncio.run(run())


@pytest.mark.parametrize("axis", ["codec", "framework", "state", "state_row", "id"])
def test_incompatible_persisted_versions_fail_closed(shared_db: AppDatabase, axis: str) -> None:
    owner = claimed(shared_db)

    async def run() -> None:
        saver = owner.saver()
        await saver.aput(saver.config(), checkpoint(owner.state()), META, {})
        with shared_db.superuser() as conn:
            updates = {
                "codec": "payload = jsonb_set(payload, '{codec_version}', '2')",
                "framework": "payload = jsonb_set(payload, '{framework_version}', '3')",
                "state": "payload = jsonb_set(payload, '{channel_values,state,state_version}', '0')",
                "state_row": "state_version = 0",
                "id": "payload = jsonb_set(payload, '{id}', '\"other\"')",
            }
            conn.execute(f"UPDATE checkpoints.snapshots SET {updates[axis]} WHERE workspace_id = %s",  # noqa: S608
                         (owner.scope.run.workspace_id,))
        error = (codec.CheckpointStateVersionError if axis.startswith("state") else
                 codec.CheckpointUnsafeTypeError if axis == "id" else codec.CheckpointCompatibilityError)
        def must_not_run(data: GraphEnvelope) -> dict[str, Any]:
            raise AssertionError("an incompatible checkpoint must fail before running a node")

        graph = StateGraph(GraphEnvelope, input_schema=GraphInput)
        graph.add_node("investigate", RunnableLambda(must_not_run))
        graph.add_node("finalize", RunnableLambda(must_not_run))
        graph.add_edge(START, "investigate")
        graph.add_edge("investigate", "finalize")
        graph.add_edge("finalize", END)
        with pytest.raises(error):
            await graph.compile(checkpointer=saver).ainvoke(None, saver.config(), durability="sync")

    asyncio.run(run())


def test_saver_requires_runtime_role_and_exact_claim_binding(shared_db: AppDatabase) -> None:
    owner = claimed(shared_db)
    args: dict[str, Any] = dict(scope=owner.scope.run, token=owner.token, graph_sha256=DIGESTS[0],
                                prompt_sha256=DIGESTS[1], config_sha256=DIGESTS[2], clock=owner.saver().clock)
    with pytest.raises(RuntimeRoleError):
        InvestigationSaver(engine=shared_db.engine(APP_MIGRATOR), **args)
    args["token"] = replace(owner.token, workspace_id=uuid4())
    with pytest.raises(ValueError):
        InvestigationSaver(engine=shared_db.engine(APP_RUNTIME), **args)


def seed(owner: Claimed) -> None:
    async def run() -> None:
        saver = owner.saver()
        config = await saver.aput(saver.config(), checkpoint(owner.state()), META, {})
        await saver.aput_writes(config, [(ERROR, Fenced("test"))], "task")
    asyncio.run(run())


@pytest.mark.parametrize("table", ["threads", "snapshots", "writes"])
def test_all_checkpoint_tables_rls_select_insert_update_fk_and_pool_reset(shared_db: AppDatabase, table: str) -> None:
    a, b = claimed(shared_db), claimed(shared_db)
    seed(a)
    seed(b)
    app = shared_db.engine(APP_RUNTIME, pool_size=1)
    full = f"checkpoints.{table}"
    for owner, foreign in ((a, b), (b, a)):
        workspace = owner.scope.run.workspace_id
        with workspace_transaction(app, workspace) as conn:
            assert conn.execute(text(f"SELECT DISTINCT workspace_id FROM {full}")).all() == [(workspace,)]  # noqa: S608
            if table == "writes":
                assert conn.execute(text("UPDATE checkpoints.writes SET value = '{}'::jsonb "
                                         "WHERE workspace_id = :w"),
                                    {"w": foreign.scope.run.workspace_id}).rowcount == 0
            else:
                # No UPDATE privilege even for the caller's own immutable rows.
                with pytest.raises(DBAPIError):
                    conn.execute(text(f"UPDATE {full} SET workspace_id = workspace_id"))  # noqa: S608
        with app.begin() as conn:
            assert conn.execute(text(f"SELECT count(*) FROM {full}")).scalar_one() == 0  # noqa: S608
        # Copy a valid foreign row under the wrong scope: RLS WITH CHECK refuses it.
        with shared_db.superuser() as conn:
            row = conn.execute(f"SELECT * FROM {full} WHERE workspace_id = %s",  # noqa: S608
                               (foreign.scope.run.workspace_id,)).fetchone()
            columns = [c[0] for c in conn.execute(f"SELECT * FROM {full} LIMIT 0").description]  # noqa: S608
        data = dict(zip(columns, row, strict=True))
        # JSON objects are bound through explicit casts, never repr/interpolation.
        json_columns = {"payload", "metadata", "value"}
        params = {k: codec.json_bytes(v).decode() if k in json_columns else v for k, v in data.items()}
        values = ", ".join(f"CAST(:{k} AS jsonb)" if k in json_columns else f":{k}" for k in columns)
        insert = text(f"INSERT INTO {full} ({', '.join(columns)}) VALUES ({values})")  # noqa: S608
        with pytest.raises(DBAPIError), workspace_transaction(app, workspace) as conn:
            conn.execute(insert, params)
        # Own workspace + foreign parent key: composite FK cannot cross tenants.
        params["workspace_id"] = workspace
        if table == "threads":
            params["thread_id"] = uuid4()
        elif table == "snapshots":
            params["checkpoint_id"] = "foreign-fk"
        else:
            params["task_id"] = "foreign-fk"
        with pytest.raises(DBAPIError), workspace_transaction(app, workspace) as conn:
            conn.execute(insert, params)
        with pytest.raises(DBAPIError), app.begin() as conn:  # no scope insert
            conn.execute(insert, params)
        with workspace_transaction(app, workspace) as conn:
            assert conn.execute(text(f"SELECT count(*) FROM {full}")).scalar_one() == 1  # noqa: S608
