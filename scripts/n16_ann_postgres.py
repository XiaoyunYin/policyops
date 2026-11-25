"""PostgreSQL ownership, loading, plans and index construction for N16."""
from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
from struct import Struct
import subprocess
import sys
from threading import Event, Thread
import time
from typing import Any
from uuid import UUID, uuid4

import psycopg
from sqlalchemy import Connection, Engine, text

from policyops.persistence.database import SqlProfile, make_engine, verify_runtime_role, workspace_transaction
from policyops.persistence.roles import ALL_ROLES, APP_RUNTIME
from policyops.retrieval.diagnostics import _nodes
from scripts.n16_ann_data import DIMENSION, K, Neighbor, Scope, Vector
from scripts.qa_env import Environment, Refused, private_root


REPO = Path(__file__).resolve().parents[1]
DDL = REPO / "evals/ann/n16-v1.sql"
INDEX = "n16_chunks_hnsw"
BTREE = "n16_chunks_workspace_generation"
DISTANCE = "embedding <=> CAST(:q AS public.vector)"
SELECT = f"SELECT id, {DISTANCE} AS distance FROM n16.chunks"  # noqa: S608 - static SQL fragments
EXACT = f"{SELECT} ORDER BY ({DISTANCE}) + 0, id LIMIT {K}"
TRUTH = f"{SELECT} ORDER BY ({DISTANCE}) + 0, id LIMIT {K + 1}"
ANN = f"{SELECT} ORDER BY embedding <=> CAST(:q AS public.vector) LIMIT {K}"
RELAXED = (
    f"WITH candidates AS MATERIALIZED ({ANN}) "  # noqa: S608 - static SQL fragments
    "SELECT id, distance FROM candidates ORDER BY distance + 0, id"
)
EXPLAIN = "EXPLAIN (ANALYZE, BUFFERS, SETTINGS, FORMAT JSON) "
SET = text("SELECT set_config(:key, :value, true)")
VECTOR_LITERAL = re.compile(r"\[[-+\deE., ]+\]")
FIELD_LENGTH = Struct("!i")
ROW_HEADER = Struct("!h")
VECTOR_HEADER = Struct("!hh")


class LocalDocker:
    def __init__(self, memory_mib: int, shm_mib: int, shared_buffers: str) -> None:
        self.environ = {key: value for key, value in os.environ.items() if key.upper() != "DOCKER_HOST"}
        context = subprocess.run(
            ["docker", "context", "show"], env=self.environ, capture_output=True, text=True, timeout=20, check=True,
        ).stdout.strip()
        observed = subprocess.run(
            ["docker", "context", "inspect", context],
            env=self.environ, capture_output=True, text=True, timeout=20, check=True,
        )
        endpoint = json.loads(observed.stdout)[0]["Endpoints"]["docker"]["Host"]
        if not endpoint.startswith(("npipe:////./pipe/", "unix:///")):
            raise Refused("docker_context_must_be_local")
        self.prefix = ["docker", "--context", context]
        self.memory_bytes, self.shm_bytes = memory_mib * 1024**2, shm_mib * 1024**2
        self.shared_buffers = shared_buffers

    def __call__(self, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if args[0] == "create":
            args = (
                "create", "--memory", str(self.memory_bytes), "--memory-swap", str(self.memory_bytes),
                "--shm-size", str(self.shm_bytes), *args[1:],
                "-c", "shared_buffers=" + self.shared_buffers,
            )
        # Docker errors may include backend details. The caller records a bounded failure code.
        return subprocess.run(
            [*self.prefix, *args], env=self.environ, capture_output=True, text=True, timeout=30, check=False,
        )


@contextmanager
def database(memory_mib: int, shm_mib: int, shared_buffers: str,
             ) -> Iterator[tuple[Environment, str, Engine, dict[str, Any]]]:
    docker = LocalDocker(memory_mib, shm_mib, shared_buffers)
    project = "policyops-n16-" + uuid4().hex[:16]
    env = Environment(project, private_root(project), runner=docker)
    vm = json.loads(env.call("info", "--format", "{{json .}}"))
    vm = {key: vm[key] for key in ("NCPU", "MemTotal", "Architecture", "OperatingSystem", "ServerVersion", "Driver")}
    if vm["MemTotal"] < docker.memory_bytes + 512 * 1024**2:
        raise Refused("docker_vm_memory_below_container_limit_plus_512MiB")
    image = json.loads(env.call("image", "inspect", env.image))[0]
    if env.image not in image["RepoDigests"]:
        raise Refused("pinned_image_digest_unconfirmed")

    failure: BaseException | None = None
    runtime = None
    try:
        env.up()
        info = env.inspect()
        if info is None:
            raise Refused("container_creation_unconfirmed")
        container = info["Id"]
        limits = info["HostConfig"]
        if (limits["Memory"], limits["MemorySwap"], limits["ShmSize"]) != (
            docker.memory_bytes, docker.memory_bytes, docker.shm_bytes,
        ):
            raise Refused("container_limits_unconfirmed")
        env.migrate()

        def connect() -> psycopg.Connection[Any]:
            connection: psycopg.Connection[Any] = env.connect(APP_RUNTIME, info=info, autocommit=False)
            connection.prepare_threshold = None
            return connection

        runtime = make_engine(connect, pool_size=1)
        verify_runtime_role(runtime, APP_RUNTIME)
        yield env, container, runtime, {
            "docker_vm": vm,
            "image": env.image,
            "image_id": image["Id"],
            "container_memory_bytes": docker.memory_bytes,
            "container_shm_bytes": docker.shm_bytes,
            "docker_pgdata_disk": env.call("exec", container, "df", "-B1", "/var/lib/postgresql/data"),
        }
    except BaseException as error:
        failure = error
        raise
    finally:
        if runtime is not None:
            runtime.dispose()
        # The QA helper checks exact labels, image, mounts and ID even following
        # a failed create/start. Leave state and credentials if cleanup is uncertain.
        try:
            if env.file("owner.json").exists():
                env.destroy(project)
                for name in ("postgres", "pg_service.conf", *ALL_ROLES, *(role + ".dsn" for role in ALL_ROLES)):
                    env.file("secrets/" + name).unlink(missing_ok=True)
                if env.file("secrets").exists():
                    env.file("secrets").rmdir()
                env.file("owner.json").unlink()
                env.root.rmdir()
        except Exception as cleanup:
            if failure is None:
                raise
            failure.add_note(f"cleanup failed for {project} ({type(cleanup).__name__})")


def setup(connection: psycopg.Connection[Any]) -> dict[str, Any]:
    with connection.transaction():
        connection.execute(DDL.read_text(encoding="utf-8"), prepare=False)
        result = connection.execute("""
            SELECT current_setting('server_version'), current_setting('server_version_num'),
                   (SELECT extversion FROM pg_extension WHERE extname = 'vector'),
                   current_setting('shared_buffers')
        """).fetchone()
        if result is None or (result[1], result[2]) != ("170011", "0.8.7"):
            raise ValueError("postgres_or_pgvector_version_mismatch")
        return dict(zip(("server_version", "server_version_num", "extversion", "shared_buffers"), result, strict=True))


def load(connection: psycopg.Connection[Any], rows: Sequence[Vector],
         positions: Mapping[str, UUID], retired: Sequence[Vector] = ()) -> None:
    """Use pgvector's float32 wire format to avoid decimal conversion of the corpus."""
    with connection.transaction(), connection.cursor() as cursor:
        cursor.execute("TRUNCATE n16.chunks, n16.generations")
        workspaces = sorted(set(positions.values()))
        cursor.executemany(
            "INSERT INTO n16.generations VALUES (%s, %s, %s)",
            [(workspace, generation, status) for workspace in workspaces
             for generation, status in ((1, "ready"), (2, "retired"))],
        )
        with cursor.copy("COPY n16.chunks FROM STDIN (FORMAT BINARY)") as copy:
            block = bytearray(b"PGCOPY\n\xff\r\n\x00" + FIELD_LENGTH.pack(0) * 2)
            for selected, generation in ((rows, 1), (retired, 2)):
                for row in selected:
                    values = row.values[:]
                    if sys.byteorder == "little":
                        values.byteswap()
                    binary_vector = VECTOR_HEADER.pack(DIMENSION, 0) + values.tobytes()
                    fields = (row.id.encode("utf-8"), positions[row.id].bytes,
                              FIELD_LENGTH.pack(generation), binary_vector)
                    block.extend(ROW_HEADER.pack(len(fields)))
                    for field in fields:
                        block.extend(FIELD_LENGTH.pack(len(field)))
                        block.extend(field)
                    if len(block) >= 1024 * 1024:
                        copy.write(block)
                        block.clear()
            copy.write(block + ROW_HEADER.pack(-1))
        cursor.execute("ANALYZE n16.generations")
        cursor.execute("ANALYZE n16.chunks")


def query_args(query: Vector) -> dict[str, str]:
    return {"q": "[" + ",".join(format(value, ".9g") for value in query.values) + "]"}


@contextmanager
def scoped(runtime: Engine, owner: Engine, scope: Scope) -> Iterator[Connection]:
    if scope.workspace is not None:
        with workspace_transaction(runtime, scope.workspace, profile=SqlProfile.RETRIEVAL) as connection:
            yield connection
    else:
        with owner.begin() as connection:
            connection.execute(SET, {"key": "row_security", "value": "off"})
            connection.execute(SET, {"key": "statement_timeout", "value": "15s"})
            yield connection


def settings(connection: Connection, *, method: str, ef: int | None, planner: str,
             work_mem: str, max_scan_tuples: int, scan_mem_multiplier: int) -> dict[str, str]:
    values = {"work_mem": work_mem, "plan_cache_mode": "force_custom_plan"}
    if ef is not None:
        values.update({
            "hnsw.ef_search": str(ef), "hnsw.iterative_scan": method,
            "hnsw.max_scan_tuples": str(max_scan_tuples), "hnsw.scan_mem_multiplier": str(scan_mem_multiplier),
        })
    if planner in ("prefer-hnsw", "prefer-btree"):
        values["enable_seqscan"] = "off"
    if planner == "prefer-hnsw":
        values.update({"enable_sort": "off", "enable_bitmapscan": "off"})
    return {
        key: str(connection.execute(SET, {"key": key, "value": value}).scalar_one())
        for key, value in values.items()
    }


def neighbors(connection: Connection, statement: str, params: dict[str, str]) -> list[Neighbor]:
    return [(str(row[0]), float(row[1])) for row in connection.execute(text(statement), params).fetchall()]


def redact_plan(value: Any) -> Any:
    if isinstance(value, str):
        return VECTOR_LITERAL.sub("<query-vector>", value)
    if isinstance(value, dict):
        return {key: redact_plan(child) for key, child in value.items()}
    if isinstance(value, list):
        return [redact_plan(child) for child in value]
    return value


def explain(connection: Connection, statement: str, params: dict[str, str]) -> dict[str, Any]:
    raw = connection.execute(text(EXPLAIN + statement), params).scalar_one()
    plan: dict[str, Any] = redact_plan((raw if isinstance(raw, list) else json.loads(raw))[0])
    return plan


def indexes(node: dict[str, Any]) -> Iterator[tuple[str, str]]:
    if node.get("Index Name") and node.get("Actual Loops", 0) > 0:
        yield node["Index Name"], node["Node Type"]
    for child in node.get("Plans", ()):
        yield from indexes(child)


def plan_summary(plan: dict[str, Any], method: str) -> tuple[str, str]:
    used = dict(indexes(plan["Plan"]))
    if INDEX in used:
        return "HNSW", used[INDEX]
    nodes = ", ".join(dict.fromkeys(_nodes(plan["Plan"])))
    if method == "exact":
        return ("exact via btree" if BTREE in used else "exact"), nodes
    return "planner chose exact", nodes


class MemorySamples:
    """Sample current cgroup usage (including file cache) during one build."""

    def __init__(self, env: Environment, container: str) -> None:
        self.env, self.container = env, container
        self.samples: list[tuple[float, int]] = []
        self.failures = 0
        self.high_water: int | None = None
        self._stop = Event()
        self._thread = Thread(target=self._poll, daemon=True)

    def sample(self) -> None:
        try:
            raw = self.env.call(
                "exec", self.container, "sh", "-c",
                "cat /sys/fs/cgroup/memory.current 2>/dev/null || cat /sys/fs/cgroup/memory/memory.usage_in_bytes",
            )
            self.samples.append((time.monotonic(), int(raw)))
        except (Refused, ValueError, OSError, subprocess.TimeoutExpired):
            self.failures += 1

    def _poll(self) -> None:
        while not self._stop.wait(1):
            self.sample()

    def __enter__(self) -> MemorySamples:
        self.sample()
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        self._thread.join(35)
        if self._thread.is_alive():
            raise RuntimeError("memory_sampler_stop_timeout")
        self.sample()
        try:
            raw = self.env.call(
                "exec", self.container, "sh", "-c",
                "cat /sys/fs/cgroup/memory.peak 2>/dev/null || "
                "cat /sys/fs/cgroup/memory/memory.max_usage_in_bytes",
            )
            self.high_water = int(raw)
        except (Refused, ValueError, OSError, subprocess.TimeoutExpired):
            self.high_water = None

    def evidence(self) -> dict[str, Any]:
        return {
            "peak_container_memory_bytes": max((value for _, value in self.samples), default=None),
            "container_lifetime_high_water_bytes": self.high_water,
            "memory_samples": len(self.samples),
            "memory_sample_failures": self.failures,
            "memory_max_sample_gap_seconds": max(
                (right[0] - left[0] for left, right in zip(self.samples, self.samples[1:], strict=False)), default=None,
            ),
        }


def build(connection: psycopg.Connection[Any], m: int, ef: int, maintenance_mib: int, workers: int,
          record: dict[str, Any]) -> None:
    def notice(diagnostic: psycopg.errors.Diagnostic) -> None:
        message = diagnostic.message_primary or ""
        if "hnsw graph no longer fits into maintenance_work_mem" in message:
            record["spill_notices"].append(message)

    connection.add_notice_handler(notice)
    started = None
    try:
        try:
            with connection.transaction():
                connection.execute("SELECT set_config('maintenance_work_mem', %s, true)", (f"{maintenance_mib}MB",))
                connection.execute("SELECT set_config('max_parallel_maintenance_workers', %s, true)", (str(workers),))
                actual = connection.execute("""
                    SELECT current_setting('maintenance_work_mem'), current_setting('max_parallel_maintenance_workers'),
                           current_setting('max_parallel_workers'), current_setting('max_worker_processes')
                """).fetchone()
                if actual is None:
                    raise ValueError("build_settings_unconfirmed")
                record.update(dict(zip(
                    ("maintenance_work_mem", "maintenance_workers", "max_parallel_workers", "max_worker_processes"),
                    actual, strict=True,
                )))
                started = time.perf_counter()
                connection.execute(
                    f"CREATE INDEX {INDEX} ON n16.chunks USING hnsw (embedding public.vector_cosine_ops) "
                    f"WITH (m = {m:d}, ef_construction = {ef:d})"
                )
        finally:
            if started is not None:
                record["build_seconds"] = time.perf_counter() - started
        sizes = connection.execute("""
            SELECT pg_relation_size('n16.n16_chunks_hnsw'),
                   pg_relation_size(oid), pg_total_relation_size(reltoastrelid)
            FROM pg_class WHERE oid = 'n16.chunks'::regclass
        """).fetchone()
        if sizes is None:
            raise ValueError("relation_sizes_unconfirmed")
        record.update(dict(zip(("index_bytes", "heap_bytes", "toast_bytes"), sizes, strict=True)))
    finally:
        connection.remove_notice_handler(notice)
