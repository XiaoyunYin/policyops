"""Run the registered N16 HNSW protocol in a disposable local PostgreSQL."""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
from typing import Any, TextIO

import psycopg
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from policyops.persistence.database import make_engine, sqlstate
from scripts.bm25_latency_probe import output_path
from scripts.n16_ann_data import (
    LAYOUTS,
    K,
    Neighbor,
    Scope,
    Vector,
    corpus,
    cutoff_ties,
    fixture,
    hash_order,
    numpy_crosscheck,
    split,
    tenant_layout,
)
from scripts.n16_ann_postgres import (
    ANN,
    DDL,
    EXACT,
    INDEX,
    RELAXED,
    REPO,
    TRUTH,
    MemorySamples,
    build,
    database,
    explain,
    load,
    neighbors,
    plan_summary,
    query_args,
    scoped,
    settings,
    setup,
)
from scripts.qa_env import Environment, Refused


CONFIG = REPO / "evals/ann/n16-v1.json"


@dataclass(frozen=True)
class Protocol:
    protocol: str
    seed: int
    sizes: list[int]
    fixture_size: int
    query_count: int
    fixture_query_count: int
    crosscheck_count: int
    k: int
    passes: int
    fixture_passes: int
    tenant_per_mille: list[int]
    builds: list[list[int]]
    ef_search: list[int]
    iteration: list[str]
    max_scan_tuples: int
    scan_mem_multiplier: int
    work_mem: str
    shared_buffers: str


@dataclass(frozen=True)
class Cell:
    scope: Scope
    method: str
    planner: str
    ef: int | None = None

    @property
    def id(self) -> str:
        return f"{self.scope.name}/{self.method}/{self.planner}/{self.ef or '-'}"


def cells(scopes: Sequence[Scope], protocol: Protocol) -> list[Cell]:
    result = []
    for scope in scopes:
        planners = ("natural", "prefer-hnsw") if scope.per_mille < 1000 else ("natural",)
        result.append(Cell(scope, "exact", "natural"))
        if scope.per_mille < 1000:
            result.append(Cell(scope, "exact", "prefer-btree"))
        result.extend(Cell(scope, method, planner, ef) for planner in planners
                      for method in protocol.iteration for ef in protocol.ef_search)
    return result


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return sha256(canonical(value)).hexdigest()


def emit(handle: TextIO, kind: str, **fields: Any) -> None:
    handle.write(canonical({"kind": kind, **fields}).decode("utf-8") + "\n")


def error_code(error: BaseException) -> str:
    if isinstance(error, Refused):
        return str(error)
    state = sqlstate(error)
    return type(error).__name__ + (f"/{state}" if state else "")


def hardware(directory: Path) -> dict[str, Any]:
    memory: int | None = None
    if os.name == "nt":
        from ctypes import byref, c_ulonglong, windll

        kib = c_ulonglong()
        if windll.kernel32.GetPhysicallyInstalledSystemMemory(byref(kib)):
            memory = kib.value * 1024
    elif hasattr(os, "sysconf"):
        memory = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    return {
        "platform": platform.platform(), "machine": platform.machine(), "processor": platform.processor(),
        "logical_cpus": os.cpu_count(), "physical_memory_bytes": memory,
        "artifact_disk_free_bytes": shutil.disk_usage(directory).free,
    }


def verify_scope(runtime: Engine, owner: Engine, scope: Scope, eligible: int) -> None:
    with scoped(runtime, owner, scope) as connection:
        actual = connection.execute(text("""
            SELECT current_user, row_security_active('n16.chunks'),
                   (SELECT count(*) FROM n16.chunks)
        """)).one()
        role = "postgres" if scope.workspace is None else "policyops_app_runtime"
        if tuple(actual) != (role, scope.workspace is not None, eligible):
            raise ValueError("scope_or_visible_count_mismatch")


def ground_truth(output: TextIO, runtime: Engine, owner: Engine, scope: Scope,
                 layout_key: str, eligible: list[Vector], queries: list[Vector], count: int, seed: int,
                 ) -> dict[str, list[Neighbor]]:
    ids = {row.id for row in eligible}
    verify_scope(runtime, owner, scope, len(ids))
    with scoped(runtime, owner, scope) as connection:
        if connection.execute(text("SELECT to_regclass('n16.n16_chunks_hnsw')")).scalar_one() is not None:
            raise ValueError("truth_requires_no_hnsw_index")
        truth: dict[str, list[Neighbor]] = {}
        for query in queries:
            ranked = neighbors(connection, TRUTH, query_args(query))
            if len(ranked) != min(K + 1, len(ids)) or any(key not in ids for key, _ in ranked):
                raise ValueError("truth_visibility_or_count_mismatch")
            truth[query.id] = ranked
            tied, crossed = cutoff_ties(ranked)
            emit(output, "truth", layout=layout_key, scope=scope.name, query=query.id, rows=ranked,
                 cutoff_tie=tied, crossing_tie=crossed)
    sample = sorted(queries, key=lambda query: hash_order(query.id, seed, "numpy-crosscheck"))[:count]
    checks = numpy_crosscheck(eligible, sample, truth)
    emit(output, "crosscheck", layout=layout_key, scope=scope.name, rows=checks)
    output.flush()
    if any(not row["ok"] for row in checks):
        raise ValueError("numpy_crosscheck_mismatch")
    return truth


def measure_cell(output: TextIO, runtime: Engine, owner: Engine, cell: Cell, attempt: dict[str, Any],
                 query_order: list[str], params: dict[str, dict[str, str]], truth: dict[str, list[Neighbor]],
                 eligible: set[str], protocol: Protocol) -> None:
    sql = {"exact": EXACT, "relaxed_order": RELAXED}.get(cell.method, ANN)
    statement = text(sql)
    plan_digest = None
    emit(output, "cell", **attempt, query_order=query_order)
    output.flush()
    with scoped(runtime, owner, cell.scope) as connection:
        effective = settings(connection, method=cell.method, ef=cell.ef, planner=cell.planner,
                             work_mem=protocol.work_mem, max_scan_tuples=protocol.max_scan_tuples,
                             scan_mem_multiplier=protocol.scan_mem_multiplier)
        probe = query_order[0]
        try:
            with connection.begin_nested():
                plan = explain(connection, sql, params[probe])
        except DBAPIError as error:
            emit(output, "plan_error", **attempt, query=probe, error=error_code(error), settings=effective)
        else:
            plan_digest = digest(plan)
            planned, node = plan_summary(plan, cell.method)
            emit(output, "plan", **attempt, query=probe, digest=plan_digest, plan=plan, observed=planned,
                 node=node, settings=effective)
            if cell.method == "exact" and planned == "HNSW":
                raise ValueError("hnsw_in_exact_baseline")
        # Same warmed session with a small untimed prefix per cell. Savepoints
        # allow a statement timeout to retain a slot without poisoning the pass.
        for query in query_order[:5]:
            try:
                with connection.begin_nested():
                    connection.execute(statement, params[query]).fetchall()
            except DBAPIError as error:
                emit(output, "warmup_error", **attempt, query=query, error=error_code(error))
        for query in query_order:
            elapsed_ms = None
            error_value = None
            returned: list[Neighbor] = []
            try:
                with connection.begin_nested():
                    start = time.perf_counter_ns()
                    try:
                        raw = connection.execute(statement, params[query]).fetchall()
                    finally:
                        elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
                returned = [(str(row[0]), float(row[1])) for row in raw]
            except DBAPIError as error:
                error_value = error_code(error)
            if any(key not in eligible for key, _ in returned):
                error_value = "visibility_mismatch"
            if cell.method == "exact" and error_value is None and returned != truth[query][:K]:
                error_value = "exact_baseline_mismatch"
            emit(output, "sample", **attempt, query=query, rows=returned, elapsed_ms=elapsed_ms,
                 plan_digest=plan_digest, error=error_value)
            if error_value in ("visibility_mismatch", "exact_baseline_mismatch"):
                raise ValueError(error_value)
    output.flush()


def run_build(output: TextIO, env: Environment, container: str, admin: psycopg.Connection[Any],
              key: str, number: int, parameters: list[int], maintenance_mib: int, workers: int) -> None:
    m, ef = parameters
    record: dict[str, Any] = {"layout": key, "build": number, "m": m, "ef_construction": ef, "spill_notices": []}
    sampler = MemorySamples(env, container)
    emit(output, "build_start", **record)
    output.flush()
    try:
        with sampler:
            build(admin, m, ef, maintenance_mib, workers, record)
    except BaseException as error:
        record["error"] = error_code(error)
        raise
    finally:
        emit(output, "build", **record, **sampler.evidence())
        output.flush()


def sweep(output: TextIO, env: Environment, container: str, runtime: Engine, owner: Engine,
          protocol: Protocol, args: argparse.Namespace, base: list[Vector], queries: list[Vector],
          sizes: list[int], builds: list[list[int]]) -> None:
    query_ids = [query.id for query in queries]
    params = {query.id: query_args(query) for query in queries}
    with env.connect("postgres") as admin:
        emit(output, "versions", **setup(admin))
        for size in sizes:
            rows = base[:size]
            for name, scopes in LAYOUTS.items():
                if args.pilot and name == "single":
                    continue
                layout_key = f"{size}/{name}"
                positions = tenant_layout([row.id for row in rows], name, protocol.seed)
                load(admin, rows, positions)
                truth_by_scope = {}
                eligible_by_scope = {}
                if not args.pilot:
                    for scope in scopes:
                        eligible = [row for row in rows if scope.workspace is None
                                    or positions[row.id] == scope.workspace]
                        eligible_by_scope[scope.name] = {row.id for row in eligible}
                        truth_by_scope[scope.name] = ground_truth(
                            output, runtime, owner, scope, layout_key, eligible, queries,
                            protocol.crosscheck_count, protocol.seed,
                        )
                for number, parameters in enumerate(builds, start=1):
                    run_build(output, env, container, admin, layout_key, number, parameters,
                              args.maintenance_mib, args.workers)
                    if not args.pilot:
                        passes = protocol.fixture_passes if args.fixture else protocol.passes
                        for pass_number in range(1, passes + 1):
                            seed = f"{protocol.seed}/{layout_key}/{number}/{pass_number}"
                            cell_order = sorted(cells(scopes, protocol),
                                                key=lambda cell: hash_order(cell.id, protocol.seed, seed + "/cells"))
                            query_order = sorted(query_ids,
                                                 key=lambda key: hash_order(key, protocol.seed, seed + "/queries"))
                            for cell in cell_order:
                                attempt = {"layout": layout_key, "build": number, "pass": pass_number, "cell": cell.id}
                                measure_cell(output, runtime, owner, cell, attempt, query_order, params,
                                             truth_by_scope[cell.scope.name], eligible_by_scope[cell.scope.name],
                                             protocol)
                    admin.execute(f"DROP INDEX n16.{INDEX}")


def scheduled(sizes: list[int], builds: list[list[int]], protocol: Protocol, pilot: bool,
              ) -> list[dict[str, Any]]:
    return [
        {
            "layout": f"{size}/{name}", "size": size,
            "builds": builds,
            "cells": [] if pilot else [
                {"id": cell.id, "scope": cell.scope.name, "per_mille": cell.scope.per_mille,
                 "visible": size * cell.scope.per_mille // 1000, "method": cell.method,
                 "planner": cell.planner, "ef": cell.ef}
                for cell in cells(scopes, protocol)
            ],
        }
        for size in sizes for name, scopes in LAYOUTS.items() if not pilot or name != "single"
    ]


def run(output: TextIO, args: argparse.Namespace) -> None:
    config = CONFIG.read_bytes()
    protocol = Protocol(**json.loads(config))
    if protocol.k != K or protocol.tenant_per_mille != [1000, 100, 10, 1]:
        raise ValueError("config_and_ddl_contract_mismatch")
    sizes = [protocol.fixture_size] if args.fixture else (
        protocol.sizes if args.include_200k else protocol.sizes[:1]
    )
    query_count = protocol.fixture_query_count if args.fixture else protocol.query_count
    builds = protocol.builds
    if args.pilot:
        builds = builds[-1:]
    elif args.fixture:
        builds = builds[:1]
    mode = "pilot" if args.pilot else "fixture" if args.fixture else "benchmark"
    dirty = subprocess.run(["git", "status", "--porcelain"], capture_output=True, check=True).stdout
    revision = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    source_hashes = {
        str(path.relative_to(REPO).as_posix()): sha256(path.read_bytes()).hexdigest()
        for path in (CONFIG, DDL, *sorted((REPO / "scripts").glob("n16_ann_*.py")))
    }
    emit(output, "run", mode=mode, utc=datetime.now(UTC).isoformat(), revision=revision, dirty=bool(dirty),
         source_hashes=source_hashes, config=asdict(protocol), queries=query_count,
         passes=protocol.fixture_passes if args.fixture else protocol.passes,
         schedule=scheduled(sizes, builds, protocol, args.pilot),
         hardware=hardware(Path(output.name).parent), maintenance_mib=args.maintenance_mib,
         workers=args.workers, real_corpus="unverified: no cache-backed QA replay in this run")
    output.flush()

    if args.fixture:
        source, pairs = {"dataset": "deterministic synthetic fixture"}, fixture(max(sizes) + query_count, protocol.seed)
    else:
        source, pairs = corpus(args.corpus)
    base, queries = split(pairs, protocol.seed, max(sizes), query_count)
    emit(output, "corpus", source=source, query_ids=[query.id for query in queries],
         base_id_digests={size: digest([row.id for row in base[:size]]) for size in sizes})
    output.flush()

    with database(args.memory_mib, args.shm_mib, protocol.shared_buffers) as (env, container, runtime, metadata):
        emit(output, "database", **metadata, project=env.project)
        output.flush()

        def connect_owner() -> psycopg.Connection[Any]:
            connection: psycopg.Connection[Any] = env.connect("postgres", autocommit=False)
            connection.prepare_threshold = None
            return connection

        owner = make_engine(connect_owner, pool_size=1)
        try:
            sweep(output, env, container, runtime, owner, protocol, args, base, queries, sizes, builds)
        finally:
            owner.dispose()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--fixture", action="store_true")
    source.add_argument("--corpus", type=Path, help="private directory from n16_ann_fetch")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--pilot", action="store_true", help="100k build-only memory pilot using m=32")
    mode.add_argument("--include-200k", action="store_true", help="add the 200k point after a successful memory pilot")
    parser.add_argument("--memory-mib", type=int, default=4096)
    parser.add_argument("--maintenance-mib", type=int, default=1024)
    parser.add_argument("--shm-mib", type=int, default=1280)
    parser.add_argument("--workers", type=int, default=0, help="maximum parallel maintenance workers")
    parser.add_argument("--out", type=Path, required=True, help="new private JSONL evidence path")
    args = parser.parse_args(argv)
    if args.fixture and (args.pilot or args.include_200k):
        parser.error("fixture mode cannot run a corpus pilot or the 200k point")
    if not (0 <= args.workers <= 4 and 64 <= args.maintenance_mib <= args.shm_mib <= args.memory_mib - 512):
        parser.error("require 0 to 4 workers and 64 <= maintenance-mib <= shm-mib <= memory-mib - 512")
    try:
        if args.corpus is not None:
            args.corpus = output_path(args.corpus)
        with output_path(args.out).open("x", encoding="utf-8", newline="\n") as handle:
            try:
                run(handle, args)
            except (Exception, KeyboardInterrupt) as error:
                emit(handle, "finish", status="failed", error=error_code(error), notes=getattr(error, "__notes__", []))
                raise
            emit(handle, "finish", status="completed")
    except (Exception, KeyboardInterrupt) as error:
        print(f"N16 benchmark failed ({error_code(error)}).", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
