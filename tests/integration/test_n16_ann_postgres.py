"""Real pgvector plan and tenant filtering checks on 2,000 synthetic vectors."""
from __future__ import annotations

from array import array
import math
from pathlib import Path
import sys
from uuid import UUID

import pytest
from sqlalchemy import text

from policyops.persistence.database import workspace_transaction
from policyops.persistence.roles import APP_RUNTIME
from policyops_testing.app_database import AppDatabase


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.n16_ann_data import DIMENSION, SCOPES, K, Vector, hash_order
from scripts.n16_ann_postgres import (
    ANN,
    RELAXED,
    TRUTH,
    build,
    explain,
    load,
    neighbors,
    plan_summary,
    query_args,
    settings,
    setup,
)


pytestmark = pytest.mark.postgres


def direction(number: int) -> Vector:
    angle = number / 1000
    values = array("f", [math.cos(angle), math.sin(angle), 0.01 * math.sin(angle * 3)])
    values.extend([0.0] * (DIMENSION - len(values)))
    return Vector(f"direction-{number:04d}", values)


def test_n16_forced_rls_postfilter_and_iteration(shared_db: AppDatabase) -> None:
    tenant = SCOPES[10].workspace
    assert tenant is not None
    foreign = UUID(int=246)
    eligible = {f"direction-{i:04d}" for i in range(1979, 1999)}
    rows = [direction(i) for i in range(1999)]
    rows.sort(key=lambda row: hash_order(row.id, 161125, "insertion"))
    # All globally closest candidates are foreign or retired. The eligible
    # region remains reachable along the arc as the graph scan continues.
    nearest = direction(0).values
    retired = Vector("retired-canary", nearest)
    query = Vector("synthetic-query", nearest)
    positions = {row.id: (tenant if row.id in eligible else foreign) for row in rows}
    positions[retired.id] = tenant

    with shared_db.superuser() as admin:
        setup(admin)
        load(admin, rows, positions, [retired])
        assert admin.execute("SELECT count(*) FROM n16.chunks").fetchone() == (2000,)
        assert admin.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                             "WHERE oid = 'n16.chunks'::regclass").fetchone() == (True, True)
        runtime = shared_db.engine(APP_RUNTIME, pool_size=1)
        with runtime.connect() as connection:
            assert connection.execute(text("SELECT count(*) FROM n16.chunks")).scalar_one() == 0
        with workspace_transaction(runtime, tenant) as connection:
            assert connection.execute(text("SELECT row_security_active('n16.chunks')")).scalar_one()
            assert set(connection.execute(text("SELECT id FROM n16.chunks")).scalars()) == eligible
            truth = neighbors(connection, TRUTH, query_args(query))
            assert len(truth) == K + 1
            assert {key for key, _ in truth} <= eligible

        build(admin, 16, 64, 64, 0, {"spill_notices": []})
        for method in ("off", "strict_order", "relaxed_order"):
            statement = RELAXED if method == "relaxed_order" else ANN
            with workspace_transaction(runtime, tenant) as connection:
                settings(connection, method=method, ef=20, planner="prefer-hnsw",
                         work_mem="16MB", max_scan_tuples=20_000, scan_mem_multiplier=1)
                plan = explain(connection, statement, query_args(query))
                result = neighbors(connection, statement, query_args(query))
            assert plan_summary(plan, method) == ("HNSW", "Index Scan")
            assert {key for key, _ in result} <= eligible
            if method == "off":
                assert len(result) < K
            else:
                assert len(result) == K
                assert [distance for _, distance in result] == sorted(distance for _, distance in result)
