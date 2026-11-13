"""Explicit pytest fixtures for the same environments owned by the standalone CLI."""

from collections.abc import Iterator
from typing import Any

import pytest

from policyops_testing.app_database import AppDatabase
from policyops_testing.safety.config import FAULTS, Config, Pair
from policyops_testing.safety.environment import Env, make_env
from policyops_testing.safety.retail import Service


def recovery_test_pairs(config: Config) -> dict[str, tuple[Pair, Pair | None]]:
    """Select distinct schedule pairs for the paired and fencing recovery checks."""
    selected: dict[str, tuple[Pair, Pair | None]] = {}
    fenced_faults = {"crash_before_send", "fail_503_before", "duplicate_delivery"}
    for fault in FAULTS:
        paired = next(pair for pair in config.pairs if pair.fault == fault)
        fenced = None
        if fault in fenced_faults:
            fenced = next(pair for pair in config.pairs
                          if pair.fault == fault and pair.variant == "pending_address"
                          and pair.pair_id != paired.pair_id)
        selected[fault] = (paired, fenced)
    return selected


@pytest.fixture(scope="module")
def safety_live(postgres: Any, shared_db: AppDatabase, tmp_path_factory: pytest.TempPathFactory
                ) -> Iterator[tuple[Service, str]]:
    service = Service(postgres, shared_db, tmp_path_factory.mktemp("t30-retail"))
    with service.running() as origin:
        yield service, origin


@pytest.fixture
def safety_env(safety_live: tuple[Service, str], shared_db: AppDatabase) -> Env:
    return make_env(safety_live, shared_db)
