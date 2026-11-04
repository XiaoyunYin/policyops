"""pytest plugin shared by the application and evaluator suites (`pytest_plugins = ["policyops_testing.plugin"]`).

* The network guard is installed in `pytest_configure`, before collection, so import-time code in test modules is
  covered too, and removed in `pytest_unconfigure`.
* `seed`: one deterministic seed per session (`POLICYOPS_TEST_SEED`, default 20261104), shown in the report
  header and applied to `random` before every test.
* `fake_provider`: factory for scripted providers; every script must be fully consumed by the end of the test.
* `allow_endpoint`: register an exact loopback endpoint for one test (revoked at teardown).
* `evidence_recorder`: an EvidenceRecorder below POLICYOPS_TEMP_DIR/tests/evidence/<session>/<test>.
* `postgres`: session-scoped owned PostgreSQL (application suite only; tests must carry the `postgres` marker,
  which default runs deselect).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
import contextlib
import os
from pathlib import Path
import random
import re
import secrets
import time
from typing import Any

import pytest

from policyops_testing import network
from policyops_testing.evidence import EvidenceRecorder
from policyops_testing.fake_provider import FakeProvider, Step


DEFAULT_SEED = 20261104
SESSION_ID = f"{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}-{secrets.token_hex(3)}"


def session_seed() -> int:
    raw = os.environ.get("POLICYOPS_TEST_SEED", str(DEFAULT_SEED))
    if not re.fullmatch(r"\d{1,18}", raw):
        raise pytest.UsageError("POLICYOPS_TEST_SEED must be a non-negative integer")
    return int(raw)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "postgres: needs Docker and the pinned PostgreSQL image (deselected by default)")
    network.install()


def pytest_unconfigure(config: pytest.Config) -> None:
    network.uninstall()


def pytest_report_header(config: pytest.Config) -> list[str]:
    guard = "on" if network.installed() else "off"
    return [f"policyops: seed={session_seed()} session={SESSION_ID} network guard={guard}"]


@pytest.fixture
def seed() -> int:
    value = session_seed()
    random.seed(value)
    return value


@pytest.fixture(autouse=True)
def _deterministic_random() -> None:
    random.seed(session_seed())


@pytest.fixture
def fake_provider() -> Iterator[Callable[[Sequence[Step]], FakeProvider]]:
    created: list[FakeProvider] = []

    def make(script: Sequence[Step]) -> FakeProvider:
        provider = FakeProvider(script=tuple(script))
        created.append(provider)
        return provider

    yield make
    for provider in created:
        provider.assert_exhausted()


@pytest.fixture
def allow_endpoint() -> Iterator[Callable[[str, int], tuple[str, int]]]:
    with contextlib.ExitStack() as stack:
        def register(host: str, port: int) -> tuple[str, int]:
            return stack.enter_context(network.allow(host, port))

        yield register


def _temp_root() -> Path:
    return Path(os.environ["POLICYOPS_TEMP_DIR"])


@pytest.fixture
def evidence_recorder(request: pytest.FixtureRequest) -> EvidenceRecorder:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "-", request.node.name)[:60]
    root = _temp_root() / "tests" / "evidence" / SESSION_ID / name
    return EvidenceRecorder(root, run_id=f"{SESSION_ID}-{name}"[:80], task_id="T05", purpose=request.node.nodeid[:200],
                            seed=session_seed())


@pytest.fixture(scope="session")
def postgres(request: pytest.FixtureRequest) -> Iterator[Any]:
    from policyops_testing.postgres import PostgresUnavailable, owned_postgres

    base = _temp_root() / "tests" / "postgres"
    base.mkdir(parents=True, exist_ok=True)
    try:
        with owned_postgres(base, SESSION_ID) as server:
            yield server
    except PostgresUnavailable as exc:
        pytest.fail(f"owned PostgreSQL unavailable (explicitly selected postgres tests fail, never skip): {exc}")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        if "postgres" in getattr(item, "fixturenames", ()) and item.get_closest_marker("postgres") is None:
            raise pytest.UsageError(f"{item.nodeid} uses the postgres fixture without the postgres marker")
