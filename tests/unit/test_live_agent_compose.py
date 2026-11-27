"""Offline checks of the local live-agent composition and its deployment boundary."""

from contextlib import nullcontext
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
import runpy
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import pytest
from sqlalchemy import Connection, create_engine
import yaml  # type: ignore[import-untyped]

from policyops.orchestration.profile import InvestigationProfile
from policyops.persistence.runs import Run
from policyops.providers.tokenizer import load
from policyops.runtime import live_agent, review, worker
from policyops.runtime.clock import DatabaseLeaseClock
from policyops.runtime.investigation import InvestigationExecutor
from policyops.runtime.spec import UNCONFIGURED, RuntimeCatalog, binding
from policyops_contracts.conversation import PolicyContext


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def composition(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    runtime = runpy.run_path(str(ROOT / "infra/compose/runtime.py"))
    engine = create_engine("postgresql+psycopg://")
    monkeypatch.setenv("POLICYOPS_ENV", "local")
    monkeypatch.setenv("POLICYOPS_PUBLIC_ORIGIN", "http://127.0.0.1:8080")
    monkeypatch.setenv("POLICYOPS_RETAIL_ORIGIN", "http://retail:8001")
    monkeypatch.delenv("POLICYOPS_LIVE_AGENT", raising=False)
    globals_ = runtime["worker"].__globals__
    monkeypatch.setitem(globals_, "SECRETS", tmp_path)
    monkeypatch.setitem(globals_, "own_engine", lambda _role: nullcontext(engine))
    monkeypatch.setitem(globals_, "demo_bindings", lambda _engine: ())
    monkeypatch.setitem(globals_, "configure", lambda *_a, **_kw: None)
    monkeypatch.setitem(globals_, "worker_loop", lambda *_a, **_kw: None)
    monkeypatch.setattr(runtime["signal"], "signal", lambda *_: None)
    monkeypatch.setattr(review, "build_review_runtime", lambda **_: SimpleNamespace(
        executor=SimpleNamespace(clock=DatabaseLeaseClock(), scopes=object(), retail=object())))
    monkeypatch.setattr("policyops.runtime.executions.build_execution_dispatcher",
                        lambda **_: SimpleNamespace(dispatch_once=lambda: 0))
    monkeypatch.setattr("policyops.runtime.outbox.build_dispatcher",
                        lambda **_: SimpleNamespace(dispatch_once=lambda: 0))
    (tmp_path / "retail_key").write_bytes(b"synthetic-retail-fixture-material")
    runtime["engine_fixture"] = engine
    return runtime


def observe_catalog(monkeypatch: pytest.MonkeyPatch) -> list[RuntimeCatalog]:
    seen: list[RuntimeCatalog] = []

    def built(**options: Any) -> SimpleNamespace:
        seen.append(options["catalog"])
        return SimpleNamespace(run_once=lambda: 0)

    monkeypatch.setattr(worker, "build_worker", built)
    return seen


def test_default_catalogs_are_unconfigured(composition: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    seen = observe_catalog(monkeypatch)
    assert composition["api_catalog"](composition["engine_fixture"]) is UNCONFIGURED
    composition["worker"]()
    assert len(seen) == 1 and seen[0] is UNCONFIGURED


def test_live_catalog_twins_and_api_refusal(composition: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
                                             tmp_path: Path) -> None:
    monkeypatch.setenv("POLICYOPS_LIVE_AGENT", "1")
    (tmp_path / "openai_api_key").write_text("synthetic-test-credential", encoding="utf-8")
    # Only replace the mounted policy data here. The integration test uses the exact pinned policy bytes.
    policy = PolicyContext.model_construct(domain="retail", source="pinned_retail_policy",
                                           text="Synthetic unit fixture", sha256="a" * 64)
    monkeypatch.setattr(live_agent, "inputs", lambda _: (policy, load()))
    seen = observe_catalog(monkeypatch)
    api = composition["api_catalog"](composition["engine_fixture"])
    composition["worker"]()
    assert len(seen) == 1 and len(api.specs) == len(seen[0].specs) == 1
    api_spec, worker_spec = api.start_spec, seen[0].start_spec
    assert api_spec is not None and worker_spec is not None
    assert api_spec.test_only is worker_spec.test_only is False
    assert binding(api_spec) == binding(worker_spec)
    assert isinstance(api_spec.executor, InvestigationExecutor)
    assert api_spec.executor.profile is InvestigationProfile.TOOL_CONTRACT_V1R1
    assert api_spec.executor.configuration.reservation("agent").model == "gpt-6-luna"
    with pytest.raises(live_agent.LiveAgentRefused, match=r"^live_agent\.api_provider_disabled$"):
        api_spec.executor.providers()


@pytest.mark.parametrize("value", [None, "", " \n"])
def test_worker_refuses_missing_or_blank_secret(composition: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
                                                tmp_path: Path, value: str | None) -> None:
    monkeypatch.setenv("POLICYOPS_LIVE_AGENT", "1")
    if value is not None:
        (tmp_path / "openai_api_key").write_text(value, encoding="utf-8")
    with pytest.raises(live_agent.LiveAgentRefused, match=r"^live_agent\.openai_secret_required$"):
        composition["worker"]()


def test_aggregate_claim_gate_counts_remaining_headroom(monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = uuid4()
    queued = cast(Run, SimpleNamespace(workspace_id=workspace, case_id=uuid4(), state="queued"))
    connection = cast(Connection, object())  # The database reads below are replaced.
    vocab = load()
    monkeypatch.setattr(live_agent, "case_binding", lambda *_: object())
    monkeypatch.setattr(live_agent, "generation", lambda *_: uuid4())
    worst = live_agent.preflight(live_agent.configuration())
    maximum = Decimal("0.50")
    used = maximum - worst
    monkeypatch.setattr(live_agent, "workspace_liability", lambda _: used)
    assert live_agent.claim_refusal(connection, queued, workspace=workspace, aggregate=maximum,
                                   worst=worst, vocab=vocab) is None
    used += Decimal("0.000001")
    assert live_agent.claim_refusal(connection, queued, workspace=workspace, aggregate=maximum,
                                   worst=worst, vocab=vocab) == "live_agent.aggregate_cap"


def test_public_deploy_cannot_load_the_overlay(composition: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    deploy = (ROOT / "infra/deploy/deploy.sh").read_text(encoding="utf-8")
    base = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    public = (ROOT / "infra/compose/public.yaml").read_text(encoding="utf-8")
    assert [line for line in deploy.splitlines() if line.startswith("compose=")] == [
        "compose=(docker compose -f compose.yaml -f infra/compose/public.yaml)"
    ]
    for source in (deploy, base, public):
        assert all(marker not in source for marker in ("live-agent.yaml", "POLICYOPS_LIVE_AGENT", "openai_api_key"))
    for source in (base, public):
        assert not any(line.lstrip().startswith(("include:", "extends:")) for line in source.splitlines())
    monkeypatch.setenv("POLICYOPS_LIVE_AGENT", "1")
    monkeypatch.setenv("POLICYOPS_PUBLIC_ORIGIN", "https://support.example.invalid")
    with pytest.raises(live_agent.LiveAgentRefused, match=r"^live_agent\.local_only$"):
        composition["live_agent_enabled"]()


def test_overlay_secret_network_and_pinned_inputs() -> None:
    base = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    overlay = yaml.safe_load((ROOT / "infra/compose/live-agent.yaml").read_text(encoding="utf-8"))
    assert base["networks"]["default"]["internal"] is True
    assert set(overlay["services"]) == {"api", "worker"}
    api, worker_service = (overlay["services"][name] for name in ("api", "worker"))
    assert api["environment"] == {"POLICYOPS_LIVE_AGENT": "1"}
    assert "secrets" not in api and "networks" not in api
    assert worker_service["secrets"] == ["openai_api_key"]
    assert set(worker_service["networks"]) == {"default", "live-agent-egress"}
    assert worker_service["volumes"] == api["volumes"]
    assert all(mount["read_only"] for mount in api["volumes"])
    assert sha256(live_agent.corpus_manifest()).hexdigest() == live_agent.MANIFEST_SHA256
