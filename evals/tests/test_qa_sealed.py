"""G1 receipts, frozen design and incident/resume negative controls (offline)."""
from __future__ import annotations

import copy
from decimal import Decimal
import json
from pathlib import Path
import sys
import time
import tomllib
from typing import Any

import pytest

from policyops_evals.canonical import canonical_bytes, sha256_bytes
from policyops_evals.qa_studies import registration
from policyops_evals.qa_studies import runner as r
from policyops_evals.qa_studies import selection as s
from policyops_evals.qa_studies.config import QAStudy, load_study, preflight
from policyops_evals.qa_studies.cross_encoder import CrossEncoderClient, Passage, WorkerError
from policyops_evals.qa_studies.guards import HealthyWorker, Streaks

from .test_g8_cross_encoder import WORKER
from .test_qa_answers import answer_study, execute_answers, install_paid
from .test_qa_runner import Memory, memory
from .test_qa_study_config import parse


__all__ = ["memory"]
CONFIGS = Path(__file__).parents[1] / "qa_studies"
GUARDS = {"ce_health_check": "synthetic-score-before-each-use-v1", "ce_restarts_per_use": 1,
          "ce_consecutive_failures": 3, "provider_consecutive_failures": 3,
          "streak_scope": "per-invocation-across-uses-not-slots"}


def report(study: QAStudy, rule: str) -> dict[str, Any]:
    metric, order = s.RULES[rule]
    values = ("281/500", "229/500") if rule == "R1" else ("223/500", "109/250")
    return {"schema_version": "policyops.qa-report/v1", "purpose": "dev", "aggregates": [
        {"arm": arm, "cohort": "dev", "scheduled": 500, "metrics": {metric: value},
         "cost": {"n": 500, "unknown": 0, "held_liability_usd": "0"}}
        for arm, value in zip(order, values, strict=True)], "comparisons": [{"result": {
            "specification_sha256": study.digest(), "missingness": "strict-non-success", "observations": [
                {"arm": arm, "scheduled": 500, "recorded": 500, "missing": 0, "integrity": True,
                 "accounting_settled": True, "held_liability_usd": "0"} for arm in order]}}]}


@pytest.fixture
def selections(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    sources = dict(s.SOURCES)
    monkeypatch.setattr(s, "temp_root", lambda: tmp_path)
    monkeypatch.setattr(s, "SOURCES", sources)
    for rule, (name, identity, _) in list(sources.items()):
        raw = canonical_bytes(report(load_study(CONFIGS / (name + ".json")), rule))
        sources[rule] = name, identity, sha256_bytes(raw)
        path = tmp_path / s.source_path(rule)
        path.parent.mkdir(parents=True)
        path.write_bytes(raw)
    return list(s.command()["receipts"])


def sealed(kind: str, receipts: list[dict[str, Any]]) -> QAStudy:
    value = json.loads((CONFIGS / ("g1-test-" + kind + "-v1.json")).read_bytes())
    value["provenance"]["development_selection_receipts"] = [r["sha256"] for r in receipts]
    for arm in value["arms"]:
        if "selection_receipt_sha256" in arm:
            arm["selection_receipt_sha256"] = receipts[0 if kind == "retrieval" else 1]["sha256"]
    return parse(value)


def test_receipts_deterministic_and_frozen_preflight(selections: list[dict[str, Any]], tmp_path: Path) -> None:
    before = {r["sha256"]: Path(r["path"]).read_bytes() for r in selections}
    assert s.command()["receipts"] == selections
    assert {r["sha256"]: Path(r["path"]).read_bytes() for r in selections} == before
    total = Decimal(0)
    for kind, n in (("retrieval", 1940), ("answers", 1302)):
        study = sealed(kind, selections)
        study.validate_data()
        s.verify(study)
        plan = registration.command(study, register_requested=False)
        assert plan["within_caps"] and not plan["authorizes_paid_execution"]
        total += Decimal(plan["ceiling_usd"])
        assert all(c.required_questions == n and c.alpha == Decimal("0.0125") and not c.uses_judge
                   for c in study.analysis.comparisons)
    assert total == Decimal("24.72354496")
    assert total < 30


@pytest.mark.parametrize("rule", ["R1", "R2"])
def test_selection_tie_order_and_complete_strict_denominator(rule: str) -> None:
    study = load_study(CONFIGS / (s.SOURCES[rule][0] + ".json"))
    value = report(study, rule)
    metric, order = s.RULES[rule]
    for row in value["aggregates"]:
        row["metrics"][metric] = "1/2"
    assert s.select(value, study, rule)["winner"] == order[0]
    # Failed slots stay in the full denominator; they do not invalidate selection.
    value["comparisons"][0]["result"]["observations"][0]["failed"] = 30
    assert s.select(value, study, rule)["scheduled_per_arm"] == 500
    for key, bad in (("missing", 1), ("recorded", 499), ("integrity", False), ("accounting_settled", False)):
        changed = copy.deepcopy(value)
        changed["comparisons"][0]["result"]["observations"][0][key] = bad
        with pytest.raises(ValueError):
            s.select(changed, study, rule)
    changed = copy.deepcopy(value)
    changed["comparisons"][0]["result"]["specification_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="specification"):
        s.select(changed, study, rule)
    changed = copy.deepcopy(value)
    changed["aggregates"].pop()
    with pytest.raises(ValueError, match="missing arm"):
        s.select(changed, study, rule)


def test_missing_mismatched_reports_and_receipts(selections: list[dict[str, Any]], tmp_path: Path) -> None:
    study = sealed("answers", selections)
    receipt = Path(selections[1]["path"])
    original = receipt.read_bytes()
    receipt.write_bytes(original + b" ")
    with pytest.raises(ValueError, match="receipt bytes"):
        registration.command(study, register_requested=False)
    receipt.write_bytes(original)
    path = tmp_path / s.source_path("R2")
    raw = path.read_bytes()
    path.write_bytes(raw + b" ")
    with pytest.raises(ValueError, match="report digest"):
        s.command()
    path.unlink()
    with pytest.raises(FileNotFoundError):
        s.command()


@pytest.mark.parametrize("change", ["split", "alpha", "claims", "receipt", "headroom", "denominator", "cohort"])
def test_sealed_contract_negative_controls(change: str) -> None:
    value = json.loads((CONFIGS / "g1-test-answers-v1.json").read_bytes())
    if change == "split":
        value["schedule"]["cohorts"][0]["split"] = "train"
    elif change == "alpha":
        value["analysis"]["comparisons"][0]["alpha"] = "0.025"
    elif change == "claims":
        value["analysis"]["withdrawn_claims"] = []
    elif change == "receipt":
        value["arms"][2].pop("selection_receipt_sha256")
    elif change == "headroom":
        value["judge"]["max_input_tokens"] = 6500
    elif change == "denominator":
        value["analysis"]["comparisons"][0]["required_questions"] = 1301
    else:
        value["schedule"]["cohorts"][0]["manifest_cohort"] = "dev"
    with pytest.raises(ValueError):
        parse(value)


def test_frozen_arm_prompt_and_receipt_binding(selections: list[dict[str, Any]]) -> None:
    study = sealed("answers", selections)
    for change in ("prompt", "receipt"):
        value = study.model_dump(mode="json")
        if change == "prompt":
            value["arms"][0]["generator"]["prompt_sha256"] = "f" * 64
        else:
            value["provenance"]["development_selection_receipts"] = []
        with pytest.raises(ValueError):
            s.verify(parse(value))


def test_registration_requires_gated_commit_before_database(selections: list[dict[str, Any]]) -> None:
    study = sealed("retrieval", selections)
    with pytest.raises(ValueError, match="gated commit"):
        registration.validate_registration(study, {"dirty_sha256": "f" * 64})


def test_run_refuses_receipt_before_materialization_or_database(selections: list[dict[str, Any]],
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    study = sealed("retrieval", selections)
    Path(selections[0]["path"]).write_bytes(b"{}")
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("materialization/database accessed before receipt check")
    monkeypatch.setattr(r, "load_inputs", forbidden)
    monkeypatch.setattr(r, "make_engine", forbidden)
    from uuid import uuid4

    with pytest.raises(ValueError, match="receipt bytes"):
        r.command(study, "run", materialization=tmp_path / "absent", app_dsn_file=tmp_path / "no-app-dsn",
                  eval_dsn_file=tmp_path / "no-eval-dsn", workspace=uuid4(), corpus="synthetic", allow_paid=True)


def test_haiku_headroom_and_exact_cost_envelopes() -> None:
    study = load_study(CONFIGS / "g1-test-answers-v1.json")
    assert study.judge is not None and study.judge.max_input_tokens == 8192
    assert Decimal("1.25") * 6516 <= 8192
    actor = r.composition_configuration(study, study.judge, "judge").actors["judge"]
    assert actor is not None
    # The application also adds 10%/256 minimum admission headroom to the official count.
    assert actor.count_headroom_percent == 10 and actor.count_headroom_min == 256
    assert 6516 + max((6516 * actor.count_headroom_percent + 99) // 100, actor.count_headroom_min) == 7168
    assert study.judge.max_input_tokens > 7168
    assert 6161 + 617 > 6500  # explains rejections even below the old raw count envelope
    assert all(s.max_input_tokens == 8192 and s.planned_calls == 1302 * 4
               for s in study.execution.stages if s.role == "judge")
    assert preflight(study)["within_caps"]
    # Every tested generator/model/prompt/output binding remains identical to dev.
    dev = load_study(CONFIGS / "g1-dev-answers-v2.json")
    assert {a.name: getattr(a, "generator", None) for a in study.arms} == {
        a.name: getattr(a, "generator", None) for a in dev.arms if a.name != "dense-history-luna"}


@pytest.mark.parametrize("recover", [True, False])
@pytest.mark.parametrize("failure", ["eof", "score-fail"])
def test_ce_health_check_restart_once_and_reap(tmp_path: Path, recover: bool, failure: str) -> None:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    raw = b'{"files":{}}'
    (artifact / "artifact-manifest.json").write_bytes(raw)
    script = tmp_path / "worker.py"
    log = tmp_path / "requests.jsonl"
    script.write_bytes(WORKER.replace("request = json.loads(line)",
        "request = json.loads(line)\n    "
        f"with open({str(log)!r}, 'a', encoding='utf8') as f: f.write(request['query']+'\\n')\n    "
        "if mode == 'score-fail' and request['query'] != 'health': sys.exit(0)").encode())
    clients: list[CrossEncoderClient] = []

    def factory(timeout: float) -> CrossEncoderClient:
        mode = "ok" if clients and recover else failure
        client = CrossEncoderClient(artifact, sha256_bytes(raw), timeout=timeout,
            command=[sys.executable, "-B", str(script), mode, sha256_bytes(raw)])
        clients.append(client)
        return client

    guarded = HealthyWorker(factory)
    guarded.deadline = time.monotonic() + 10
    try:
        if recover:
            assert guarded.rerank("q", [Passage(id="p", text="p")], top_k=1).ranking == ["p"]
            assert guarded.rerank("again", [Passage(id="p", text="p")], top_k=1).ranking == ["p"]
        else:
            with pytest.raises(WorkerError):
                guarded.rerank("q", [Passage(id="p", text="p")], top_k=1)
        assert len(clients) == 2  # exactly one replacement, successful worker reused
        assert clients[0].process.poll() is not None
        if recover:
            assert log.read_text(encoding="utf8").splitlines()[-4:] == ["health", "q", "health", "again"]
    finally:
        for client in clients:
            client.close()
    assert all(c.process.poll() is not None for c in clients)


def test_incident_streaks_ignore_other_work_and_reset_on_recovery() -> None:
    streak = Streaks()
    for _ in range(2):
        streak.observe_ce(True)
        streak.observe_provider(False)
    assert streak.reason() is None
    streak.observe_ce(False)
    assert streak.ce == 0
    for _ in range(3):
        streak.observe_provider(True, "claude-haiku-5-5")
        streak.observe_provider(False, "gpt-6-luna")
        streak.observe_ce(False)
    assert streak.reason() == "consecutive_provider_failures"


def test_existing_tokenizer_exception_covers_only_exact_public_binding() -> None:
    import re

    value = tomllib.loads((CONFIGS.parents[1] / ".gitleaks.toml").read_text(encoding="utf-8"))
    entry = next(a for a in value["allowlists"] if "tokenizer digest" in a["description"])
    # Python regex uses \Z where the pinned Go scanner spells strict end as \z.
    def matches(pattern: str, text: str) -> bool:
        return re.fullmatch(pattern.replace(r"\z", r"\Z"), text) is not None
    assert entry["condition"] == "AND" and entry["targetRules"] == ["generic-api-key"]
    assert matches(entry["paths"][0], "evals/qa_studies/g1-test-answers-v1.json")
    assert not matches(entry["paths"][0], "evals/qa_studies/unrelated.json")
    assert matches(entry["regexes"][0], "d241a60d5e8f04cc1b2b3e9ef7a4921b27bf526d9f6050ab90f9267a1f9e5c66")
    assert not matches(entry["regexes"][0], "f" * 64)


@pytest.mark.parametrize("incident", ["ce", "provider"])
def test_guard_aborts_before_next_claim_and_resume_preserves_failures(incident: str, tmp_path: Path,
        memory: Memory, monkeypatch: pytest.MonkeyPatch) -> None:
    study, inputs, path, source = answer_study(tmp_path)
    value = study.model_dump(mode="json")
    value["schedule"]["repetitions"] = 2
    value["execution"]["incident_guards"] = GUARDS
    study = parse(value)
    install_paid(monkeypatch, memory)
    calls: list[str] = []

    def execute(self: r.AnswerExecutor, arm: Any, query: Any, *args: Any, **kwargs: Any) -> None:
        calls.append(str(self.item.id))
        if incident == "ce" and arm.name != "rrf-bm25-base-ce":
            return
        if incident == "ce":
            args[3].rerank_metadata["ce_failed"] = True
            raise r.Refused("cross_encoder_failure")
        args[3].provider_outcomes.append(("gpt-6-luna", True))
        raise r.Refused("answer_call_failed")

    monkeypatch.setattr(r.AnswerExecutor, "execute", execute)
    first = execute_answers(study, inputs, path, source, memory)
    assert first["abort_reason"] == "consecutive_" + incident + "_failures"
    assert not first["execution_complete"]
    failed = {k: copy.deepcopy(v) for k, v in memory.rows.items() if v["outcome"] == "error"}
    assert len(failed) == 3
    before = set(calls)
    monkeypatch.setattr(r.AnswerExecutor, "execute", lambda *args, **kwargs: None)
    assert execute_answers(study, inputs, path, source, memory, resume=True)["execution_complete"]
    assert set(calls) == before
    assert all(memory.rows[k] == v for k, v in failed.items())
