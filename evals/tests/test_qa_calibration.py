"""G6 sampling, freezing, strict missingness, admission and registration."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from decimal import Decimal
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal
from uuid import UUID, uuid4, uuid5

import pytest

from policyops.budget.ledger import Scope
from policyops.providers.accounting import AccountingUnconfirmed
from policyops.providers.calls import AttemptRecord, CallReport
from policyops.providers.tokenizer import InputRefused
from policyops_contracts.model import ModelResult, ReportedUsage
from policyops_evals.canonical import canonical_bytes, sha256_bytes, with_self_digest
from policyops_evals.cli import main
from policyops_evals.qa_studies import calibration as g6
from policyops_evals.qa_studies.judges import ARMS


@pytest.fixture
def sample() -> dict[str, Any]:
    items = []
    for split in ("dev", "test"):
        for name in g6.CONSTITUENTS:
            for index in range(2):
                row = g6.Row(split, index, name, f"Document {split} {name} {index}.", "A claim.", bool(index))
                items.append(row.public({a.name: 1000 for a in ARMS}))
    return with_self_digest({"schema_version": "policyops.g6-sample/v1", "protocol": g6.PROTOCOL,
        "source_revision": g6.REVISION, "source_sha256": g6.SPLIT_HASHES, "items": items})


def stub_agreement(items: list[dict[str, Any]], predictions: list[bool | None], **_: Any) -> dict[str, Any]:
    negatives = sum(not i["label"] for i in items)
    false_pass = sum(not i["label"] and p is True for i, p in zip(items, predictions, strict=True)) / negatives
    return {"n": len(items), "errors": predictions.count(None),
        "coverage": sum(p is not None for p in predictions) / len(items), "kappa": 0.8,
        "kappa_low": 0.6, "kappa_high": 0.9, "balanced_accuracy": 0.8,
        "per_class_recall": {"positive": 0.8, "negative": 0.8},
        "false_pass_rate": {"point": false_pass, "low": 0, "high": 0.2}, "confusion": {}}


def fake_run(path: Path, sample: dict[str, Any], *, split: str = "dev",
             receipt: dict[str, Any] | None = None) -> Path:
    path.mkdir()
    schedule = g6.scheduled(sample, split, receipt)
    plan = g6.planning(sample, split, max_usd=g6.STAGE_USD[split], max_calls=len(schedule),
                       max_counts=len(schedule), max_seconds=7200, receipt=receipt)
    (path / "run.json").write_bytes(canonical_bytes({"schema_version": "policyops.g6-run/v1",
        "plan": plan, "selection": receipt, "registration": {"sha256": "a" * 64} if split == "test" else None}))
    lines = [{"arm": a.name, "id": i["id"], "predicted": i["label"], "accounting_settled": True,
              "cost_usd": "0.0001"} for a, i in schedule]
    (path / "predictions.jsonl").write_bytes(b"".join((json.dumps(r) + "\n").encode() for r in lines))
    (path / "settlement.json").write_bytes(canonical_bytes({"failure": None, "scope": {
        "held_usd": "0", "overrun": False, "contract_block": False}}))
    return path


def test_sampler_real_pinned_bytes_and_exact_counts() -> None:
    raw = os.environ.get("POLICYOPS_AGGREFACT_DIR")
    if not raw:
        pytest.skip("set POLICYOPS_AGGREFACT_DIR to the pinned private conversion")
    rebuilt = g6.build_sample(Path(raw))
    committed = g6.load_sample()
    assert canonical_bytes(rebuilt) == canonical_bytes(committed)
    assert len(canonical_bytes(rebuilt)) < 1_000_000
    assert [rebuilt["counts"][f"dev/{name}"]["selected"] for name in g6.CONSTITUENTS] == [100] * 4
    assert [rebuilt["counts"][f"test/{name}"]["selected"] for name in g6.CONSTITUENTS[:3]] == [400] * 3
    assert rebuilt["counts"]["test/Wice"]["selected"] == rebuilt["counts"]["test/Wice"]["eligible"] == 338
    assert sum(i["split"] == "test" for i in rebuilt["items"]) == 1538
    assert {k: v["excluded"] for k, v in rebuilt["counts"].items()} == {
        "dev/RAGTruth": 0, "dev/ExpertQA": 94, "dev/ClaimVerify": 83, "dev/Wice": 22,
        "test/RAGTruth": 178, "test/ExpertQA": 92, "test/ClaimVerify": 106, "test/Wice": 20}
    dev_docs = {i["document_sha256"] for i in rebuilt["items"] if i["split"] == "dev"}
    dev_claims = {i["claim_sha256"] for i in rebuilt["items"] if i["split"] == "dev"}
    assert not dev_docs & {i["document_sha256"] for i in rebuilt["items"] if i["split"] == "test"}
    assert not dev_claims & {i["claim_sha256"] for i in rebuilt["items"] if i["split"] == "test"}


def test_public_manifest_contains_only_approved_item_fields() -> None:
    sample = g6.load_sample()
    def inspect(value: Any) -> None:
        if isinstance(value, dict):
            assert not ({"doc", "document", "claim", "text", "reason", "contamination_identifier"} & value.keys())
            for item in value.values():
                inspect(item)
        elif isinstance(value, list):
            for item in value:
                inspect(item)
    inspect(sample)
    assert all(set(i) == g6.ITEM_FIELDS for i in sample["items"])


def test_overlap_folding_and_sampler_determinism(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert g6.content_hash("Cafe\u0301\n  policy") == g6.content_hash("Café policy")
    source: dict[str, list[g6.Row]] = {"dev": [], "test": []}
    for split in source:
        for constituent in g6.CONSTITUENTS:
            count = 110 if split == "dev" else (358 if constituent == "Wice" else 410)
            source[split].extend(g6.Row(split, index, constituent, f"doc {split} {constituent} {index}",
                f"claim {split} {constituent} {index}", index % 3 != 0) for index in range(count))
    # Overlap with a non-constituent dev row must also be dropped.
    source["dev"].append(g6.Row("dev", 999, "Lfqa", "Shared document.", "Shared claim.", True))
    source["test"].extend([
        g6.Row("test", 500, "RAGTruth", "Shared\n document.", "A unique test claim.", True),
        g6.Row("test", 501, "ExpertQA", "Unique document.", "Shared   claim.", False)])
    monkeypatch.setattr(g6, "rows", lambda _, split: iter(source[split]))
    monkeypatch.setattr(g6, "eligibility", lambda *_: ({a.name: 1000 for a in ARMS}, None))
    (tmp_path / "conversion-manifest.json").write_bytes(b"{}")
    tokenizer: Any = SimpleNamespace(identity_sha256="a" * 64)
    first = g6.build_sample(tmp_path, tokenizer)
    assert canonical_bytes(first) == canonical_bytes(g6.build_sample(tmp_path, tokenizer))
    for split in source:
        source[split] = [replace(r, gold=not r.gold) for r in source[split]]
    changed_labels = g6.build_sample(tmp_path, tokenizer)
    assert [i["id"] for i in first["items"]] == [i["id"] for i in changed_labels["items"]]
    assert first["exclusions"]["test/RAGTruth/dev_overlap"] == 1
    assert first["exclusions"]["test/ExpertQA/dev_overlap"] == 1
    assert first["overlap_test_exclusions"] == [["RAGTruth", 500, True, False], ["ExpertQA", 501, False, True]]


def test_eligibility_common_envelope_and_local_safety(monkeypatch: pytest.MonkeyPatch) -> None:
    row = g6.Row("dev", 1, "Wice", "doc", "claim", True)
    monkeypatch.setattr(g6, "local_count", lambda *_: 5454)
    counts, reason = g6.eligibility(row, object())  # type: ignore[arg-type]
    assert reason is None and len(counts) == 3
    monkeypatch.setattr(g6, "local_count", lambda *_: 5455)
    assert g6.eligibility(row, object())[1] == "envelope"  # type: ignore[arg-type]
    def refused(*_: Any) -> int:
        raise InputRefused("input_piece_too_long", 0)
    monkeypatch.setattr(g6, "local_count", refused)
    assert g6.eligibility(row, object())[1] == "local_bounds"  # type: ignore[arg-type]


def test_preflight_arithmetic_and_stage_partition(sample: dict[str, Any]) -> None:
    plan = g6.planning(sample, "dev", max_usd=Decimal("3"), max_calls=24, max_counts=24, max_seconds=7200)
    assert plan["caps"]["retries"] == plan["caps"]["repairs"] == 0
    assert plan["price_revision"] == "pricing.2026-11-05.v1"
    assert plan["authorizes_paid_execution"] is False
    assert Decimal(plan["reservation_ceiling_usd"]) == Decimal("24") * Decimal("0.000856")
    assert Decimal(plan["local_count_output_ceiling_usd"]) == Decimal(24) * Decimal("0.0003816")
    assert sum(g6.STAGE_USD.values()) == Decimal(5)
    assert g6.scope_key(sample, "dev") != g6.scope_key(sample, "test")
    changed = sample | {"manifest_sha256": "f" * 64}
    assert g6.scope_key(sample, "dev") == g6.scope_key(changed, "dev")
    assert g6.scope_manifest(sample, "dev", None) != g6.scope_manifest(changed, "dev", None)


@pytest.mark.parametrize("usd,calls,counts,seconds", [
    ("3.01", 24, 24, 7200), ("NaN", 24, 24, 7200), ("0", 24, 24, 7200),
    ("3", 23, 24, 7200), ("3", 24, 25, 7200), ("3", 24, 24, 0), (".001", 24, 24, 7200)])
def test_caps_refuse(sample: dict[str, Any], usd: str, calls: int, counts: int, seconds: int) -> None:
    with pytest.raises(ValueError):
        g6.planning(sample, "dev", max_usd=Decimal(usd), max_calls=calls, max_counts=counts, max_seconds=seconds)


def test_paid_opt_in_precedes_database_or_credentials(sample: dict[str, Any],
                                                     monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def forbidden() -> None:
        pytest.fail("database access before paid admission")
    monkeypatch.setattr(g6, "environment_repository", forbidden)
    plan = g6.planning(sample, "dev", max_usd=Decimal(3), max_calls=24, max_counts=24, max_seconds=7200)
    with pytest.raises(ValueError, match="execute-paid"):
        g6.command_run(sample, plan, None, directory=tmp_path, output=tmp_path, execute_paid=False, config_path=None)
    with pytest.raises(ValueError, match="selection"):
        g6.planning(sample, "test", max_usd=Decimal(2), max_calls=8, max_counts=8, max_seconds=7200)


def test_selection_tiebreaks_and_receipt_hash(sample: dict[str, Any], tmp_path: Path) -> None:
    run = fake_run(tmp_path / "dev", sample)
    report = g6.report_run(sample, run, calculate=stub_agreement)
    names = [a.name for a in ARMS]
    report["arms"][names[0]]["macro_balanced_accuracy"] = "0.90"
    report["arms"][names[0]]["cost_usd"] = "2.9"
    assert g6.select_arm(report, sample)["binding"]["arm"] == names[0]
    report["arms"][names[0]]["macro_balanced_accuracy"] = "0.8"
    report["arms"][names[1]]["pooled"]["false_pass_rate"]["point"] = 0.1
    report["arms"][names[2]]["cost_usd"] = "0.1"
    assert g6.select_arm(report, sample)["binding"]["arm"] == names[2]
    report["arms"][names[1]]["pooled"]["false_pass_rate"]["point"] = 0.0
    assert g6.select_arm(report, sample)["binding"]["arm"] == names[1]
    receipt = g6.select_arm(report, sample)
    path = tmp_path / "selection.json"
    path.write_bytes(canonical_bytes(receipt))
    assert g6.digest(receipt) == sha256_bytes(path.read_bytes())
    assert g6.selection(path, sample) == receipt
    changed = deepcopy(receipt)
    changed["binding"]["effort"] = "high"
    path.write_bytes(canonical_bytes(changed))
    with pytest.raises(ValueError):
        g6.selection(path, sample)
    report["arms"][names[0]]["complete"] = False
    with pytest.raises(ValueError, match="complete"):
        g6.select_arm(report, sample)


@pytest.mark.parametrize("failure", ["missing", "invalid", "unsettled", "held", "stopped"])
def test_incomplete_run_fails_selection_and_judge_gate(sample: dict[str, Any], tmp_path: Path, failure: str) -> None:
    dev = fake_run(tmp_path / "dev", sample)
    receipt = g6.select_arm(g6.report_run(sample, dev, calculate=stub_agreement), sample)
    run = fake_run(tmp_path / "test", sample, split="test", receipt=receipt)
    predictions = [json.loads(line) for line in (run / "predictions.jsonl").read_bytes().splitlines()]
    settlement = json.loads((run / "settlement.json").read_bytes())
    if failure == "missing":
        predictions.pop()
    elif failure == "invalid":
        predictions[0]["predicted"] = None
    elif failure == "unsettled":
        predictions[0]["accounting_settled"] = False
    elif failure == "held":
        settlement["scope"]["held_usd"] = "0.001"
    else:
        settlement["failure"] = "deadline"
    (run / "predictions.jsonl").write_bytes(b"".join((json.dumps(r) + "\n").encode() for r in predictions))
    (run / "settlement.json").write_bytes(canonical_bytes(settlement))
    report = g6.report_run(sample, run, calculate=stub_agreement)
    assert not report["gate_passed"]
    assert report["judge_result"]["complete"] is False


def test_error_is_none_in_document_cluster_statistics(sample: dict[str, Any], tmp_path: Path) -> None:
    run = fake_run(tmp_path / "dev", sample)
    lines = (run / "predictions.jsonl").read_bytes().splitlines()
    row = json.loads(lines[0])
    row["predicted"] = None
    lines[0] = json.dumps(row).encode()
    (run / "predictions.jsonl").write_bytes(b"\n".join(lines) + b"\n")
    report = g6.report_run(sample, run, calculate=stub_agreement)
    assert report["arms"][ARMS[0].name]["pooled"]["errors"] == 1
    assert report["arms"][ARMS[0].name]["pooled"]["coverage"] == 7 / 8


def test_prior_registration_and_changed_selection_refused() -> None:
    scope = uuid4()
    payload = {"selection_receipt_sha256": "a" * 64}
    repository: Any = SimpleNamespace(run_configuration=lambda _: None)
    with pytest.raises(ValueError, match="missing or changed"):
        g6.require_registration(repository, scope, payload)
    receipt = {"payload": payload, "sha256": g6.digest(payload), "created_at": datetime.now(UTC).isoformat()}
    repository.run_configuration = lambda _: {"registration": receipt}
    repository.registration_precedes_claims = lambda *_: True
    assert g6.require_registration(repository, scope, payload) == receipt
    with pytest.raises(ValueError, match="missing or changed"):
        g6.require_registration(repository, scope, {"selection_receipt_sha256": "b" * 64})
    repository.registration_precedes_claims = lambda *_: False
    with pytest.raises(ValueError, match="precede"):
        g6.require_registration(repository, scope, payload)


def test_committed_test_config_and_source_required(sample: dict[str, Any], tmp_path: Path,
                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    receipt = g6.select_arm(g6.report_run(sample, fake_run(tmp_path / "dev", sample),
                                         calculate=stub_agreement), sample)
    with pytest.raises(ValueError):
        g6.committed_config(tmp_path / "untracked.json", g6.test_configuration(sample, receipt))
    monkeypatch.setattr(g6, "committed_config", lambda *_: "evals/manifests/fake.json")
    with pytest.raises(ValueError, match="clean"):
        g6.registration_payload(sample, receipt, tmp_path, {}, {"dirty_sha256": "f" * 64})


def test_statistics_contract_is_called_with_document_clusters(sample: dict[str, Any],
                                                             monkeypatch: pytest.MonkeyPatch) -> None:
    @dataclass
    class Result:
        n: int
    captured: dict[str, Any] = {}
    def binary(gold: Any, predicted: Any, clusters: Any, **kwargs: Any) -> Result:
        captured.update(gold=gold, predicted=predicted, clusters=clusters, **kwargs)
        return Result(len(gold))
    monkeypatch.setattr(g6, "binary_agreement", binary)
    items = sample["items"][:2]
    assert g6.agreement(items, [True, None]) == {"n": 2}
    assert captured["clusters"] == [i["document_sha256"] for i in items]
    assert captured["predicted"] == [True, None]
    assert captured["seed"] == 20261114 and captured["replicates"] == 10000


def test_real_statistics_adapter_reports_errors_and_confusion(sample: dict[str, Any]) -> None:
    items = sample["items"][:8]
    predictions = [i["label"] for i in items]
    actual = g6.agreement(items, predictions, replicates=10)
    assert actual["kappa"] == 1 and actual["balanced_accuracy"] == 1
    assert actual["false_pass_rate"]["point"] == 0
    assert actual["confusion"] == {"true_negative": 4, "false_positive": 0, "false_negative": 0,
                                    "true_positive": 4, "error_negative": 0, "error_positive": 0}


@pytest.mark.parametrize("mode", ["settled", "unresolved", "accounting-error"])
def test_offline_run_driver_caps_and_stop_on_unsettled(sample: dict[str, Any], tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch, mode: Literal["settled", "unresolved", "accounting-error"]) -> None:
    plan = g6.planning(sample, "dev", max_usd=Decimal(3), max_calls=24, max_counts=24, max_seconds=7200)
    scope_id = uuid4()
    states = {scope_id: Scope(scope_id, "study", Decimal(3), 24, Decimal(0), Decimal(0), 0, 0, False)}
    invoked = []
    class Store:
        def scope(self, identity: UUID) -> Scope:
            return states[identity]

        def ensure_invocation(self, scope: UUID, invocation: UUID, _: Any) -> UUID:
            assert scope == scope_id
            return invocation

        def ensure_scenario(self, scope: UUID, task: str, _: int, __: str, ___: Any) -> UUID:
            identity = uuid5(scope, task)
            states[identity] = Scope(identity, "scenario", Decimal(3), 1, Decimal(0), Decimal(0), 0, 0, False)
            return identity
    store = Store()
    monkeypatch.setattr(g6, "build_eval_ledger", lambda **_: (object(), store))
    monkeypatch.setattr(g6, "load", lambda: object())
    monkeypatch.setattr(g6, "require_clean_environment", lambda _: None)
    monkeypatch.setenv("OPENAI_API_KEY", "offline-fixture")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "offline-fixture")
    monkeypatch.setattr(g6, "eligibility", lambda *_: ({a.name: 1000 for a in ARMS}, None))
    private_rows = [g6.Row(i["split"], i["row_index"], i["constituent"],
        f"Document {i['split']} {i['constituent']} {i['row_index']}.", "A claim.", i["label"])
        for i in sample["items"] if i["split"] == "dev"]
    monkeypatch.setattr(g6, "rows", lambda *_: iter(private_rows))
    async def fake_call(*args: Any, **kwargs: Any) -> CallReport:
        limits = kwargs["limits"]
        assert limits.retries_per_request == limits.repairs == 0
        assert limits.attempt_seconds == 60
        binding = args[2]
        assert args[3] == uuid5(scope_id, "g6-invocation/v1")
        assert args[6] == "judge"
        invoked.append(args[4])
        states[binding.scenario_id] = replace(states[binding.scenario_id], spent_usd=Decimal(".0002"))
        states[scope_id] = replace(states[scope_id], spent_usd=Decimal(".0002") * len(invoked),
                                  calls_consumed=len(invoked), counts_used=len(invoked))
        report = CallReport(ModelResult(provider="openai", requested_model="gpt-6-luna", outcome="structured",
            structured_json='{"supported":false,"reason":"A brief fixture reason."}',
            usage=ReportedUsage(state="known", input_total=1000, cache_read=0, output=50)),
            "result", None, [AttemptRecord(uuid4(), args[4], None,
                                          fate="settled" if mode == "settled" else "unresolved")])
        if mode == "accounting-error":
            raise AccountingUnconfirmed(report)
        return report
    monkeypatch.setattr(g6, "call", fake_call)
    repository: Any = SimpleNamespace(engine=object())
    lease: Any = SimpleNamespace()
    asyncio.run(g6.execute(repository, scope_id, lease, sample, plan, None, tmp_path, tmp_path))
    predictions = [json.loads(line) for line in (tmp_path / "predictions.jsonl").read_bytes().splitlines()]
    assert len(invoked) == (24 if mode == "settled" else 1)
    assert len(set(invoked)) == len(invoked)
    assert len(predictions) == len(invoked)
    assert all(p["predicted"] is False if mode == "settled" else p["predicted"] is None for p in predictions)
    assert predictions[0]["billing"]["usage"]["input_total"] == 1000
    assert "Document dev" not in (tmp_path / "predictions.jsonl").read_text(encoding="utf-8")
    assert "fixture reason" not in (tmp_path / "predictions.jsonl").read_text(encoding="utf-8")


def test_persisted_admission_precedes_key_read(sample: dict[str, Any], tmp_path: Path,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
    plan = g6.planning(sample, "dev", max_usd=Decimal(3), max_calls=24, max_counts=24, max_seconds=7200)
    private_rows = [g6.Row(i["split"], i["row_index"], i["constituent"],
        f"Document {i['split']} {i['constituent']} {i['row_index']}.", "A claim.", i["label"])
        for i in sample["items"] if i["split"] == "dev"]
    monkeypatch.setattr(g6, "rows", lambda *_: iter(private_rows))
    monkeypatch.setattr(g6, "load", lambda: object())
    monkeypatch.setattr(g6, "eligibility", lambda *_: ({a.name: 1000 for a in ARMS}, None))
    identity = uuid4()
    occupied = Scope(identity, "study", Decimal(3), 24, Decimal(".001"), Decimal(0), 1, 0, False)
    monkeypatch.setattr(g6, "build_eval_ledger", lambda **_: (object(), SimpleNamespace(scope=lambda _: occupied)))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    repository: Any = SimpleNamespace(engine=object())
    lease: Any = SimpleNamespace()
    with pytest.raises(ValueError, match="already attempted"):
        asyncio.run(g6.execute(repository, identity, lease, sample, plan, None, tmp_path, tmp_path))


def test_output_containment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    g6.write_private(tmp_path / "report.json", {"ok": True})
    with pytest.raises(ValueError, match="private output"):
        g6.write_private(g6.ROOT / "should-not-exist.json", {})
    with pytest.raises(FileExistsError):
        g6.write_private(tmp_path / "report.json", {}, exclusive=True)


def test_cli_preflight_and_opt_in_refusal(capsys: pytest.CaptureFixture[str]) -> None:
    sample = g6.load_sample()
    count = len(g6.scheduled(sample, "dev"))
    assert main(["judge-calibration", "preflight", "--split", "dev", "--max-usd", "3", "--max-calls", str(count),
                 "--max-counts", str(count), "--max-seconds", "7200"]) == 0
    assert '"authorizes_paid_execution": false' in capsys.readouterr().out


def test_billing_record_serializes_frozen_ledger_evidence() -> None:
    # Regression (coordinator, first paid G6 dev call): asdict() deep-copied MappingProxyType fields of the real
    # Usage/Diagnostic evidence and raised TypeError after a settled call, aborting the stage.
    from policyops.budget.ledger import Diagnostic
    from policyops.budget.pricing import Usage
    from policyops.providers.results import Evidence
    from policyops_evals.qa_studies.calibration import billing_record

    evidence = Evidence(Usage(input_total=1000, cache_read=0, cache_writes={"30m": 10}, output=50),
                        ReportedUsage(state="known", input_total=1000, cache_read=0, output=50), "req-1", "gpt-6-luna",
                        None, Diagnostic(("usage_malformed",), {}))
    attempt = SimpleNamespace(attempt_id=uuid4(), fate="settled", count_granted=True, dispatch_granted=True,
                              evidence=evidence)
    report = SimpleNamespace(status="result", failure_code=None, result=None, attempts=(attempt,))
    record = billing_record(report)  # type: ignore[arg-type]
    usage = record["attempts"][0]["usage_evidence"]
    assert usage["usage"]["cache_writes"] == {"30m": 10}
    assert usage["diagnostic"] == {"codes": ["usage_malformed"], "counts": {}}
    assert json.loads(json.dumps(record)) == record
