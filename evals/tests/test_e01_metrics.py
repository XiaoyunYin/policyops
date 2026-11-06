"""E01 metrics (T15a), offline and pure: hand-calculated controls H1-H10 on synthetic stems (never real labels), the
type-7 bootstrap and its task/group clustering, exact slot binding, and dev-only label access that never opens a
test-split task file. Hand values are verification references, not runtime or quality evidence."""

from __future__ import annotations

from collections.abc import Sequence
from fractions import Fraction
import hashlib
import itertools
import json
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

import pytest

from policyops_contracts.e01 import (
    ActorReservation,
    Bounds,
    CandidateDocument,
    DeliveredDocument,
    E01Arm,
    E01Manifest,
    E01Selection,
    Envelope,
    RetrievalStepRecord,
    SlotSpec,
    TrajectoryRecord,
    slot_id_for,
)
from policyops_contracts.retrieval import RerankConfig, RetrievalConfig
from policyops_evals import banking, upstream
from policyops_evals.canonical import ManifestError, id_list_digest
from policyops_evals.e01_metrics import (
    ReportError,
    bind,
    build_report,
    decimal_text,
    paired_interval,
    type7,
)


STUDY = UUID(int=42)
CONFIGS = {"A0": RetrievalConfig(mode="lexical"), "A1": RetrievalConfig(mode="dense", dense_policy="refuse"),
           "A2": RetrievalConfig(mode="hybrid"), "A3": RetrievalConfig(mode="hybrid", rerank=RerankConfig())}
ENVELOPES = (Envelope(group="banking_insitu", cap_calls=48, cap_usd="0.1013504", chat_calls=38, embedding_batches=10,
                      max_input_tokens_per_chat_call=16000, max_output_tokens_per_chat_call=2048,
                      max_input_tokens_per_embedding_batch=8192),
             Envelope(group="replay_provider", cap_calls=20, cap_usd="0.0278784", chat_calls=10, embedding_batches=10,
                      max_input_tokens_per_chat_call=16000, max_output_tokens_per_chat_call=2048,
                      max_input_tokens_per_embedding_batch=8192))


def manifest(tasks: Sequence[str], trials: int, cells: Sequence[tuple[str, str, bool]]) -> E01Manifest:
    """`cells`: (phase, arm, optional) for every task and trial."""
    slots = []
    for task in sorted(tasks):
        for trial in range(trials):
            for phase, arm_id, optional in cells:
                provider = not (phase == "replay" and arm_id == "A0")
                group = None if not provider else ("replay_provider" if phase == "replay" else "banking_insitu")
                slots.append(SlotSpec(slot_id=slot_id_for(STUDY, phase, arm_id, task, trial), phase=phase,  # type: ignore[arg-type]
                                      arm_id=arm_id, task_id=task, trial=trial,  # type: ignore[arg-type]
                                      plan="declared_optional" if optional else "scheduled",
                                      provider_path=provider, envelope=group))  # type: ignore[arg-type]
    return E01Manifest(
        study_id=STUDY, purpose="dev_selection", domain="banking_knowledge", split_manifest_sha256="a" * 64,
        dev_task_ids_digest="b" * 64, task_ids=tuple(sorted(tasks)), trials=trials, seeds=tuple(range(trials)),
        arms=tuple(E01Arm(arm_id=a, config=c, config_sha256=c.sha256()) for a, c in CONFIGS.items()),  # type: ignore[arg-type]
        bounds=Bounds(simulator_turns=12, investigator_calls=16, retrieval_steps=10), envelopes=ENVELOPES,
        actors=(ActorReservation(actor="agent", model="gpt-6-luna", config_sha256="c" * 64, worst_usd="0.002624"),),
        price_revision="pricing.2026-11-05.v1", margin="0.05", bootstrap_seed=7, bootstrap_resamples=1000,
        slots=tuple(slots))


def doc(stem: str) -> UUID:
    return uuid5(NAMESPACE_URL, stem)


def step(number: int, delivered: Sequence[str], candidates: Sequence[str] = (), ranked: Sequence[str] = ()
         ) -> RetrievalStepRecord:
    pool = list(dict.fromkeys([*delivered, *candidates, *ranked]))
    ranked = list(ranked) if ranked else pool  # the delivery order is a complete permutation of the pool
    return RetrievalStepRecord(
        step=number, trace_id=uuid5(NAMESPACE_URL, f"t{number}"), payload_sha256="1" * 64, request_sha256="2" * 64,
        query_sha256="3" * 64, config_sha256=CONFIGS["A2"].sha256(), generation_id=UUID(int=9),
        generation_current_at_export=True, mode="hybrid",
        delivered=tuple(DeliveredDocument(evidence_number=i, document_id=doc(s), document_version_id=doc("v" + s),
                                          stem=s) for i, s in enumerate(delivered, 1)),
        candidates=tuple(CandidateDocument(rank=i, document_id=doc(s), stem=s) for i, s in enumerate(pool, 1)),
        ranked=tuple(ranked), evidence_tokens=10)


def as_arm(steps: Sequence[RetrievalStepRecord], arm_id: str) -> tuple[RetrievalStepRecord, ...]:
    """Steps as the authoritative export of this arm records them (its intent config digest, mode and rerank)."""
    config = CONFIGS[arm_id]
    return tuple(s.model_copy(update={"config_sha256": config.sha256(), "mode": config.mode,
                                      "rerank_status": "applied" if config.rerank is not None else None})
                 for s in steps)


def record(m: E01Manifest, phase: str, arm_id: str, task: str, trial: int, status: str = "completed",
           steps: Sequence[RetrievalStepRecord] = (), *, bind_steps: bool = True, **extra: Any) -> TrajectoryRecord:
    return TrajectoryRecord(manifest_sha256=m.digest(), slot_id=slot_id_for(STUDY, phase, arm_id, task, trial),
                            phase=phase, arm_id=arm_id, task_id=task, trial=trial, status=status,  # type: ignore[arg-type]
                            steps=as_arm(steps, arm_id) if bind_steps else tuple(steps), **extra)


def metrics(report: Any, phase: str, arm_id: str, variant: str) -> Any:
    return next(a for a in report.arms if (a.phase, a.arm_id, a.variant) == (phase, arm_id, variant))


ACQ = [("acquisition", "A2", False)]


def test_h1_duplicates_long_task_and_the_candidate_pool_are_separate() -> None:
    g = [f"d{i}" for i in range(1, 26)]
    m = manifest(["t1"], 1, ACQ)
    steps = [step(1, ["d1", "d1", "d2"]), step(2, ["d2", "d3", "x1"]), step(3, ["d4", "d5", "d6", "d7", "d8"]),
             step(4, ["d8", "d9", "d10"]), step(5, ["x2", "x3"]), step(6, ["d11", "d12", "d1"]),
             step(7, ["d12"], candidates=["d13"])]
    report = build_report(m, [record(m, "acquisition", "A2", "t1", 0, steps=steps)], {"t1": g}, {"t1": "g1"})
    strict = metrics(report, "acquisition", "A2", "strict")
    assert (strict.task_macro_coverage, strict.candidate_task_macro_coverage) == ("0.48", "0.52")
    assert (strict.all_required_rate, strict.delivered_documents, strict.retrieval_steps) == ("0", 15, 7)


def test_h2_thirty_required_documents_and_all_required() -> None:
    g = [f"d{i}" for i in range(30)]
    m = manifest(["t1"], 2, ACQ)
    full = [step(i + 1, g[5 * i:5 * i + 5]) for i in range(6)]
    almost = [step(i + 1, g[5 * i:min(5 * i + 5, 29)]) for i in range(6)]  # 29 of the 30
    report = build_report(m, [record(m, "acquisition", "A2", "t1", 0, steps=full),
                              record(m, "acquisition", "A2", "t1", 1, steps=almost)], {"t1": g}, {"t1": "g"})
    strict = metrics(report, "acquisition", "A2", "strict")
    assert strict.task_macro_coverage == decimal_text(Fraction(59, 60)) == "0.983333333333"
    assert strict.all_required_rate == "0.5"


def test_h3_document_macro_limits_a_frequent_document() -> None:
    tasks = ["t1", "t2", "t3"]
    labels = {t: ["F", f"u{i}"] for i, t in enumerate(tasks, 1)}
    m = manifest(tasks, 1, [("replay", "A0", False), ("replay", "A1", False), ("replay", "A2", False)])
    records = []
    for i, t in enumerate(tasks, 1):
        records.append(record(m, "replay", "A0", t, 0, steps=[step(1, ["F"])]))
        records.append(record(m, "replay", "A1", t, 0, steps=[step(1, [f"u{i}"])]))
        records.append(record(m, "replay", "A2", t, 0, steps=[step(1, ["F", f"u{i}"])]))
    report = build_report(m, records, labels, {t: t for t in tasks})
    p, q = metrics(report, "replay", "A0", "strict"), metrics(report, "replay", "A1", "strict")
    assert (p.task_macro_coverage, q.task_macro_coverage) == ("0.5", "0.5")
    assert (p.document_macro_coverage, q.document_macro_coverage) == ("0.25", "0.75")


def test_h4_strict_and_complete_case_denominators() -> None:
    g = ["d1", "d2"]
    m = manifest(["t1"], 4, ACQ)
    records = [record(m, "acquisition", "A2", "t1", 0, steps=[step(1, g)]),
               record(m, "acquisition", "A2", "t1", 1, steps=[step(1, ["d1"])]),
               record(m, "acquisition", "A2", "t1", 2, status="infra_error"),
               record(m, "acquisition", "A2", "t1", 3, status="budget_stop")]
    report = build_report(m, records, {"t1": g}, {"t1": "g"})
    strict, observed, complete = (metrics(report, "acquisition", "A2", v)
                                  for v in ("strict", "observed_progress", "complete_case"))
    assert (strict.task_macro_coverage, complete.task_macro_coverage) == ("0.375", "0.75")
    assert observed.task_macro_coverage == "0.375"  # these failed slots delivered nothing
    assert dict(strict.status_counts) == {"completed": 2, "infra_error": 1, "budget_stop": 1}
    assert (strict.included_slots, complete.included_slots) == (4, 2)


def test_h5_query_proxies_and_their_ceilings() -> None:
    g = [f"d{i}" for i in range(25)]
    ranked = ["n1", "d0", "d1", "n2", "d2", "n3", "d3", "d4", "n4", "d5"]  # relevant at ranks 2,3,5,7,8,10
    m = manifest(["t1", "t2"], 1, ACQ)
    second = ["e1"] + [f"n{i}" for i in range(13)] + ["e2"]
    report = build_report(m, [record(m, "acquisition", "A2", "t1", 0, steps=[step(1, [], ranked=ranked)]),
                              record(m, "acquisition", "A2", "t2", 0, steps=[step(1, [], ranked=second)])],
                          {"t1": g, "t2": ["e1", "e2"]}, {"t1": "g", "t2": "g"})
    strict = metrics(report, "acquisition", "A2", "strict")
    # Task means: t1 R@10 6/25, ceiling 10/25, MRR 1/2; t2 R@10 1/2, R@20 1, MRR 1, R-prec 1/2.
    assert strict.query_recall_at_10 == decimal_text((Fraction(6, 25) + Fraction(1, 2)) / 2)
    assert strict.query_recall_at_10_ceiling == decimal_text((Fraction(10, 25) + 1) / 2)
    assert strict.query_recall_at_20 == decimal_text((Fraction(6, 25) + 1) / 2)
    assert strict.query_mrr_at_10 == decimal_text((Fraction(1, 2) + 1) / 2)
    assert strict.query_r_precision == decimal_text((Fraction(6, 25) + Fraction(1, 2)) / 2)


def test_h6_type7_quantiles_and_task_cluster_intervals() -> None:
    differences = [Fraction(1, 10), Fraction(2, 10), Fraction(6, 10)]
    draws = sorted(sum(c, Fraction(0)) / 3 for c in itertools.product(differences, repeat=3))  # all 27 resamples
    assert type7(draws, Fraction(1, 40)) == Fraction(73, 600) and type7(draws, Fraction(39, 40)) == Fraction(77, 150)
    tasks = {"a": "a", "b": "b", "c": "c"}
    equal = paired_interval(dict.fromkeys(tasks, Fraction(1, 5)), tasks, seed=1, resamples=500, kind="task")
    assert (equal.estimate, equal.lower, equal.upper) == ("0.2", "0.2", "0.2")
    once = paired_interval(dict(zip(tasks, differences, strict=True)), tasks, seed=11, resamples=2000, kind="task")
    again = paired_interval(dict(zip(tasks, differences, strict=True)), tasks, seed=11, resamples=2000, kind="task")
    assert once == again and once.estimate == "0.3"
    assert Fraction(once.lower) >= Fraction(1, 10) and Fraction(once.upper) <= Fraction(6, 10)


def test_group_sensitivity_keeps_the_task_weighted_estimand() -> None:
    differences = {f"t{i}": Fraction(5, 6) for i in range(4)} | {"t4": Fraction(1, 6)}
    groups = {f"t{i}": "g1" for i in range(4)} | {"t4": "g2"}
    interval = paired_interval(differences, groups, seed=3, resamples=2000, kind="group")
    assert interval.estimate == "0.7" and interval.clusters == "group"  # not the unweighted group mean 0.5
    assert Fraction(1, 6) <= Fraction(interval.lower) <= Fraction(interval.upper) <= Fraction(5, 6)


def test_paired_comparisons_cover_replay_and_confirmation_against_a2() -> None:
    m = manifest(["t1", "t2"], 1, [("acquisition", "A2", False), ("replay", "A0", False), ("replay", "A2", False),
                                   ("confirmation", "A3", True)])
    records = []
    for t in ("t1", "t2"):
        records += [record(m, "acquisition", "A2", t, 0, steps=[step(1, ["d1"])]),
                    record(m, "replay", "A0", t, 0, steps=[step(1, ["d1", "d2"])]),
                    record(m, "replay", "A2", t, 0, steps=[step(1, ["d1"])]),
                    record(m, "confirmation", "A3", t, 0, steps=[step(1, ["d2"])])]
    selection = E01Selection(manifest_sha256=m.digest(), replay_report_sha256="e" * 64, confirmation_arms=("A3",))
    report = build_report(m, records, {"t1": ["d1", "d2"], "t2": ["d1", "d2"]}, {"t1": "g", "t2": "g"}, selection)
    pairs = {(c.phase, c.arm_id, c.baseline_arm_id): c for c in report.comparisons}
    assert pairs[("replay", "A0", "A2")].task_cluster.estimate == "0.5"
    assert pairs[("confirmation", "A3", "A2")].task_cluster.estimate == "0"
    assert report.not_scheduled_slots == 0


def test_h9_failure_after_full_delivery_is_zero_strictly_and_undefined_complete_case() -> None:
    m = manifest(["t1"], 1, ACQ)
    report = build_report(m, [record(m, "acquisition", "A2", "t1", 0, status="budget_stop",
                                     steps=[step(1, ["d1", "d2"])])], {"t1": ["d1", "d2"]}, {"t1": "g"})
    strict, observed, complete = (metrics(report, "acquisition", "A2", v)
                                  for v in ("strict", "observed_progress", "complete_case"))
    assert (strict.task_macro_coverage, strict.all_required_rate, strict.document_macro_coverage) == ("0", "0", "0")
    assert (observed.task_macro_coverage, observed.all_required_rate) == ("1", "1")
    assert (complete.included_slots, complete.task_macro_coverage, complete.all_required_rate) == (0, None, None)
    assert complete.document_macro_coverage is None and complete.query_mrr_at_10 is None
    assert strict.delivered_documents == 2  # actual progress is retained


@pytest.mark.parametrize("case", ["missing", "duplicate", "wrong_arm", "unscheduled", "not_selected", "wrong_manifest",
                                  "undecided"])
def test_h10_slot_identity_is_an_exact_bijection(case: str) -> None:
    cells = [("acquisition", "A2", False), ("confirmation", "A0", True), ("confirmation", "A3", True)]
    m = manifest(["t1", "t2"], 1, cells)
    selection = E01Selection(manifest_sha256=m.digest(), replay_report_sha256="e" * 64, confirmation_arms=("A3",))
    good = [record(m, p, a, t, 0) for t in ("t1", "t2") for p, a, _ in cells if a != "A0"]
    records = list(good)
    chosen: E01Selection | None = selection
    if case == "missing":
        records = good[1:]
    elif case == "duplicate":
        records = [*good, good[0]]
    elif case == "wrong_arm":
        records[0] = records[0].model_copy(update={"arm_id": "A3"})
    elif case == "unscheduled":
        records.append(record(m, "replay", "A1", "t1", 0))
    elif case == "not_selected":
        records.append(record(m, "confirmation", "A0", "t1", 0))
    elif case == "wrong_manifest":
        records[0] = records[0].model_copy(update={"manifest_sha256": "f" * 64})
    else:
        chosen = None
    with pytest.raises(ReportError) as raised:
        bind(m, records, chosen)
    expected = {"missing": "missing_outcome", "duplicate": "duplicate_outcome", "wrong_arm": "wrong_slot_identity",
                "unscheduled": "unscheduled_outcome", "not_selected": "unscheduled_outcome",
                "wrong_manifest": "wrong_manifest", "undecided": "optional_undecided"}[case]
    assert raised.value.code == expected
    assert len(bind(m, good, selection)) == 4


def test_not_selected_optional_slots_are_reported_not_scheduled() -> None:
    m = manifest(["t1"], 1, [("acquisition", "A2", False), ("confirmation", "A0", True), ("confirmation", "A3", True)])
    selection = E01Selection(manifest_sha256=m.digest(), replay_report_sha256="e" * 64, confirmation_arms=())
    report = build_report(m, [record(m, "acquisition", "A2", "t1", 0)], {"t1": ["d1"]}, {"t1": "g"}, selection)
    assert report.not_scheduled_slots == 2 and {a.phase for a in report.arms} == {"acquisition"}


def test_costs_are_unknown_unless_the_record_carries_ledger_cost() -> None:
    m = manifest(["t1"], 2, ACQ)
    records = [record(m, "acquisition", "A2", "t1", 0, spent_usd="0.002", held_usd="0"),
               record(m, "acquisition", "A2", "t1", 1)]
    strict = metrics(build_report(m, records, {"t1": ["d1"]}, {"t1": "g"}), "acquisition", "A2", "strict")
    assert (strict.spent_usd, strict.held_usd, strict.cost_unknown_slots) == ("0.002", "0", 1)


def test_labels_must_cover_exactly_the_manifest_tasks() -> None:
    m = manifest(["t1"], 1, ACQ)
    with pytest.raises(ReportError, match="labels_mismatch"):
        build_report(m, [record(m, "acquisition", "A2", "t1", 0)], {"t1": ["d1"], "t9": ["d1"]}, {"t1": "g"})


def test_records_and_reports_carry_no_label_or_instruction_fields() -> None:
    names = set(TrajectoryRecord.model_json_schema()["properties"]) | set(
        RetrievalStepRecord.model_json_schema()["properties"])
    assert not names & {"required_documents", "user_scenario", "instructions", "evaluation_criteria", "query", "text"}


# -- dev-only label access -------------------------------------------------------------------------------------------

CANARY = "CANARY-e01-hidden-instruction"


def _write(root: Path, path: str, value: Any) -> str:
    data = json.dumps(value).encode("utf-8")
    target = root.joinpath(*path.split("/"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _manifests(root: Path, *, write_test: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    consumed = []
    for task_id, docs in (("task_001", ["doc_b", "doc_a"]), ("task_002", ["doc_c"])):
        path = f"{upstream.BANKING_TASKS_DIR}/{task_id}.json"
        sha = _write(root, path, {"id": task_id, "required_documents": docs, "user_scenario": {"instructions": CANARY}})
        consumed.append({"path": path, "sha256": sha})
    test_path = f"{upstream.BANKING_TASKS_DIR}/task_003.json"
    consumed.append({"path": test_path, "sha256": "0" * 64})  # never opened: absent or deliberately wrong
    if write_test:
        (root.joinpath(*test_path.split("/"))).write_bytes(b"not json and not the pinned bytes")
    dev = ["task_001", "task_002"]
    split = {"splits": {"dev": {"task_ids": dev, "digest": id_list_digest(dev), "count": 2},
                        "test": {"task_ids": ["task_003"], "digest": id_list_digest(["task_003"]), "count": 1}},
             "grouping": {"members": [{"group": "task_001", "split": "dev", "task_ids": dev},
                                      {"group": "task_003", "split": "test", "task_ids": ["task_003"]}]}}
    return split, {"consumed": consumed}


@pytest.mark.parametrize("write_test", [False, True])
def test_dev_labels_open_only_dev_task_files_and_keep_only_labels(tmp_path: Path, write_test: bool) -> None:
    split, source = _manifests(tmp_path, write_test=write_test)
    found = banking.dev_labels(tmp_path, split, source)
    assert dict(found.labels) == {"task_001": ("doc_a", "doc_b"), "task_002": ("doc_c",)}
    assert dict(found.groups) == {"task_001": "task_001", "task_002": "task_001"}
    assert CANARY not in repr(found) and CANARY not in found.digest()


def test_dev_labels_refuse_tampered_files_and_inconsistent_splits(tmp_path: Path) -> None:
    split, source = _manifests(tmp_path, write_test=False)
    tampered = json.loads(json.dumps(source))
    tampered["consumed"][0]["sha256"] = "f" * 64
    with pytest.raises(ManifestError, match="pinned SHA-256"):
        banking.dev_labels(tmp_path, split, tampered)
    overlap = json.loads(json.dumps(split))
    overlap["splits"]["test"]["task_ids"] = ["task_002"]
    with pytest.raises(ManifestError, match="overlap"):
        banking.dev_labels(tmp_path, overlap, source)
    wrong = json.loads(json.dumps(split))
    wrong["splits"]["dev"]["digest"] = "0" * 64
    with pytest.raises(ManifestError, match="digest"):
        banking.dev_labels(tmp_path, wrong, source)


# -- review regressions (draft-protocol-binding-findings-1) ----------------------------------------------------------

def test_incomplete_or_differently_trialled_cohorts_cannot_form_a_manifest() -> None:
    full = manifest(["t1", "t2"], 2, [("replay", "A1", False), ("replay", "A2", False)])
    data = full.model_dump()
    # Keep A1 trial 0 and A2 trial 1 only (the observed unpaired frame): refused, not silently paired.
    partial = tuple(s for s in data["slots"] if (s["arm_id"], s["trial"]) in {("A1", 0), ("A2", 1)})
    with pytest.raises(ValueError, match="cohort does not cover"):
        E01Manifest.model_validate(data | {"slots": partial})
    missing_task = tuple(s for s in data["slots"] if not (s["arm_id"] == "A1" and s["task_id"] == "t2"))
    with pytest.raises(ValueError, match="cohort does not cover"):
        E01Manifest.model_validate(data | {"slots": missing_task})


def test_balanced_cohorts_pair_by_exact_task_and_trial_keys() -> None:
    m = manifest(["t1", "t2"], 2, [("replay", "A1", False), ("replay", "A2", False)])
    records = [record(m, "replay", a, t, i, steps=[step(1, ["d1"] if a == "A1" else [])])
               for t in ("t1", "t2") for i in range(2) for a in ("A1", "A2")]
    report = build_report(m, records, {"t1": ["d1"], "t2": ["d1"]}, {"t1": "g", "t2": "g"})
    (comparison,) = report.comparisons
    assert (comparison.arm_id, comparison.baseline_arm_id, comparison.task_cluster.estimate) == ("A1", "A2", "1")


def test_unpaired_cohorts_are_refused_before_averaging() -> None:
    from policyops_evals.e01_metrics import Outcome, compare

    m = manifest(["t1"], 2, [("replay", "A1", False), ("replay", "A2", False)])
    slots = {(s.arm_id, s.trial): s for s in m.slots}
    a1 = [Outcome(slots[("A1", 0)], record(m, "replay", "A1", "t1", 0))]
    a2 = [Outcome(slots[("A2", 1)], record(m, "replay", "A2", "t1", 1))]
    with pytest.raises(ReportError, match="unpaired_cohorts"):
        compare(a1, a2, {"t1": frozenset({"d1"})}, {"t1": "g"}, seed=1, resamples=100, phase="replay")


@pytest.mark.parametrize("break_it", ["eleven_steps", "duplicate_step", "wrong_mode", "same_mode_wrong_config",
                                      "rerank_on_unreranked_arm", "over_chunks", "ranking_outside_pool"])
def test_steps_are_bound_to_their_arm_and_the_declared_bounds(break_it: str) -> None:
    m = manifest(["t1"], 1, [("replay", "A1", False), ("replay", "A2", False)])
    good = as_arm([step(1, ["d1"])], "A1")[0]
    if break_it == "eleven_steps":
        steps = [good.model_copy(update={"step": n, "trace_id": uuid5(NAMESPACE_URL, f"x{n}")}) for n in range(1, 12)]
    elif break_it == "duplicate_step":
        steps = [good, good.model_copy(update={"trace_id": UUID(int=77)})]
    elif break_it == "wrong_mode":
        steps = [good.model_copy(update={"mode": "hybrid"})]
    elif break_it == "same_mode_wrong_config":
        other = RetrievalConfig(mode="dense", dense_policy="refuse", branch_documents=5)
        steps = [good.model_copy(update={"config_sha256": other.sha256()})]
    elif break_it == "rerank_on_unreranked_arm":
        steps = [good.model_copy(update={"rerank_status": "applied"})]
    elif break_it == "over_chunks":
        steps = [as_arm([step(1, [f"d{i}" for i in range(7)])], "A1")[0]]
    else:
        steps = [good.model_copy(update={"ranked": ("elsewhere",)})]
    bad = record(m, "replay", "A1", "t1", 0, steps=steps, bind_steps=False)
    expected = {"eleven_steps": "steps_over_bound", "duplicate_step": "duplicate_step",
                "wrong_mode": "step_arm_mismatch", "same_mode_wrong_config": "step_arm_mismatch",
                "rerank_on_unreranked_arm": "step_arm_mismatch", "over_chunks": "step_over_bound",
                "ranking_outside_pool": "step_inconsistent"}[break_it]
    with pytest.raises(ReportError) as raised:
        bind(m, [bad, record(m, "replay", "A2", "t1", 0)])
    assert raised.value.code == expected
    ten = [step(n, ["d1"]) for n in range(1, 11)]
    for n, s in enumerate(ten, 1):
        ten[n - 1] = s.model_copy(update={"trace_id": uuid5(NAMESPACE_URL, f"ten{n}")})
    assert len(bind(m, [record(m, "replay", "A1", "t1", 0, steps=ten), record(m, "replay", "A2", "t1", 0)])) == 2


# -- review regressions (draft-candidate-relation-finding-1) ---------------------------------------------------------

def _single(arm_id: str, record_step: RetrievalStepRecord) -> tuple[E01Manifest, list[TrajectoryRecord]]:
    m = manifest(["t1"], 1, [("replay", arm_id, False), ("replay", "A2", False)])
    return m, [record(m, "replay", arm_id, "t1", 0, steps=[record_step], bind_steps=False),
               record(m, "replay", "A2", "t1", 0)]


@pytest.mark.parametrize("break_it", ["delivered_outside_pool", "partial_ranking", "duplicate_candidate",
                                      "gapped_ranks", "stem_mapping_conflict", "uuid_mapping_conflict"])
def test_intrinsically_impossible_step_relations_are_refused(break_it: str) -> None:
    good = as_arm([step(1, ["d1"], candidates=["d2", "d3"])], "A1")[0]
    candidates = list(good.candidates)
    if break_it == "delivered_outside_pool":  # delivered d1 while the pool holds only d2
        broken = good.model_copy(update={"candidates": (candidates[1].model_copy(update={"rank": 1}),),
                                         "ranked": ("d2",)})
    elif break_it == "partial_ranking":
        broken = good.model_copy(update={"ranked": good.ranked[:2]})
    elif break_it == "duplicate_candidate":
        broken = good.model_copy(update={"candidates": (*candidates, candidates[0].model_copy(update={"rank": 4}))})
    elif break_it == "gapped_ranks":
        broken = good.model_copy(update={"candidates": tuple(c.model_copy(update={"rank": c.rank * 2})
                                                             for c in candidates)})
    elif break_it == "stem_mapping_conflict":
        broken = good.model_copy(update={"delivered": (good.delivered[0].model_copy(update={"stem": "d3"}),)})
    else:
        broken = good.model_copy(update={"delivered": (good.delivered[0].model_copy(
            update={"document_id": doc("elsewhere")}),)})
    m, records = _single("A1", broken)
    with pytest.raises(ReportError, match="step_inconsistent"):
        bind(m, records)


def test_a_valid_subset_delivery_and_the_full_policy_relation_are_accepted() -> None:
    subset = as_arm([step(1, ["d2"], candidates=["d1", "d2", "d3"])], "A1")[0]  # budget skipped d1 and d3
    m, records = _single("A1", subset)
    assert len(bind(m, records)) == 2
    full_config = RetrievalConfig(mode="full_policy")
    full = step(1, ["d1", "d2"]).model_copy(update={"mode": "full_policy", "config_sha256": full_config.sha256(),
                                                    "ranked": ()})
    from policyops_evals.e01_metrics import _relations_hold

    assert _relations_hold(full, ranked_mode=False)
    assert not _relations_hold(full.model_copy(update={"ranked": ("d1", "d2")}), ranked_mode=False)
    extra = full.model_copy(update={"candidates": (*full.candidates, CandidateDocument(
        rank=3, document_id=doc("d9"), stem="d9"))})
    assert not _relations_hold(extra, ranked_mode=False)  # full policy: candidates are exactly the delivered set
