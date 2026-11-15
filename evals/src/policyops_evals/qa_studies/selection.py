"""Deterministic G1 dev selection; no dataset materialization or provider access.

Reports and receipts live below POLICYOPS_TEMP_DIR. Public specifications bind
digests, never machine-specific private paths. Receipts bind relative paths AND
bytes; preflight regenerates them from the pinned reports and dev contracts.
"""
from __future__ import annotations

from fractions import Fraction
import json
import os
from pathlib import Path
from typing import Any

from policyops_evals.canonical import canonical_bytes, sha256_bytes
from policyops_evals.qa_studies.config import ROOT, QAStudy, _unique_object, load_study


SOURCES = {
    "R1": ("g1-dev-retrieval-v3", "cf02421b-eaf9-5e1b-ad53-74d0054ef610",
           "72d4adb80a709aea5736d042a4a7f4dbea649fbfa67f5d8c7f6dca351cdeb751"),
    "R2": ("g1-dev-answers-v2", "32e31366-495f-5d70-be31-ed5c7855bba9",
           "94ed6483e3b1730ab1f32e9dd6dd6cf7085318f815f6d73c983d2440d4b21175"),
}
RULES = {"R1": ("recall_at_5", ("dense-history", "bm25-history")),
         "R2": ("gold_citation", ("rrf-bm25-base-ce", "rrf-bm25-luna-rerank"))}


def temp_root() -> Path:
    raw = os.environ.get("POLICYOPS_TEMP_DIR", "")
    root = Path(raw).resolve()
    if not raw or not Path(raw).is_absolute() or root == ROOT or root.is_relative_to(ROOT):
        raise ValueError("selection requires external absolute POLICYOPS_TEMP_DIR")
    return root


def source_path(rule: str) -> str:
    _, identity, digest = SOURCES[rule]
    return f"benchmarks/qa-studies/{identity}/report-{digest}.json"


def select(report: dict[str, Any], study: QAStudy, rule: str) -> dict[str, Any]:
    """Strict full scheduled denominator, including failures; first in order wins ties."""
    metric, order = RULES[rule]
    if (study.purpose != "dev" or report.get("purpose") != "dev"
            or report.get("schema_version") != "policyops.qa-report/v1"
            or len(study.schedule.cohorts) != 1 or study.schedule.repetitions != 1):
        raise ValueError("selection dev report identity mismatch")
    cohort = study.schedule.cohorts[0]
    if (cohort.name != "dev" or cohort.split != "train" or cohort.question_count != 500
            or cohort.dialogue_count != 80):
        raise ValueError("selection dev cohort mismatch")
    observations: dict[str, Any] = {}
    for comparison in report["comparisons"]:
        result = comparison["result"]
        if result["specification_sha256"] != study.digest() or result["missingness"] != "strict-non-success":
            raise ValueError("selection report specification mismatch")
        for observation in result["observations"]:
            if observation["arm"] not in order:
                continue
            if (observation["scheduled"] != 500 or observation["recorded"] != 500
                    or observation["missing"] != 0 or observation["integrity"] is not True
                    or observation["accounting_settled"] is not True
                    or Fraction(observation["held_liability_usd"]) != 0):
                raise ValueError("selection incomplete denominator or accounting")
            observations[observation["arm"]] = observation
    values: dict[str, Fraction] = {}
    for arm in order:
        rows = [a for a in report["aggregates"] if (a["arm"], a["cohort"]) == (arm, "dev")]
        if arm not in observations or len(rows) != 1 or rows[0]["scheduled"] != 500:
            raise ValueError("selection missing arm or denominator")
        row = rows[0]
        if row["cost"]["n"] != 500 or row["cost"]["unknown"] or Fraction(row["cost"]["held_liability_usd"]):
            raise ValueError("selection incomplete aggregate")
        text = row["metrics"][metric]
        if not isinstance(text, str) or len(text) > 128:
            raise ValueError("selection metric bound")
        value = Fraction(text)
        if not 0 <= value <= 1 or (value * 500).denominator != 1:
            raise ValueError("selection invalid binary rate")
        values[arm] = value
    winner = max(order, key=lambda name: values[name])
    return {"schema_version": "policyops.g1-selection/v1", "rule": rule, "metric": metric,
            "tie_order": list(order), "cohort": "dev", "scheduled_per_arm": 500,
            "missingness": "strict-non-success", "specification_sha256": study.digest(),
            "values": {arm: str(value) for arm, value in values.items()}, "winner": winner,
            "winner_binding": next(a.model_dump(mode="json") for a in study.arms if a.name == winner)}


def produce(rule: str, root: Path) -> dict[str, Any]:
    name, identity, digest = SOURCES[rule]
    relative = source_path(rule)
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or path.stat().st_size > 2_000_000:
        raise ValueError("selection report containment/size")
    raw = path.read_bytes()
    if sha256_bytes(raw) != digest:
        raise ValueError("selection source report digest mismatch")
    study = load_study(ROOT / "evals/qa_studies" / (name + ".json"))
    if str(study.study_id) != identity:
        raise ValueError("selection source study mismatch")
    result = select(json.loads(raw, object_pairs_hook=_unique_object), study, rule)
    return result | {"source_report": {"path": relative, "sha256": digest,
                                        "path_sha256": sha256_bytes(relative.encode())}}


def command() -> dict[str, Any]:
    root = temp_root()
    # Verify both before creating either receipt.
    receipts = [produce(rule, root) for rule in RULES]
    output = (root / "benchmarks/qa-selections").resolve()
    if not output.is_relative_to(root):
        raise ValueError("selection output containment")
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    for receipt in receipts:
        raw = canonical_bytes(receipt)
        digest = sha256_bytes(raw)
        path = output / (digest + ".json")
        if not path.resolve().is_relative_to(root):
            raise ValueError("selection receipt containment")
        if path.exists():
            if path.read_bytes() != raw:
                raise ValueError("selection receipt collision")
        else:
            with path.open("xb") as handle:
                handle.write(raw)
        rows.append({"rule": receipt["rule"], "winner": receipt["winner"], "values": receipt["values"],
                     "sha256": digest, "path": str(path)})
    return {"receipts": rows, "authorizes_paid_execution": False}


def verify(study: QAStudy) -> None:
    if study.purpose != "sealed_test" or study.protocol_version != "g1.sealed-v1":
        return
    root = temp_root()
    expected = {sha256_bytes(canonical_bytes(r)): r for r in (produce(rule, root) for rule in RULES)}
    if set(study.provenance.development_selection_receipts) != set(expected):
        raise ValueError("sealed selection receipts mismatch")
    for digest, receipt in expected.items():
        path = root / "benchmarks/qa-selections" / (digest + ".json")
        if (not path.resolve().is_relative_to(root) or path.stat().st_size > 100_000
                or path.read_bytes() != canonical_bytes(receipt)):
            raise ValueError("sealed selection receipt bytes mismatch")
        if receipt["rule"] == ("R1" if study.name == "g1-test-retrieval-v1" else "R2"):
            arm = next((a for a in study.arms if a.name == receipt["winner"]), None)
            if (arm is None or getattr(arm, "selection_receipt_sha256", None) != digest
                    or arm.model_dump(mode="json", exclude={"selection_receipt_sha256"}) != receipt["winner_binding"]):
                raise ValueError("sealed selected arm binding mismatch")
    retrieval = study.name == "g1-test-retrieval-v1"
    dev = load_study(ROOT / "evals/qa_studies" / (
        "g1-dev-retrieval-v3.json" if retrieval else "g1-dev-answers-v2.json"))
    names = ({"rrf-bm25-history", "dense-history"} if retrieval else
             {"rrf-bm25-history-luna", "rrf-bm25-base-ce", "rrf-bm25-luna-rerank", "closed-book-luna"})
    bindings = {a.name: a.model_dump(mode="json") for a in dev.arms if a.name in names}
    if {a.name: a.model_dump(mode="json", exclude={"selection_receipt_sha256"}) for a in study.arms} != bindings:
        raise ValueError("sealed frozen dev arm mismatch")
    if not retrieval and (dev.judge is None or study.judge != dev.judge.model_copy(update={"max_input_tokens": 8192})):
        raise ValueError("sealed frozen judge mismatch")
