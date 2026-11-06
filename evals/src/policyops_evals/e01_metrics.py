"""E01 retrieval-selection metrics (T15a): pure, deterministic and exact (fractions), evaluator side only.

Inputs: one `E01Manifest`, the slots' `TrajectoryRecord`s and the dev labels (task -> required stems) with each task's
heuristic group. Labels are task-level targets for a whole trajectory, never per-turn relevance.

**Binding.** Records must be in exact bijection with the manifest's scheduled slots: a missing, duplicate,
unscheduled (optional or not selected) or misidentified record (manifest digest, slot ID, phase, arm, task, trial) is
a `ReportError`. A still-undecided optional slot is an error too. `not_selected` optional slots are reported as not
scheduled, never as failed measurements. Every step of a record must belong to its slot's arm: the intent's
configuration digest equals the arm's, the mode is the arm's, at most `bounds.retrieval_steps` steps with distinct step
numbers and traces, and each step within the per-step bounds that configuration implies (delivered chunks, evidence
tokens, the bounded candidate pool, contiguous evidence numbers, a ranking drawn from the candidates, a rerank record
exactly for a reranked arm). The authoritative export proves the trace-side facts; this check binds them to the arm.

**Variants** (consistent across every coverage metric):
- `strict` (headline): every scheduled slot; a non-completed slot has empty delivered and candidate sets;
- `observed_progress`: every scheduled slot with its actual (possibly partial) sets;
- `complete_case`: completed slots only; undefined (None) when there is none.
Delivered documents, steps, evidence tokens and costs are always the actual totals over all scheduled slots of the
arm. Costs are summed only where the record carries ledger cost; other slots are counted as cost-unknown.

**Coverage.** Trial c = |G ∩ D| / |G|; task score = mean of the task's included trials; task-macro = mean of task
scores. Document-macro: for each required stem, the share of included trials requiring it that delivered it, averaged
over stems (each document weighs once, which limits a frequently required document). All-required = share of
included trials with G ⊆ D. Candidate coverage uses the candidate sets.

**Query proxies** (diagnostic; per step with a ranked list): Recall@k = |G ∩ L[:k]| / |G| with its ceiling
min(k, |G|) / |G|, MRR@10, R-precision = |G ∩ L[:|G|]| / |G|. A slot's value is the mean over its ranked steps, or 0
when it has none or is excluded by the strict rule; then trials, then tasks are averaged.

**Intervals.** Paired task-cluster bootstrap of the strict task-score difference (arm - baseline): B resamples of
clusters with replacement from `random.Random(seed)`, each draw the exact task-weighted mean difference over the
drawn clusters' tasks; bounds are type-7 linear-interpolation quantiles of the sorted draws at 2.5% and 97.5%
(h = (B - 1)p). The group sensitivity resamples the 19 heuristic groups instead, still weighting tasks equally.
Computation is exact; values are rendered ROUND_HALF_EVEN to 12 decimal places. These intervals are dev selection aids
on few tasks with several arms, not confirmatory significance.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal, localcontext
from fractions import Fraction
import hashlib
import json
import math
import random

from policyops_contracts.e01 import (
    ArmMetrics,
    E01Manifest,
    E01Report,
    E01Selection,
    Interval,
    OutcomeStatus,
    PairedComparison,
    RetrievalStepRecord,
    SlotSpec,
    TrajectoryRecord,
    Variant,
)


PLACES = 12
VARIANTS: tuple[Variant, ...] = ("strict", "observed_progress", "complete_case")
STATUSES: tuple[OutcomeStatus, ...] = ("completed", "budget_stop", "interrupted", "infra_error", "simulator_error",
                                       "retrieval_error")
LOWER, UPPER = Fraction(1, 40), Fraction(39, 40)


class ReportError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def decimal_text(value: Fraction) -> str:
    """Exact fraction → decimal string, ROUND_HALF_EVEN to 12 places, trailing zeros removed."""
    with localcontext() as context:
        context.prec = 60
        exact = Decimal(value.numerator) / Decimal(value.denominator)
        rounded = exact.quantize(Decimal(1).scaleb(-PLACES), rounding=ROUND_HALF_EVEN)
    text = format(rounded.normalize(), "f")
    return "0" if text in ("-0", "0") else text


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def labels_digest(labels: Mapping[str, Iterable[str]], groups: Mapping[str, str]) -> str:
    return _digest({"labels": {t: sorted(labels[t]) for t in sorted(labels)},
                    "groups": {t: groups[t] for t in sorted(groups)}})


# -- binding ---------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Outcome:
    slot: SlotSpec
    record: TrajectoryRecord

    @property
    def completed(self) -> bool:
        return self.record.status == "completed"

    def delivered(self) -> frozenset[str]:
        return frozenset(d.stem for step in self.record.steps for d in step.delivered)

    def candidates(self) -> frozenset[str]:
        return frozenset(c.stem for step in self.record.steps for c in step.candidates)


def scheduled(manifest: E01Manifest, selection: E01Selection | None) -> dict[object, SlotSpec]:
    """The slots that need an outcome: every scheduled slot plus the optional slots of the selected arms."""
    optional = [s for s in manifest.slots if s.plan == "declared_optional"]
    if optional and selection is None:
        raise ReportError("optional_undecided", f"{len(optional)} optional slots have no selection decision")
    if selection is not None and selection.manifest_sha256 != manifest.digest():
        raise ReportError("wrong_manifest", "the selection belongs to another manifest")
    chosen = set(selection.confirmation_arms) if selection is not None else set()
    return {s.slot_id: s for s in manifest.slots if s.plan == "scheduled" or s.arm_id in chosen}


def _check_steps(record: TrajectoryRecord, manifest: E01Manifest) -> None:
    arm = next(a for a in manifest.arms if a.arm_id == record.arm_id)
    config = arm.config
    if len(record.steps) > manifest.bounds.retrieval_steps:
        raise ReportError("steps_over_bound", str(record.slot_id))
    if (len({s.step for s in record.steps}) != len(record.steps)
            or len({s.trace_id for s in record.steps}) != len(record.steps)):
        raise ReportError("duplicate_step", str(record.slot_id))
    ranked_mode = config.mode != "full_policy"
    max_chunks = config.max_chunks if ranked_mode else config.full_policy_max_chunks
    for step in record.steps:
        if step.config_sha256 != arm.config_sha256 or step.mode != config.mode:
            raise ReportError("step_arm_mismatch", f"{record.slot_id} step {step.step}")
        if (len(step.delivered) > max_chunks or step.evidence_tokens > config.max_evidence_tokens
                or [d.evidence_number for d in step.delivered] != list(range(1, len(step.delivered) + 1))):
            raise ReportError("step_over_bound", f"{record.slot_id} step {step.step}")
        if ranked_mode and len(step.candidates) > 2 * config.branch_documents:
            raise ReportError("step_over_bound", f"{record.slot_id} step {step.step}")
        if not _relations_hold(step, ranked_mode):
            raise ReportError("step_inconsistent", f"{record.slot_id} step {step.step}")
        if (step.rerank_status is not None) != (config.rerank is not None and ranked_mode):
            raise ReportError("step_arm_mismatch", f"{record.slot_id} step {step.step}")


def _relations_hold(step: RetrievalStepRecord, ranked_mode: bool) -> bool:
    """Intrinsic step relations: unique candidates with contiguous ranks; one consistent stem per document UUID (and
    one UUID per stem) across candidates and delivered entries; ranked modes deliver a subset of the candidate pool
    (not necessarily all of it: the evidence budget can skip documents) and rank a complete unique permutation of it;
    the full-policy control has candidates equal to its delivered documents and no ranking."""
    candidate_ids = [c.document_id for c in step.candidates]
    stems = [c.stem for c in step.candidates]
    if len(set(candidate_ids)) != len(candidate_ids) or len(set(stems)) != len(stems):
        return False
    if [c.rank for c in step.candidates] != list(range(1, len(step.candidates) + 1)):
        return False
    mapping = {c.document_id: c.stem for c in step.candidates}
    for delivered in step.delivered:
        if mapping.setdefault(delivered.document_id, delivered.stem) != delivered.stem:
            return False
    if len(set(mapping.values())) != len(mapping):
        return False
    delivered_ids = {d.document_id for d in step.delivered}
    if not ranked_mode:
        return set(candidate_ids) == delivered_ids and not step.ranked
    return delivered_ids <= set(candidate_ids) and sorted(step.ranked) == sorted(stems)


def bind(manifest: E01Manifest, records: Sequence[TrajectoryRecord],
         selection: E01Selection | None = None) -> dict[object, Outcome]:
    """Exact bijection between scheduled slots and records (see the module docstring)."""
    digest = manifest.digest()
    slots = scheduled(manifest, selection)
    declared = {s.slot_id for s in manifest.slots}
    bound: dict[object, Outcome] = {}
    for record in records:
        if record.manifest_sha256 != digest:
            raise ReportError("wrong_manifest", str(record.slot_id))
        slot = slots.get(record.slot_id)
        if slot is None:
            detail = "not selected" if record.slot_id in declared else "not in the manifest"
            raise ReportError("unscheduled_outcome", f"{record.slot_id} is {detail}")
        if (record.phase, record.arm_id, record.task_id, record.trial) != (slot.phase, slot.arm_id, slot.task_id,
                                                                            slot.trial):
            raise ReportError("wrong_slot_identity", str(record.slot_id))
        if record.slot_id in bound:
            raise ReportError("duplicate_outcome", str(record.slot_id))
        _check_steps(record, manifest)
        bound[record.slot_id] = Outcome(slot, record)
    missing = [slot_id for slot_id in slots if slot_id not in bound]
    if missing:
        raise ReportError("missing_outcome", f"{len(missing)} scheduled slots have no outcome")
    return bound


# -- per-arm metrics -------------------------------------------------------------------------------------------------

def _mean(values: Sequence[Fraction]) -> Fraction | None:
    return sum(values, Fraction(0)) / len(values) if values else None


def _sets(outcome: Outcome, variant: Variant) -> tuple[frozenset[str], frozenset[str]] | None:
    """(delivered, candidates) for this variant, or None when the variant excludes the slot."""
    if variant == "complete_case" and not outcome.completed:
        return None
    if variant == "strict" and not outcome.completed:
        return frozenset(), frozenset()
    return outcome.delivered(), outcome.candidates()


def _proxies(outcome: Outcome, required: frozenset[str], variant: Variant) -> dict[str, Fraction] | None:
    if variant == "complete_case" and not outcome.completed:
        return None
    zero = {k: Fraction(0) for k in ("r10", "c10", "r20", "c20", "mrr", "rprec")}
    if variant == "strict" and not outcome.completed:
        return zero
    rows = []
    g = len(required)
    for step in outcome.record.steps:
        ranked = list(step.ranked)
        if not ranked:
            continue
        first = next((i for i, stem in enumerate(ranked[:10], 1) if stem in required), None)
        rows.append({"r10": Fraction(len(required & set(ranked[:10])), g), "c10": Fraction(min(10, g), g),
                     "r20": Fraction(len(required & set(ranked[:20])), g), "c20": Fraction(min(20, g), g),
                     "mrr": Fraction(1, first) if first else Fraction(0),
                     "rprec": Fraction(len(required & set(ranked[:g])), g)})
    if not rows:
        return zero
    return {k: sum((r[k] for r in rows), Fraction(0)) / len(rows) for k in zero}


def _task_macro(values: Mapping[str, list[Fraction]]) -> Fraction | None:
    scores = [m for m in (_mean(v) for v in values.values()) if m is not None]
    return _mean(scores)


def task_scores(outcomes: Sequence[Outcome], labels: Mapping[str, frozenset[str]],
                variant: Variant = "strict") -> dict[str, Fraction]:
    per: dict[str, list[Fraction]] = {}
    for outcome in outcomes:
        sets = _sets(outcome, variant)
        if sets is None:
            continue
        required = labels[outcome.slot.task_id]
        per.setdefault(outcome.slot.task_id, []).append(Fraction(len(required & sets[0]), len(required)))
    return {t: sum(v, Fraction(0)) / len(v) for t, v in per.items()}


def arm_metrics(outcomes: Sequence[Outcome], labels: Mapping[str, frozenset[str]], variant: Variant) -> ArmMetrics:
    first = outcomes[0].slot
    coverage: dict[str, list[Fraction]] = {}
    candidate: dict[str, list[Fraction]] = {}
    proxies: dict[str, dict[str, list[Fraction]]] = {}
    per_document: dict[str, list[int]] = {}
    complete: list[int] = []
    included = 0
    for outcome in outcomes:
        sets = _sets(outcome, variant)
        if sets is None:
            continue
        included += 1
        delivered, candidates = sets
        task = outcome.slot.task_id
        required = labels[task]
        coverage.setdefault(task, []).append(Fraction(len(required & delivered), len(required)))
        candidate.setdefault(task, []).append(Fraction(len(required & candidates), len(required)))
        complete.append(1 if required <= delivered else 0)
        for stem in required:
            per_document.setdefault(stem, []).append(1 if stem in delivered else 0)
        values = _proxies(outcome, required, variant)
        if values is not None:
            for key, value in values.items():
                proxies.setdefault(key, {}).setdefault(task, []).append(value)
    documents = [Fraction(sum(v), len(v)) for v in per_document.values()]

    def text(value: Fraction | None) -> str | None:
        return None if value is None else decimal_text(value)

    def proxy(key: str) -> str | None:
        return text(_task_macro(proxies[key])) if key in proxies else None

    counts = {s: 0 for s in STATUSES}
    known = [o.record for o in outcomes if o.record.spent_usd is not None and o.record.held_usd is not None]
    for outcome in outcomes:
        counts[outcome.record.status] += 1
    return ArmMetrics(
        arm_id=first.arm_id, phase=first.phase, variant=variant, scheduled_slots=len(outcomes),
        included_slots=included, status_counts=tuple((s, counts[s]) for s in STATUSES if counts[s]),
        task_macro_coverage=text(_task_macro(coverage)), document_macro_coverage=text(_mean(documents)),
        all_required_rate=text(Fraction(sum(complete), len(complete)) if complete else None),
        candidate_task_macro_coverage=text(_task_macro(candidate)),
        query_recall_at_10=proxy("r10"), query_recall_at_10_ceiling=proxy("c10"), query_recall_at_20=proxy("r20"),
        query_recall_at_20_ceiling=proxy("c20"), query_mrr_at_10=proxy("mrr"), query_r_precision=proxy("rprec"),
        delivered_documents=sum(len(o.delivered()) for o in outcomes),
        retrieval_steps=sum(len(o.record.steps) for o in outcomes),
        evidence_tokens=sum(step.evidence_tokens for o in outcomes for step in o.record.steps),
        spent_usd=_usd_sum([r.spent_usd for r in known]) if known else None,
        held_usd=_usd_sum([r.held_usd for r in known]) if known else None,
        cost_unknown_slots=len(outcomes) - len(known))


def _usd_sum(values: Sequence[str | None]) -> str:
    total = sum((Decimal(v) for v in values if v is not None), Decimal(0))
    return format(total.normalize(), "f") if total else "0"


# -- intervals -------------------------------------------------------------------------------------------------------

def type7(sorted_draws: Sequence[Fraction], p: Fraction) -> Fraction:
    """Type-7 (linear interpolation) empirical quantile of sorted draws: h = (B - 1)p."""
    h = (len(sorted_draws) - 1) * p
    low = math.floor(h)
    if low + 1 >= len(sorted_draws):
        return sorted_draws[-1]
    return sorted_draws[low] + (h - low) * (sorted_draws[low + 1] - sorted_draws[low])


def comparison_seed(seed: int, arm: str, baseline: str, phase: str, clusters: str) -> int:
    """A reproducible per-comparison seed derived from the manifest's bootstrap seed."""
    material = f"{seed}:{arm}:{baseline}:{phase}:{clusters}".encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def paired_interval(differences: Mapping[str, Fraction], clusters: Mapping[str, str], *, seed: int,
                    resamples: int, kind: str) -> Interval:
    """Resample clusters with replacement; each draw is the task-weighted mean difference over drawn clusters."""
    members: dict[str, list[str]] = {}
    for task in sorted(differences):
        members.setdefault(clusters[task], []).append(task)
    names = sorted(members)
    rng = random.Random(seed)  # noqa: S311 - a reproducible statistical resample, not cryptography
    draws = []
    for _ in range(resamples):
        total, count = Fraction(0), 0
        for _ in names:
            for task in members[names[rng.randrange(len(names))]]:
                total += differences[task]
                count += 1
        draws.append(total / count)
    draws.sort()
    estimate = sum(differences.values(), Fraction(0)) / len(differences)
    return Interval(estimate=decimal_text(estimate), lower=decimal_text(type7(draws, LOWER)),
                    upper=decimal_text(type7(draws, UPPER)), resamples=resamples,
                    clusters="task" if kind == "task" else "group")


def compare(arm: Sequence[Outcome], baseline: Sequence[Outcome], labels: Mapping[str, frozenset[str]],
            groups: Mapping[str, str], *, seed: int, resamples: int, phase: str) -> PairedComparison:
    """Paired strict task-score difference over exactly the same (task, trial) keys (checked before averaging); a
    confirmation arm pairs with the acquisition baseline by those same seeded keys."""
    keys_a = sorted((o.slot.task_id, o.slot.trial) for o in arm)
    keys_b = sorted((o.slot.task_id, o.slot.trial) for o in baseline)
    if keys_a != keys_b or len(set(keys_a)) != len(keys_a):
        raise ReportError("unpaired_cohorts", "the compared arms do not share exactly the same task/trial keys")
    a, b = task_scores(arm, labels), task_scores(baseline, labels)
    differences = {t: a[t] - b[t] for t in a}
    arm_id, base_id = arm[0].slot.arm_id, baseline[0].slot.arm_id
    tasks = {t: t for t in differences}
    return PairedComparison(
        arm_id=arm_id, baseline_arm_id=base_id, phase=phase,  # type: ignore[arg-type]
        task_cluster=paired_interval(differences, tasks, seed=comparison_seed(seed, arm_id, base_id, phase, "task"),
                                     resamples=resamples, kind="task"),
        group_sensitivity=paired_interval(differences, groups,
                                          seed=comparison_seed(seed, arm_id, base_id, phase, "group"),
                                          resamples=resamples, kind="group"))


# -- the report ------------------------------------------------------------------------------------------------------

def build_report(manifest: E01Manifest, records: Sequence[TrajectoryRecord], labels: Mapping[str, Iterable[str]],
                 groups: Mapping[str, str], selection: E01Selection | None = None) -> E01Report:
    required = {t: frozenset(labels[t]) for t in labels}
    if set(required) != set(manifest.task_ids) or not all(required.values()):
        raise ReportError("labels_mismatch", "labels must cover exactly the manifest's tasks, each non-empty")
    if not set(manifest.task_ids) <= set(groups):
        raise ReportError("groups_mismatch", "every task needs a group")
    bound = bind(manifest, records, selection)
    by_arm: dict[tuple[str, str], list[Outcome]] = {}
    for outcome in sorted(bound.values(), key=lambda o: (o.slot.phase, o.slot.arm_id, o.slot.task_id, o.slot.trial)):
        by_arm.setdefault((outcome.slot.phase, outcome.slot.arm_id), []).append(outcome)
    arms = tuple(arm_metrics(by_arm[key], required, variant) for key in sorted(by_arm) for variant in VARIANTS)
    comparisons = []
    seed, b = manifest.bootstrap_seed, manifest.bootstrap_resamples
    for (phase, arm_id), outcomes in sorted(by_arm.items()):
        if phase == "replay" and arm_id != "A2" and ("replay", "A2") in by_arm:
            comparisons.append(compare(outcomes, by_arm[("replay", "A2")], required, groups, seed=seed, resamples=b,
                                       phase="replay"))
        if phase == "confirmation" and ("acquisition", "A2") in by_arm:
            comparisons.append(compare(outcomes, by_arm[("acquisition", "A2")], required, groups, seed=seed,
                                       resamples=b, phase="confirmation"))
    return E01Report(
        manifest_sha256=manifest.digest(),
        records_sha256=_digest(sorted(r.digest() for r in records)),
        labels_sha256=labels_digest(required, {t: groups[t] for t in required}),
        arms=arms, comparisons=tuple(comparisons),
        not_scheduled_slots=len(manifest.slots) - len(scheduled(manifest, selection)))
