"""E01 study planning (T15a): pure enumeration, common budget envelopes, a Decimal preflight and the selection rule.

No I/O, provider call, count request or ledger write. Every number is derived from the pinned local registry, price
snapshot and actor configuration (`Configuration.reservation(actor)`), never from expected spend:

- each chat attempt (simulator, investigator, reranker) reserves its actor's worst case at the actor maxima, and each
  embedding batch reserves its actor's `max_request_tokens` worst case, whatever the actual query length;
- comparable arms share ONE outer per-slot envelope (equal budgets for the paired comparison): banking in-situ A0-A3
  use the A3 envelope (simulator U + investigator A chat calls, S embedding batches, S rerank calls); replay A1-A3 the
  A3 replay envelope (S embedding batches + S rerank calls); retail R0/R1 the R1 envelope. Unused capacity is a
  diagnostic, not a different budget;
- lexical replay (A0) has no provider path: no envelope, no ledger scope, no invented zero-USD cap.

A manifest is **proposed** only: it records the plan, not a measurement. The ceiling of a study is the sum of its
activatable slots' envelope caps (the declared optional confirmation slots count at most two arms: one simpler arm and
A3). It bounds reservations; an attempt whose true usage exceeds its reservation settles the exact bill (T10 overrun),
which a ceiling cannot bound. Corpus ingestion is a separate operation with its own caps and approval and is never
added to slot ceilings.

Selection (dev, descriptive; the margin is a proposed policy, not a measured result): the replay screen may only
propose confirmation arms; the final arm needs paired in-situ evidence; A3 is never chosen from replay alone.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from uuid import UUID

from policyops.budget.config import Actor, Caps, ChatActor, Configuration, EmbeddingActor
from policyops_contracts.e01 import (
    ActorReservation,
    ArmId,
    Bounds,
    E01Arm,
    E01Manifest,
    E01Selection,
    Envelope,
    EnvelopeGroup,
    Interval,
    SlotSpec,
    slot_id_for,
)
from policyops_contracts.retrieval import RerankConfig, RetrievalConfig


DEFAULT_BOUNDS = Bounds(simulator_turns=12, investigator_calls=16, retrieval_steps=10)
DEFAULT_MARGIN = "0.05"
BANKING_ARMS: tuple[ArmId, ...] = ("A0", "A1", "A2", "A3")
RETAIL_ARMS: tuple[ArmId, ...] = ("R0", "R1")
SIMPLER: tuple[ArmId, ...] = ("A0", "A1")  # simplicity / cost order A0 < A1 < A2 < A3


class PlanError(ValueError):
    pass


def arm_config(arm_id: ArmId) -> RetrievalConfig:
    """The T13/T14 defaults of each arm (identical per-step budgets)."""
    return {
        "A0": RetrievalConfig(mode="lexical"),
        "A1": RetrievalConfig(mode="dense", dense_policy="refuse"),
        "A2": RetrievalConfig(mode="hybrid"),
        "A3": RetrievalConfig(mode="hybrid", rerank=RerankConfig()),
        "R0": RetrievalConfig(mode="full_policy"),
        "R1": RetrievalConfig(mode="hybrid"),
    }[arm_id]


def arm(arm_id: ArmId) -> E01Arm:
    config = arm_config(arm_id)
    return E01Arm(arm_id=arm_id, config=config, config_sha256=config.sha256())


def _usd(value: Decimal) -> str:
    return format(value.normalize(), "f") if value else "0"


def actor_reservations(configuration: Configuration, actors: Sequence[Actor]) -> tuple[ActorReservation, ...]:
    result = []
    for name in actors:
        reservation = configuration.reservation(name)
        result.append(ActorReservation(actor=name, model=reservation.model, config_sha256=reservation.config_sha256,
                                       worst_usd=_usd(reservation.worst_usd)))
    return tuple(result)


def envelope(configuration: Configuration, bounds: Bounds, group: EnvelopeGroup) -> Envelope:
    """The common outer envelope of a group, from the actual actor reservations."""
    worst = {a: configuration.reservation(a).worst_usd for a in ("simulator", "agent", "reranker", "embedding")}
    u, a, s = bounds.simulator_turns, bounds.investigator_calls, bounds.retrieval_steps
    chat, batches = {"banking_insitu": (u + a + s, s), "replay_provider": (s, s), "retail": (u + a, s)}[group]
    usd = {"banking_insitu": (u * worst["simulator"] + a * worst["agent"] + s * worst["reranker"]
                              + s * worst["embedding"]),
           "replay_provider": s * worst["reranker"] + s * worst["embedding"],
           "retail": u * worst["simulator"] + a * worst["agent"] + s * worst["embedding"]}[group]
    chats = [configuration.actors[x] for x in ("simulator", "agent", "reranker")]
    embedding = configuration.actors["embedding"]
    if not all(isinstance(c, ChatActor) for c in chats) or not isinstance(embedding, EmbeddingActor):
        raise PlanError("the study actors are not configured as chat and embedding actors")
    Caps(run_usd=usd, run_calls=chat + batches)  # the ledger's own cap validation (positive USD and calls)
    return Envelope(group=group, cap_calls=chat + batches, cap_usd=_usd(usd), chat_calls=chat,
                    embedding_batches=batches,
                    max_input_tokens_per_chat_call=max(c.max_input for c in chats),  # type: ignore[union-attr]
                    max_output_tokens_per_chat_call=max(c.max_output for c in chats),  # type: ignore[union-attr]
                    max_input_tokens_per_embedding_batch=embedding.max_request_tokens)


def _slot(study_id: UUID, phase: str, arm_id: ArmId, task_id: str, trial: int, *, optional: bool = False,
          group: EnvelopeGroup | None) -> SlotSpec:
    return SlotSpec(slot_id=slot_id_for(study_id, phase, arm_id, task_id, trial), phase=phase,  # type: ignore[arg-type]
                    arm_id=arm_id, task_id=task_id, trial=trial, plan="declared_optional" if optional else "scheduled",
                    provider_path=group is not None, envelope=group)


def banking_manifest(*, study_id: UUID, split_manifest_sha256: str, dev_task_ids: Sequence[str],
                     dev_task_ids_digest: str, configuration: Configuration, seeds: Sequence[int],
                     bootstrap_seed: int, bounds: Bounds = DEFAULT_BOUNDS, margin: str = DEFAULT_MARGIN
                     ) -> E01Manifest:
    """Acquisition A2 in-situ; replay A0 (no provider), A1, A2, A3; declared optional confirmation A0, A1, A3."""
    tasks, trials = sorted(dev_task_ids), len(seeds)
    slots: list[SlotSpec] = []
    for task in tasks:
        for trial in range(trials):
            slots.append(_slot(study_id, "acquisition", "A2", task, trial, group="banking_insitu"))
            slots.append(_slot(study_id, "replay", "A0", task, trial, group=None))
            slots.extend(_slot(study_id, "replay", a, task, trial, group="replay_provider") for a in ("A1", "A2", "A3"))
            slots.extend(_slot(study_id, "confirmation", a, task, trial, optional=True, group="banking_insitu")
                         for a in ("A0", "A1", "A3"))
    return E01Manifest(
        study_id=study_id, purpose="dev_selection", domain="banking_knowledge",
        split_manifest_sha256=split_manifest_sha256, dev_task_ids_digest=dev_task_ids_digest, task_ids=tuple(tasks),
        trials=trials, seeds=tuple(seeds), arms=tuple(arm(a) for a in BANKING_ARMS), bounds=bounds,
        envelopes=tuple(envelope(configuration, bounds, g) for g in ("banking_insitu", "replay_provider")),
        actors=actor_reservations(configuration, ("agent", "simulator", "reranker", "embedding")),
        price_revision=configuration.registry.snapshot.revision, margin=margin, bootstrap_seed=bootstrap_seed,
        slots=tuple(slots))


def retail_manifest(*, study_id: UUID, split_manifest_sha256: str, dev_task_ids: Sequence[str],
                    dev_task_ids_digest: str, configuration: Configuration, seeds: Sequence[int],
                    bootstrap_seed: int, bounds: Bounds = DEFAULT_BOUNDS, margin: str = DEFAULT_MARGIN
                    ) -> E01Manifest:
    """The retail-only control: R0 full policy versus R1 hybrid under one common envelope."""
    tasks, trials = sorted(dev_task_ids), len(seeds)
    slots = [_slot(study_id, "retail_control", a, task, trial, group="retail")
             for task in tasks for trial in range(trials) for a in RETAIL_ARMS]
    return E01Manifest(
        study_id=study_id, purpose="retail_dev_control", domain="retail", split_manifest_sha256=split_manifest_sha256,
        dev_task_ids_digest=dev_task_ids_digest, task_ids=tuple(tasks), trials=trials, seeds=tuple(seeds),
        arms=tuple(arm(a) for a in RETAIL_ARMS), bounds=bounds, envelopes=(envelope(configuration, bounds, "retail"),),
        actors=actor_reservations(configuration, ("agent", "simulator", "embedding")),
        price_revision=configuration.registry.snapshot.revision, margin=margin, bootstrap_seed=bootstrap_seed,
        slots=tuple(slots))


@dataclass(frozen=True)
class Ceiling:
    """Reservation ceilings (never expected spend). Chat calls, embedding batches (each one count-unit-capable call
    under the ledger's cap_counts = cap_calls), tokens and USD are kept apart."""

    phase: str
    slots: int
    chat_calls: int
    embedding_batches: int
    max_input_tokens: int
    max_output_tokens: int
    usd: Decimal


def _slot_usd(slots: Sequence[SlotSpec], envelopes: Mapping[EnvelopeGroup, Envelope]) -> Decimal:
    return sum((Decimal(envelopes[s.envelope].cap_usd) for s in slots if s.envelope is not None), Decimal(0))


def ceilings(manifest: E01Manifest) -> tuple[tuple[Ceiling, ...], Decimal]:
    """Per-phase ceilings and the study ceiling. Optional confirmation counts the most expensive LEGAL selection,
    summed from the declared slots themselves: the costliest single simpler arm (A0 or A1, at most one can be
    selected) plus A3. Any scheduled slots of a phase are kept, never overwritten. Corpus ingestion is separate and
    not included."""
    envelopes = {e.group: e for e in manifest.envelopes}
    per: dict[str, list[SlotSpec]] = {}
    optional: dict[str, list[SlotSpec]] = {}
    for slot in manifest.slots:
        if slot.plan == "declared_optional":
            optional.setdefault(slot.arm_id, []).append(slot)
        else:
            per.setdefault(slot.phase, []).append(slot)
    if optional:
        simpler = [optional[a] for a in SIMPLER if a in optional]
        selected = list(max(simpler, key=lambda cohort: _slot_usd(list(cohort), envelopes))) if simpler else []
        selected += optional.get("A3", [])
        per.setdefault("confirmation", []).extend(selected)
    result = []
    total = Decimal(0)
    for phase in sorted(per):
        slots = per[phase]
        scoped = [envelopes[s.envelope] for s in slots if s.envelope is not None]
        usd = sum((Decimal(e.cap_usd) for e in scoped), Decimal(0))
        result.append(Ceiling(
            phase=phase, slots=len(slots), chat_calls=sum(e.chat_calls for e in scoped),
            embedding_batches=sum(e.embedding_batches for e in scoped),
            max_input_tokens=sum(e.chat_calls * e.max_input_tokens_per_chat_call
                                 + e.embedding_batches * e.max_input_tokens_per_embedding_batch for e in scoped),
            max_output_tokens=sum(e.chat_calls * e.max_output_tokens_per_chat_call for e in scoped), usd=usd))
        total += usd
    return tuple(result), total


# -- selection -------------------------------------------------------------------------------------------------------

def _lower(interval: Interval) -> Decimal:
    return Decimal(interval.lower)


def confirmation_arms(replay: Mapping[ArmId, Interval], margin: str) -> tuple[ArmId, ...]:
    """Replay screen (diagnostic only): the simplest A0/A1 whose replay lower bound vs A2 is >= -margin, and A3 if its
    replay lower bound vs A2 is > 0. Every candidate's replay interval is required."""
    missing = [a for a in ("A0", "A1", "A3") if a not in replay]
    if missing:
        raise PlanError(f"replay intervals are required for {missing}")
    m = Decimal(margin)
    chosen: list[ArmId] = []
    simpler = next((a for a in SIMPLER if _lower(replay[a]) >= -m), None)
    if simpler is not None:
        chosen.append(simpler)
    if _lower(replay["A3"]) > 0:
        chosen.append("A3")
    return tuple(sorted(chosen))


def selection(manifest: E01Manifest, replay_report_sha256: str, replay: Mapping[ArmId, Interval]) -> E01Selection:
    return E01Selection(manifest_sha256=manifest.digest(), replay_report_sha256=replay_report_sha256,
                        confirmation_arms=confirmation_arms(replay, manifest.margin))


def final_arm(chosen: E01Selection, in_situ: Mapping[ArmId, Interval], margin: str) -> ArmId:
    """In-situ decision table: A3 if confirmed in-situ with lower bound > 0; else the confirmed simpler arm if its
    in-situ lower bound is >= -margin; else A2. Every confirmed arm needs its in-situ paired interval vs A2."""
    m = Decimal(margin)
    missing = [a for a in chosen.confirmation_arms if a not in in_situ]
    if missing:
        raise PlanError(f"in-situ paired intervals are required for the confirmed arms {missing}")
    if "A3" in chosen.confirmation_arms and _lower(in_situ["A3"]) > 0:
        return "A3"
    simpler = next((a for a in chosen.confirmation_arms if a in SIMPLER), None)
    if simpler is not None and _lower(in_situ[simpler]) >= -m:
        return simpler
    return "A2"
