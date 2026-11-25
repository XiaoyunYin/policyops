"""Run the frozen canary rules and comparison on controlled-clock synthetic schedules."""

from collections.abc import Sequence
from dataclasses import asdict, dataclass
import json
from math import sqrt
from random import Random
from statistics import median
from typing import Literal
from uuid import UUID

from policyops_evals.scenarios.n15_scorer import POSITIVE_WINDOW, ScheduledSlot, Score, Snapshot, Windows


# N15 v1. Freeze these choices on synthetic controls before reading any private recording.
CADENCE = EVALUATION_SECONDS = 15
SLOT_DEADLINE = 12
FRESH_SECONDS = 90
HOLD_SECONDS = 120
MIN_CLASSIFIED = 16
EXACT_FLOOR = 0.75
WILSON_Z = 1.959963984540054
FIXTURE_ORDERS = (0, 1, 2)
PHASE = 40
HEALTHY_NOISE = 21 / 192
NOISE_SEEDS = range(15000, 15200)
type Rule = Literal["fixed", "wilson"]
RULES: tuple[Rule, ...] = ("fixed", "wilson")


def wilson_lower(failures: int, classified: int) -> float:
    if not 0 <= failures <= classified or classified == 0:
        raise ValueError("Wilson interval requires a nonempty binomial sample")
    p = failures / classified
    z2 = WILSON_Z**2
    return (p + z2 / (2 * classified) - WILSON_Z * sqrt((p * (1 - p) + z2 / (4 * classified)) / classified)
            ) / (1 + z2 / classified)


@dataclass(frozen=True)
class State:
    firing: bool
    blind: bool
    valid_clear: bool


class Monitor:
    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        self.pending: float | None = None

    def evaluate(self, snapshot: Snapshot | None, now: float, *, started: float) -> State:
        if snapshot is None:
            self.pending = None
            return State(False, True, False)
        age = now - (snapshot.last_finalized if snapshot.last_finalized is not None else started)
        fresh = snapshot.last_finalized is not None and 0 <= age <= FRESH_SECONDS
        classified = snapshot.classified
        stale = age >= FRESH_SECONDS if snapshot.last_finalized is None else not fresh
        blind = (stale or snapshot.proposal["unavailable"] > 0 or snapshot.ambiguous["unavailable"] > 0
                 or (snapshot.proposal.total() >= POSITIVE_WINDOW and classified < MIN_CLASSIFIED))
        valid = fresh and classified >= MIN_CLASSIFIED
        exact = snapshot.proposal["exact"]
        low = valid and (exact / classified < EXACT_FLOOR if self.rule == "fixed"
                         else wilson_lower(classified - exact, classified) > 1 - EXACT_FLOOR)
        if not low:
            self.pending = None
        elif self.pending is None:
            self.pending = now
        firing = self.pending is not None and now - self.pending >= HOLD_SECONDS
        return State(firing, blind, valid and not low and not blind)


@dataclass(frozen=True)
class Delay:
    slots: int
    seconds: int


@dataclass(frozen=True)
class Observation:
    firing: Delay | None
    valid_clear: Delay | None
    missed_episode: bool | None
    healthy_firings: int
    healthy_hours: float
    blind_intervals_seconds: tuple[tuple[int, int], ...]


def evaluate(scores: Sequence[Score], rule: Rule, *, onset: int | None = None,
             restoration: int | None = None, trailing_seconds: int = 0) -> Observation:
    schedule = [ScheduledSlot(UUID(int=index + 1), score.proposal is not None,
                              index * CADENCE, index * CADENCE + SLOT_DEADLINE)
                for index, score in enumerate(scores)]
    windows = Windows(schedule)
    monitor = Monitor(rule)
    fire = clear = None
    was_firing = False
    healthy_firings = 0
    blind_start = None
    blind_intervals = []
    end = len(schedule) * CADENCE + trailing_seconds
    cursor = 0
    for now in range(0, end, EVALUATION_SECONDS):
        while cursor < len(schedule) and schedule[cursor].due <= now:
            windows.finalize(schedule[cursor].id, scores[cursor], schedule[cursor].due)
            cursor += 1
        state = monitor.evaluate(windows.snapshot(), now, started=0)
        if state.blind and blind_start is None:
            blind_start = now
        elif not state.blind and blind_start is not None:
            blind_intervals.append((blind_start, now))
            blind_start = None
        if state.firing and not was_firing:
            if onset is None or now < onset * CADENCE:
                healthy_firings += 1
            elif fire is None and restoration is not None and now < restoration * CADENCE:
                delay = now - onset * CADENCE
                fire = Delay(delay // CADENCE, delay)
        if (restoration is not None and now >= restoration * CADENCE
                and fire is not None and clear is None and state.valid_clear):
            delay = now - restoration * CADENCE
            clear = Delay(delay // CADENCE, delay)
        was_firing = state.firing
    if blind_start is not None:
        blind_intervals.append((blind_start, end))
    healthy_slots = len(scores) if onset is None else onset
    return Observation(fire, clear, (fire is None if onset is not None else None), healthy_firings,
                       healthy_slots * CADENCE / 3600, tuple(blind_intervals))


def healthy(positive: bool) -> Score:
    if positive:
        return Score(proposal="exact", gateway="accepted")
    return Score(ambiguous="clarified", gateway="not_reached")


FAULT_SCORES = {
    "wrong_target": Score(proposal="wrong_target", gateway="target_refused"),
    "abstain": Score(proposal="abstain", gateway="not_reached"),
    "malformed": Score(proposal="invalid", gateway="not_reached"),
}


def fault_schedule(fault: str, stride: int, order: int) -> list[Score]:
    scores = []
    positive_index = 0
    for index in range(3 * PHASE):
        positive = index % 5 != 4
        if positive and PHASE <= index < 2 * PHASE:
            injected = (positive_index + order) % stride == 0
            scores.append(FAULT_SCORES[fault] if injected else healthy(True))
            positive_index += 1
        else:
            scores.append(healthy(positive))
    return scores


def noisy_schedule(seed: int) -> list[Score]:
    random = Random(seed)  # noqa: S311 - a reproducible synthetic failure schedule
    return [Score(proposal="other_miss", gateway="not_reached") if index % 5 != 4 and random.random() < HEALTHY_NOISE
            else healthy(index % 5 != 4) for index in range(3 * PHASE)]


def healthy_rate(rows: Sequence[Observation]) -> dict[str, float | int | None]:
    hours = sum(row.healthy_hours for row in rows)
    alerts = sum(row.healthy_firings for row in rows)
    return {"new_firings": alerts, "hours": hours, "firings_per_hour": alerts / hours if hours else None,
            "rule_of_three_upper_per_hour": 3 / hours if hours and alerts == 0 else None}


def study() -> dict[str, object]:
    episodes = []
    observations: dict[Rule, list[Observation]] = {rule: [] for rule in RULES}
    for fault in FAULT_SCORES:
        for stride in (1, 2, 4):
            for order in FIXTURE_ORDERS:
                schedule = fault_schedule(fault, stride, order)
                row = {rule: evaluate(schedule, rule, onset=PHASE, restoration=2 * PHASE) for rule in RULES}
                for rule in RULES:
                    if stride != 4:
                        observations[rule].append(row[rule])
                episodes.append({"fault": fault, "intensity": 1 / stride, "fixture_order": order,
                                 "rules": {rule: asdict(result) for rule, result in row.items()}})
    noisy = {rule: [evaluate(noisy_schedule(seed), rule) for seed in NOISE_SEEDS] for rule in RULES}
    summary = {rule: {
        "misses": sum(row.missed_episode is True for row in observations[rule]),
        "episodes": len(observations[rule]),
        "median_detection_seconds": median([row.firing.seconds for row in observations[rule]
                                            if row.firing is not None]),
        "noisy_healthy": healthy_rate(noisy[rule]),
    } for rule in RULES}
    # Rank by missed above-floor episodes, noisy-healthy firings, then detection delay.
    def rank(rule: Rule) -> tuple[int, int, float]:
        rows = observations[rule]
        delays = [row.firing.seconds for row in rows if row.firing is not None]
        return (sum(row.missed_episode is True for row in rows), sum(row.healthy_firings for row in noisy[rule]),
                median(delays) if delays else float("inf"))

    winner = min(RULES, key=rank)
    return {"version": "n15-v1", "cadence_seconds": CADENCE, "phase_slots": PHASE, "episodes": episodes,
            "noisy_healthy_failure_probability": HEALTHY_NOISE,
            "noisy_healthy_repeats": [
                {"seed": seed, "rules": {rule: asdict(noisy[rule][index]) for rule in RULES}}
                for index, seed in enumerate(NOISE_SEEDS)
            ], "summary": summary, "synthetic_winner": winner}


if __name__ == "__main__":
    print(json.dumps(study(), sort_keys=True))
