"""Pinned ALL scoring with strict NL coverage, preserving ENV on judge failure."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
from typing import TYPE_CHECKING, Any

from policyops_evals.harness.actors import ActorBindings


if TYPE_CHECKING:
    from tau2.data_model.simulation import RewardInfo, SimulationRun
    from tau2.data_model.tasks import Task


class JudgeRefused(ValueError):
    pass


def validate_judgement(text: str, expected: tuple[str, ...]) -> None:
    if type(text) is not str or len(text) > 65_536 or len(expected) > 64:
        raise JudgeRefused("judge_bounds")
    # Before JSON allocation: cap nesting and reject duplicate keys/non-finite values.
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 8:
                raise JudgeRefused("judge_bounds")
        elif char in "]}":
            depth -= 1

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise JudgeRefused("judge_duplicate_key")
            out[key] = value
        return out

    def invalid(value: str) -> Any:
        raise JudgeRefused("judge_json")

    try:
        data = json.loads(text, object_pairs_hook=pairs, parse_constant=invalid)
    except (ValueError, RecursionError):
        raise JudgeRefused("judge_json") from None
    if type(data) is not dict or set(data) != {"results"} or type(data["results"]) is not list:
        raise JudgeRefused("judge_shape")
    results = data["results"]
    if len(results) != len(expected):
        raise JudgeRefused("judge_coverage")
    outcomes: list[str] = []
    for item in results:
        if (type(item) is not dict or set(item) != {"expectedOutcome", "metExpectation", "reasoning"}
                or type(item["expectedOutcome"]) is not str or type(item["metExpectation"]) is not bool
                or type(item["reasoning"]) is not str or not 1 <= len(item["reasoning"]) <= 8000):
            raise JudgeRefused("judge_shape")
        outcomes.append(item["expectedOutcome"])
    if Counter(outcomes) != Counter(expected):
        raise JudgeRefused("judge_coverage")


@dataclass(frozen=True)
class Score:
    environment: RewardInfo
    composite: RewardInfo | None
    error: str | None = None


def score(simulation: SimulationRun, task: Task, *, actors: ActorBindings, domain: str = "retail",
          env_kwargs: dict[str, Any] | None = None) -> Score:
    from tau2.data_model.semantic_communication import CommunicateScorer, CommunicateScoring
    from tau2.data_model.tasks import RewardType
    from tau2.evaluator.evaluator import EvaluationType, evaluate_simulation

    criteria = task.evaluation_criteria
    assertions = criteria.nl_assertions if criteria is not None else None
    if assertions is not None and (type(assertions) is not list or len(assertions) > 64):
        raise JudgeRefused("assertion_bounds")
    expected = tuple(assertions or ())
    if any(type(s) is not str or not 1 <= len(s) <= 8000 for s in expected):
        raise JudgeRefused("assertion_bounds")
    # Bound before upstream builds trajectory_str and the NL prompt.
    if type(simulation.messages) is not list or len(simulation.messages) > 256:
        raise JudgeRefused("transcript_bounds")
    total = 0
    for message in simulation.messages:
        content = message.content
        if content is not None:
            if type(content) is not str or len(content) > 200_000:
                raise JudgeRefused("transcript_bounds")
            total += len(content)
            if total > 160_000:
                raise JudgeRefused("transcript_bounds")
    options = dict(simulation=simulation, task=task, solo_mode=False, domain=domain,
        strict_replay=True, env_kwargs=env_kwargs,
        communicate_scoring=CommunicateScoring(scorer=CommunicateScorer.SUBSTRING, judge=None))
    environment = evaluate_simulation(evaluation_type=EvaluationType.ENV, **options)
    try:
        with actors.judging(lambda text: validate_judgement(text, expected)):
            composite = evaluate_simulation(evaluation_type=EvaluationType.ALL, **options)
        if criteria is not None and RewardType.NL_ASSERTION in criteria.reward_basis and expected:
            checks = composite.nl_assertions or []
            if Counter(c.nl_assertion for c in checks) != Counter(expected):
                raise JudgeRefused("judge_coverage")
        return Score(environment, composite)
    except Exception:
        return Score(environment, None, "scoring_unavailable")
