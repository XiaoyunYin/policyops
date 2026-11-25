"""Regrade N13-bound private tapes and report aggregate N15 results offline."""

from argparse import ArgumentParser
from dataclasses import asdict
import json
import os
from pathlib import Path
from random import Random

from policyops_evals.scenarios import Refused, n3, study
from policyops_evals.scenarios.arms import Arm
from policyops_evals.scenarios.cases import POSITIVES
from policyops_evals.scenarios.grading import grade_slot
from policyops_evals.scenarios.n13_replay import _temp_path, replay_frame, verified_tape
from policyops_evals.scenarios.n15_monitor import CADENCE, RULES, evaluate
from policyops_evals.scenarios.n15_scorer import Capture, Score, Scorer


EXPECTED = {Arm.REVISION: 171, Arm.BASELINE: 3}
PAIRS = 192
RESAMPLE_SEEDS = (15031, 15032, 15033)


def report(source: Path, manifests: Path, fixture_root: Path) -> dict[str, object]:
    n3.grader_digest()
    digest, frame = replay_frame(source, manifests, n3.fixture_inputs(fixture_root))
    positives = [item for item in frame if item.case.gold.stratum in POSITIVES]
    scorer = Scorer({item.slot.id: item.case.gold for item in positives})
    scored: dict[Arm, dict[tuple[str, int], Score]] = {Arm.BASELINE: {}, Arm.REVISION: {}}
    regraded = {arm: 0 for arm in scored}
    for item in positives:
        bound = verified_tape(source, digest, item)
        if bound is None:
            raise Refused("recorded N3 positive is missing its tape")
        result, tape = bound
        grade = grade_slot(item.case.gold, tape.records or None, stop=result.stop_reason)
        if grade.primary != result.grade.primary:
            raise Refused("recorded N3 grade does not reconcile")
        regraded[item.arm] += int(grade.primary is True)
        pair = (item.case.key, item.repeat)
        if pair in scored[item.arm]:
            raise Refused("duplicate recorded N3 positive")
        scored[item.arm][pair] = scorer.score(item.slot.id, Capture(tuple(tape.records), result.stop_reason))
    revision, baseline = scored[Arm.REVISION], scored[Arm.BASELINE]
    if len(revision) != PAIRS or revision.keys() != baseline.keys() or regraded != EXPECTED:
        raise Refused("N3 paired positive totals do not reconcile")

    # Primary order is the registered tool-contract schedule, paired to default by case and repeat.
    # Resamples permute the same pairs for all three phases. Recovery reuses the revision capture.
    runs = []
    for seed in (None, *RESAMPLE_SEEDS):
        order = list(revision)
        if seed is not None:
            Random(seed).shuffle(order)  # noqa: S311 - predeclared evaluation permutation
        schedule = [arm[pair] for arm in (revision, baseline, revision) for pair in order]
        runs.append({"kind": "primary" if seed is None else "resample", "seed": seed,
                     "rules": {rule: asdict(evaluate(schedule, rule, onset=PAIRS, restoration=2 * PAIRS))
                               for rule in RULES}})
    return {"version": "n15-v1", "cadence_seconds": CADENCE, "pairs": PAIRS, "n3_exact": regraded,
            "canary_exact": {arm: sum(score.proposal == "exact" for score in rows.values())
                             for arm, rows in scored.items()}, "runs": runs}


def main() -> int:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--recording-root", required=True, type=Path)
    parser.add_argument("--manifests", required=True, type=Path)
    parser.add_argument("--fixture-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        root = study.private_root(Path(os.environ["POLICYOPS_TEMP_DIR"]))
        source = _temp_path(root, args.recording_root)
        manifests = _temp_path(root, args.manifests)
        for name in ("held-out.visible.jsonl", "held-out.gold.jsonl"):
            study.private_child(manifests, name)
        output = _temp_path(root, args.out)
        if output.exists():
            raise Refused("aggregate report requires a new output path")
        values = report(source, manifests, args.fixture_root)
        with output.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(values, handle, sort_keys=True)
            handle.write("\n")
    except Exception as error:
        print(json.dumps({"error": type(error).__name__}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
