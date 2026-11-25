"""Replay recorded N3 held-out first calls through the N13 target rule for $0."""

from argparse import ArgumentParser
from collections import Counter
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Literal
from uuid import UUID

from policyops.domain.retail_rules import (
    MAX_SIBLING_READS,
    ORDER_TARGETS,
    Denied,
    Escalated,
    TargetSelection,
    select_order_target,
)
from policyops.gateway.stores import stated_order_ids
from policyops_contracts.retail import ModifyUserAddress, ToolName
from policyops_contracts.retail_service import FIXTURE_SHA256
from policyops_evals.scenarios import Refused, n3, read_bounded, study
from policyops_evals.scenarios.arms import Arm
from policyops_evals.scenarios.batch import read_result, slot_directory
from policyops_evals.scenarios.cases import POSITIVES, Scenario
from policyops_evals.scenarios.generator import FixtureData
from policyops_evals.scenarios.grading import _arguments, _output, _write
from policyops_evals.scenarios.recording import Tape, first_consequential_call, object_from


type Outcome = Literal["passed", "refused", "facts_unavailable", "outside_rule", "target_outside_customer",
                       "no_consequential_call", "malformed_call", "missing_tape"]


@dataclass(frozen=True)
class ReplayRow:
    outcome: Outcome
    false_block: bool = False


def replay(case: Scenario, fixture: FixtureData, tape: Tape, *, exact_proposal: bool) -> ReplayRow:
    first = first_consequential_call(tape.records)
    if first is None:
        return ReplayRow("no_consequential_call")
    if not first.only_call or not _output(tape.records[first.exchange_index]):
        return ReplayRow("malformed_call")
    tool = ToolName(first.name)
    if tool not in ORDER_TARGETS:
        return ReplayRow("outside_rule")
    action = _write(first.name, _arguments(first.name, first.call_id, first.arguments))
    if action is None or isinstance(action, ModifyUserAddress):
        return ReplayRow("malformed_call")
    # N3 seeded exactly this opener. Investigation never committed retail writes, so the pinned
    # fixture is the authoritative snapshot at the first consequential call.
    ids = stated_order_ids((("seeded", 1, case.visible.message),))
    closure = case.world.order_closure
    if action.order_id not in closure:
        return ReplayRow("target_outside_customer")
    eligible = None
    if not ids:
        if len(closure) - 1 > MAX_SIBLING_READS:
            return ReplayRow("facts_unavailable")
        status, _ = ORDER_TARGETS[tool]
        eligible = frozenset(oid for oid in closure if fixture.orders[oid]["status"] == status)
    result = select_order_target(tool, action.order_id, TargetSelection(ids, eligible))
    if isinstance(result, Denied):
        return ReplayRow("refused", exact_proposal)
    if isinstance(result, Escalated):
        return ReplayRow("facts_unavailable")
    return ReplayRow("passed")


def replay_frame(source: Path, manifests: Path, fixture: FixtureData) -> tuple[str, tuple[n3.Assignment, ...]]:
    registration = object_from(read_bounded(study.private_child(source, "registration.json"), 64 * 1024))
    receipt = registration["receipt"]
    payload = receipt["payload"]
    digest = study.validate_receipt(receipt, payload)["sha256"]
    unseal = object_from(read_bounded(study.private_child(source, "unseal.json"), 64 * 1024))
    gate = unseal["dev_gate"]
    expected_manifests = {key: value for key, value in study.MANIFEST_SHA256.items() if key.startswith("held-out.")}
    if (payload["schema"] != "policyops.scenario-study/n3-v1" or payload["revision"] != n3.REVISION_LABEL
            or payload["fixture"]["sha256"] != FIXTURE_SHA256 or gate["verdict"] != "admit"
            or gate["candidate_sha256"] != payload["candidate_sha256"]
            or unseal["registration_sha256"] != digest or gate["registration_sha256"] != digest
            or unseal["manifests"] != expected_manifests):
        raise Refused("recorded N3 unseal binding mismatch")
    cases = n3.load_cases(manifests, fixture, "held-out")
    groups = n3.case_groups(cases, "held-out", candidate=Arm.REVISION)
    blocks = n3.blocks(groups, "held-out", UUID(registration["study_id"]), UUID(payload["workspace"]))
    frame = tuple(item for block in blocks for item in block
                  if item.case.gold.stratum in (*POSITIVES, n3.AMBIGUOUS_STRATUM))
    return str(digest), frame


def replay_slot(source: Path, digest: str, fixture: FixtureData, item: n3.Assignment) -> ReplayRow:
    result = read_result(source, item.slot, digest)
    directory = study.private_child(slot_directory(source, item.slot), "tape")
    if result is None or not directory.is_dir():
        return ReplayRow("missing_tape")
    for exchange in directory.glob("[0-9][0-9].json"):
        study.private_child(directory, exchange.name)
    tape = Tape(directory)
    tape_digest = sha256(b"\n".join(exchange.model_dump_json().encode() for exchange in tape.records)).hexdigest()
    if tape_digest != result.tape_sha256:
        raise Refused("recorded N3 tape digest mismatch")
    return replay(item.case, fixture, tape, exact_proposal=result.grade.primary is True)


def _temp_path(root: Path, path: Path) -> Path:
    target = study.private_root(path)
    if not path.absolute().is_relative_to(root) or not target.is_relative_to(root) or path.absolute() != target:
        raise Refused("replay paths must be unlinked and under POLICYOPS_TEMP_DIR")
    return target


def main() -> int:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--recording-root", type=Path, required=True)
    parser.add_argument("--manifests", type=Path, required=True)
    parser.add_argument("--fixture-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="A new private JSON report")
    args = parser.parse_args()
    try:
        root = study.private_root(Path(os.environ["POLICYOPS_TEMP_DIR"]))
        source = _temp_path(root, args.recording_root)
        manifests = _temp_path(root, args.manifests)
        for name in ("held-out.visible.jsonl", "held-out.gold.jsonl"):
            study.private_child(manifests, name)
        output = _temp_path(root, args.out)
        fixture = n3.fixture_inputs(args.fixture_root)
        digest, frame = replay_frame(source, manifests, fixture)
        rows = []
        counts: dict[str, dict[str, Counter[str]]] = {
            arm: {group: Counter(scheduled=0, false_blocks=0) for group in ("ambiguous", "positive")}
            for arm in (Arm.BASELINE, Arm.REVISION)
        }
        for item in frame:
            row = replay_slot(source, digest, fixture, item)
            group = "ambiguous" if item.case.gold.stratum == n3.AMBIGUOUS_STRATUM else "positive"
            totals = counts[item.arm][group]
            totals["scheduled"] += 1
            totals[row.outcome] += 1
            totals["false_blocks"] += row.false_block
            rows.append({"case": item.case.key, "arm": item.arm, "stratum": item.case.gold.stratum, **asdict(row)})
        with output.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump({"counts": counts, "attempts": rows}, handle, sort_keys=True)
            handle.write("\n")
        return int(any(totals["missing_tape"] for arm in counts.values() for totals in arm.values()))
    except Exception as exc:
        # Validation errors can include private tape content. The per-case report is file-only.
        print(json.dumps({"error": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
