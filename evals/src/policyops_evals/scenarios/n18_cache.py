"""Reprice retained N7 usage and model fixed-workload 30-minute caching economics."""

import argparse
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from decimal import Decimal
from hashlib import sha256
import json
from pathlib import Path
from typing import Any
from uuid import UUID, uuid5

from policyops.budget.prices import SNAPSHOT_2026_11_05
from policyops_evals.canonical import canonical_bytes
from policyops_evals.scenarios import Refused, study
from policyops_evals.scenarios.arms import Arm
from policyops_evals.scenarios.batch import read_result, slot_directory
from policyops_evals.scenarios.n7 import ARMS, CACHE_OPTIONS
from policyops_evals.scenarios.n7_report import MODEL, Usage, raw_usage
from policyops_evals.scenarios.n18_evidence import document, exchanges, registration
from policyops_evals.scenarios.recording import object_from
from policyops_evals.scenarios.runtime import Slot


TIER = SNAPSHOT_2026_11_05.price(MODEL).tier_for(10_000)
RATE_READ, RATE_OUTPUT = TIER.cache_read, TIER.output
if RATE_READ is None or RATE_OUTPUT is None:
    raise ValueError("N7 requires dated chat and cache prices")
RATES = (TIER.input, RATE_READ, TIER.cache_writes["30m"], RATE_OUTPUT)
COMPONENTS = ("uncached_input", "reads", "writes_30m", "output")


@dataclass(frozen=True)
class Tokens:
    uncached_input: int = 0
    reads: int = 0
    writes_30m: int = 0
    output: int = 0

    def __add__(self, other: "Tokens") -> "Tokens":
        return Tokens(self.uncached_input + other.uncached_input, self.reads + other.reads,
                      self.writes_30m + other.writes_30m, self.output + other.output)

    @classmethod
    def from_usage(cls, usage: Usage, arm: Arm) -> "Tokens":
        if (usage.write_12h or SNAPSHOT_2026_11_05.price(MODEL).tier_for(usage.input) != TIER
                or (arm is Arm.A0 and (usage.read or usage.write))):
            raise Refused("N7 usage disagrees with the registered cache mode or rate tier")
        return cls(usage.input - usage.read - usage.write, usage.read, usage.write_30m, usage.output)

    def usd_parts(self) -> dict[str, Decimal]:
        return {name: (getattr(self, name) * rate).scaleb(-6) for name, rate in zip(COMPONENTS, RATES, strict=True)}

    @property
    def settled(self) -> Decimal:
        return sum(self.usd_parts().values(), Decimal(0))


def fixed_workload(tokens: Tokens) -> dict[str, Decimal | int]:
    """Treat recorded read/write tokens as eligible and keep residual input and output fixed.

    At read share h the eligible input costs E*(h*r+(1-h)*w) per million,
    where r is the read rate and w is the 30-minute write rate. Cache bypass
    pays the ordinary input rate for the eligible tokens as well.
    """
    eligible = tokens.reads + tokens.writes_30m
    if eligible <= 0:
        raise ValueError("fixed workload requires observed cache-eligible tokens")
    ordinary, read, write, output = RATES
    fixed = tokens.uncached_input * ordinary + tokens.output * output
    cold = (fixed + eligible * write).scaleb(-6)
    hit = (fixed + eligible * read).scaleb(-6)
    bypass = (fixed + eligible * ordinary).scaleb(-6)
    observed = (fixed + tokens.reads * read + tokens.writes_30m * write).scaleb(-6)
    return {"eligible_input": eligible, "observed_read_share": Decimal(tokens.reads) / eligible,
            "modelled_all_cold_usd": cold, "modelled_all_hit_usd": hit, "modelled_bypass_usd": bypass,
            "break_even_read_share": (write - ordinary) / (write - read), "observed_mix_usd": observed,
            "observed_to_modelled_bypass_ratio": observed / bypass}


def _schedule(report: dict[str, Any], payload: dict[str, Any], size: int) -> list[dict[str, Any]]:
    slots = report["slots"]
    schedule = payload["schedule"]
    if (not isinstance(slots, list) or len(slots) != size or schedule["slots"] != size
            or schedule["pairs"] != size // 2 or report["scheduled"] != size or report["recorded"] != size):
        raise Refused("N7 scheduled and recorded denominators differ")
    order = []
    for first, second in zip(slots[::2], slots[1::2], strict=True):
        arms = [Arm(first["arm"]), Arm(second["arm"])]
        identity = first["case"], first["repeat"]
        if set(arms) != set(ARMS) or (second["case"], second["repeat"]) != identity:
            raise Refused("N7 paired slot mismatch")
        order.append([*identity, arms])
    if sha256(canonical_bytes(order)).hexdigest() != schedule["sha256"]:
        raise Refused("N7 slots differ from the registered schedule")
    return slots


def reprice(root: Path, phase: str, size: int, *, pilot_sha256: str | None = None) -> dict[str, Any]:
    study_id, digest, payload = registration(root, "policyops.scenario-study/n7-v1")
    report = document(root, "report.json")
    if (report["schema"] != "policyops.scenario-study/n7-report-v1" or report["registration_sha256"] != digest
            or report["phase"] != phase or payload["phase"] != phase or not report["integrity"]
            or not report["complete"] or payload["model"]["price_revision"] != SNAPSHOT_2026_11_05.revision
            or payload["model"]["name"] != MODEL or payload["pilot_registration_sha256"] != pilot_sha256):
        raise Refused("N7 registration/report/price binding failed")
    slots = _schedule(report, payload, size)
    totals = dict.fromkeys(ARMS, Tokens())
    calls = dict.fromkeys(ARMS, 0)
    workspace = UUID(payload["workspace"])
    for row in slots:
        arm = Arm(row["arm"])
        slot = Slot(workspace, uuid5(study_id, f"n7/dev/{arm}/{row['repeat']}/{row['case']}"))
        result = read_result(root, slot, digest)
        if (str(slot.id) != row["slot"] or result is None or result.ledger is None or result.ledger.held
                or result.ledger.price_revision != SNAPSHOT_2026_11_05.revision or result.failure_kind is not None):
            raise Refused("N7 slot has no reconciled retained ledger")
        seen = set()
        tokens = Tokens()
        for record in exchanges(study.private_child(slot_directory(root, slot), "tape"), result):
            if record.phase != "create":
                continue
            request = object_from(record.request)
            raw = raw_usage(record.response) if record.complete and record.status == 200 else None
            if (raw is None or raw[1] in seen or request.get("prompt_cache_options") != CACHE_OPTIONS[arm]
                    or "prompt_cache_key" in request):
                raise Refused("N7 taped create has no unique attributable usage")
            usage, request_id = raw
            seen.add(request_id)
            tokens += Tokens.from_usage(usage, arm)
        if (len(seen) != result.ledger.consumed_calls or tokens.settled != result.ledger.settled
                or tokens.settled != Decimal(row["settled_usd"])):
            raise Refused("N7 repriced slot does not match the settled ledger")
        totals[arm] += tokens
        calls[arm] += len(seen)
    arms = {}
    for arm, tokens in totals.items():
        frozen = report["arms"][arm]
        if (tokens.settled != Decimal(frozen["ledger"]["settled_usd"])
                or calls[arm] != frozen["calls"]["taped_creates"]):
            raise Refused("N7 repriced arm does not match the reported ledger")
        arms[arm] = {"tokens": asdict(tokens), "cost_usd": tokens.usd_parts(),
                     "calls": calls[arm], "settled_usd": tokens.settled}
    settled = sum((tokens.settled for tokens in totals.values()), Decimal(0))
    if settled != Decimal(report["ledger"]["settled_usd"]):
        raise Refused("N7 repriced study does not match the reported ledger")
    return {"registration_sha256": digest, "scheduled": size, "arms": arms, "settled_usd": settled,
            "observed_on_off_ratio": totals[Arm.A1].settled / totals[Arm.A0].settled,
            "fixed_cache_on_workload": fixed_workload(totals[Arm.A1])}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path, help="N7 run root containing pilot and study directories")
    args = parser.parse_args(argv)
    root = study.private_root(args.run)
    pilot = reprice(study.private_child(root, "pilot"), "pilot", 6)
    study_result = reprice(study.private_child(root, "study"), "study", 512, pilot_sha256=pilot["registration_sha256"])
    print(json.dumps({"price_revision": SNAPSHOT_2026_11_05.revision,
                      "rates_usd_per_million": dict(zip(COMPONENTS, RATES, strict=True)),
                      "pilot": pilot, "study": study_result}, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
