"""G6 evaluation-only calibration: deterministic sampling, capped calls and freezing.

No data text or model explanations are exported. Two immutable ledger study
scopes (dev $3, test $2) partition the $5 ceiling; deterministic keys prevent a
new invocation from resetting either stage. Test registration uses the existing
EvaluationRepository, because QAStudy intentionally describes MultiDoc2Dial.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass, fields, is_dataclass, replace
from datetime import UTC, datetime
from decimal import Decimal
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Any, Literal
import unicodedata
from uuid import UUID, uuid5

import httpx2
from pydantic import BaseModel, SecretStr

from policyops.budget.config import DEFAULT_ACTORS, Caps, ChatActor, Configuration
from policyops.budget.ledger import EvalBinding
from policyops.budget.preflight import ChatBound, Manifest, preflight
from policyops.budget.prices import SNAPSHOT_2026_11_05
from policyops.budget.pricing import worst_case
from policyops.budget.registry import REGISTRY, Registry
from policyops.persistence.budget import EvalLedgerStore, build_eval_ledger
from policyops.persistence.evaluation import EvaluationRepository, EvaluationRun, StudyLock, environment_repository
from policyops.providers.accounting import AccountingUnconfirmed
from policyops.providers.calls import CallLimits, CallReport, Providers, call
from policyops.providers.canonical import canonical_bytes as provider_bytes
from policyops.providers.contract import require_clean_environment
from policyops.providers.results import STOP_REASONS
from policyops.providers.serialize import prepare
from policyops.providers.tokenizer import InputRefused, Tokenizer, load
from policyops_contracts.provider_failures import failure_code
from policyops_evals.canonical import canonical_bytes, sha256_bytes, verify_self_digest, with_self_digest
from policyops_evals.qa_studies.judges import (
    ARMS,
    ELIGIBILITY_MAX_INPUT,
    MAX_INPUT,
    SAMPLING_ARMS,
    JudgeArm,
    admitted_tokens,
    arm_named,
    local_count,
    parse_verdict,
    request,
)
from policyops_evals.qa_studies.registration import JudgeResult, prices, source_provenance
from policyops_evals.qa_studies.statistics import binary_agreement


ROOT = Path(__file__).resolve().parents[4]
PUBLIC_MANIFEST = ROOT / "evals/manifests/llm-aggrefact-g6-v1/manifest.json"
REVISION = "981dfd0bd8e58e7238a9ab92b2e6ea44bce918e4"
PROTOCOL = "policyops.g6/v1"
SELECTION_RULE_VERSION = "g6-selection/v2"
DEV_REVISION = {
    "version": "g6-dev/v2",
    "timing": "After observing the three low-effort dev results; before any test data or test execution.",
    "arms": "Added two high-effort Luna dev selection candidates with identical v2 prompts/schema; test untouched.",
    "selection": "Prefer false-pass point <= 0.10, then pooled kappa, macro balanced accuracy, cost, arm name.",
}
# The application registry stays unchanged. Only this evaluation composition
# permits the coordinator-authorized high-effort Luna candidates.
G6_REGISTRY = Registry(REGISTRY.snapshot, {**REGISTRY.models, "gpt-6-luna": replace(
    REGISTRY.chat("gpt-6-luna", effort="low", cache_mode="none"), efforts=frozenset({"none", "low", "high"}))})
SEED = "g6/v1|20261114|"
CONSTITUENTS = ("RAGTruth", "ExpertQA", "ClaimVerify", "Wice")
SPLIT_HASHES = {
    "dev": "8333df9e0533f0651b296bc855af14767d340db26290e01da7c5188c6f83cd12",
    "test": "88c4365757414a5f4f853dc54dd0d28e90cdb967051d8b7d4e18fa80dc991074",
}
SPLIT_ROWS = {"dev": 30420, "test": 29320}
# Coordinator 2026-11-14: test raised to $3 (total $6) so a high-effort dev selection fits its conservative reservation.
STAGE_USD = {"dev": Decimal("3"), "test": Decimal("3")}
Split = Literal["dev", "test"]
ITEM_FIELDS = {"id", "constituent", "split", "row_index", "claim_sha256", "document_sha256", "label",
               "local_input_tokens"}


def digest(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def private_path(path: Path) -> Path:
    raw = os.environ.get("POLICYOPS_TEMP_DIR", "")
    root = Path(raw).resolve()
    target = path.resolve()
    if (not raw or not Path(raw).is_absolute() or root == ROOT or ROOT in root.parents
            or root not in target.parents or target == ROOT or ROOT in target.parents):
        raise ValueError("G6 private output must be inside POLICYOPS_TEMP_DIR, outside checkout")
    return target


def write_private(path: Path, value: Any, *, exclusive: bool = False) -> None:
    target = private_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb" if exclusive else "wb") as handle:
        handle.write(canonical_bytes(value))
        handle.flush()
        os.fsync(handle.fileno())


def read_json(path: Path, maximum: int = 8_000_000) -> dict[str, Any]:
    with path.open("rb") as handle:
        data = handle.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("G6 JSON size bound")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("G6 object required")
    return value


def content_hash(text: str) -> str:
    """NFC + whitespace folding for conservative overlap/cluster grouping."""
    return sha256_bytes(" ".join(unicodedata.normalize("NFC", text).split()).encode())


@dataclass(frozen=True, repr=False)
class Row:
    split: str
    index: int
    constituent: str
    document: str
    claim: str
    gold: bool

    @property
    def id(self) -> str:
        return f"{self.split}/{self.constituent}/{self.index}"

    def public(self, counts: dict[str, int]) -> dict[str, Any]:
        return {"id": self.id, "split": self.split, "constituent": self.constituent, "row_index": self.index,
                "claim_sha256": sha256_bytes(self.claim.encode()), "document_sha256": content_hash(self.document),
                "label": self.gold, "local_input_tokens": counts}


def rows(directory: Path, split: str) -> Iterator[Row]:
    """Pinned bytes, bounded lines, exact indices/schema; never log a row."""
    path = directory / f"{split}.jsonl"
    conversion = read_json(directory / "conversion-manifest.json")
    if (conversion.get("source_revision") != REVISION
            or conversion["files"][path.name]["sha256"] != SPLIT_HASHES[split]
            or path.stat().st_size != conversion["files"][path.name]["bytes"]):
        raise ValueError("G6 conversion identity mismatch")
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1 << 20):
            hasher.update(block)
    if hasher.hexdigest() != SPLIT_HASHES[split]:
        raise ValueError("G6 private source hash mismatch")
    count = 0
    with path.open("rb") as handle:
        while line := handle.readline(1_000_001):
            if len(line) > 1_000_000:
                raise ValueError("G6 source line bound")
            item = json.loads(line)
            if (set(item) != {"row_index", "dataset", "doc", "claim", "label", "contamination_identifier"}
                    or type(item["row_index"]) is not int or item["row_index"] != count
                    or type(item["label"]) is not int or item["label"] not in (0, 1)
                    or any(not isinstance(item[k], str) for k in ("dataset", "doc", "claim"))):
                raise ValueError("G6 source schema mismatch")
            yield Row(split, count, item["dataset"], item["doc"], item["claim"], bool(item["label"]))
            count += 1
    if count != SPLIT_ROWS[split]:
        raise ValueError("G6 source row count mismatch")


def configuration(arm: JudgeArm, split: str, usd: Decimal, calls: int, seconds: int) -> Configuration:
    if (not usd.is_finite() or not 0 < usd <= STAGE_USD[split] or type(calls) is not int or calls < 1
            or type(seconds) is not int or not 1 <= seconds <= 86400):
        raise ValueError("G6 cap outside stage ceiling")
    caps = Caps(request_max_input=MAX_INPUT, request_max_output=arm.max_output,
        scenario_usd=usd, scenario_calls=1, invocation_usd=usd, invocation_calls=calls,
        study_usd=STAGE_USD[split], study_calls=calls, active_seconds=seconds)
    actors = {name: replace(value, max_input=MAX_INPUT, max_output=arm.max_output)
              if isinstance(value, ChatActor) else value for name, value in DEFAULT_ACTORS.items()}
    return Configuration(registry=G6_REGISTRY, actors={**actors, "judge": ChatActor("judge", arm.model, arm.effort,
        max_input=MAX_INPUT, max_output=arm.max_output)}, caps=caps)


@lru_cache(maxsize=3)
def _count_template(arm: JudgeArm) -> tuple[bytes, bytes]:
    """Only generic template bytes are cached; never benchmark content.

    Provider preparation is expensive and its invariant schema/configuration is
    identical for every row. Substitute one entire canonical JSON string value,
    not document fragments. Tests compare this with actual prepare on both
    providers; execution prepares every selected request through call as usual.
    """
    req = request(arm, "__G6_DOCUMENT__", "__G6_STATEMENT__", frozen_sampling=True)
    config = configuration(arm, "dev", Decimal("3"), 1200, 7200)
    prepared = prepare(req, config, "judge")
    marker = provider_bytes(req.messages[0].parts[0].model_dump()["text"])
    if prepared.count_body.count(marker) != 1:
        raise ValueError("G6 provider count template ambiguity")
    return prepared.count_body, marker


def count_projection(arm: JudgeArm, row: Row) -> bytes:
    # The published sample is frozen to v1 prompt/schema projections. Runtime
    # v2 prompts and provider caps are bound separately in planning().
    arm = arm_named(arm.sampling_name)
    req = request(arm, row.document, row.claim, frozen_sampling=True)
    body, marker = _count_template(arm)
    return body.replace(marker, provider_bytes(req.messages[0].parts[0].model_dump()["text"]), 1)


def eligibility(row: Row, tokenizer: Tokenizer) -> tuple[dict[str, int], str | None]:
    counts: dict[str, int] = {}
    try:
        for arm in SAMPLING_ARMS:
            counts[arm.name] = local_count(tokenizer, count_projection(arm, row))
    except (InputRefused, ValueError):
        return {}, "local_bounds"
    return counts, "envelope" if any(admitted_tokens(n) > ELIGIBILITY_MAX_INPUT for n in counts.values()) else None


def build_sample(directory: Path, tokenizer: Tokenizer | None = None) -> dict[str, Any]:
    tokenizer = tokenizer or load()
    pools: dict[tuple[str, str], list[dict[str, Any]]] = {}
    totals: Counter[str] = Counter()
    excluded: Counter[str] = Counter()
    documents: dict[str, Counter[str]] = {}
    claims: dict[str, Counter[str]] = {}
    overlaps: list[list[Any]] = []
    for split in ("dev", "test"):
        documents[split], claims[split] = Counter(), Counter()
        for row in rows(directory, split):
            doc_hash, claim_hash = content_hash(row.document), content_hash(row.claim)
            documents[split][doc_hash] += 1
            claims[split][claim_hash] += 1
            if row.constituent not in CONSTITUENTS:
                continue
            key = f"{split}/{row.constituent}"
            totals[key] += 1
            doc_overlap = split == "test" and doc_hash in documents["dev"]
            claim_overlap = split == "test" and claim_hash in claims["dev"]
            counts, refusal = eligibility(row, tokenizer)
            if refusal:
                excluded[key + "/" + refusal] += 1
            if doc_overlap or claim_overlap:
                excluded[key + "/dev_overlap"] += 1
                overlaps.append([row.constituent, row.index, doc_overlap, claim_overlap])
            if refusal or doc_overlap or claim_overlap:
                excluded[key + "/any"] += 1
                continue
            pools.setdefault((split, row.constituent), []).append(row.public(counts))
    selected = []
    counts_by_constituent: dict[str, Any] = {}
    for split in ("dev", "test"):
        for constituent in CONSTITUENTS:
            pool = pools.get((split, constituent), [])
            size = 100 if split == "dev" else (len(pool) if constituent == "Wice" else 400)
            if len(pool) < size or size == 0:
                raise ValueError("G6 insufficient eligible rows")
            ranked = sorted(pool, key=lambda r: (sha256_bytes(
                (SEED + r["id"]).encode()), r["row_index"]))
            sample = ranked[:size]
            selected.extend(sorted(sample, key=lambda r: r["row_index"]))
            key = f"{split}/{constituent}"
            counts_by_constituent[key] = {"source": totals[key], "eligible": len(pool), "selected": len(sample),
                "positive": sum(r["label"] for r in sample), "excluded": excluded[key + "/any"]}
    audit = {split: {"rows": sum(documents[split].values()), "unique_documents": len(documents[split]),
        "duplicate_document_rows": sum(n - 1 for n in documents[split].values()),
        "unique_claims": len(claims[split]), "duplicate_claim_rows": sum(n - 1 for n in claims[split].values())}
        for split in ("dev", "test")}
    return with_self_digest({"schema_version": "policyops.g6-sample/v1", "protocol": PROTOCOL,
        "source": "https://huggingface.co/datasets/lytang/LLM-AggreFact", "licence": "CC BY-ND 4.0",
        "use": "evaluation only; no training, fine-tuning or learned calibration; dev prompt/model selection only",
        "source_revision": REVISION, "source_sha256": SPLIT_HASHES,
        "conversion_manifest_sha256": sha256_bytes((directory / "conversion-manifest.json").read_bytes()),
        "seed": SEED, "ranking": "sha256(seed + split/constituent/row_index); row_index tie break",
        # Named for the vocabulary, not "token…": a 64-hex value after a token-like key reads as an API key to scanners.
        "cl100k_vocabulary_sha256": tokenizer.identity_sha256,
        "eligibility": "all three count projections: local cl100k + max(ceil(10%),256) <= 6000; no truncation",
        "overlap_rule": "NFC + whitespace-folded SHA256 documents OR claims; test versus ALL official dev rows",
        "counts": counts_by_constituent, "exclusions": dict(sorted(excluded.items())),
        "overlap_test_exclusions": overlaps, "duplicate_audit": audit,
        "cross_split_documents": len(documents["dev"].keys() & documents["test"].keys()),
        "cross_split_claims": len(claims["dev"].keys() & claims["test"].keys()),
        "wice_test_rule": "all eligible nonoverlapping test rows (source has 358, not 400)",
        "items": selected})


def load_sample(path: Path = PUBLIC_MANIFEST) -> dict[str, Any]:
    sample = read_json(path, 1_000_000)
    verify_self_digest(sample)
    if (sample.get("schema_version") != "policyops.g6-sample/v1" or sample.get("source_revision") != REVISION
            or sample.get("source_sha256") != SPLIT_HASHES or sample.get("protocol") != PROTOCOL):
        raise ValueError("G6 sample binding mismatch")
    ids = set()
    for item in sample["items"]:
        if (set(item) != ITEM_FIELDS or type(item["label"]) is not bool or item["id"] in ids
                or item["constituent"] not in CONSTITUENTS or item["split"] not in ("dev", "test")
                or item["id"] != f"{item['split']}/{item['constituent']}/{item['row_index']}"):
            raise ValueError("G6 public item schema mismatch")
        ids.add(item["id"])
    return sample


def selection(path: Path, sample: dict[str, Any]) -> dict[str, Any]:
    receipt = read_json(path)
    if (receipt.get("schema_version") != "policyops.g6-selection/v1" or receipt.get("protocol") != PROTOCOL
            or receipt.get("selection_rule_version") != SELECTION_RULE_VERSION
            or receipt.get("sample_sha256") != sample["manifest_sha256"]
            or receipt.get("binding") != arm_named(receipt["binding"]["arm"]).binding()
            or canonical_bytes(receipt) != path.read_bytes()):
        raise ValueError("G6 frozen selection mismatch")
    return receipt


def scheduled(sample: dict[str, Any], split: str, receipt: dict[str, Any] | None = None
              ) -> list[tuple[JudgeArm, dict[str, Any]]]:
    if split not in STAGE_USD or (split == "test" and receipt is None):
        raise ValueError("G6 test requires frozen selection")
    arms = ARMS if split == "dev" else (arm_named(receipt["binding"]["arm"]),) if receipt else ()
    # Interleave arms on identical items; deterministic order is registered.
    return [(arm, item) for item in sample["items"] if item["split"] == split for arm in arms]


def planning(sample: dict[str, Any], split: str, *, max_usd: Decimal, max_calls: int,
             max_counts: int, max_seconds: int, receipt: dict[str, Any] | None = None) -> dict[str, Any]:
    schedule = scheduled(sample, split, receipt)
    if max_calls != len(schedule) or max_counts != max_calls:
        raise ValueError("G6 inference/count caps must equal the frozen schedule")
    plans = []
    local_estimate = Decimal(0)
    for arm in ARMS:
        items = [item for current, item in schedule if current == arm]
        if not items:
            continue
        config = configuration(arm, split, max_usd, max_calls, max_seconds)
        budget_manifest = Manifest(v="policyops.eval-budget-manifest/v1", name="g6-" + arm.name, version="v1",
            code_revision=PROTOCOL, dataset="llm-aggrefact", dataset_revision=REVISION, split_id=split,
            prompt_revision=arm.prompt_sha256, price_revision=SNAPSHOT_2026_11_05.revision,
            tasks=tuple(item["id"] for item in items), trials_per_task=1, study_ceiling_usd=STAGE_USD[split],
            actors=(ChatBound(actor="judge", model=arm.model, effort=arm.effort, max_input=MAX_INPUT,
                max_output=arm.max_output, logical_calls=1, max_repairs=0, retries_per_request=0),))
        plan = preflight(budget_manifest, config.caps, registry=config.registry)
        plans.append(plan.model_dump(mode="json"))
        local_estimate += sum((worst_case(SNAPSHOT_2026_11_05.price(arm.model),
            max_input=admitted_tokens(item["local_input_tokens"][arm.sampling_name]), max_output=arm.max_output)
            for item in items), Decimal(0))
    worst = sum((Decimal(p["new_study_usd"]) for p in plans), Decimal(0))
    if any(p["verdict"] != "within_caps_prior_unverified" for p in plans) or worst > max_usd:
        raise ValueError("G6 aggregate preflight exceeds caps")
    return {"protocol": PROTOCOL, "dev_revision": DEV_REVISION, "split": split,
        "sample_sha256": sample["manifest_sha256"],
        "selection_receipt_sha256": None if receipt is None else digest(receipt),
        "schedule_sha256": digest([(a.name, r["id"]) for a, r in schedule]),
        "bindings": [arm.binding() for arm in ARMS if any(a == arm for a, _ in schedule)],
        "price_revision": SNAPSHOT_2026_11_05.revision,
        "caps": {"usd": str(max_usd), "calls": max_calls, "counts": max_counts, "seconds": max_seconds,
                 "stage_usd": str(STAGE_USD[split]), "total_usd": "6", "retries": 0, "repairs": 0},
        "local_count_output_ceiling_usd": str(local_estimate), "reservation_ceiling_usd": str(worst),
        "local_estimate_basis": "frozen v1 sampling projections; not a runtime/provider token ceiling",
        "actor_preflights": plans, "within_caps": True, "authorizes_paid_execution": False}


def scope_key(sample: dict[str, Any], split: str) -> str:
    # A changed sample/configuration must conflict with this scope's manifest,
    # never mint fresh money under a new hash-derived study key.
    return f"g6/v1/llm-aggrefact/{REVISION}/{split}"


def scope_manifest(sample: dict[str, Any], split: str, receipt: dict[str, Any] | None) -> str:
    return digest({"protocol": PROTOCOL, "sample": sample["manifest_sha256"], "split": split,
                   "bindings": [a.binding() for a in ARMS], "selection": receipt})


def committed_config(path: Path, expected: dict[str, Any]) -> str:
    target = path.resolve()
    if ROOT not in target.parents or target.read_bytes() != canonical_bytes(expected):
        raise ValueError("G6 test configuration mismatch")
    relative = target.relative_to(ROOT).as_posix()
    result = subprocess.run(["git", "show", "HEAD:" + relative], cwd=ROOT, capture_output=True, timeout=30)
    if result.returncode or result.stdout != target.read_bytes():
        raise ValueError("G6 test configuration must be committed before registration")
    return relative


def test_configuration(sample: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    return {"schema_version": "policyops.g6-test/v1", "protocol": PROTOCOL,
        "sample_sha256": sample["manifest_sha256"], "selection_receipt_sha256": digest(receipt),
        "binding": receipt["binding"], "analysis": {"seed": 20261114, "replicates": 10000,
            "clusters": "document_sha256", "gate": "complete and kappa >= .6 and lower > .4 and false_pass <= .1"},
        "price_revision": SNAPSHOT_2026_11_05.revision, "stage_cap_usd": str(STAGE_USD["test"]), "g6_cap_usd": "6",
        "schedule_sha256": digest([(a.name, i["id"]) for a, i in scheduled(sample, "test", receipt)])}


def registration_payload(sample: dict[str, Any], receipt: dict[str, Any], config_path: Path,
                         plan: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    relative = committed_config(config_path, test_configuration(sample, receipt))
    if source["dirty_sha256"] != digest([]):
        raise ValueError("G6 register/run requires a fixed clean source tree")
    return {"schema_version": "policyops.g6-registration/v1", "configuration": relative,
        "configuration_sha256": sha256_bytes(config_path.read_bytes()), "selection_receipt_sha256": digest(receipt),
        "sample_sha256": sample["manifest_sha256"], "plan_sha256": digest(plan),
        "source": source, "price_snapshot_sha256": digest(prices())}


def test_run_record(scope: UUID, payload: dict[str, Any]) -> EvaluationRun:
    return EvaluationRun(id=uuid5(scope, "g6-test"), study_scope=scope, dataset="llm-aggrefact",
        dataset_revision=payload["source"]["source_head"], split_id="test", config_sha256=digest(payload),
        config_json=canonical_bytes({"g6": payload}).decode(), created_at=datetime.now(UTC))


def require_registration(repository: EvaluationRepository, scope: UUID, payload: dict[str, Any]) -> dict[str, Any]:
    config = repository.run_configuration(uuid5(scope, "g6-test"))
    registered = None if config is None else config.get("registration")
    if (not isinstance(registered, dict) or registered.get("payload") != payload
            or registered.get("sha256") != digest(payload) or not registered.get("created_at")):
        raise ValueError("G6 test refused: missing or changed prior registration/selection")
    at = datetime.fromisoformat(registered["created_at"])
    if (at.tzinfo is None or at.utcoffset() != UTC.utcoffset(at)
            or not repository.registration_precedes_claims(scope, at)):
        raise ValueError("G6 registration must precede test claims/attempts")
    return registered


def verdict_record(report: CallReport) -> tuple[bool | None, bool]:
    result = report.result
    settled = bool(report.attempts) and all(a.fate == "settled" or (
        a.fate == "released" and not a.dispatch_granted and a.evidence is None) for a in report.attempts)
    parsed = (parse_verdict(result.structured_json) if report.status == "result" and result is not None
              and result.outcome == "structured" and not result.tool_calls else None)
    valid = (parsed is not None and all(a.fate == "settled" for a in report.attempts) and settled
             and not report.cleanup_unconfirmed)
    return (parsed.supported if valid and parsed else None), settled and not report.cleanup_unconfirmed


def invalidity_diagnostics(report: CallReport) -> dict[str, Any]:
    """Bounded metadata only. Output length is billed tokens, never output text.

    The provider adapter discards invalid payloads. Its closed schema keyword
    codes distinguish the causes without retaining content or schema paths.
    """
    result = report.result
    category = None
    if result is None:
        category = "count_refused" if report.reason in {"count_rejected", "count_not_admitted"} else "call_error"
    elif result.outcome == "refused":
        category = "refusal"
    elif result.outcome == "truncated":
        category = "max_tokens" if result.stop_reason in {"max_tokens", "max_output_tokens"} else "truncated"
    elif result.tool_calls or result.reason_code in {"unknown_tool", "duplicate_tool_call", "too_many_tool_calls",
            "tool_call_malformed", "tool_arguments_not_json", "tool_arguments_schema", "tool_call_invalid",
            "tool_arguments_too_large"}:
        category = "tool_call"
    elif result.reason_code is not None or result.outcome != "structured":
        category = {"output_not_json": "not_json", "output_schema_required": "schema_missing_field",
                    "output_schema_type": "wrong_type", "output_schema_max_length": "reason_overlength"
                    }.get(result.reason_code or "", "invalid_output")
    elif parse_verdict(result.structured_json) is None:
        # Covers strict DTO checks beyond JSON Schema (e.g. whitespace-only).
        category = "invalid_output"
    return {"category": category, "output_tokens": None if result is None else result.usage.output,
            "stop_reason": None if result is None or result.stop_reason not in STOP_REASONS else result.stop_reason}


def safe_reason(reason: str | None) -> str | None:
    """Do not serialize arbitrary exception/provider strings as diagnostics."""
    allowed = {"count_rejected", "count_failed", "count_not_admitted", "count_cap", "count_unclaimed",
        "blocked_by_overrun", "blocked_by_contract", "configuration_changed", "request_mismatch",
        "legacy_intent", "run_not_active", "accounting_unconfirmed", "deadline", "deadline_already_passed",
        "output_schema", "output_schema_required", "output_schema_type", "output_schema_max_length",
        "output_not_json", "timeout", "cancelled", "count.attempt_timeout"}
    if reason is None or reason in allowed:
        return reason
    # Existing closed provider failure codes retain count-phase attribution.
    code = failure_code(reason)
    if code is None:
        return "other"
    return ("count." if reason.startswith("count.") else "") + code


def plain(value: Any, depth: int = 0) -> Any:
    """JSON-ready copy of billing evidence. `dataclasses.asdict` deep-copies field values, and the ledger's frozen
    `Usage.cache_writes`/`Diagnostic.counts` are `MappingProxyType`, which cannot be copied, so convert explicitly."""
    if depth > 8:
        raise ValueError("G6 billing evidence nesting bound")
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: plain(getattr(value, f.name), depth + 1) for f in fields(value)}
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return {str(k): plain(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [plain(v, depth + 1) for v in value]
    return str(value)


def billing_record(report: CallReport) -> dict[str, Any]:
    return {"status": report.status, "failure_code": report.failure_code,
        "reason": safe_reason(report.reason),
        "usage": None if report.result is None else report.result.usage.model_dump(mode="json"),
        "attempts": [{"id": str(a.attempt_id), "fate": a.fate, "count_granted": a.count_granted,
            "dispatch_granted": a.dispatch_granted, "reason": safe_reason(a.reason),
            "usage_evidence": None if a.evidence is None else plain(a.evidence)}
            for a in report.attempts]}


async def execute(repository: EvaluationRepository, scope: UUID, lease: StudyLock,
                  sample: dict[str, Any], plan: dict[str, Any], receipt: dict[str, Any] | None,
                  directory: Path, output: Path) -> dict[str, Any]:
    schedule = scheduled(sample, plan["split"], receipt)
    wanted = {i["id"]: i for _, i in schedule}
    # Verify source bytes and every selected row BEFORE reading a credential.
    selected = {r.id: r for r in rows(directory, plan["split"]) if r.id in wanted}
    tokenizer = load()
    for identity, item in wanted.items():
        row = selected[identity]
        counts, refusal = eligibility(row, tokenizer)
        if refusal or row.public(counts) != item:
            raise ValueError("G6 selected private/public row mismatch")
    cap = plan["caps"]
    configs = {a.name: configuration(a, plan["split"], Decimal(cap["usd"]), cap["calls"], cap["seconds"])
               for a, _ in schedule}
    ledgers = {name: build_eval_ledger(env="evaluation", engine=repository.engine, configuration=config)
               for name, config in configs.items()}
    store = next(iter(ledgers.values()))[1]
    position = store.scope(scope)
    if (position is None or position.spent_usd or position.held_usd or position.calls_consumed or position.calls_held
            or position.counts_used or position.overrun or position.contract_block):
        raise ValueError("G6 stage already attempted/blocked; no automatic replay or budget reset")
    # Persisted stage preflight, aggregated across arms, not merely per actor.
    if (Decimal(plan["reservation_ceiling_usd"]) > position.cap_usd
            or len(schedule) > position.cap_calls):
        raise ValueError("G6 persisted aggregate admission refused")
    invocation_id = uuid5(scope, "g6-invocation/v1")
    invocation = store.ensure_invocation(scope, invocation_id, next(iter(configs.values())).caps)
    credentials: dict[str, SecretStr] = {}
    for arm, _ in schedule:
        provider = SNAPSHOT_2026_11_05.price(arm.model).provider
        if provider not in credentials:
            require_clean_environment(provider)
            key_name = "OPENAI_API_KEY" if provider == "openai" else "ANTHROPIC_API_KEY"
            credentials[provider] = SecretStr(os.environ[key_name])
    providers = Providers(credentials, lambda _: httpx2.AsyncHTTPTransport(trust_env=False))
    deadline = time.monotonic() + cap["seconds"]
    failure = None
    executed = 0
    primary: BaseException | None = None
    try:
        with (output / "predictions.jsonl").open("xb") as handle:
            for arm, item in schedule:
                if time.monotonic() >= deadline:
                    failure = "stage_deadline"
                    break
                config = configs[arm.name]
                ledger, _ = ledgers[arm.name]
                scenario = store.ensure_scenario(scope, arm.name + "/" + item["id"], 0,
                                                  scope_manifest(sample, plan["split"], receipt), config.caps)
                row = selected[item["id"]]
                try:
                    result = await call(ledger, providers, EvalBinding(scope, invocation, scenario), invocation_id,
                        arm.name + "/" + item["id"], request(arm, row.document, row.claim), "judge", deadline=deadline,
                        limits=CallLimits(retries_per_request=0, repairs=0, attempt_seconds=60))
                except AccountingUnconfirmed as error:
                    result = error.report
                    failure = "accounting_unconfirmed"
                predicted, settled = verdict_record(result)
                record = {"id": item["id"], "arm": arm.name, "predicted": predicted,
                    "accounting_settled": settled, "cost_usd": None,
                    "billing": billing_record(result), "invalidity": invalidity_diagnostics(result)}
                try:
                    state = store.scope(scenario)
                    record["cost_usd"] = None if state is None else str(state.spent_usd)
                    if (state is None or state.held_usd or state.calls_held or state.overrun or state.contract_block
                            or (any(a.fate == "released" for a in result.attempts) and state.spent_usd)):
                        failure = failure or "scenario_accounting_unconfirmed"
                        record["accounting_settled"] = False
                    study = store.scope(scope)
                    if (study is None or study.held_usd or study.calls_held or study.overrun or study.contract_block):
                        failure = failure or "study_accounting_unconfirmed"
                        record["accounting_settled"] = False
                except Exception:
                    # Keep available normalized billing evidence even if the DB
                    # is unavailable after a response/failed settlement.
                    failure = failure or "scenario_accounting_unavailable"
                    record["accounting_settled"] = False
                if not record["accounting_settled"]:
                    record["predicted"] = None
                handle.write((json.dumps(record, sort_keys=True) + "\n").encode())
                handle.flush()
                os.fsync(handle.fileno())
                executed += 1
                if result.status in {"budget", "deadline", "contract_gap"}:
                    failure = failure or "call_" + result.status
                if failure or not settled or result.cleanup_unconfirmed:
                    failure = failure or "unsettled_or_cleanup_unconfirmed"
                    break
    except BaseException as error:
        primary = error
        failure = "execution_exception"
        raise
    finally:
        try:
            try:
                position = store.scope(scope)
                if (position is None or position.held_usd or position.calls_held
                        or position.overrun or position.contract_block):
                    failure = failure or "study_accounting_unconfirmed"
            except Exception:
                position = None
                failure = failure or "study_accounting_unavailable"
            write_private(output / "settlement.json", {"failure": failure,
                "scope": None if position is None else json.loads(json.dumps(asdict(position), default=str))})
        except BaseException:
            if primary is None:
                raise
            primary.add_note("G6 settlement artifact unavailable; inspect the persisted ledger")
    return {"complete": executed == len(schedule) and failure is None,
            "executed": executed, "scheduled": len(schedule), "failure": failure}


def command_run(sample: dict[str, Any], plan: dict[str, Any], receipt: dict[str, Any] | None, *,
                directory: Path, output: Path, execute_paid: bool, config_path: Path | None,
                register_requested: bool = False) -> dict[str, Any]:
    if not execute_paid and not register_requested:
        raise ValueError("G6 paid execution requires --execute-paid and explicit caps")
    if execute_paid and register_requested:
        raise ValueError("G6 registration and execution must be separate commands")
    if register_requested and plan["split"] != "test":
        raise ValueError("G6 only test is preregistered")
    source = source_provenance()
    payload = None
    if plan["split"] == "test":
        if receipt is None or config_path is None:
            raise ValueError("G6 test requires selection and committed configuration")
        payload = registration_payload(sample, receipt, config_path, plan, source)
    repository = environment_repository()
    if repository is None:
        raise ValueError("G6 evaluation database required")
    try:
        store = EvalLedgerStore(repository.engine, env="evaluation")
        scope = store.ensure_study(scope_key(sample, plan["split"]), scope_manifest(sample, plan["split"], receipt),
            cap_usd=STAGE_USD[plan["split"]], cap_calls=plan["caps"]["calls"])
        with repository.study_lock(scope) as lease:
            if register_requested and payload is not None:
                registered = repository.register([test_run_record(scope, payload)], payload, digest(payload), lease)
                return {"registered": True, "receipt": registered, "within_caps": True}
            registration = require_registration(repository, scope, payload) if payload is not None else None
            target = private_path(output)
            target.mkdir(parents=True, exist_ok=False)
            header = {"schema_version": "policyops.g6-run/v1", "plan": plan,
                "source": source, "scope_id": str(scope), "registration": registration,
                "started_at": datetime.now(UTC).isoformat(), "selection": receipt, "complete": False}
            write_private(target / "run.json", header, exclusive=True)
            outcome = asyncio.run(execute(repository, scope, lease, sample, plan, receipt, directory, target))
            write_private(target / "run.json", header | outcome)
            return {"run": str(target), "within_caps": True, **outcome}
    finally:
        repository.engine.dispose()


def agreement(items: Sequence[dict[str, Any]], predictions: Sequence[bool | None], *,
              seed: int = 20261114, replicates: int = 10000) -> dict[str, Any]:
    result = binary_agreement([i["label"] for i in items], predictions,
        [i["document_sha256"] for i in items], seed=seed, replicates=replicates)
    value = json.loads(json.dumps(asdict(result), default=str))
    if not isinstance(value, dict):
        raise ValueError("G6 agreement contract mismatch")
    return value


def report_run(sample: dict[str, Any], run: Path, *, replicates: int = 10000,
               calculate: Callable[..., dict[str, Any]] = agreement) -> dict[str, Any]:
    header = read_json(run / "run.json")
    plan = header["plan"]
    if plan["sample_sha256"] != sample["manifest_sha256"]:
        raise ValueError("G6 report sample mismatch")
    receipt = header["selection"]
    if receipt is not None and plan["selection_receipt_sha256"] != digest(receipt):
        raise ValueError("G6 report selection mismatch")
    # Historical three-arm runs retain their frozen schedule. They remain
    # reportable but cannot satisfy selection's five-candidate requirement.
    bound_names = {b["arm"] for b in plan["bindings"]}
    schedule = [(a, i) for a, i in scheduled(sample, plan["split"], receipt) if a.name in bound_names]
    if (len(bound_names) != len(plan["bindings"]) or {a.name for a, _ in schedule} != bound_names
            or digest([(a.name, i["id"]) for a, i in schedule]) != plan["schedule_sha256"]):
        raise ValueError("G6 report frozen schedule mismatch")
    expected = {(a.name, i["id"]) for a, i in schedule}
    recorded: dict[tuple[str, str], dict[str, Any]] = {}
    path = run / "predictions.jsonl"
    if path.exists():
        with path.open("rb") as handle:
            for line in handle:
                if len(line) > 50000:
                    raise ValueError("G6 prediction bounds")
                row = json.loads(line)
                key = (row["arm"], row["id"])
                if key not in expected or key in recorded or (row["predicted"] is not None
                                                             and type(row["predicted"]) is not bool):
                    raise ValueError("G6 unexpected/duplicate prediction")
                recorded[key] = row
    settlement = read_json(run / "settlement.json") if (run / "settlement.json").exists() else None
    scope = None if settlement is None else settlement["scope"]
    accounting = bool(scope is not None and Decimal(scope["held_usd"]) == 0 and scope["calls_held"] == 0
                      and not scope["overrun"] and not scope["contract_block"]
                      and all(r["accounting_settled"] for r in recorded.values()))
    arms: dict[str, Any] = {}
    for arm in ARMS:
        items = [i for a, i in schedule if a == arm]
        if not items:
            continue
        predictions = [recorded.get((arm.name, i["id"]), {}).get("predicted") for i in items]
        pooled = calculate(items, predictions, replicates=replicates)
        constituents = {name: calculate([i for i in items if i["constituent"] == name],
            [p for i, p in zip(items, predictions, strict=True) if i["constituent"] == name], replicates=replicates)
            for name in CONSTITUENTS}
        balanced = [v["balanced_accuracy"] for v in constituents.values()]
        macro = None if any(v is None for v in balanced) else sum(Decimal(str(v)) for v in balanced) / 4
        costs = [r.get("cost_usd") for (name, _), r in recorded.items() if name == arm.name]
        executed = len(costs)
        valid = sum(p is not None for p in predictions)
        complete = (bool(items) and accounting
                    and len(costs) == len(items) and all(c is not None for c in costs)
                    and settlement is not None and settlement["failure"] is None)
        arms[arm.name] = {"binding": next(b for b in plan["bindings"] if b["arm"] == arm.name),
            "complete": complete, "pooled": pooled, "scheduled": len(items), "executed": executed,
            "valid": valid, "coverage": valid / len(items), "errors": len(items) - valid,
            "execution_coverage": executed / len(items),
            "error_categories": dict(Counter(r.get("invalidity", {}).get("category") or "unspecified"
                for (name, _), r in recorded.items() if name == arm.name and r["predicted"] is None)),
            "count_refused": sum(r.get("invalidity", {}).get("category") == "count_refused"
                                 for (name, _), r in recorded.items() if name == arm.name),
            "constituents": constituents, "macro_balanced_accuracy": None if macro is None else str(macro),
            "cost_usd": str(sum((Decimal(c) for c in costs if c is not None), Decimal(0))),
            "missing": sum((arm.name, i["id"]) not in recorded for i in items)}
    judge = None
    if plan["split"] == "test":
        arm_report = next(iter(arms.values()))
        pooled = arm_report["pooled"]
        false_pass = pooled["false_pass_rate"]
        false_pass = false_pass["point"]
        if all(v is not None for v in (pooled["kappa"], pooled["kappa_low"], false_pass)):
            judge = JudgeResult(selection_receipt_sha256=plan["selection_receipt_sha256"],
                complete=arm_report["complete"] and header["registration"] is not None,
                kappa=Decimal(str(pooled["kappa"])), kappa_lower=Decimal(str(pooled["kappa_low"])),
                false_pass=Decimal(str(false_pass)).quantize(Decimal("0.0000000001")))
    return {"schema_version": "policyops.g6-report/v1", "protocol": PROTOCOL,
        "dev_revision": DEV_REVISION, "split": plan["split"],
        "sample_sha256": sample["manifest_sha256"], "run_header_sha256": sha256_bytes((run / "run.json").read_bytes()),
        "predictions_sha256": None if not path.exists() else sha256_bytes(path.read_bytes()),
        "settlement_sha256": (sha256_bytes((run / "settlement.json").read_bytes()) if settlement is not None else None),
        "selection_receipt_sha256": plan["selection_receipt_sha256"], "seed": 20261114, "replicates": replicates,
        "accounting_settled": accounting, "arms": arms,
        "judge_result": None if judge is None else judge.model_dump(mode="json"),
        "gate_passed": judge is not None and judge.passed(),
        "limitations": ["Sampled subset agreement, not the full leaderboard or domain answer calibration.",
            "Public benchmark contamination cannot be excluded; WiCE uses all eligible nonoverlapping test rows.",
            "Silver MultiDoc2Dial controls not run; transfer remains unverified."]}


def select_arm(report: dict[str, Any], sample: dict[str, Any]) -> dict[str, Any]:
    if (report["split"] != "dev" or report["sample_sha256"] != sample["manifest_sha256"]
            or set(report["arms"]) != {a.name for a in ARMS} or report["replicates"] != 10000
            or any(report["arms"][a.name]["binding"] != a.binding() for a in ARMS)
            or any(not v["complete"] or v["macro_balanced_accuracy"] is None for v in report["arms"].values())):
        raise ValueError("G6 selection requires all five complete dev arms")
    def rank(name: str) -> tuple[bool, Decimal, Decimal, Decimal, str]:
        arm = report["arms"][name]
        rate = arm["pooled"]["false_pass_rate"]
        rate = rate["point"]
        kappa = arm["pooled"]["kappa"]
        if rate is None or kappa is None:
            raise ValueError("G6 undefined selection metric")
        return (Decimal(str(rate)) > Decimal("0.10"), -Decimal(str(kappa)),
                -Decimal(arm["macro_balanced_accuracy"]), Decimal(arm["cost_usd"]), name)
    chosen = min(report["arms"], key=rank)
    return {"schema_version": "policyops.g6-selection/v1", "protocol": PROTOCOL,
        "sample_sha256": sample["manifest_sha256"], "binding": arm_named(chosen).binding(),
        "dev_report_sha256": digest(report), "dev_metrics": report["arms"],
        "dev_revision": DEV_REVISION, "selection_rule_version": SELECTION_RULE_VERSION,
        "dev_false_pass_criterion_met": rank(chosen)[0] is False,
        "selection_rule": "false-pass point <= 0.10 first; pooled kappa descending, macro constituent balanced "
            "accuracy descending, cost ascending, arm name ascending; if none eligible, use the same tie breaks"}
