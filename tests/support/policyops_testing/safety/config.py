"""Frozen, bounded Slice A schedule. No provider calls are part of Slice A."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import random
from typing import Annotated, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator


Fault = Literal["crash_before_send", "commit_then_timeout", "crash_before_checkpoint", "duplicate_delivery",
                "fail_503_before"]
Variant = Literal["cancel", "pending_address", "delivered_return"]
Arm = Literal["ledger", "naive_new_id"]
FAULTS: tuple[Fault, ...] = ("crash_before_send", "commit_then_timeout", "crash_before_checkpoint",
                           "duplicate_delivery", "fail_503_before")
VARIANTS: tuple[Variant, ...] = ("cancel", "pending_address", "delivered_return")
ARMS: tuple[Arm, Arm] = ("ledger", "naive_new_id")
REPO = Path(__file__).resolve().parents[4]
DEFAULT_CONFIG = REPO / "tests/fixtures/safety/t30-v3.json"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Pair(StrictModel):
    pair_id: Annotated[str, Field(pattern=r"^pair-\d{3}$")]
    seed: Annotated[int, Field(ge=0, lt=2**64)]
    fault: Fault
    variant: Variant
    arms: tuple[Arm, Arm]
    concurrent: bool

    @model_validator(mode="after")
    def distinct_arms(self) -> Pair:
        if set(self.arms) != set(ARMS):
            raise ValueError("each pair needs both arms")
        return self

    def identity(self, arm: Arm, resource: str) -> UUID:
        return uuid5(NAMESPACE_URL, f"policyops.t30.v1/{self.pair_id}/{self.seed}/{arm}/{resource}")


class Grant(StrictModel):
    table: Annotated[tuple[str, ...], Field(max_length=7)]
    update_columns: Annotated[tuple[str, ...], Field(max_length=64)]
    select_columns: Annotated[tuple[str, ...], Field(max_length=64)]


class Config(StrictModel):
    schema_version: Literal["policyops.safety-config/v1", "policyops.safety-config/v2", "policyops.safety-config/v3"]
    study_id: Literal["t30-slice-a-v1", "t30-slice-a-v2", "t30-slice-a-v3"]
    master_seed: Literal[2026111204]
    pairs: Annotated[tuple[Pair, ...], Field(min_length=100, max_length=100)]
    matrix_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=2000)]
    naive_max_sends: Literal[3]
    max_passes: Literal[12]
    relay_timeout_seconds: Annotated[float, Field(ge=0.25, le=0.25)]
    limitations: tuple[str, ...]
    role_grants: dict[str, dict[str, Grant]]
    grants_source_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    @model_validator(mode="after")
    def exact_schedule(self) -> Config:
        if self.pairs != schedule(self.master_seed):
            raise ValueError("schedule differs from the preregistered algorithm")
        if len(set(self.matrix_ids)) != len(self.matrix_ids):
            raise ValueError("matrix IDs must be unique")
        return self


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def schedule(seed: int = 2026111204) -> tuple[Pair, ...]:
    rng = random.Random(seed)  # noqa: S311 - frozen experiment schedule
    faults: list[Fault] = [fault for fault in FAULTS for _ in range(20)]
    rng.shuffle(faults)
    variants: list[Variant] = [VARIANTS[i % 3] for i in range(100)]
    rng.shuffle(variants)
    pairs = []
    for index, (fault, variant) in enumerate(zip(faults, variants, strict=True)):
        arms: tuple[Arm, Arm] = ARMS if rng.randrange(2) == 0 else (ARMS[1], ARMS[0])
        pairs.append(Pair(pair_id=f"pair-{index:03}", seed=rng.getrandbits(63), fault=fault, variant=variant,
                          arms=arms, concurrent=index % 2 == 0))
    return tuple(pairs)


def load_config(path: Path = DEFAULT_CONFIG) -> Config:
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("config exceeds 1 MiB")
    return Config.model_validate_json(path.read_bytes())


E05_CONFIG = REPO / "tests/fixtures/safety/t30-e05-v1.json"
E05_PROMPT = REPO / "tests/fixtures/safety/prompts/e05-v1.txt"
E05_ARMS = ("gateway", "prompt_only", "replay_gateway")
E05_CATEGORIES = ("customer_message", "tool_output", "forged_authority", "cross_scope", "stale_replay", "tampering")


class E05Fixture(StrictModel):
    fixture_id: Annotated[str, Field(pattern=r"^e05-\d{3}$")]
    seed: Annotated[int, Field(ge=0, lt=2**64)]
    category: Literal["customer_message", "tool_output", "forged_authority", "cross_scope", "stale_replay",
                      "tampering", "valid"]
    scenario: Annotated[str, Field(min_length=1, max_length=64)]
    expected_blocker: Annotated[str, Field(min_length=1, max_length=200)]
    authorized_effect: Literal["none", "trusted_call"]
    trusted_call_json: Annotated[str, Field(max_length=4096)]
    candidate_name: Annotated[str, Field(min_length=1, max_length=64)]
    candidate_arguments_json: Annotated[str, Field(min_length=1, max_length=4096)]
    customer_text: Annotated[str, Field(min_length=1, max_length=2048)]
    tool_text: Annotated[str, Field(min_length=1, max_length=2048)]
    scripted_kind: Literal["compliant", "malicious", "malformed", "multi_call", "timeout", "usage_error"]

    @property
    def valid(self) -> bool:
        return self.category == "valid"


class E05Config(StrictModel):
    study_id: Literal["t30-e05-v1"]
    master_seed: Literal[2026111205]
    prompt_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    fixtures: Annotated[tuple[E05Fixture, ...], Field(min_length=60, max_length=60)]
    price_revision: Literal["pricing.2026-11-05.v1"]
    model: Literal["gpt-6-luna"]
    effort: Literal["low"]
    max_input: Literal[6000]
    max_output: Literal[512]
    fixture_usd: Literal["0.002"]
    study_usd: Literal["0.12"]
    inference_calls: Literal[60]
    count_calls: Literal[60]
    retries: Literal[0]
    repairs: Literal[0]
    trial_seconds: Literal[45]
    attempt_seconds: Literal[20]
    limitations: tuple[str, ...]

    @model_validator(mode="after")
    def complete(self) -> E05Config:
        from collections import Counter

        if {f.fixture_id for f in self.fixtures} != {f"e05-{i:03}" for i in range(60)}:
            raise ValueError("E05 fixture IDs differ from the 60-slot manifest")
        if Counter(f.category for f in self.fixtures) != {**dict.fromkeys(E05_CATEGORIES, 8), "valid": 12}:
            raise ValueError("E05 category denominators differ")
        if digest(self.model_dump(mode="json")) != "087d2e5e010b83fb350e1306a6f56b682401deb3dfa8978738f8af2618bb36e2":
            raise ValueError("E05 frozen configuration identity differs")
        return self


def load_e05_config(path: Path = E05_CONFIG) -> E05Config:
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("E05 config exceeds 1 MiB")
    config = E05Config.model_validate_json(path.read_bytes())
    if hashlib.sha256(E05_PROMPT.read_bytes()).hexdigest() != config.prompt_sha256:
        raise ValueError("E05 prompt hash mismatch")
    # Freeze truth, payloads AND order independently of caller-supplied configuration.
    if path.resolve() != E05_CONFIG.resolve() and path.read_bytes() != E05_CONFIG.read_bytes():
        raise ValueError("E05 config differs from frozen revision")
    return config
