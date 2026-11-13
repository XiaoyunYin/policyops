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
DEFAULT_CONFIG = REPO / "tests/fixtures/safety/t30-v1.json"


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
    schema_version: Literal["policyops.safety-config/v1"]
    study_id: Literal["t30-slice-a-v1"]
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
