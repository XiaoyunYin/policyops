"""The versioned per-case state codec.

`retail-state/v1` is the upstream `RetailDB` dumped in JSON mode and written as canonical JSON (sorted keys, compact
separators, UTF-8, NaN/Infinity refused). Python's float repr round-trips exactly, so decoding and re-encoding gives
the same bytes; `encode` checks that, and nothing is rounded or repaired. A state larger than `MAX_STATE_BYTES` is
refused in both directions.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


CODEC = "retail-state/v1"
MAX_STATE_BYTES = 8 * 1024 * 1024


class StateTooLarge(ValueError):
    pass


class CodecError(ValueError):
    pass


def dump(db: Any) -> dict[str, Any]:
    data: dict[str, Any] = db.model_dump(mode="json")
    return data


def encode(db: Any, *, verify: Any = None) -> bytes:
    """Canonical bytes of an upstream `RetailDB`. With `verify` (the `RetailDB` class) the bytes must decode and
    re-encode to themselves."""
    raw = json.dumps(dump(db), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                     allow_nan=False).encode("utf-8")
    if len(raw) > MAX_STATE_BYTES:
        raise StateTooLarge(f"state is {len(raw)} bytes; the cap is {MAX_STATE_BYTES}")
    if verify is not None and encode(decode(raw, verify)) != raw:
        raise CodecError("state does not round-trip exactly")
    return raw


def decode(raw: bytes, retail_db: Any) -> Any:
    if len(raw) > MAX_STATE_BYTES:
        raise StateTooLarge(f"state is {len(raw)} bytes; the cap is {MAX_STATE_BYTES}")
    return retail_db.model_validate_json(raw)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
