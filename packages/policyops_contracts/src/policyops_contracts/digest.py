"""Canonical bytes and SHA-256 digests for binding records.

Canonical form: the model's JSON-mode dump (exact integers, UTC timestamps as
ISO-8601 with "Z", enum values), JSON with sorted keys, no insignificant
whitespace, UTF-8. Sequence order is preserved, so item pairs and multiplicity
are part of the digest. Floats are refused outright: binding records must not
contain them.
"""

import hashlib
import json
from typing import Any

from pydantic import BaseModel


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("binding records must not contain floats")
    if isinstance(value, dict):
        for item in value.values():
            _reject_floats(item)
    elif isinstance(value, list):
        for item in value:
            _reject_floats(item)


def canonical_bytes(model: BaseModel, *, exclude: set[str] | None = None) -> bytes:
    data = model.model_dump(mode="json", exclude=exclude)
    _reject_floats(data)
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def text_sha256(text: str) -> str:
    return sha256_hex(text.encode("utf-8"))
