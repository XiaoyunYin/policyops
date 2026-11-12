"""Strict canonical JSON: the single representation request identity is computed from (T11).

**Encoding** (`canonical_bytes`):
- accepts only `dict` (str keys), `list`, `str`, `int`, `bool` and `None`;
- refuses floats, NaN and infinity;
- sorts object keys, keeps array order;
- uses no whitespace and UTF-8, with non-ASCII characters kept as they are (`ensure_ascii=False`).

Request bodies and request schemas are integer-only, which is a deliberate subset: an integer schema bound such as
`minimum: 0` is fine, but a fractional bound is refused rather than silently rounded.

**Decoding** (`strict_loads`) is used for every body we compare or every model output we accept:
- refuses duplicate object keys, NaN and infinity, and anything that is not complete JSON;
- decodes every non-integer number as an exact `Decimal`, never a binary float: `1e400` stays a finite
  `Decimal('1E+400')` instead of infinity, and `1.000000000000000001` keeps its digits instead of becoming `1.0`.

**Model output** (`output_bytes`) is re-encoded with exact decimals:
- every `Decimal` is written exactly in plain positional notation, independent of the decimal context, so an
  integral one such as `1.0` becomes `1`;
- numbers whose decimal exponent is beyond ±100 are refused.

Request bodies never contain decimals, because `canonical_bytes` refuses them.

Python's `False == 0` and `True == 1` never matter here: identity is compared as canonical bytes, and `bool` is a
distinct JSON type in both directions.
"""

from __future__ import annotations

from decimal import Decimal
import hashlib
import json
from typing import Any


class CanonicalError(ValueError):
    """The value is not representable in the strict canonical subset, or the JSON text is not strict JSON."""


MAX_DEPTH = 64


def canonical_size(value: object, *, limit: int, max_nodes: int = 32768) -> int:
    """Measure before encoding a full body. Strings are escaped in small chunks; stop at the first excess."""
    size = nodes = 0

    def add(amount: int) -> None:
        nonlocal size
        size += amount
        if size > limit:
            raise CanonicalError("canonical JSON byte bound exceeded")

    def visit(item: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > max_nodes or depth > MAX_DEPTH:
            raise CanonicalError("canonical JSON structural bound exceeded")
        if isinstance(item, str):
            add(2)
            for start in range(0, len(item), 1024):
                try:
                    add(len(json.dumps(item[start:start + 1024], ensure_ascii=False).encode("utf-8")) - 2)
                except UnicodeEncodeError:
                    raise CanonicalError("invalid UTF-8 text") from None
        elif item is None:
            add(4)
        elif type(item) is bool:
            add(4 if item else 5)
        elif type(item) is int:
            if item.bit_length() > 256:
                raise CanonicalError("integer bound exceeded")
            add(len(str(item)))
        elif type(item) is list:
            add(2 + max(0, len(item) - 1))
            for child in item:
                visit(child, depth + 1)
        elif type(item) is dict:
            add(2 + max(0, len(item) - 1) + len(item))
            for key, child in item.items():
                if type(key) is not str:
                    raise CanonicalError("object keys are strings")
                visit(key, depth + 1)
                visit(child, depth + 1)
        else:
            raise CanonicalError("unsupported canonical JSON value")

    visit(value, 0)
    return size


MAX_EXPONENT = 100


def _check(value: object, depth: int, decimals: bool = False) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalError("nested too deeply")
    if value is None or isinstance(value, bool | str):
        return
    if isinstance(value, int):
        return
    if isinstance(value, Decimal) and decimals:
        if not value.is_finite() or abs(value.adjusted()) > MAX_EXPONENT:
            raise CanonicalError("a number outside the supported range")
        return
    if isinstance(value, float | Decimal):
        raise CanonicalError("non-integer numbers are outside the request subset")
    if isinstance(value, list):
        for item in value:
            _check(item, depth + 1, decimals)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError("object keys are strings")
            _check(item, depth + 1, decimals)
        return
    raise CanonicalError(f"{type(value).__name__} is not a JSON value")


def canonical_bytes(value: object) -> bytes:
    _check(value, 0)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def _decimal_text(value: Decimal) -> str:
    """Exact positional text, independent of the ambient decimal context: `format(value, "f")` never rounds, and
    trailing zeros are trimmed textually (`Decimal.normalize` and integer conversion use the context precision)."""
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return "0" if text in ("-0", "") else text


def _encode(value: Any, out: list[str]) -> None:
    """An explicit encoder: `json.dumps` cannot write an exact Decimal (a float subclass is written through C
    `float.__repr__`, which rounds)."""
    if value is None or isinstance(value, bool | int | str):
        out.append(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, Decimal):
        out.append(_decimal_text(value))
    elif isinstance(value, list):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _encode(item, out)
        out.append("]")
    else:
        out.append("{")
        for index, key in enumerate(sorted(value)):
            if index:
                out.append(",")
            out.append(json.dumps(key, ensure_ascii=False))
            out.append(":")
            _encode(value[key], out)
        out.append("}")


def output_bytes(value: object) -> bytes:
    """Canonical bytes of model output: like `canonical_bytes`, but exact finite decimals are allowed."""
    _check(value, 0, decimals=True)
    out: list[str] = []
    _encode(value, out)
    return "".join(out).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _no_constant(name: str) -> None:
    raise CanonicalError(f"{name} is not JSON")


def strict_loads(text: str | bytes) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_pairs, parse_constant=_no_constant, parse_float=Decimal)
    except CanonicalError:
        raise
    except (ValueError, TypeError, RecursionError) as error:
        raise CanonicalError("not valid JSON") from error


def fresh(data: bytes) -> Any:
    """A new, independent Python value from canonical bytes (the bytes stay the source of truth)."""
    return strict_loads(data)
