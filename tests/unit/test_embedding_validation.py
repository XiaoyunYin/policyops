"""T12 embedding response validation: the embedding-local bounded parser (linear precheck, confined bad values, taint)
and the six-row accounting classification. Pure; no network, provider or database."""

from __future__ import annotations

import json
import math
from pathlib import Path
import struct
import subprocess
import sys
import time
from typing import Any

import pytest

from policyops.budget.config import Configuration
from policyops.providers import embeddings as emb


PREPARED = emb.prepare(["first input", "second input"], Configuration())
LOCAL = 7


def vector(seed: int = 1) -> list[float]:
    return [((i * 7 + seed) % 13 - 6) / 100.0 for i in range(1536)]


def response(*, model: str = "text-embedding-3-small", prompt: Any = LOCAL, total: Any = LOCAL,
             data: Any = None, **extra: Any) -> dict[str, Any]:
    items = data if data is not None else [{"object": "embedding", "index": i, "embedding": vector(i + 1)}
                                           for i in range(2)]
    return {"object": "list", "data": items, "model": model, "usage": {"prompt_tokens": prompt, "total_tokens": total},
            **extra}


def raw(body: Any) -> bytes:
    return body if isinstance(body, bytes) else json.dumps(body).encode()


def outcome(body: Any) -> emb.Classified:
    return emb.classify(raw(body), PREPARED, LOCAL)


# -- the six accounting rows ---------------------------------------------------------------------------------------

def test_a_valid_response_is_published_with_float32_vectors_and_finite_norms() -> None:
    result = outcome(response())
    assert result.outcome == "published" and result.settles and result.block is None
    assert result.billing == emb.Billing("text-embedding-3-small", LOCAL, LOCAL)
    assert result.vectors is not None and result.norms is not None and len(result.vectors) == 2
    expected = struct.unpack("<1536f", struct.pack("<1536f", *vector(1)))
    assert result.vectors[0] == expected  # rounded to float32, in index order
    assert all(math.isfinite(n) and n > 0 for n in result.norms)


@pytest.mark.parametrize(("body", "expected", "settles", "block"), [
    (b"not json", "unknown", False, None),
    (response(prompt=None), "unknown", False, None),
    (response(prompt=True, total=True), "unknown", False, None),
    (response(prompt="7", total="7"), "unknown", False, None),
    (response(prompt=LOCAL, total=LOCAL + 1), "usage_contradiction", False, "embedding_usage_contradiction"),
    (response(model="text-embedding-3-large"), "model_mismatch", False, "embedding_model_mismatch"),
    (response(prompt=LOCAL + 1, total=LOCAL + 1), "count_mismatch", True, "embedding_count_mismatch"),
    (response(data=[]), "vectors_invalid", True, None),
])
def test_the_accounting_table(body: Any, expected: str, settles: bool, block: str | None) -> None:
    result = outcome(body)
    assert (result.outcome, result.settles, result.block) == (expected, settles, block)
    assert result.vectors is None or expected == "published"


def test_a_missing_model_or_usage_object_is_unknown_billing() -> None:
    body = response()
    del body["usage"]
    assert outcome(body).outcome == "unknown"
    body = response()
    del body["model"]
    assert outcome(body).outcome == "unknown"


# -- vector subtree failures keep valid billing ------------------------------------------------------------------

def items(**changes: Any) -> list[dict[str, Any]]:
    base = [{"object": "embedding", "index": i, "embedding": vector(i + 1)} for i in range(2)]
    base[1] = base[1] | changes
    return base


@pytest.mark.parametrize("data", [
    items(embedding=vector()[:1535]), items(embedding=[*vector(), 0.1]),
    items(embedding=[True] * 1536), items(embedding=["0.1", *vector()[1:]]), items(embedding="AAAA"),
    items(embedding=[0.0] * 1536), items(embedding=[1e-46] * 1536),  # zero after float32 rounding
    items(embedding=[1e39, *vector()[1:]]), items(index=0), items(index=2), items(index=True),
    items(object="vector"), [{"object": "embedding", "index": 0, "embedding": vector()}],
])
def test_an_invalid_vector_subtree_settles_its_known_bill_and_publishes_nothing(data: list[Any]) -> None:
    result = outcome(response(data=data))
    assert result.outcome == "vectors_invalid" and result.settles and result.billing is not None
    assert result.vectors is None


def test_a_body_beyond_the_parse_bounds_keeps_the_hold_and_invents_no_bill() -> None:
    result = outcome(response(data=items(embedding=["0.1"] * 1536)))  # more strings than the precheck admits
    assert (result.outcome, result.billing, result.settles) == ("unknown", None, False)


def test_indexes_may_arrive_out_of_order() -> None:
    shuffled = list(reversed(items()))
    result = outcome(response(data=shuffled))
    assert result.outcome == "published" and result.vectors is not None
    assert result.vectors[0] == struct.unpack("<1536f", struct.pack("<1536f", *vector(1)))


def with_vector_text(body: dict[str, Any], replacement: str) -> bytes:
    """The JSON text with the second vector's first number replaced by a raw literal."""
    text = json.dumps(body)
    first = json.dumps(vector(2)[0])
    marker = '"index": 1, "embedding": [' + first
    assert text.count(marker) == 1
    return text.replace(marker, '"index": 1, "embedding": [' + replacement).encode()


@pytest.mark.parametrize(("literal", "expected"), [
    ("0." + "1" * 21, "published"),  # 23 characters
    ("0." + "1" * 22, "published"),  # 24
    ("0." + "1" * 23, "vectors_invalid"),  # 25: an INVALID marker, never converted
    ("NaN", "vectors_invalid"), ("Infinity", "vectors_invalid"), ("-Infinity", "vectors_invalid"),
    ("1" * 4300, "vectors_invalid"),  # never handed to int() (which would refuse it, or convert it slowly)
])
def test_bad_numbers_inside_a_vector_keep_billing(literal: str, expected: str) -> None:
    result = emb.classify(with_vector_text(response(), literal), PREPARED, LOCAL)
    assert result.outcome == expected and result.billing is not None


@pytest.mark.parametrize("usage_text", [
    '{"prompt_tokens": 1234567890123456789012345, "total_tokens": 7}',
    '{"prompt_tokens": NaN, "total_tokens": 7}',
    '{"prompt_tokens": 7, "prompt_tokens": 7, "total_tokens": 7}',
    '{"prompt_tokens": 7.0, "total_tokens": 7.0}',
])
def test_bad_billing_fields_are_unknown_never_chosen(usage_text: str) -> None:
    text = json.dumps(response()).replace('{"prompt_tokens": 7, "total_tokens": 7}', usage_text)
    assert usage_text in text
    assert emb.classify(text.encode(), PREPARED, LOCAL).outcome == "unknown"


def test_a_duplicated_root_model_is_unknown_billing() -> None:
    text = json.dumps(response()).replace('"model": "text-embedding-3-small"',
                                          '"model": "text-embedding-3-small", "model": "text-embedding-3-small"')
    assert emb.classify(text.encode(), PREPARED, LOCAL).outcome == "unknown"


@pytest.mark.parametrize("extra", [
    '"note": 1, "note": 2',  # a duplicate in an unused root field
    '"note": NaN',  # an invalid value in an unused root field
    '"note": [1, 2, 0.1234567890123456789012345]',
])
def test_any_bad_value_anywhere_taints_the_vectors_but_not_unambiguous_billing(extra: str) -> None:
    text = json.dumps(response())
    tainted = text[:-1] + ", " + extra + "}"
    result = emb.classify(tainted.encode(), PREPARED, LOCAL)
    assert result.outcome == "vectors_invalid" and result.billing == emb.Billing("text-embedding-3-small", 7, 7)


def test_a_duplicate_inside_a_vector_item_or_usage_extra_field_taints_only_the_vectors() -> None:
    text = json.dumps(response()).replace('"index": 1,', '"index": 1, "object": "embedding",')
    assert emb.classify(text.encode(), PREPARED, LOCAL).outcome == "vectors_invalid"
    text = json.dumps(response()).replace('"total_tokens": 7}', '"total_tokens": 7, "x": 1, "x": 1}')
    result = emb.classify(text.encode(), PREPARED, LOCAL)
    assert result.outcome == "vectors_invalid" and result.billing is not None


def test_billing_is_read_whichever_order_the_keys_arrive_in() -> None:
    body = response()
    usage_first = {"usage": body["usage"], "model": body["model"], "object": "list", "data": body["data"]}
    assert outcome(usage_first).outcome == outcome(body).outcome == "published"


def test_json_whitespace_is_accepted_between_tokens() -> None:
    text = json.dumps(response(), indent="\t").replace("\n", "\r\n")
    assert emb.classify(text.encode(), PREPARED, LOCAL).outcome == "published"


# -- the bounded precheck ------------------------------------------------------------------------------------------

def nested(depth: int) -> str:
    return "[" * depth + "]" * depth


@pytest.mark.parametrize(("depth", "parseable"), [(8, True), (9, False)])
def test_nesting_depth_is_bounded(depth: int, parseable: bool) -> None:
    text = json.dumps(response())[:-1] + ', "deep": ' + "[" * (depth - 1) + "]" * (depth - 1) + "}"
    result = emb.classify(text.encode(), PREPARED, LOCAL)
    assert (result.outcome != "unknown") is parseable


def strings_in(value: Any) -> int:
    if isinstance(value, dict):
        return sum(1 + strings_in(v) for v in value.values())
    if isinstance(value, list):
        return sum(strings_in(v) for v in value)
    return 1 if isinstance(value, str) else 0


@pytest.mark.parametrize(("extra", "parseable"), [(0, True), (1, False)])
def test_string_count_is_bounded(extra: int, parseable: bool) -> None:
    body = response()
    used = strings_in(body) + 1  # plus the key of the padding list
    body["pad"] = ["s"] * (emb.MAX_STRINGS - used + extra)
    assert strings_in(body) == emb.MAX_STRINGS + extra
    assert (outcome(body).outcome != "unknown") is parseable


@pytest.mark.parametrize(("length", "parseable"), [(emb.MAX_STRING_CHARS, True), (emb.MAX_STRING_CHARS + 1, False)])
def test_string_length_is_bounded(length: int, parseable: bool) -> None:
    assert (outcome(response(note="x" * length)).outcome != "unknown") is parseable


@pytest.mark.parametrize(("escape", "parseable"), [
    (r"A\n\t\"\\\/", True), (r"😀", True), (r"\x41", False), (r"\u00", False), ("\x01", False),
])
def test_string_escapes(escape: str, parseable: bool) -> None:
    text = json.dumps(response())[:-1] + ', "note": "' + escape + '"}'
    assert (emb.classify(text.encode(), PREPARED, LOCAL).outcome != "unknown") is parseable


def test_too_many_containers_and_non_utf8_are_unparseable() -> None:
    assert outcome(response(pad=[[]] * emb.MAX_CONTAINERS)).outcome == "unknown"
    assert emb.classify(json.dumps(response()).encode("utf-16"), PREPARED, LOCAL).outcome == "unknown"


WATCHDOG = """
import sys, time
from policyops.providers.embeddings import Unparseable, loads
payload = sys.stdin.buffer.read()
started = time.perf_counter()
try:
    loads(payload)
    result = "parsed"
except Unparseable:
    result = "refused"
print(result, round(time.perf_counter() - started, 4))
"""


@pytest.mark.parametrize(("name", "payload", "expected"), [
    ("unterminated escaped quotes", b'"' + b'\\"' * 16_384, "refused"),
    ("4 MiB unterminated escaped quotes", b'"' + b'\\"' * ((4 << 20) // 2 - 1), "refused"),
    ("4 MiB of commas inside a list", b"[" + b"1," * ((4 << 20) // 2 - 2) + b"1]", "parsed"),
    ("positive control: escaped quotes in a valid string", json.dumps({"a": '"' * 1000}).encode(), "parsed"),
])
def test_adversarial_bodies_finish_quickly_in_an_owned_child(name: str, payload: bytes, expected: str,
                                                              tmp_path: Path) -> None:
    """Owned watchdog: a regression to super-linear scanning would hang; the child is killed at the timeout."""
    process = subprocess.Popen([sys.executable, "-I", "-B", "-c", WATCHDOG], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=tmp_path)
    try:
        out, err = process.communicate(payload, timeout=20)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=10)
        pytest.fail(f"{name}: the parser did not finish within 20 s")
    assert process.returncode == 0, err.decode(errors="replace")[-2000:]
    result, seconds = out.decode().split()
    print(f"parse {name}: {len(payload)} bytes, {result} in {seconds}s")
    assert result == expected and float(seconds) < 5.0


def test_the_largest_admitted_response_parses_quickly() -> None:
    prepared = emb.prepare([f"input {i}" for i in range(64)], Configuration())
    body = response(data=[{"object": "embedding", "index": i, "embedding": vector(i)} for i in range(64)])
    data = json.dumps(body, indent=6).encode()
    assert 2 << 20 < len(data) < 4 << 20
    started = time.perf_counter()
    result = emb.classify(data, prepared, LOCAL)
    elapsed = time.perf_counter() - started
    print(f"classify 64x1536 pretty-printed: {len(data)} bytes in {elapsed:.3f}s")
    assert result.outcome == "published" and elapsed < 10.0
