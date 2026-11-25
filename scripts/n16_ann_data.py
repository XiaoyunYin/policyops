"""Deterministic N16 corpus selection, tenancy and independent ground-truth check."""
from __future__ import annotations

from array import array
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
import gzip
from hashlib import sha256
from importlib import import_module
import json
import math
from pathlib import Path
from typing import Any
from uuid import UUID

from scripts.n16_ann_fetch import ARCHIVE, REVISION, ROWS, SHA256, verify_archive, verify_licence


DIMENSION = 1536
K = 10
DISTANCE_TOLERANCE = 0.00002
MAX_LINE_BYTES = 4 * 1024 * 1024
FILLER = UUID(int=2)


@dataclass(frozen=True)
class Vector:
    id: str
    values: array[float]


@dataclass(frozen=True)
class Scope:
    name: str
    per_mille: int
    workspace: UUID | None


SCOPES = {share: Scope(f"runtime-{share}", share, UUID(int=share + 16)) for share in (1000, 100, 10, 1)}
OWNER = Scope("owner-no-rls", 1000, None)
LAYOUTS = {"single": (SCOPES[1000],), "filtered": (SCOPES[100], SCOPES[10], SCOPES[1], OWNER)}

Neighbor = tuple[str, float]


def vector(source_id: str, values: list[Any]) -> Vector:
    if not 1 <= len(source_id) <= 128 or any(ord(c) < 32 for c in source_id):
        raise ValueError("invalid_source_id")
    if len(values) != DIMENSION or any(type(value) not in (float, int) for value in values):
        raise ValueError("invalid_vector_dimension_or_values")
    try:
        packed = array("f", values)
    except OverflowError:
        raise ValueError("invalid_float32_vector") from None
    norm_squared = math.fsum(value * value for value in packed)
    if not 2.0 ** -126 <= norm_squared <= (2.0 - 2.0 ** -23) * 2.0 ** 127:
        raise ValueError("zero_or_nonfinite_float32_norm")
    return Vector(source_id, packed)


def corpus(directory: Path) -> tuple[dict[str, Any], Iterator[Vector]]:
    def read_rows(path: Path) -> Iterator[Vector]:
        count = 0
        with gzip.open(path, "rb") as handle:
            while line := handle.readline(MAX_LINE_BYTES + 1):
                count += 1
                if len(line) > MAX_LINE_BYTES or count > ROWS:
                    raise ValueError("corpus_row_limit")
                row = json.loads(line)
                source_id, values = row.get("id"), row.get("embedding")
                if not isinstance(source_id, str) or not isinstance(values, list):
                    raise ValueError("corpus_row_shape")
                yield vector(source_id, values)
        if count != ROWS:
            raise ValueError("corpus_row_count")

    manifest: dict[str, Any] = json.loads((directory / "source.json").read_bytes())
    card, licence = (directory / "README.md").read_bytes(), (directory / "Original_License").read_bytes()
    if (
        (manifest["revision"], manifest["sha256"], manifest["rows"]) != (REVISION, SHA256, ROWS)
        or manifest["card_sha256"] != sha256(card).hexdigest()
        or manifest["licence_sha256"] != sha256(licence).hexdigest()
    ):
        raise ValueError("corpus_manifest_mismatch")
    verify_licence(card.decode("utf-8"), licence.decode("utf-8"))
    path = directory / ARCHIVE
    verify_archive(path)
    return manifest, read_rows(path)


def fixture(count: int, seed: int) -> Iterator[Vector]:
    """Deterministic synthetic directions from a local, seeded generator."""
    from random import Random

    random = Random(seed)  # noqa: S311 - scientific fixture, not a security primitive
    for number in range(count):
        yield vector(f"fixture-{number:05d}", [random.uniform(-1, 1) for _ in range(DIMENSION)])


def hash_order(source_id: str, seed: int, purpose: str) -> tuple[bytes, str]:
    return sha256(f"{purpose}\0{seed}\0{source_id}".encode()).digest(), source_id


def split(rows: Iterable[Vector], seed: int, size: int, n_queries: int) -> tuple[list[Vector], list[Vector]]:
    unique: dict[str, Vector] = {}
    for row in rows:
        if row.id in unique:
            raise ValueError("duplicate_source_id")
        unique[row.id] = row
    if len(unique) < size + n_queries:
        raise ValueError("insufficient_corpus_rows")
    ordered = sorted(unique, key=lambda source_id: hash_order(source_id, seed, "split"))
    return ([unique[key] for key in ordered[n_queries:n_queries + size]], [unique[key] for key in ordered[:n_queries]])


def tenant_layout(ids: Sequence[str], name: str, seed: int) -> dict[str, UUID]:
    if name == "single":
        workspace = SCOPES[1000].workspace
        if workspace is None:
            raise ValueError("invalid_single_workspace")
        return dict.fromkeys(ids, workspace)
    if name != "filtered":
        raise ValueError("invalid_layout")
    ordered = sorted(ids, key=lambda source_id: hash_order(source_id, seed, "tenant"))
    positions: dict[str, UUID] = {}
    offset = 0
    for scope in LAYOUTS[name]:
        if scope.workspace is not None:
            count = len(ids) * scope.per_mille // 1000
            positions.update(dict.fromkeys(ordered[offset:offset + count], scope.workspace))
            offset += count
    positions.update(dict.fromkeys(ordered[offset:], FILLER))
    return positions


def cutoff_ties(neighbors: Sequence[Neighbor]) -> tuple[bool, bool]:
    """A tie touching rank k and a tie that extends beyond it."""
    crosses = len(neighbors) > K and neighbors[K - 1][1] == neighbors[K][1]
    touches = len(neighbors) >= K and neighbors[K - 2][1] == neighbors[K - 1][1]
    return touches or crosses, crosses


def numpy_crosscheck(rows: Sequence[Vector], queries: Sequence[Vector], truth: dict[str, list[Neighbor]],
                     ) -> list[dict[str, Any]]:
    # NumPy is already present in the evaluator lock. The root CI and the
    # fixture integration tests do not need to install the evaluator.
    np = import_module("numpy")
    query_matrix = np.asarray([row.values for row in queries], dtype=np.float32)
    query_norm = np.linalg.norm(query_matrix, axis=1)
    ids = [row.id for row in rows]
    positions = {source_id: i for i, source_id in enumerate(ids)}
    scores = np.empty((len(rows), len(queries)), dtype=np.float32)
    for offset in range(0, len(rows), 4096):
        block = np.asarray([row.values for row in rows[offset:offset + 4096]], dtype=np.float32)
        denominator = np.linalg.norm(block, axis=1)[:, None] * query_norm[None, :]
        cosine = (block @ query_matrix.T) / denominator
        scores[offset:offset + len(block)] = 1 - np.clip(cosine, -1, 1)

    checks = []
    for column, query in enumerate(queries):
        distances = scores[:, column]
        limit = min(K, len(ids))
        cutoff = float(np.partition(distances, limit - 1)[limit - 1])
        candidates = np.flatnonzero(distances <= cutoff)
        closest = sorted(candidates, key=lambda i: (distances[i], ids[i]))[:limit]
        expected = dict(truth[query.id][:K])
        actual = {ids[i] for i in closest}
        mismatches = expected.keys() ^ actual
        max_error = max(abs(float(distances[positions[key]]) - distance) for key, distance in expected.items())
        checks.append({
            "query": query.id,
            "numpy_ids": [ids[i] for i in closest],
            "cutoff_disagreements": sorted(mismatches),
            "max_abs_distance_error": max_error,
            "ok": (
                len(expected) == limit
                and max_error <= DISTANCE_TOLERANCE
                and all(abs(float(distances[positions[key]]) - cutoff) <= DISTANCE_TOLERANCE for key in mismatches)
            ),
        })
    return checks
