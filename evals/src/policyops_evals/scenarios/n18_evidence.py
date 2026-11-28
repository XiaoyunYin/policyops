"""Bounded, read-only inputs for the offline N18 analyses."""

from hashlib import sha256
import json
from pathlib import Path
from typing import Any
from uuid import UUID

from policyops.persistence.evaluation import registration_digest
from policyops_evals.scenarios import Refused, read_bounded
from policyops_evals.scenarios.batch import Result
from policyops_evals.scenarios.recording import MAX_BODY_BYTES, MAX_EXCHANGES, Exchange, digest
from policyops_evals.scenarios.study import private_child, private_root


def document(root: Path, name: str) -> dict[str, Any]:
    value = json.loads(read_bounded(private_child(root, name), 1 << 20))
    if not isinstance(value, dict):
        raise Refused("expected a scenario document")
    return value


def registration(root: Path, schema: str) -> tuple[UUID, str, dict[str, Any]]:
    value = document(root, "registration.json")
    receipt = value["receipt"]
    payload = receipt["payload"]
    if payload["schema"] != schema or registration_digest(payload) != receipt["sha256"]:
        raise Refused("invalid study registration")
    return UUID(value["study_id"]), receipt["sha256"], payload


def exchanges(directory: Path, result: Result) -> list[Exchange]:
    records: list[Exchange] = []
    if directory.is_dir():
        for index, path in enumerate(sorted(_entries(directory))):
            if path.name != f"{index:02}.json":
                raise Refused("invalid cassette exchange name or order")
            raw = read_bounded(private_child(directory, path.name), 12 * MAX_BODY_BYTES)
            record = Exchange.model_validate_json(raw)
            if (record.index != index or digest(record.request) != record.request_sha256
                    or digest(record.response) != record.response_sha256
                    or any(body is not None and len(body.encode()) > MAX_BODY_BYTES
                           for body in (record.request, record.response))):
                raise Refused("invalid cassette exchange binding")
            records.append(record)
    tape_hash = sha256(b"\n".join(record.model_dump_json().encode() for record in records)).hexdigest()
    if tape_hash != result.tape_sha256:
        raise Refused("cassette does not match the retained result")
    return records


def _entries(directory: Path) -> list[Path]:
    paths: list[Path] = []
    for path in directory.iterdir():
        if len(paths) >= MAX_EXCHANGES:
            raise Refused("cassette exchange limit exceeded")
        paths.append(path)
    return paths


def output_path(path: Path) -> Path:
    """Keep reports with private scheduled-slot data outside all checkouts."""
    parent = private_root(path.parent)
    parent.mkdir(parents=True, exist_ok=True)
    return private_child(parent, path.name)
