"""Read cursor bounds and resource bindings, without a database."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from policyops.auth.service import AuthError
from policyops.services.run_reads import ReadCursor, encode, position


def test_canonical_cursor_binds_tenant_resource_and_list_kind() -> None:
    w, resource, row = uuid4(), uuid4(), uuid4()
    now = datetime(2026, 11, 12, tzinfo=UTC)
    raw = encode(ReadCursor(w=w, resource=resource, kind="runs", at=now, id=row))
    assert len(raw) <= 400 and position(raw, w, resource, "runs", 25) == (now, row)
    for value, workspace, target, kind in (
        (raw + "=", w, resource, "runs"), (raw, uuid4(), resource, "runs"),
        (raw, w, uuid4(), "runs"), (raw, w, resource, "citations"),
        ("x" * 401, w, resource, "runs"), ("😀", w, resource, "runs"), ("!", w, resource, "runs"),
    ):
        with pytest.raises(AuthError, match="Invalid page bounds"):
            position(value, workspace, target, kind, 25)  # type: ignore[arg-type]


@pytest.mark.parametrize("limit", [0, -1, 101])
def test_service_enforces_page_limit_even_without_http(limit: int) -> None:
    with pytest.raises(AuthError):
        position(None, uuid4(), uuid4(), "runs", limit)
