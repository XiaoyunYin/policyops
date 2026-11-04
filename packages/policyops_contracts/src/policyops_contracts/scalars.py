"""Constrained scalar types shared by every contract module.

Timestamps must be timezone-aware UTC (offset zero); naive or offset times are
rejected rather than converted. Text fields are length-bounded and reject most
control characters (newline and tab are allowed). That is not a safety
guarantee: bounded text can still contain HTML, prompt text, personal data or
secrets, so rendering must escape it, logging must redact it and services must
control where it comes from. Application entity IDs are UUIDs and every
reference carries its workspace (tenant) scope. Upstream retail identifiers keep
their pinned upstream formats.
"""

from datetime import datetime, timedelta
from typing import Annotated
from uuid import UUID

from pydantic import AfterValidator, Field, StringConstraints

from policyops_contracts.base import WireModel


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("timestamps must be timezone-aware UTC")
    return value


UtcDatetime = Annotated[datetime, AfterValidator(_require_utc)]
Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
GitObjectId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
PositiveVersion = Annotated[int, Field(ge=1, le=2**53)]
Sequence = Annotated[int, Field(ge=1, le=2**53)]


def _no_controls(value: str) -> str:
    if any((ord(char) < 32 and char not in "\n\t") or 0x7F <= ord(char) < 0xA0 for char in value):
        raise ValueError("control characters are not allowed")
    return value


ShortText = Annotated[str, StringConstraints(min_length=1, max_length=200), AfterValidator(_no_controls)]
MessageText = Annotated[str, StringConstraints(min_length=1, max_length=4000), AfterValidator(_no_controls)]
SafeDetail = Annotated[str, StringConstraints(min_length=1, max_length=500), AfterValidator(_no_controls)]
Slug = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]

# Upstream retail identifiers (formats verified against the pinned retail DB in T04 preparation).
UserId = Annotated[str, StringConstraints(pattern=r"^[a-z]+(?:_[a-z]+)*_\d{1,6}$", max_length=64)]
OrderId = Annotated[str, StringConstraints(pattern=r"^#W\d{7}$")]
ProductId = Annotated[str, StringConstraints(pattern=r"^\d{10}$")]
ItemId = Annotated[str, StringConstraints(pattern=r"^\d{10}$")]
PaymentMethodId = Annotated[str, StringConstraints(pattern=r"^(?:credit_card|paypal|gift_card)_\d{7}$")]


class CaseScope(WireModel):
    """Tenant (workspace) and case scope carried by every case-level reference."""

    workspace_id: UUID
    case_id: UUID


class RunScope(WireModel):
    workspace_id: UUID
    case_id: UUID
    run_id: UUID
