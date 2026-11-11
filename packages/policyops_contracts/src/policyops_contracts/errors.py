"""Stable, bounded error envelope.

`detail` is length-bounded free text written by the service; the type cannot
ensure it is free of secrets or personal data, so producers must write safe
messages and never include stack traces, payloads or credentials. Replayable
run events carry only the code and identifiers (events.ErrorRaised).
"""

from enum import StrEnum
from typing import Literal
from uuid import UUID

from policyops_contracts.base import WireModel
from policyops_contracts.scalars import SafeDetail, Slug


class ErrorCode(StrEnum):
    INVALID_INPUT = "invalid_input"
    UNAUTHENTICATED = "unauthenticated"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    STALE_VERSION = "stale_version"
    CONTEXT_CHANGED = "context_changed"
    EXPIRED = "expired"
    CUSTOMER_NOT_AUTHENTICATED = "customer_not_authenticated"
    CUSTOMER_MISMATCH = "customer_mismatch"
    POLICY_DENIED = "policy_denied"
    POLICY_UNSUPPORTED = "policy_unsupported"
    CONSENT_REQUIRED = "consent_required"
    CONSENT_AMBIGUOUS = "consent_ambiguous"
    APPROVAL_REQUIRED = "approval_required"
    SEPARATION_OF_DUTIES = "separation_of_duties"
    PROTOCOL_VIOLATION = "protocol_violation"
    UPSTREAM_MONEY_PRECISION = "upstream_money_precision"
    RATE_LIMITED = "rate_limited"
    UNAVAILABLE = "unavailable"
    INTERNAL = "internal"


class ErrorEnvelope(WireModel):
    schema_version: Literal["policyops.error/v1"] = "policyops.error/v1"
    code: ErrorCode
    detail: SafeDetail
    rule_id: Slug | None = None
    correlation_id: UUID
    retryable: bool
