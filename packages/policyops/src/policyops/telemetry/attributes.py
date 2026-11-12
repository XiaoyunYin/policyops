"""The only telemetry attribute/label boundary. Values are closed, not merely key-filtered."""

from collections.abc import Mapping
import re
from typing import Literal, TypedDict
from uuid import UUID

from policyops_contracts.retail import ToolName


Outcome = Literal["ok", "error", "cancelled", "retry", "refused", "unknown", "skipped", "completed",
                  "failed", "deadline", "budget", "contract_gap", "result", "invalid_output", "structured",
                  "truncated", "settled", "capped", "recorded", "lost_claim", "unchanged", "contradiction"]


class Attributes(TypedDict, total=False):
    run_id: UUID
    job_id: UUID
    proposal_id: UUID
    operation_id: UUID
    attempt: int
    generation: int
    provider: str
    model: str
    operation: str
    outcome: str
    cost_class: str
    input_tokens: int
    output_tokens: int
    tool: str
    access: str
    node: str
    kind: str
    mode: str
    phase: str
    sqlstate_class: str
    exception_type: str
    error_code: str
    http_method: str
    http_route: str
    http_status: int
    startup_phase: str
    startup_category: str


ENUMS: dict[str, frozenset[str]] = {
    "provider": frozenset({"openai", "anthropic"}),
    "model": frozenset({"gpt-6-luna", "gpt-6.1-sol", "claude-haiku-5-5", "claude-opus-5-5",
                         "text-embedding-3-small"}),
    "operation": frozenset({"chat", "embedding", "count", "reserve", "dispatch", "reconcile"}),
    "outcome": frozenset({"ok", "error", "cancelled", "retry", "refused", "unknown", "skipped", "completed",
                          "failed", "deadline", "budget", "contract_gap", "result", "invalid_output", "structured",
                          "truncated", "settled", "capped", "recorded", "lost_claim", "unchanged", "contradiction",
                          "succeeded", "reconciled", "reserved", "dispatched"}),
    "cost_class": frozenset({"known", "unconfirmed", "not_dispatched"}),
    "tool": frozenset(t.value for t in ToolName),
    "access": frozenset({"read", "write", "control"}),
    "node": frozenset({"investigate", "retrieve", "read", "propose", "finalize"}),
    "kind": frozenset({"run.execute", "run.review"}),
    "mode": frozenset({"lexical", "dense", "hybrid", "full_policy"}),
    "phase": frozenset({"acquire", "setup", "body", "commit"}),
    "sqlstate_class": frozenset({"00", "01", "02", "03", "08", "09", "0A", "0B", "0F", "0L", "0P",
                                 "0Z", "20", "21", "22", "23", "24", "25", "26", "27", "28", "2B", "2D",
                                 "2F", "34", "38", "39", "3B", "3D", "3F", "40", "42", "44", "53", "54",
                                 "55", "57", "58", "72", "F0", "HV", "P0", "XX"}),
    "error_code": frozenset({"boundary_error", "sql_failure", "export_failure", "executor_error",
                             "worker_job_error", "review_error", "review_finish_error", "claim_lost"}),
    "http_method": frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}),
    "startup_phase": frozenset({"auth runtime engine", "app runtime engine", "auth runtime role check",
                                "app runtime role check", "authentication wiring", "application"}),
}
IDS = frozenset({"run_id", "job_id", "proposal_id", "operation_id"})
INTEGERS = frozenset({"attempt", "generation", "input_tokens", "output_tokens"})
ROUTES: set[str] = set()
TYPE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,79}\Z")
# Startup categories use the same bounded type-name policy as exception_type, plus closed, value-free suffixes.
# Never accept a RuntimeRoleError's free-form authenticated/session/current role names.
STARTUP_CATEGORY = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]{0,79}(?: \(SQLSTATE [0-9A-Z]{5}\)| \(no SQLSTATE: "
    r"(?:password authentication refused|authentication method refused|connect timeout|connection refused|"
    r"host name not resolved|role or database does not exist|connection failed)\))?\Z")
STARTUP_ROLE_CATEGORIES = frozenset({
    "RuntimeRoleError: policyops_auth_runtime has privileges a runtime role must not have",
    "RuntimeRoleError: policyops_app_runtime has privileges a runtime role must not have",
    "RuntimeRoleError: a pooled connection authenticated as a different role",
    "RuntimeRoleError: this engine was already verified for a different runtime role",
})
METRIC_KEYS = frozenset({"provider", "model", "outcome", "error_code", "kind"})


def clean(values: Mapping[str, object], *, metric: bool = False) -> dict[str, str | int]:
    result: dict[str, str | int] = {}
    for key, value in values.items():
        if metric and key not in METRIC_KEYS:
            continue
        if key in IDS and isinstance(value, UUID):
            result[key] = str(value)
        elif (
            (key in INTEGERS and type(value) is int and 0 <= value <= 2**53)
            or (key == "http_status" and type(value) is int and 100 <= value <= 599)
            or (isinstance(value, str) and (
                value in ENUMS.get(key, ()) or (key == "http_route" and value in ROUTES)
                or (key == "startup_category" and len(value) <= 240
                    and (STARTUP_CATEGORY.fullmatch(value) or value in STARTUP_ROLE_CATEGORIES))
                or (key == "exception_type" and TYPE_NAME.fullmatch(value))))
        ):
            result[key] = value
    return result
