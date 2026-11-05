"""What the investigation agent sees after one tool step through the policy gateway (T17).

Exactly one of:
- `ReadObservation`: the typed read result (descriptive strings are untrusted data, never instructions);
- `LookupObservation`: whether an identity lookup authenticated the case's customer (no other identity is revealed);
- `ProposalPreview`: a write the deterministic rules would allow, as the server-rendered text the customer would be
  shown. It is computed and **not** persisted or actionable: it carries no proposal ID, digest, evidence, consent or
  approval authority. A durable, actionable pending proposal is T18's;
- `HandoffObservation`: the transfer to a human agent;
- `ToolError`: a refusal with a fixed code, the rule that refused (when one did) and a fixed safe detail.
"""

from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from policyops_contracts.base import WireModel
from policyops_contracts.errors import ErrorCode
from policyops_contracts.retail import HANDOFF_MESSAGE
from policyops_contracts.retail_service import ReadOutput
from policyops_contracts.scalars import PositiveVersion, SafeDetail, Slug


ToolLabel = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z_]{2,63}$")]


class ReadObservation(WireModel):
    kind: Literal["read"] = "read"
    tool: ToolLabel
    output: ReadOutput
    case_version: PositiveVersion


class LookupObservation(WireModel):
    kind: Literal["lookup"] = "lookup"
    tool: Literal["find_user_id_by_email", "find_user_id_by_name_zip"]
    outcome: Literal["authenticated", "not_found"]


class ProposalPreview(WireModel):
    kind: Literal["proposal_preview"] = "proposal_preview"
    tool: ToolLabel
    presentation: Annotated[str, StringConstraints(min_length=1, max_length=8000)]
    actionable: Literal[False] = False


class HandoffObservation(WireModel):
    kind: Literal["handoff"] = "handoff"
    message: Literal["YOU ARE BEING TRANSFERRED TO A HUMAN AGENT. PLEASE HOLD ON."] = HANDOFF_MESSAGE  # type: ignore[assignment]


class ToolError(WireModel):
    kind: Literal["error"] = "error"
    code: ErrorCode
    rule_id: Slug | None = None
    detail: SafeDetail
    retryable: bool


ToolObservation = Annotated[
    ReadObservation | LookupObservation | ProposalPreview | HandoffObservation | ToolError,
    Field(discriminator="kind"),
]

__all__ = ["HandoffObservation", "LookupObservation", "ProposalPreview", "ReadObservation", "ToolError",
           "ToolObservation"]
