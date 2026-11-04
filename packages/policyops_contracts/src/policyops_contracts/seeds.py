"""Demo/dev case seeds, server-only customer binding and policy authentication.

A public `DemoSeed` names an allowlisted dev task and how it may be used; it
holds no scenario text, reference actions, outcomes or customer identity.
`CaseCustomerBinding` is server-side scope authorization for one case (never
sent to the model or the browser). `CustomerAuthentication` records that, in
this run, a policy lookup returned the bound customer; it can only confirm the
binding, never replace it.
"""

from typing import Annotated, Literal, Self

from pydantic import StringConstraints, model_validator

from policyops_contracts.base import WireModel
from policyops_contracts.scalars import CaseScope, RunScope, Sequence, Sha256Hex, UserId, UtcDatetime


SeedKind = Literal["mutation", "read_only"]


class DemoSeed(WireModel):
    """Operator/server metadata for one allowlisted dev task; never part of the agent's input.

    `label` is deliberately neutral ("Retail demo <task id>"): a label derived
    from the reference actions would leak expected intent into a case. `kind`
    (mutation / read_only) is an eligibility tag for seed selection only.
    """

    seed_id: Annotated[str, StringConstraints(pattern=r"^retail-demo-\d{1,4}$")]
    label: Annotated[str, StringConstraints(pattern=r"^Retail demo \d{1,4}$")]
    domain: Literal["retail"]
    upstream_task_id: Annotated[str, StringConstraints(pattern=r"^\d{1,4}$")]
    kind: SeedKind
    allowlist_sha256: Sha256Hex

    @model_validator(mode="after")
    def _neutral(self) -> Self:
        task_id = self.upstream_task_id
        if (self.seed_id, self.label) != (f"retail-demo-{task_id}", f"Retail demo {task_id}"):
            raise ValueError("seed ID and label must be the neutral forms of the task ID")
        return self


class CaseCustomerBinding(WireModel):
    """Server-only: which upstream customer a seeded case is scoped to."""

    schema_version: Literal["policyops.case-customer-binding/v1"] = "policyops.case-customer-binding/v1"
    scope: CaseScope
    seed_id: Annotated[str, StringConstraints(pattern=r"^retail-demo-\d{1,4}$")]
    user_id: UserId
    bound_at: UtcDatetime


class CustomerAuthentication(WireModel):
    schema_version: Literal["policyops.customer-authentication/v1"] = "policyops.customer-authentication/v1"
    scope: RunScope
    user_id: UserId
    lookup_tool: Literal["find_user_id_by_email", "find_user_id_by_name_zip"]
    lookup_call_sha256: Sha256Hex
    step_sequence: Sequence
    authenticated_at: UtcDatetime
