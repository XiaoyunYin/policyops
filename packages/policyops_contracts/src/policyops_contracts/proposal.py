"""Immutable action proposals and their binding digest.

A proposal binds, under one SHA-256 `action_digest`: the tenant/case/run
scope, the bound customer, the proposal identity and version, the typed write
call, the computed effect and the exact server-rendered text shown for it, the
policy version and rules checked, the resource and evidence versions read and
the expiry. Construction and deserialization both re-verify the effect against
the call, the text against the effect and the digest against the content, so a
proposal record cannot silently disagree with what was displayed.

This proves internal consistency of the record only. Whether a consent or
approval was actually persisted, and execution-time rechecks, belong to the
services (T17-T19).
"""

from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, StringConstraints, model_validator

from policyops_contracts.base import WireModel
from policyops_contracts.digest import canonical_bytes, sha256_hex, text_sha256
from policyops_contracts.policy import PolicyRef
from policyops_contracts.presentation import render_effect
from policyops_contracts.retail import (
    CancelEffect,
    CancelPendingOrder,
    Effect,
    ExchangeDeliveredOrderItems,
    ItemsEffect,
    ModifyPendingOrderAddress,
    ModifyPendingOrderItems,
    ModifyPendingOrderPayment,
    ModifyUserAddress,
    OrderAddressEffect,
    PaymentChangeEffect,
    ResourceVersion,
    ReturnDeliveredOrderItems,
    ReturnEffect,
    UserAddressEffect,
    WriteToolCall,
)
from policyops_contracts.scalars import PositiveVersion, RunScope, Sha256Hex, Slug, UserId, UtcDatetime
from policyops_contracts.timing import within_ttl


PROPOSAL_SCHEMA: Literal["policyops.action-proposal/v1"] = "policyops.action-proposal/v1"


class EvidenceRef(WireModel):
    evidence_id: UUID
    document_version_id: UUID
    content_sha256: Sha256Hex


class Presentation(WireModel):
    text: Annotated[str, StringConstraints(min_length=1, max_length=8000)]
    text_sha256: Sha256Hex


def _matches(action: WriteToolCall, effect: Effect, customer: UserId) -> bool:
    if isinstance(action, CancelPendingOrder):
        return isinstance(effect, CancelEffect) and (effect.order_id, effect.reason) == (action.order_id, action.reason)
    if isinstance(action, ModifyPendingOrderAddress):
        return (isinstance(effect, OrderAddressEffect) and effect.order_id == action.order_id
                and effect.address_after == action.address())
    if isinstance(action, ModifyPendingOrderPayment):
        return (isinstance(effect, PaymentChangeEffect) and effect.order_id == action.order_id
                and effect.to_payment_method_id == action.payment_method_id)
    if isinstance(action, ModifyPendingOrderItems | ExchangeDeliveredOrderItems):
        return (isinstance(effect, ItemsEffect) and effect.kind == action.tool and effect.order_id == action.order_id
                and tuple(line.item_id for line in effect.changes) == action.item_ids
                and tuple(line.new_item_id for line in effect.changes) == action.new_item_ids
                and effect.payment_method_id == action.payment_method_id)
    if isinstance(action, ReturnDeliveredOrderItems):
        return (isinstance(effect, ReturnEffect) and effect.order_id == action.order_id
                and tuple(line.item_id for line in effect.items) == action.item_ids
                and effect.refund_payment_method_id == action.payment_method_id)
    return (isinstance(effect, UserAddressEffect) and effect.user_id == action.user_id == customer
            and effect.address_after == action.address())


class ProposalBody(WireModel):
    schema_version: Literal["policyops.action-proposal/v1"] = PROPOSAL_SCHEMA
    proposal_id: UUID
    proposal_version: PositiveVersion
    intent_digest: Sha256Hex
    scope: RunScope
    customer_user_id: UserId
    action: WriteToolCall
    effect: Effect
    presentation: Presentation
    policy: PolicyRef
    rule_ids: Annotated[tuple[Slug, ...], Field(min_length=1, max_length=64)]
    resource_versions: Annotated[tuple[ResourceVersion, ...], Field(min_length=1, max_length=64)]
    evidence: Annotated[tuple[EvidenceRef, ...], Field(max_length=32)] = ()
    rationale: Annotated[str, StringConstraints(min_length=1, max_length=1000)]
    created_at: UtcDatetime
    expires_at: UtcDatetime

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if not within_ttl(self.created_at, self.expires_at):
            raise ValueError("proposal expiry must be after creation and within 15 minutes")
        if not _matches(self.action, self.effect, self.customer_user_id):
            raise ValueError("effect does not describe exactly the proposed call")
        if self.presentation.text != render_effect(self.effect):
            raise ValueError("presentation text is not the server rendering of the effect")
        if self.presentation.text_sha256 != text_sha256(self.presentation.text):
            raise ValueError("presentation digest mismatch")
        keys = [(item.kind, item.resource_id) for item in self.resource_versions]
        if keys != sorted(set(keys)):
            raise ValueError("resource versions must be sorted and unique")
        evidence = [str(item.evidence_id) for item in self.evidence]
        if evidence != sorted(set(evidence)):
            raise ValueError("evidence references must be sorted and unique")
        if list(self.rule_ids) != sorted(set(self.rule_ids)):
            raise ValueError("rule IDs must be sorted and unique")
        target = ("user", self.customer_user_id) if isinstance(self.action, ModifyUserAddress) else (
            "order", self.action.order_id)
        if target not in keys:
            raise ValueError("the target resource version must be bound")
        return self


def proposal_digest(body: ProposalBody) -> str:
    return sha256_hex(canonical_bytes(body, exclude={"action_digest"}))


class ActionProposal(ProposalBody):
    action_digest: Sha256Hex

    @model_validator(mode="after")
    def _digest(self) -> Self:
        if self.action_digest != proposal_digest(self):
            raise ValueError("action_digest does not match the proposal contents")
        return self

    @classmethod
    def seal(cls, body: ProposalBody) -> "ActionProposal":
        return cls.model_validate({**body.model_dump(), "action_digest": proposal_digest(body)})


def presentation_for(effect: Effect) -> Presentation:
    text = render_effect(effect)
    return Presentation(text=text, text_sha256=text_sha256(text))
