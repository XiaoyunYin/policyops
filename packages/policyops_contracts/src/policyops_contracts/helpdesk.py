"""Bounded Zammad wire fields consumed by PolicyOps."""

from typing import Annotated

from pydantic import ConfigDict, Field, StringConstraints

from policyops_contracts.base import WireModel
from policyops_contracts.scalars import UtcDatetime


ExternalId = Annotated[int, Field(ge=1, le=2**53 - 1)]
ConnectionId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,63}$")]


class TicketWakeup(WireModel):
    ticket_id: ExternalId
    updated_at: UtcDatetime


class Ticket(WireModel):
    model_config = ConfigDict(extra="ignore")

    id: ExternalId
    group_id: ExternalId
    customer_id: ExternalId
    state_id: ExternalId
    updated_at: UtcDatetime


class Article(WireModel):
    model_config = ConfigDict(extra="ignore")

    id: ExternalId
    ticket_id: ExternalId
    internal: bool
    created_by_id: ExternalId
    created_at: UtcDatetime
    sender: Annotated[str, Field(min_length=1, max_length=64)]
    content_type: Annotated[str, Field(min_length=1, max_length=128)]
    body: str
