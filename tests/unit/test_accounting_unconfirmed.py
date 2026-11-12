"""Known provider usage remains reachable after SQL accounting fails; no retry or release follows."""

import asyncio
import time
from typing import Any
from uuid import uuid4

import pytest

from policyops.budget.ledger import RunBinding
from policyops.persistence.database import DatabaseUnavailable, TransactionOutcomeUnknown
from policyops.providers.accounting import AccountingUnconfirmed
from policyops.providers.calls import CallLimits, call
from policyops_testing.retrieval_fixtures import Scripted, count_reply, luna_reply
from tests.unit.test_provider_call_grants import REQUEST, Books


@pytest.mark.parametrize("failure", [DatabaseUnavailable("body", "55P03"), TransactionOutcomeUnknown()])
def test_settlement_failure_retains_usage_request_id_and_cleanup_and_stops(failure: Exception) -> None:
    class Failing(Books):
        def settle(self, attempt_id: Any, settlement: Any) -> None:
            super().settle(attempt_id, settlement)
            raise failure

    ledger = Failing()
    transport = Scripted(counts=[count_reply(1200)], creates=[luna_reply('{"decision":"a"}')])
    with pytest.raises(AccountingUnconfirmed) as stopped:
        asyncio.run(call(ledger, transport.providers()(), RunBinding(uuid4()), uuid4(), "accounting",  # type: ignore[arg-type]
                         REQUEST, "agent", deadline=time.monotonic() + 30, limits=CallLimits()))
    record, = stopped.value.report.attempts
    assert record.evidence is not None and record.evidence.usage is not None
    assert record.evidence.usage.input_total == 900 and record.evidence.provider_request_id is not None
    assert record.cleanup_confirmed is True and record.fate is None
    assert ledger.log.count("settle") == 1 and "release" not in ledger.log and "mark_unresolved" not in ledger.log
    assert transport.seen == ["count", "create"]


def test_lost_dispatch_commit_acknowledgement_never_sends_or_releases() -> None:
    class Failing(Books):
        def begin_dispatch(self, *args: Any, **kwargs: Any) -> Any:
            super().begin_dispatch(*args, **kwargs)
            raise TransactionOutcomeUnknown()

    ledger = Failing()
    transport = Scripted(counts=[count_reply(1200)])
    with pytest.raises(TransactionOutcomeUnknown):
        asyncio.run(call(ledger, transport.providers()(), RunBinding(uuid4()), uuid4(), "dispatch",  # type: ignore[arg-type]
                         REQUEST, "agent", deadline=time.monotonic() + 30))
    assert transport.seen == ["count"] and "release" not in ledger.log and "mark_unresolved" not in ledger.log
