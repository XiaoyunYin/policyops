"""Fictional T29 tests: real budget rules, memory storage, SDK mock transport.

The store is not evidence of PostgreSQL properties (Slice B owns those checks).
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
import json
import threading
from typing import Any, cast
from uuid import UUID, uuid4

import httpx2
from pydantic import SecretStr

from policyops.budget.config import DEFAULT_ACTORS, Caps, ChatActor, Configuration
from policyops.budget.ledger import Attempt, Binding, EvalBinding, Ledger, Scope, ScopeKind, ScopeRef, Settlement
from policyops.providers.calls import Providers


CANARY = "FICTIONAL-HIDDEN-T29-724d"


class MemoryStore:
    def __init__(self, binding: EvalBinding, *, calls: int = 20) -> None:
        self.refs = tuple(ScopeRef.of(cast(ScopeKind, kind), scope) for kind, scope in
            (("study", binding.study_id), ("invocation", binding.invocation_id), ("scenario", binding.scenario_id)))
        self.scopes = {ref.id: Scope(ref.id, ref.kind, Decimal("0.30"), calls, Decimal(0), Decimal(0), 0, 0,
                                    False, cap_counts=calls) for ref in self.refs}
        self.attempts: dict[UUID, Attempt] = {}
        self.lock = threading.Lock()

    @contextmanager
    def transaction(self) -> Iterator[Any]:
        with self.lock:
            scopes, attempts = self.scopes.copy(), self.attempts.copy()
            try:
                yield self
            except BaseException:
                self.scopes, self.attempts = scopes, attempts
                raise

    def now(self) -> datetime:
        return datetime.now(UTC)

    def bind(self, binding: Binding, caps: Caps) -> tuple[ScopeRef, ...]:
        assert isinstance(binding, EvalBinding)
        assert {binding.study_id, binding.invocation_id, binding.scenario_id} == set(self.scopes)
        return self.refs

    def attempt_refs(self, attempt_id: UUID) -> tuple[ScopeRef, ...] | None:
        return self.refs if attempt_id in self.attempts else None

    def run_active(self, refs: Sequence[ScopeRef]) -> bool:
        return True

    def check_admission(self, refs: Sequence[ScopeRef]) -> None:
        pass

    def lock_scopes(self, refs: Sequence[ScopeRef]) -> list[Scope]:
        return [self.scopes[ref.id] for ref in refs]

    def lock_attempt(self, attempt_id: UUID) -> Attempt | None:
        return self.attempts.get(attempt_id)

    def insert_attempt(self, attempt: Attempt, now: datetime) -> None:
        assert attempt.id not in self.attempts
        self.attempts[attempt.id] = attempt

    def update_attempt(self, attempt: Attempt, now: datetime, settlement: Settlement | None = None) -> None:
        self.attempts[attempt.id] = attempt

    def update_scope(self, scope: Scope, now: datetime) -> None:
        self.scopes[scope.id] = scope

    def record_usage(self, attempt: Attempt, settlement: Settlement, now: datetime) -> None:
        pass


def books(*, calls: int = 20) -> tuple[Ledger, EvalBinding, MemoryStore]:
    binding = EvalBinding(uuid4(), uuid4(), uuid4())
    store = MemoryStore(binding, calls=calls)
    config = Configuration(actors={**DEFAULT_ACTORS, "judge": ChatActor("judge", "gpt-6-luna", "low")},
                           caps=replace(Caps(), scenario_calls=calls, invocation_calls=calls, study_calls=calls))
    return Ledger(store, config), binding, store


class Routes(httpx2.AsyncBaseTransport):
    def __init__(self, outputs: list[Any]) -> None:
        self.outputs = outputs.copy()
        self.seen: list[dict[str, Any]] = []
        self.closed = 0

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(await request.aread())
        count = request.url.path.endswith("input_tokens")
        self.seen.append({"kind": "count" if count else "create", "body": body})
        if count:
            data: Any = {"object": "response.input_tokens", "input_tokens": 900}
        else:
            assert self.outputs, "unscripted provider call"
            output = self.outputs.pop(0)
            if isinstance(output, BaseException):
                raise output
            if callable(output):
                return cast(httpx2.Response, await output(request))
            data = {"id": "resp_" + uuid4().hex, "object": "response", "model": "gpt-6-luna",
                "status": "completed", "service_tier": "default",
                "usage": {"input_tokens": 900, "input_tokens_details": {"cached_tokens": 0,
                    "cache_write_tokens": 0}, "output_tokens": 40,
                    "output_tokens_details": {"reasoning_tokens": 8}, "total_tokens": 940},
                "output": output if isinstance(output, list) else [{"type": "message", "role": "assistant",
                    "content": [{"type": "output_text", "text": output, "annotations": []}]}]}
        return httpx2.Response(200, headers={"content-type": "application/json"}, content=json.dumps(data).encode(),
                               request=request)

    async def aclose(self) -> None:
        self.closed += 1

    def providers(self) -> Providers:
        return Providers(credentials={"openai": SecretStr("synthetic-t29-credential-0000")}, transport=lambda _: self)


def tool(name: str, arguments: dict[str, Any], call_id: str = "call_t29") -> list[dict[str, Any]]:
    return [{"type": "function_call", "id": "fc_t29", "call_id": call_id,
             "name": name, "arguments": json.dumps(arguments)}]


def judgement(expected: str = "The agent confirmed the address change.", met: bool = True) -> str:
    return json.dumps({"results": [{"expectedOutcome": expected, "metExpectation": met,
                                    "reasoning": "Fictional scripted judgement."}]})
