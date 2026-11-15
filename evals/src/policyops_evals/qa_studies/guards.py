"""Sealed infrastructure protection. Local probes are synthetic, never paid.

A CE use gets one replacement process, including health and score failures.
No retries of paid calls. Streaks count uses across intervening other work.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
import time
from typing import Protocol

from policyops_evals.qa_studies.cross_encoder import CrossEncoderClient, Passage, Response, WorkerError


class Client(Protocol):
    def rerank(self, query: str, passages: Sequence[Passage], *, top_k: int) -> Response: ...


class HealthyWorker:
    def __init__(self, factory: Callable[[float], CrossEncoderClient]) -> None:
        self.factory = factory
        self.client: CrossEncoderClient | None = None
        self.deadline = 0.0

    def rerank(self, query: str, passages: Sequence[Passage], *, top_k: int) -> Response:
        for attempt in range(2):
            try:
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise WorkerError("worker_deadline")
                if self.client is None:
                    self.client = self.factory(remaining)
                self.client.timeout = min(remaining, 600)
                self.client.rerank("health", [Passage(id="health", text="health")], top_k=1)
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise WorkerError("worker_deadline")
                self.client.timeout = min(remaining, 600)
                return self.client.rerank(query, passages, top_k=top_k)
            except WorkerError:
                if self.client is not None:
                    # Unconfirmed cleanup stops replacement; no orphaned workers.
                    self.client.close()
                    self.client = None
                if attempt:
                    raise
        raise AssertionError("unreachable")


@dataclass
class Streaks:
    ce: int = 0
    provider: dict[str, int] = field(default_factory=dict)

    def observe_ce(self, failed: bool) -> None:
        self.ce = self.ce + 1 if failed else 0

    def observe_provider(self, failed: bool, channel: str = "provider") -> None:
        self.provider[channel] = self.provider.get(channel, 0) + 1 if failed else 0

    def reason(self) -> str | None:
        return ("consecutive_ce_failures" if self.ce >= 3 else
                "consecutive_provider_failures" if any(n >= 3 for n in self.provider.values()) else None)


