"""The registered upstream `HalfDuplexAgent` factory and adapter over an injected synchronous bridge (T29, offline).

**Imports upstream on load.** The module refuses to load unless upstream's import side effects are disabled
(`PYTHON_DOTENV_DISABLED=1`, `LITELLM_LOCAL_MODEL_COST_MAP=True`), then imports `tau2` eagerly and defines the
agent class at module level. Import it only in a prepared interpreter.

**The factory** `create_policyops_agent(tools, domain_policy, **_ignored)` drops `_ignored` as its first statement:
`task`, `llm`, `llm_args`, audio settings and any future keyword are never read, iterated, compared, hashed,
formatted, logged, serialized or retained. Its run configuration comes from the current `TrialSlot` (a context
variable set by the harness with `trial(slot)`), never from keywords. The upstream tools are read only for their
descriptors (accepted `tools.map_upstream_tools`) and are not retained: the agent passes `tools=[]` to upstream's base
class, which no half-duplex upstream code reads. It keeps no tool, toolkit or environment reference.

**The poison boundary is real `build_agent` plus this factory**: `build_agent` only forwards `task` as a keyword. The
rest of upstream's build path (orchestrator, user simulator, environment, evaluation) reads the Task by design and is
outside this claim.

**The bridge** is an injected synchronous port (`AgentBridge`), a typed fake in tests; the process client is later.
Only contracts DTOs, opaque session IDs, config digests and request sequence numbers cross it.
- The agent owns a caller-made session UUID from before `open` until it is released. Every acquisition, validation,
  deadline or exception path closes that ID once, under the slot's finite cleanup grace and without reading the trial
  clock. A foreign returned ID is never closed, and the primary error is always the one raised.
- Each `user_turn`/`tool_return` carries a monotonically increasing `seq`, echoed by the event. Every event must
  match the request's session, `seq` and (for a `TurnEnded`) the opened config digest and the 0-based user-turn index
  (`TurnOutcome.turn`). A stale or replayed envelope is refused before any upstream action. This is typed fake-port
  correlation, not channel replay proof. A terminal outcome is surfaced as `AgentTerminated` with its own reason and
  `pending_tool`, never as a fabricated message, and the appended transcript is not reconstructed.
- One absolute trial budget: the end, clock readings, margin and grace are validated as finite, and each call gets a
  finite, positive, capped number of seconds. A late return is never turned into an upstream action. Any terminal
  closes the agent permanently.
- One owner thread and a fail-fast non-reentrant guard: a wrong-thread or re-entrant call does no bridge work. A stop
  requested while busy is applied in the outer call's `finally`, and that call then returns no success.

Refusals are fixed `AdapterRefused` codes; raw-data exception chains are suppressed, and diagnostics are bounded fixed
codes. No process, resource or hard-interruption guarantee is claimed.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import math
import os
import re
import threading
from typing import Any, Literal, Protocol
from uuid import UUID, uuid4

from pydantic import ValidationError

from policyops_contracts.conversation import (
    MAX_ENTRIES,
    AgentMessage,
    AgentToolCall,
    PendingToolOutcome,
    PolicyContext,
    TerminalReason,
    ToolCatalog,
    ToolResult,
    TurnOutcome,
    UserMessage,
)
from policyops_contracts.digest import text_sha256
from policyops_contracts.policy import RETAIL_POLICY
from policyops_evals.harness import messages
from policyops_evals.harness.messages import MessageRefused
from policyops_evals.harness.tools import CatalogMapping, CatalogRefused, map_upstream_tools


if os.environ.get("PYTHON_DOTENV_DISABLED") != "1" or \
        os.environ.get("LITELLM_LOCAL_MODEL_COST_MAP", "").lower() != "true":
    raise ImportError("upstream_not_prepared")

from tau2.agent.base_agent import HalfDuplexAgent
from tau2.data_model import message as upstream_message


FACTORY_NAME = "policyops_minimal_v1"
MAX_SECONDS = 900.0
MAX_EVENTS = MAX_ENTRIES  # a conservative per-session event ceiling; model budgets stay the runtime's/T11's
MAX_DIAGNOSTICS = 64
MAX_POLICY_CHARS = 64_000  # the PolicyContext bound
DIGEST = re.compile(r"^[0-9a-f]{64}$")
Domain = Literal["retail", "banking_knowledge"]

AdapterCode = Literal[
    "slot_unavailable", "catalog_refused", "policy_invalid", "state_mismatch", "already_initialized",
    "unsupported_initial_history", "protocol_out_of_order", "multi_tool_message", "wrong_message_type",
    "message_refused", "stale_event", "session_mismatch", "bridge_protocol", "bridge_failed", "clock_invalid",
    "budget_invalid", "agent_closed", "wrong_thread", "reentrant_call", "registration_conflict", "event_limit",
    "not_initialized",
]


class AdapterRefused(Exception):
    """A fixed, content-free refusal at the adapter boundary."""

    def __init__(self, code: AdapterCode) -> None:
        self.code: AdapterCode = code
        super().__init__(code)


class AgentTerminated(Exception):
    """The conversation ended without a customer-facing message (the runtime's terminal, or the trial deadline)."""

    def __init__(self, reason: TerminalReason, detail: str | None = None,
                 pending_tool: PendingToolOutcome | None = None) -> None:
        self.reason: TerminalReason = reason
        self.detail = detail
        self.pending_tool = pending_tool
        super().__init__(reason if detail is None else f"{reason}:{detail}")


# -- the injected bridge (typed fake-port contract; wire frames are a later slice) ---------------------------------

@dataclass(frozen=True)
class OpenSession:
    session_id: UUID          # caller-owned before the call
    policy: PolicyContext
    catalog: ToolCatalog
    opening: AgentMessage


@dataclass(frozen=True)
class SessionOpened:
    session_id: UUID
    config_sha256: str


@dataclass(frozen=True)
class UserTurnRequest:
    session_id: UUID
    seq: int
    turn: int                 # 0-based user-turn index
    message: UserMessage


@dataclass(frozen=True)
class ToolReturnRequest:
    session_id: UUID
    seq: int
    result: ToolResult


@dataclass(frozen=True)
class ToolRequest:
    session_id: UUID
    seq: int                  # echoes the request it answers
    call: AgentToolCall


@dataclass(frozen=True)
class TurnEnded:
    session_id: UUID
    seq: int
    outcome: TurnOutcome


BridgeEvent = ToolRequest | TurnEnded


class AgentBridge(Protocol):
    """Synchronous and injected; each call returns exactly the response to that call. `close` of an unknown or
    never-opened ID must be a harmless no-op. Bridges own their own resources and thread requirements."""

    def open(self, request: OpenSession, *, seconds: float) -> SessionOpened: ...
    def user_turn(self, request: UserTurnRequest, *, seconds: float) -> BridgeEvent: ...
    def tool_return(self, request: ToolReturnRequest, *, seconds: float) -> BridgeEvent: ...
    def close(self, session_id: UUID, *, seconds: float) -> None: ...


# -- the trial slot and budget --------------------------------------------------------------------------------------

def _finite(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        return None
    return float(value)


@dataclass(frozen=True)
class TrialBudget:
    """One absolute budget for the trial: never reset per call. `clock` is a monotonic source."""

    end: float
    clock: Callable[[], float]
    margin: float
    grace: float              # cleanup only: one close attempt, independent of the trial clock

    def __post_init__(self) -> None:
        end, margin, grace = _finite(self.end), _finite(self.margin), _finite(self.grace)
        if end is None or margin is None or grace is None or not callable(self.clock) \
                or not 0.0 <= margin <= 60.0 or not 0.1 <= grace <= 30.0:
            raise AdapterRefused("budget_invalid")


@dataclass
class SlotClaim:
    """The slot's only mutable part: an atomic, permanent single-use claim."""

    lock: threading.Lock = field(default_factory=threading.Lock)
    claimed: bool = False
    claimant: UUID | None = None

    def take(self) -> UUID:
        with self.lock:
            if self.claimed:
                raise AdapterRefused("slot_unavailable")
            self.claimed, self.claimant = True, uuid4()
            return self.claimant


@dataclass(frozen=True)
class TrialSlot:
    """Explicit run configuration for one trial; nothing task-derived. The claim is consumed by one factory call and
    never re-armed by a context reset or re-entry."""

    slot_id: UUID
    domain: Domain
    bridge: AgentBridge
    budget: TrialBudget
    knowledge_tool: bool = False
    claim: SlotClaim = field(default_factory=SlotClaim)


_CURRENT: ContextVar[TrialSlot | None] = ContextVar("policyops_trial_slot", default=None)


@contextmanager
def trial(slot: TrialSlot) -> Iterator[TrialSlot]:
    if type(slot) is not TrialSlot or slot.claim.claimed:
        raise AdapterRefused("slot_unavailable")
    token = _CURRENT.set(slot)
    try:
        yield slot
    finally:
        _CURRENT.reset(token)


# -- the factory ------------------------------------------------------------------------------------------------

def create_policyops_agent(tools: object, domain_policy: object, **_ignored: object) -> PolicyOpsAgent:
    del _ignored  # first statement: hidden keywords (task, llm, ...) are dropped unread
    slot = _CURRENT.get()
    if slot is None:
        raise AdapterRefused("slot_unavailable")
    slot.claim.take()
    if not isinstance(tools, list | tuple):
        raise AdapterRefused("catalog_refused")
    try:
        catalog = map_upstream_tools(tools, knowledge_tool=slot.knowledge_tool)
    except CatalogRefused:
        raise AdapterRefused("catalog_refused") from None
    return PolicyOpsAgent(catalog, _policy_context(domain_policy, slot.domain), slot)


def _policy_context(text: object, domain: Domain) -> PolicyContext:
    if type(text) is not str or not 1 <= len(text) <= MAX_POLICY_CHARS:  # bounded before any encode or hash
        raise AdapterRefused("policy_invalid")
    try:
        digest = text_sha256(text)
        source: Literal["pinned_retail_policy", "harness_domain_policy"] = (
            "pinned_retail_policy" if domain == "retail" and digest == RETAIL_POLICY.sha256
            else "harness_domain_policy")
        return PolicyContext(domain=domain, source=source, text=text, sha256=digest)
    except (ValidationError, UnicodeEncodeError):
        raise AdapterRefused("policy_invalid") from None


def register(registry: Any = None, name: str = FACTORY_NAME) -> None:
    """Idempotent only for this very factory; any other factory under the name refuses (fail closed)."""
    if registry is None:
        from tau2.registry import registry as default_registry
        registry = default_registry
    existing = registry.get_agent_factory(name)
    if existing is create_policyops_agent:
        return
    if existing is not None:
        raise AdapterRefused("registration_conflict")
    registry.register_agent_factory(create_policyops_agent, name)


# -- the agent ---------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class _State:
    session_id: UUID
    step: int


def _slug(error: BaseException) -> str:
    return re.sub(r"[^a-z0-9_]", "", type(error).__name__.lower())[:40] or "error"


class PolicyOpsAgent(HalfDuplexAgent):  # type: ignore[misc]  # upstream ships no type information
    def __init__(self, catalog: CatalogMapping, policy: PolicyContext, slot: TrialSlot) -> None:
        super().__init__(tools=[], domain_policy=policy.text)  # descriptors only; no upstream Tool is retained
        self._catalog, self._policy, self._slot = catalog, policy, slot
        self._bridge, self._budget = slot.bridge, slot.budget
        self._owner = threading.get_ident()
        self._busy = False
        self._stop_requested = False
        self._dead = False
        self._initialized = False
        self._owned: UUID | None = None      # the session this agent must release
        self._session: UUID | None = None
        self._config: str | None = None
        self._expected: _State | None = None
        self._pending: str | None = None      # the call ID awaiting its upstream ToolMessage
        self._seq = 0
        self._turn = -1                       # 0-based index of the user turn in flight
        self._events = 0
        self.seed: int | None = None
        self.diagnostics: list[tuple[str, str | None]] = []
        self.diagnostics_dropped = 0

    # -- guards and bookkeeping ----------------------------------------------------------------------------------

    def _diag(self, code: str, detail: str | None = None) -> None:
        if len(self.diagnostics) < MAX_DIAGNOSTICS:
            self.diagnostics.append((code, detail))
        else:
            self.diagnostics_dropped += 1

    def _now(self) -> float:
        try:
            now = _finite(self._budget.clock())
        except Exception:  # a broken clock is refused as such; cleanup never reads it
            now = None
        if now is None:
            raise AdapterRefused("clock_invalid")
        return now

    def _seconds(self) -> float:
        seconds = self._budget.end - self._now() - self._budget.margin
        if not math.isfinite(seconds):
            raise AdapterRefused("clock_invalid")
        if seconds <= 0:
            raise AgentTerminated("deadline", "trial_budget_exhausted")
        return min(seconds, MAX_SECONDS)

    def _late(self) -> bool:
        return self._now() >= self._budget.end

    def _release(self) -> None:
        """Close the owned session once, under the finite grace, without reading the trial clock."""
        self._dead = True
        session, self._owned = self._owned, None
        if session is None:
            return
        try:
            self._bridge.close(session, seconds=self._budget.grace)
        except BaseException as error:  # cleanup must neither replace the primary error nor escape stop
            self._diag("close_failed", _slug(error))

    def _guarded(self, work: Callable[[], Any]) -> Any:
        if threading.get_ident() != self._owner:
            raise AdapterRefused("wrong_thread")
        if self._busy:
            raise AdapterRefused("reentrant_call")
        if self._dead:
            raise AdapterRefused("agent_closed")
        self._busy = True
        try:
            result = work()
        except (AdapterRefused, AgentTerminated):
            self._release()
            raise
        except Exception as error:  # an unexpected local failure: released, fixed code, raw chain suppressed
            self._diag("internal_error", _slug(error))
            self._release()
            raise AdapterRefused("bridge_failed") from None
        except BaseException:
            self._release()
            raise
        finally:
            self._busy = False
        if self._stop_requested:  # a stop arrived while busy: released, and no success is returned
            self._release()
            raise AdapterRefused("agent_closed")
        return result

    def _port(self, call: Callable[[], Any], kind: str) -> Any:
        """One bridge call; a late return is never accepted."""
        try:
            result = call()
        except Exception as error:  # including a port-raised AdapterRefused/AgentTerminated: never trusted
            self._diag("bridge_failed", _slug(error))
            raise AdapterRefused("bridge_failed") from None
        if self._late():  # the adapter's own deadline check, outside the port-exception translation
            self._diag("late_result", kind)
            raise AgentTerminated("deadline", "late_bridge_result")
        return result

    # -- upstream half-duplex API ---------------------------------------------------------------------------------

    def get_init_state(self, message_history: Sequence[Any] | None = None) -> _State:
        state: _State = self._guarded(lambda: self._init(message_history))
        return state

    def _init(self, message_history: Sequence[Any] | None) -> _State:
        if self._initialized:
            raise AdapterRefused("already_initialized")
        self._initialized = True
        history: object = [] if message_history is None else message_history
        if type(history) not in (list, tuple) or len(history) != 1:  # type: ignore[arg-type]
            self._diag("message_refused", "unsupported_initial_history")  # refused before any copy or iteration
            raise AdapterRefused("unsupported_initial_history")
        try:
            opening = messages.opening_from_history(history)
        except MessageRefused as refused:
            self._diag("message_refused", refused.code)
            raise AdapterRefused("unsupported_initial_history") from None
        seconds = self._seconds()
        session = uuid4()
        self._owned = session  # owned from acquisition: every later failure closes it
        opened = self._port(lambda: self._bridge.open(
            OpenSession(session, self._policy, self._catalog.catalog, opening), seconds=seconds), "opened")
        if type(opened) is not SessionOpened:
            raise AdapterRefused("bridge_protocol")
        if type(opened.session_id) is not UUID or opened.session_id != session:
            self._diag("foreign_session_returned")  # never closed: not ours
            raise AdapterRefused("session_mismatch")
        if type(opened.config_sha256) is not str or not DIGEST.fullmatch(opened.config_sha256):
            raise AdapterRefused("bridge_protocol")
        self._session, self._config = session, opened.config_sha256
        self._expected = _State(session, 0)
        return self._expected

    def generate_next_message(self, message: Any, state: Any) -> tuple[Any, _State]:
        result: tuple[Any, _State] = self._guarded(lambda: self._next(message, state))
        return result

    def _next(self, message: Any, state: Any) -> tuple[Any, _State]:
        expected, session = self._expected, self._session
        if expected is None or session is None:
            raise AdapterRefused("not_initialized")
        if state is not expected:
            raise AdapterRefused("state_mismatch")
        if self._events >= MAX_EVENTS:
            raise AdapterRefused("event_limit")
        seq = self._seq + 1
        kind = type(message)
        if kind is upstream_message.UserMessage:
            if self._pending is not None:
                raise AdapterRefused("protocol_out_of_order")
            text = self._message(lambda: messages.user_message(message))
            turn = self._turn + 1
            seconds = self._seconds()
            event = self._port(lambda: self._bridge.user_turn(
                UserTurnRequest(session, seq, turn, text), seconds=seconds), "user_turn")
        elif kind is upstream_message.ToolMessage:
            if self._pending is None:
                raise AdapterRefused("protocol_out_of_order")
            pending = self._pending
            result = self._message(lambda: messages.tool_result(message, pending))
            turn = self._turn
            seconds = self._seconds()
            event = self._port(lambda: self._bridge.tool_return(
                ToolReturnRequest(session, seq, result), seconds=seconds), "tool_return")
        elif kind is upstream_message.MultiToolMessage:
            raise AdapterRefused("multi_tool_message")
        else:
            raise AdapterRefused("wrong_message_type")
        reply, pending_after = self._accept(event, seq, turn)
        # Commit only after a fully validated event: invalid results never advance the state or counters.
        self._seq, self._turn, self._pending, self._events = seq, turn, pending_after, self._events + 1
        self._expected = _State(session, expected.step + 1)
        return reply, self._expected

    def _message(self, convert: Callable[[], Any]) -> Any:
        try:
            return convert()
        except MessageRefused as refused:
            self._diag("message_refused", refused.code)
            raise AdapterRefused("message_refused") from None

    def _accept(self, event: object, seq: int, turn: int) -> tuple[Any, str | None]:
        if type(event) not in (ToolRequest, TurnEnded):
            raise AdapterRefused("bridge_protocol")
        assert isinstance(event, ToolRequest | TurnEnded)  # noqa: S101 - narrowed by the exact type check
        if type(event.session_id) is not UUID or event.session_id != self._session:
            raise AdapterRefused("session_mismatch")
        if type(event.seq) is not int or event.seq != seq:
            raise AdapterRefused("stale_event")
        if isinstance(event, ToolRequest):  # exact type already checked above
            call = self._revalidated(event.call, AgentToolCall)
            reply = self._message(lambda: messages.assistant_tool_call(call, self._catalog))
            return reply, call.call_id
        outcome = self._revalidated(event.outcome, TurnOutcome)
        if outcome.conversation_id != self._session or outcome.config_sha256 != self._config \
                or outcome.turn != turn:
            raise AdapterRefused("stale_event")
        if outcome.terminal is not None:
            raise AgentTerminated(outcome.terminal, outcome.detail, outcome.pending_tool)
        assert outcome.message is not None  # noqa: S101 - TurnOutcome: exactly one of message / terminal
        said = outcome.message
        return self._message(lambda: messages.assistant_text(said)), None

    @staticmethod
    def _revalidated(value: object, model: Any) -> Any:
        if type(value) is not model:
            raise AdapterRefused("bridge_protocol")
        try:  # a constructed-without-validation object cannot skip its validators
            return model.model_validate_json(value.model_dump_json())  # type: ignore[attr-defined]
        except Exception:  # any malformed object (missing attributes included) is a protocol violation
            raise AdapterRefused("bridge_protocol") from None

    def is_stop(self, message: Any) -> bool:
        return False

    def set_seed(self, seed: int) -> None:
        if isinstance(seed, int) and not isinstance(seed, bool):
            self.seed = seed  # recorded only: providers are not seeded
        else:
            self._diag("seed_invalid")

    def stop(self, message: Any = None, state: Any = None) -> None:
        """Idempotent; uses only agent-owned fields (never the caller's state) and never raises."""
        if threading.get_ident() != self._owner:
            self._diag("stop_wrong_thread")
            return
        if self._busy:
            self._stop_requested = True
            return
        self._release()
