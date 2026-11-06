"""The agent channel's wire contract (T29): typed frames, a strict canonical bounded codec, and a pure checker.

Only this module's frames cross the agent channel between the evaluator's process client and the app's agent
runtime; both import it, and it imports only the standard library, pydantic and `policyops_contracts`. There is no
I/O here: reading is over an injected exact reader, and the checker is a pure state machine.

**Frames** (`v = "policyops.wire/v1"`, `channel = "agent"`) are strict, frozen, extra-forbidding models. The two
directions are disjoint unions (`ToRuntime`, `FromRuntime`). Every leaf is an existing bounded conversation DTO or a
bounded scalar; budgets are integer milliseconds, so frames hold no floats, dicts or `Any`. No protocol field exists
for a URL, command, path, header, query or credential. Visible content (policy, user text, tool content, agent text,
embedded tool-schema text) can still hold any characters within its bounds: what a frame carries is visible DTO
content by trusted construction, which no schema walk can prove.

**Framing:** a 4-byte unsigned big-endian payload length (bound to wire v1), then the canonical JSON payload
(`digest.canonical_bytes`). The length only delimits a frame; neither it nor canonical identity provides
authentication, integrity against a malicious peer or confidentiality.

**Decoding, each step bounded before the next allocates:** the header is checked against the 4 MiB cap before the
payload is requested; strict UTF-8; one non-allocating pre-scan (depth, value nodes, raw string length, integer digit
runs, no floats) before any JSON structure exists; stdlib parsing for duplicate keys and non-finite values; strict
pydantic validation; and canonical identity (the payload must be exactly the canonical bytes of the validated frame).

**Encoding** walks the frame first, before any `model_dump`: only the exact whitelisted envelope, body and
conversation DTO classes and bounded primitives, UUIDs, tuples and lists are accepted; field sets must be exact;
cycles, breadth, depth, node count, oversized integers (checked before any decimal conversion) and the **aggregate**
canonical byte count are bounded, with repeated references counted every time they would be serialized. Only then is
the frame serialized, size-checked and round-trip decoded, so every validator runs on what is sent.

**Work:** the pre-scan, UTF-8 decoding, the stdlib scanner, pydantic-core parsing and regex, and the DTOs' own
validators are linear in the capped size; canonical re-encoding sorts keys per object (O(k log k) each). Memory is a
bounded multiple of the cap. Synchronous CPU work cannot be interrupted by a timeout: the caps are the control, and
no timing is claimed.

**Refusals** are fixed `WireRefused` codes raised without any exception chain, so no payload reaches a message.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
import re
import types
from typing import Annotated, Any, Literal, Union, get_args, get_origin
from uuid import UUID

from pydantic import BaseModel, Field, ValidationError

from policyops_contracts.base import WireModel
from policyops_contracts.conversation import (
    AgentMessage,
    AgentToolCall,
    PendingToolOutcome,
    PolicyContext,
    RuntimeNotice,
    ToolCatalog,
    ToolDescriptor,
    ToolResult,
    TurnOutcome,
    UserMessage,
)
from policyops_contracts.digest import canonical_bytes
from policyops_contracts.scalars import Sha256Hex


WIRE_VERSION = "policyops.wire/v1"
HEADER_BYTES = 4
MAX_FRAME_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 32
MAX_NODES = 20_000
MAX_RAW_STRING = 400_000          # policy text (64,000 characters) fully escaped as \uXXXX is 384,000
MAX_DIGITS = 19
MAX_SEQ = 2**31 - 1
MAX_INT = 2**63                   # no frame integer comes close; checked before any decimal conversion

Seq = Annotated[int, Field(ge=1, le=MAX_SEQ)]
BudgetMs = Annotated[int, Field(ge=1, le=900_000)]
TurnIndex = Annotated[int, Field(ge=0, le=MAX_SEQ)]

RefusedCode = Literal["protocol", "session_unknown", "session_exists", "frame_invalid", "frame_too_large",
                      "budget_exhausted", "configuration_refused", "internal_error"]
WireRefusedCode = Literal[
    "header_invalid", "frame_too_large", "frame_truncated", "not_utf8", "too_deep", "too_many_nodes",
    "string_too_long", "number_too_long", "float_number", "non_finite", "duplicate_key", "malformed_json",
    "frame_invalid", "frame_not_canonical", "encode_invalid", "direction_mismatch", "channel_mismatch",
    "session_mismatch", "sequence_mismatch", "reply_mismatch", "unexpected_body", "config_mismatch",
    "connection_closed",
]


class WireRefused(ValueError):
    """A fixed, content-free wire refusal."""

    def __init__(self, code: WireRefusedCode) -> None:
        self.code: WireRefusedCode = code
        super().__init__(code)


# -- frames -------------------------------------------------------------------------------------------------------

class OpenSessionBody(WireModel):
    kind: Literal["open_session"] = "open_session"
    policy: PolicyContext
    catalog: ToolCatalog
    opening: AgentMessage
    budget_ms: BudgetMs


class UserTurnBody(WireModel):
    kind: Literal["user_turn"] = "user_turn"
    turn: TurnIndex
    message: UserMessage
    budget_ms: BudgetMs


class ToolReturnBody(WireModel):
    kind: Literal["tool_return"] = "tool_return"
    result: ToolResult
    budget_ms: BudgetMs


class CloseSessionBody(WireModel):
    kind: Literal["close_session"] = "close_session"
    budget_ms: BudgetMs


class SessionOpenedBody(WireModel):
    kind: Literal["session_opened"] = "session_opened"
    config_sha256: Sha256Hex


class ToolRequestBody(WireModel):
    kind: Literal["tool_request"] = "tool_request"
    call: AgentToolCall


class TurnEndedBody(WireModel):
    kind: Literal["turn_ended"] = "turn_ended"
    outcome: TurnOutcome


class SessionClosedBody(WireModel):
    kind: Literal["session_closed"] = "session_closed"


class RefusedBody(WireModel):
    kind: Literal["refused"] = "refused"
    code: RefusedCode


ToRuntimeBody = Annotated[OpenSessionBody | UserTurnBody | ToolReturnBody | CloseSessionBody,
                          Field(discriminator="kind")]
FromRuntimeBody = Annotated[SessionOpenedBody | ToolRequestBody | TurnEndedBody | SessionClosedBody | RefusedBody,
                            Field(discriminator="kind")]
TO_RUNTIME_KINDS = frozenset({"open_session", "user_turn", "tool_return", "close_session"})
FROM_RUNTIME_KINDS = frozenset({"session_opened", "tool_request", "turn_ended", "session_closed", "refused"})


class ToRuntime(WireModel):
    """A request from the evaluator's client to the agent runtime."""

    v: Literal["policyops.wire/v1"] = "policyops.wire/v1"
    channel: Literal["agent"] = "agent"
    session_id: UUID
    seq: Seq
    body: ToRuntimeBody


class FromRuntime(WireModel):
    """A reply from the agent runtime; `reply_to` is the request's `seq`."""

    v: Literal["policyops.wire/v1"] = "policyops.wire/v1"
    channel: Literal["agent"] = "agent"
    session_id: UUID
    seq: Seq
    reply_to: Seq
    body: FromRuntimeBody


Frame = ToRuntime | FromRuntime
ALLOWED_REPLIES: dict[str, frozenset[str]] = {
    "open_session": frozenset({"session_opened", "refused"}),
    "user_turn": frozenset({"tool_request", "turn_ended", "refused"}),
    "tool_return": frozenset({"tool_request", "turn_ended", "refused"}),
    "close_session": frozenset({"session_closed", "refused"}),
}

# The exact classes an encoded frame may contain (no subclass, no other model).
WHITELIST: frozenset[type[BaseModel]] = frozenset({
    ToRuntime, FromRuntime, OpenSessionBody, UserTurnBody, ToolReturnBody, CloseSessionBody, SessionOpenedBody,
    ToolRequestBody, TurnEndedBody, SessionClosedBody, RefusedBody, PolicyContext, ToolCatalog, ToolDescriptor,
    AgentMessage, UserMessage, ToolResult, AgentToolCall, TurnOutcome, PendingToolOutcome, RuntimeNotice,
})


# -- encode: bounded aggregate accounting before any serialization -------------------------------------------------

Allowed = tuple[frozenset[type], frozenset[type] | None]  # (value types, tuple item types)
_ALLOWED: dict[tuple[type, str], Allowed] = {}


def _types(annotation: Any) -> Allowed:
    """The exact Python types a declared field may hold (and, for a tuple, its items), from the annotation."""
    origin = get_origin(annotation)
    if origin is Annotated:
        return _types(get_args(annotation)[0])
    if origin is Union or origin is types.UnionType:
        values: set[type] = set()
        items: set[type] = set()
        for arg in get_args(annotation):
            value_types, item_types = _types(arg)
            values |= value_types
            items |= item_types or set()
        return frozenset(values), frozenset(items) or None
    if origin is Literal:
        return frozenset(type(arg) for arg in get_args(annotation)), None
    if origin is tuple:
        args = get_args(annotation)
        if len(args) != 2 or args[1] is not Ellipsis:
            raise TypeError("only homogeneous tuples are supported")
        return frozenset({tuple}), _types(args[0])[0]
    if annotation is type(None) or annotation is None:
        return frozenset({type(None)}), None
    if annotation in (str, int, bool, UUID) or annotation in WHITELIST:
        return frozenset({annotation}), None
    raise TypeError(f"unsupported field annotation {annotation!r}")


def _field_types(model: type[BaseModel], name: str) -> Allowed:
    key = (model, name)
    if key not in _ALLOWED:
        _ALLOWED[key] = _types(model.model_fields[name].annotation)
    return _ALLOWED[key]

def _string_bytes(value: str, cache: dict[int, int]) -> int:
    """Canonical JSON byte length of one string (quotes and escapes included), computed once per string object."""
    known = cache.get(id(value))
    if known is not None:
        return known
    try:
        size = len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
    except UnicodeEncodeError:  # an unpaired surrogate is not representable
        raise WireRefused("encode_invalid") from None
    cache[id(value)] = size
    return size


def account(frame: object) -> int:
    """The exact canonical byte length of `frame`, refused early on any shape or bound violation. Iterative; every
    reference is counted each time it would be serialized; containers are length-checked before their items are
    pushed; nothing is serialized beyond one bounded temporary per distinct string."""
    if type(frame) not in (ToRuntime, FromRuntime):
        raise WireRefused("encode_invalid")
    total, nodes = 0, 0
    strings: dict[int, int] = {}
    # (value, depth, ancestor ids, the exact types this position may hold, the item types if it is a tuple)
    stack: list[tuple[object, int, frozenset[int], frozenset[type], frozenset[type] | None]] = [
        (frame, 1, frozenset(), frozenset({type(frame)}), None)]
    while stack:
        value, depth, ancestors, allowed, item_types = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise WireRefused("too_many_nodes")
        if depth > MAX_DEPTH:
            raise WireRefused("too_deep")
        kind = type(value)
        if kind not in allowed and not (kind is list and tuple in allowed):  # a constructed list stands for a tuple
            raise WireRefused("encode_invalid")  # e.g. a str where a UUID is declared, a dict, a float
        if kind is str:
            text: str = value  # type: ignore[assignment]
            if len(text) > MAX_RAW_STRING:
                raise WireRefused("string_too_long")
            if total + len(text) + 2 > MAX_FRAME_BYTES:  # a lower bound: refuse before encoding the string
                raise WireRefused("frame_too_large")
            total += _string_bytes(text, strings)
        elif kind is bool:
            total += 4 if value else 5
        elif kind is int:
            number: int = value  # type: ignore[assignment]
            if not -MAX_INT < number < MAX_INT:  # compared, never converted to decimal first
                raise WireRefused("number_too_long")
            total += len(str(number))
        elif value is None:
            total += 4
        elif kind is UUID:
            total += 38
        elif kind is tuple or kind is list:
            items: tuple[object, ...] | list[object] = value  # type: ignore[assignment]
            if id(items) in ancestors:
                raise WireRefused("encode_invalid")
            if len(items) > MAX_NODES - nodes:  # breadth checked before anything is pushed
                raise WireRefused("too_many_nodes")
            total += 2 + max(len(items) - 1, 0)
            inner = ancestors | {id(items)}
            child_types = item_types or frozenset()
            stack.extend((item, depth + 1, inner, child_types, None) for item in items)
        elif kind in WHITELIST:
            model: BaseModel = value  # type: ignore[assignment]
            if id(model) in ancestors:
                raise WireRefused("encode_invalid")
            fields = kind.model_fields
            data = model.__dict__
            extra = model.__pydantic_extra__
            if type(data) is not dict or len(data) != len(fields) or extra is not None:  # O(1), before any key
                raise WireRefused("encode_invalid")
            for name in fields:  # bounded by the declared (trusted) field count
                if name not in data:
                    raise WireRefused("encode_invalid")
            nodes += len(fields)  # keys count as nodes, as the decoder's pre-scan counts them
            total += 2 + max(len(fields) - 1, 0) + sum(len(name) + 3 for name in fields)  # {}, commas, "k":
            inner = ancestors | {id(model)}
            try:
                declared = [(name, *_field_types(kind, name)) for name in fields]
            except TypeError:  # pragma: no cover - every whitelisted field annotation is supported
                raise WireRefused("encode_invalid") from None
            stack.extend((data[name], depth + 1, inner, value_types, items_of)
                         for name, value_types, items_of in declared)
        else:
            raise WireRefused("encode_invalid")  # floats, dicts, bytes, arbitrary objects and other models
        if total > MAX_FRAME_BYTES:
            raise WireRefused("frame_too_large")
    return total


def encode_payload(frame: Frame) -> bytes:
    """Canonical payload bytes: bounded accounting first, then serialization, size and a strict round trip."""
    expected = account(frame)
    try:
        payload = canonical_bytes(frame)
    except Exception:  # a constructed-invalid value that cannot even serialize
        raise WireRefused("encode_invalid") from None
    if not 1 <= len(payload) <= MAX_FRAME_BYTES or len(payload) != expected:
        raise WireRefused("frame_too_large" if len(payload) > MAX_FRAME_BYTES else "encode_invalid")
    try:
        decoded: Frame = (decode_payload(payload, ToRuntime) if type(frame) is ToRuntime
                          else decode_payload(payload, FromRuntime))
    except WireRefused:
        raise WireRefused("encode_invalid") from None
    if decoded != frame:
        raise WireRefused("encode_invalid")
    return payload


def encode_frame(frame: Frame) -> bytes:
    payload = encode_payload(frame)
    return len(payload).to_bytes(HEADER_BYTES, "big") + payload


# -- decode ---------------------------------------------------------------------------------------------------------

_OUTSIDE = re.compile(
    r'[ \t\r\n]*(?:([{\[])|([}\]])|([,:])|(")|(-?[0-9]+)([.eE]?)|(true|false|null)|(NaN|-?Infinity)|(.))', re.S)
_IN_STRING = re.compile(r'["\\]')


def prescan(text: str) -> None:
    """One non-allocating pass before any JSON structure exists: depth, value nodes, raw string lengths, integer digit
    runs and floats. Escape validity is left to the parser (a malformed escape is `malformed_json`)."""
    position, depth, nodes, end = 0, 0, 0, len(text)
    while position < end:
        match = _OUTSIDE.match(text, position)
        if match is None or match.end() == position:  # trailing whitespace only
            break
        position = match.end()
        opener, closer, _separator, quote, digits, fraction, literal, constant, other = match.groups()
        if opener is not None:
            depth += 1
            nodes += 1
            if depth > MAX_DEPTH:
                raise WireRefused("too_deep")
        elif closer is not None:
            depth -= 1
        elif quote is not None:
            nodes += 1
            start = position
            while True:
                found = _IN_STRING.search(text, position)
                if found is None:
                    raise WireRefused("malformed_json")
                if found.group() == "\\":
                    position = found.end() + 1
                    continue
                position = found.end()
                break
            if position - start - 1 > MAX_RAW_STRING:
                raise WireRefused("string_too_long")
        elif digits is not None:
            nodes += 1
            if fraction:
                raise WireRefused("float_number")
            if len(digits.lstrip("-")) > MAX_DIGITS:
                raise WireRefused("number_too_long")
        elif literal is not None:
            nodes += 1
        elif constant is not None:
            raise WireRefused("non_finite")
        elif other is not None:
            if other in ".eE":
                raise WireRefused("float_number")
            raise WireRefused("malformed_json")
        if nodes > MAX_NODES:
            raise WireRefused("too_many_nodes")


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WireRefused("duplicate_key")
        result[key] = value
    return result


def _constant(name: str) -> object:
    raise WireRefused("non_finite")


def _float(text: str) -> object:
    raise WireRefused("float_number")


def decode_payload[F: (ToRuntime, FromRuntime)](payload: bytes, model: type[F]) -> F:
    """Strict, bounded, canonical decode of one payload into the expected direction's frame."""
    if model not in (ToRuntime, FromRuntime) or type(payload) is not bytes:
        raise WireRefused("frame_invalid")
    if not 1 <= len(payload) <= MAX_FRAME_BYTES:
        raise WireRefused("frame_too_large" if len(payload) > MAX_FRAME_BYTES else "header_invalid")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise WireRefused("not_utf8") from None
    prescan(text)
    try:
        parsed = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float)
    except WireRefused:
        raise
    except RecursionError:
        raise WireRefused("too_deep") from None
    except ValueError:  # JSONDecodeError, or an integer-conversion limit
        raise WireRefused("malformed_json") from None
    if not isinstance(parsed, dict):
        raise WireRefused("frame_invalid")
    if parsed.get("channel") != "agent":
        raise WireRefused("channel_mismatch")
    body = parsed.get("body")
    kind = body.get("kind") if isinstance(body, dict) else None
    if type(kind) is not str:  # an array, object, number or null discriminator: malformed, never hashed
        raise WireRefused("frame_invalid")
    other = FROM_RUNTIME_KINDS if model is ToRuntime else TO_RUNTIME_KINDS
    if kind in other:
        raise WireRefused("direction_mismatch")
    try:
        frame = model.model_validate_json(payload, strict=True)
        canonical = canonical_bytes(frame)
    except Exception:  # ValidationError, or a value pydantic accepted but cannot re-encode (e.g. a lone surrogate)
        raise WireRefused("frame_invalid") from None
    if canonical != payload:
        raise WireRefused("frame_not_canonical")
    return frame


def read_frame[F: (ToRuntime, FromRuntime)](read_exact: Callable[[int], bytes], model: type[F]) -> F:
    """One frame from an injected exact reader: the header is checked before the payload is requested."""
    header = read_exact(HEADER_BYTES)
    if type(header) is not bytes:
        raise WireRefused("header_invalid")
    if len(header) != HEADER_BYTES:
        raise WireRefused("frame_truncated")
    length = int.from_bytes(header, "big")
    if length == 0:
        raise WireRefused("header_invalid")
    if length > MAX_FRAME_BYTES:
        raise WireRefused("frame_too_large")
    payload = read_exact(length)
    if type(payload) is not bytes:
        raise WireRefused("header_invalid")
    if len(payload) != length:
        raise WireRefused("frame_truncated")
    return decode_payload(payload, model)


# -- adapter <-> wire sequence numbers --------------------------------------------------------------------------------

def to_wire_seq(adapter_seq: int) -> int:
    """Adapter `user_turn`/`tool_return` seq k (1, 2, ...) travels as wire seq k + 1 (wire seq 1 is the open)."""
    if type(adapter_seq) is not int or not 1 <= adapter_seq <= MAX_SEQ - 1:
        raise WireRefused("sequence_mismatch")
    return adapter_seq + 1


def to_adapter_seq(reply_to: int) -> int:
    if type(reply_to) is not int or not 2 <= reply_to <= MAX_SEQ:
        raise WireRefused("sequence_mismatch")
    return reply_to - 1


# -- the pure connection checker ---------------------------------------------------------------------------------

State = Literal["PREOPEN", "OPENING", "OPEN_REFUSED", "OPEN_IDLE", "TURN_OUTSTANDING", "AWAITING_TOOL", "TERMINAL",
                "FAILED", "CLOSING", "CLOSED"]
CLEANUP_STATES = frozenset({"OPENING", "OPEN_REFUSED", "OPEN_IDLE", "TURN_OUTSTANDING", "AWAITING_TOOL", "TERMINAL",
                            "FAILED"})


_REQUEST_BODY: dict[str, type[BaseModel]] = {"PREOPEN": OpenSessionBody, "OPEN_IDLE": UserTurnBody,
                                              "AWAITING_TOOL": ToolReturnBody}
_AFTER_REQUEST: dict[str, State] = {"PREOPEN": "OPENING", "OPEN_IDLE": "TURN_OUTSTANDING",
                                    "AWAITING_TOOL": "TURN_OUTSTANDING"}


@dataclass(frozen=True)
class Emit:
    """Send this frame: `payload` is its validated canonical bytes (frame it with `HEADER_BYTES`)."""

    frame: ToRuntime
    payload: bytes


@dataclass(frozen=True)
class NoOp:
    """Nothing to send (a close before any open, or a repeated close)."""

    reason: Literal["never_opened", "already_closing", "already_closed"]


@dataclass(frozen=True)
class Deliver:
    """A valid reply for the caller."""

    frame: FromRuntime


@dataclass(frozen=True)
class Discard:
    """The one correlated late reply to a request abandoned by a cleanup close: validated, never delivered."""

    frame: FromRuntime


@dataclass(frozen=True)
class Closed:
    """The close's reply. `acknowledged` is False for a `refused` reply (remote cleanup uncertain)."""

    acknowledged: bool


class WireConnection:
    """Transport invariants for one agent-channel connection (half duplex; one outstanding request).

    Validation state is local; whether a failed peer actually cleaned up is never claimed. After any violation the
    connection is usable only for the cleanup close, and nothing stale, foreign or config-mismatched is delivered."""

    def __init__(self, session_id: UUID) -> None:
        if type(session_id) is not UUID:
            raise WireRefused("session_mismatch")
        self.session_id = session_id
        self.state: State = "PREOPEN"
        self.next_send = 1
        self.next_recv = 1
        self.outstanding: tuple[int, str] | None = None
        self.abandoned: tuple[int, str] | None = None
        self.config: str | None = None
        self.failure: WireRefusedCode | None = None
        self.discarded = 0
        self.cleanup_uncertain = False

    def _fail(self, code: WireRefusedCode) -> WireRefused:
        if self.state == "CLOSING":
            self.state, self.cleanup_uncertain = "CLOSED", True
        elif self.state != "CLOSED":
            self.state = "FAILED"
        self.failure = self.failure or code
        return WireRefused(code)

    def _validated(self, body: OpenSessionBody | UserTurnBody | ToolReturnBody | CloseSessionBody) -> Emit:
        """The next frame, completely validated by the bounded codec. Nothing is committed here: a refused body
        emits nothing and consumes no sequence number."""
        if self.next_send > MAX_SEQ:
            raise WireRefused("sequence_mismatch")
        try:
            frame = ToRuntime.model_construct(v="policyops.wire/v1", channel="agent", session_id=self.session_id,
                                              seq=self.next_send, body=body)
            encoded = encode_payload(frame)  # nested models are re-validated: no constructed or copied bypass
        except WireRefused:
            raise WireRefused("encode_invalid") from None
        return Emit(decode_payload(encoded, ToRuntime), encoded)

    def _commit(self, emit: Emit) -> Emit:
        self.outstanding = (emit.frame.seq, emit.frame.body.kind)
        self.next_send += 1
        return emit

    def request(self, body: OpenSessionBody | UserTurnBody | ToolReturnBody) -> Emit:
        """The next non-close request, if this state allows it."""
        if self.state == "CLOSED":
            raise WireRefused("connection_closed")
        expected = _REQUEST_BODY.get(self.state)
        if expected is None or type(body) is not expected:
            raise WireRefused("unexpected_body")  # a local misuse; the connection state is unchanged
        emit = self._validated(body)  # may refuse; nothing has changed yet
        self.state = _AFTER_REQUEST[self.state]
        return self._commit(emit)

    def close(self, budget_ms: int) -> Emit | NoOp:
        """The cleanup close, available from every state that sent anything. Repeated closes emit nothing."""
        if self.state == "PREOPEN":
            self.state = "CLOSED"
            return NoOp("never_opened")
        if self.state == "CLOSING":
            return NoOp("already_closing")
        if self.state == "CLOSED":
            return NoOp("already_closed")
        try:
            body = CloseSessionBody(budget_ms=budget_ms)
        except ValidationError:
            raise WireRefused("frame_invalid") from None
        emit = self._validated(body)
        self.abandoned, self.outstanding = self.outstanding, None
        self.state = "CLOSING"
        return self._commit(emit)

    def receive(self, frame: FromRuntime) -> Deliver | Discard | Closed:
        if self.state == "CLOSED":
            raise WireRefused("connection_closed")
        if type(frame) is not FromRuntime:
            raise self._fail("unexpected_body")
        try:  # complete bounded validation before anything is delivered, counted or committed
            frame = decode_payload(encode_payload(frame), FromRuntime)
        except WireRefused:
            raise self._fail("frame_invalid") from None
        if frame.session_id != self.session_id:
            raise self._fail("session_mismatch")
        if frame.seq != self.next_recv:
            raise self._fail("sequence_mismatch")
        kind = frame.body.kind
        if self.state == "CLOSING":
            close_seq = self.outstanding[0] if self.outstanding else None
            if frame.reply_to == close_seq and kind in ALLOWED_REPLIES["close_session"]:
                self.next_recv += 1
                self.state, self.outstanding = "CLOSED", None
                self.cleanup_uncertain = kind == "refused"
                return Closed(acknowledged=kind == "session_closed")
            late = self.abandoned
            if late is not None and frame.reply_to == late[0] and kind in ALLOWED_REPLIES[late[1]]:
                self._check_turn(frame)
                self.next_recv += 1
                self.abandoned = None  # at most one correlated late reply
                self.discarded += 1
                return Discard(frame)
            raise self._fail("reply_mismatch")
        if self.outstanding is None or self.state not in ("OPENING", "TURN_OUTSTANDING"):
            raise self._fail("unexpected_body")
        seq, request = self.outstanding
        if frame.reply_to != seq:
            raise self._fail("reply_mismatch")
        if kind not in ALLOWED_REPLIES[request]:
            raise self._fail("unexpected_body")
        self._check_turn(frame)
        self.next_recv += 1
        self.outstanding = None
        body = frame.body
        if self.state == "OPENING":
            if isinstance(body, SessionOpenedBody):
                self.config, self.state = body.config_sha256, "OPEN_IDLE"
            else:
                self.state = "OPEN_REFUSED"
        elif isinstance(body, ToolRequestBody):
            self.state = "AWAITING_TOOL"
        elif isinstance(body, TurnEndedBody):
            self.state = "OPEN_IDLE" if body.outcome.terminal is None else "TERMINAL"
        else:
            self.state = "FAILED"
            self.failure = self.failure or "unexpected_body"
        return Deliver(frame)

    def _check_turn(self, frame: FromRuntime) -> None:
        body = frame.body
        if isinstance(body, TurnEndedBody) and (body.outcome.config_sha256 != self.config
                                                or body.outcome.conversation_id != self.session_id):
            raise self._fail("config_mismatch")


__all__ = [
    "ALLOWED_REPLIES", "FROM_RUNTIME_KINDS", "HEADER_BYTES", "MAX_FRAME_BYTES", "TO_RUNTIME_KINDS", "WHITELIST",
    "WIRE_VERSION", "CloseSessionBody", "Closed", "Deliver", "Discard", "Emit", "FromRuntime", "NoOp",
    "OpenSessionBody", "RefusedBody", "RefusedCode", "SessionClosedBody", "SessionOpenedBody", "ToRuntime",
    "ToolRequestBody", "ToolReturnBody", "TurnEndedBody", "UserTurnBody", "WireConnection", "WireRefused",
    "WireRefusedCode", "account", "decode_payload", "encode_frame", "encode_payload", "prescan", "read_frame",
    "to_adapter_seq", "to_wire_seq",
]
