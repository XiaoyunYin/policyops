"""T29 agent-channel wire contract: frames, the strict canonical bounded codec, bounded encode accounting, and the
pure connection checker. Offline and pure; imports only `policyops_contracts` (no app, process, socket or pipe)."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import random
import traceback
import tracemalloc
from typing import Any
from uuid import UUID, uuid4

import pytest

from policyops_contracts import wire as W
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
from policyops_contracts.digest import canonical_bytes as original_canonical
from policyops_contracts.digest import text_sha256


WIRE = Path(W.__file__)
S = UUID(int=7)
CFG = "6" * 64
POLICY = PolicyContext(domain="retail", source="fictional", text="Fictional policy.",
                       sha256=text_sha256("Fictional policy."))
CATALOG = ToolCatalog(mode="descriptor", tools=(ToolDescriptor(
    name="get_order", description="Read an order (fictional).",
    parameters_schema_json='{"additionalProperties":false,"properties":{},"type":"object"}', read_only=True),))
HIDDEN = {"user_scenario", "instructions", "known_info", "unknown_info", "reason_for_call", "evaluation_criteria",
          "nl_assertions", "reward_basis", "required_documents", "initial_state", "task",
          "url", "uri", "command", "shell", "sql", "path", "header", "headers", "api_key", "credential", "token",
          "secret", "password"}


def build(model: Any, **fields: Any) -> Any:
    """`model_construct` for deliberately invalid test objects (typed as Any on purpose)."""
    return model.model_construct(**fields)


def record(calls: list[int], target: Any) -> Any:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        return target(*args, **kwargs)
    return wrapper


def state(connection: W.WireConnection) -> str:
    return connection.state


def outcome(*, message: str | None = "Done.", terminal: Any = None, appended: tuple[Any, ...] = (),
            config: str = CFG, conversation: UUID = S, pending: PendingToolOutcome | None = None) -> TurnOutcome:
    return TurnOutcome(conversation_id=conversation, turn=0, config_sha256=config,
                       message=None if message is None else AgentMessage(text=message), terminal=terminal,
                       appended=appended, model_calls=1, invalid_steps=0, counts_claimed=1, inferences_dispatched=1,
                       cleanup_unconfirmed=False, pending_tool=pending)


def to(seq: int, body: Any, session: UUID = S) -> W.ToRuntime:
    return W.ToRuntime(session_id=session, seq=seq, body=body)


def frm(seq: int, reply_to: int, body: Any, session: UUID = S) -> W.FromRuntime:
    return W.FromRuntime(session_id=session, seq=seq, reply_to=reply_to, body=body)


OPEN = W.OpenSessionBody(policy=POLICY, catalog=CATALOG, opening=AgentMessage(text="Hi! How can I help you today?"),
                         budget_ms=30_000)
TURN = W.UserTurnBody(turn=0, message=UserMessage(text="Where is order #W0000001?\r\n\tThanks ☃"), budget_ms=5)
RETURN = W.ToolReturnBody(result=ToolResult(call_id="c1", content='{"status":"pending"}', is_error=True), budget_ms=5)
CLOSE = W.CloseSessionBody(budget_ms=5)
OPENED = W.SessionOpenedBody(config_sha256=CFG)
CALL = W.ToolRequestBody(call=AgentToolCall(call_id="c1", name="get_order", arguments_json="{}"))
ENDED = W.TurnEndedBody(outcome=outcome(appended=(UserMessage(text="q"), RuntimeNotice(code="empty_reply"))))
CLOSED = W.SessionClosedBody()
REFUSED = W.RefusedBody(code="protocol")
ALL_FRAMES: list[Any] = [to(1, OPEN), to(2, TURN), to(3, RETURN), to(4, CLOSE), frm(1, 1, OPENED), frm(2, 2, CALL),
              frm(3, 3, ENDED), frm(4, 4, CLOSED), frm(5, 4, REFUSED)]


def code_of(thunk: Any) -> str:
    with pytest.raises(W.WireRefused) as caught:
        thunk()
    error = caught.value
    assert error.__cause__ is None and (error.__suppress_context__ or error.__context__ is None)
    return error.code


def payload(frame: Any) -> bytes:
    return W.encode_payload(frame)


# -- frames and codec ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("frame", ALL_FRAMES, ids=[f"{type(f).__name__}-{f.body.kind}" for f in ALL_FRAMES])
def test_every_body_round_trips_canonically_and_account_is_exact(frame: Any) -> None:
    framed = W.encode_frame(frame)
    assert framed == W.encode_frame(frame)  # deterministic bytes
    assert int.from_bytes(framed[:4], "big") == len(framed) - 4 == W.account(frame)
    assert W.decode_payload(framed[4:], type(frame)) == frame
    chunks = [framed]

    def read_exact(n: int) -> bytes:
        head, chunks[0] = chunks[0][:n], chunks[0][n:]
        return head
    assert W.read_frame(read_exact, type(frame)) == frame


def test_a_near_cap_frame_round_trips_and_one_over_is_refused_before_serialization(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    heavy = ToolResult(call_id="c", content="\x01" * 32_000)  # each \x01 is 6 escaped bytes
    near = frm(3, 3, W.TurnEndedBody(outcome=outcome(appended=(heavy,) * 21)))
    tracemalloc.start()
    framed = W.encode_frame(near)
    assert W.decode_payload(framed[4:], W.FromRuntime) == near
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert W.MAX_FRAME_BYTES - 200_000 < len(framed) - 4 <= W.MAX_FRAME_BYTES
    (tmp_path / "near-cap-measurement.json").write_text(json.dumps(
        {"payload_bytes": len(framed) - 4, "tracemalloc_peak_bytes": peak}), encoding="utf-8")  # evidence only
    dumps: list[int] = []
    monkeypatch.setattr(W, "canonical_bytes", record(dumps, lambda model: b""))
    over = frm(3, 3, W.TurnEndedBody(outcome=build(TurnOutcome,
        **{**dict(outcome()), "appended": (heavy,) * 22})))
    assert code_of(lambda: W.encode_frame(over)) == "frame_too_large" and dumps == []


def test_the_header_is_checked_before_the_payload_is_requested() -> None:
    def reader(header: bytes, body: bytes = b"") -> tuple[Any, list[int]]:
        requests: list[int] = []
        parts = [header, body]

        def read_exact(n: int) -> Any:
            requests.append(n)
            return parts.pop(0) if parts else b""
        return read_exact, requests

    for header, code in [((0).to_bytes(4, "big"), "header_invalid"),
                         ((W.MAX_FRAME_BYTES + 1).to_bytes(4, "big"), "frame_too_large"),
                         ((2**32 - 1).to_bytes(4, "big"), "frame_too_large"), (b"\x00\x01", "frame_truncated")]:
        read_exact, requests = reader(header)
        assert code_of(lambda r=read_exact: W.read_frame(r, W.ToRuntime)) == code
        assert requests == [4]  # the payload was never requested
    read_exact, requests = reader((10).to_bytes(4, "big"), b"short")
    assert code_of(lambda: W.read_frame(read_exact, W.ToRuntime)) == "frame_truncated" and requests == [4, 10]
    text_reader: Any = lambda n: "text"  # noqa: E731 - a reader returning the wrong type
    assert code_of(lambda: W.read_frame(text_reader, W.ToRuntime)) == "header_invalid"
    good = W.encode_frame(to(1, CLOSE))
    assert int.from_bytes(good[:4], "big") == len(good) - 4  # 4-byte unsigned big-endian


def raw(text: str) -> bytes:
    return text.encode("utf-8")


VALID = payload(to(4, CLOSE)).decode()


def test_parser_strictness_refuses_with_fixed_codes_before_or_during_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    canary = f"canary-{uuid4().hex}"
    cases = {
        "duplicate_key": raw(VALID[:-1] + ',"seq":4}'),
        "non_finite": raw(VALID.replace('"seq":4', '"seq":NaN')),
        "float_number": raw(VALID.replace('"seq":4', '"seq":4.0')),
        "number_too_long": raw(VALID.replace('"seq":4', '"seq":' + "9" * 20)),
        "not_utf8": raw(VALID)[:10] + b"\xff" + raw(VALID)[10:],
        "malformed_json": raw(VALID.replace('"agent"', '"ag\\xent"')),
        "too_deep": raw('{"channel":"agent","x":' + "[" * 33 + "]" * 33 + "}"),
        "too_many_nodes": raw('{"channel":"agent","x":[' + ",".join(["1"] * 20_001) + "]}"),
        "string_too_long": raw('{"channel":"agent","x":"' + "a" * 400_001 + '"}'),
        "frame_not_canonical": raw(VALID.replace(",", ", ", 1)),
        "frame_invalid": raw(VALID.replace('"budget_ms":5', f'"budget_ms":5,"extra":"{canary}"')),
        "channel_mismatch": raw(VALID.replace('"agent"', '"actor"')),
        "direction_mismatch": payload(frm(1, 1, OPENED)),
    }
    loads: list[int] = []
    monkeypatch.setattr(json, "loads", record(loads, json.loads))  # the module wire.py parses with
    for code, data in cases.items():
        before = len(loads)
        with pytest.raises(W.WireRefused) as caught:
            W.decode_payload(data, W.ToRuntime)
        assert caught.value.code == code, code
        assert canary not in "".join(traceback.format_exception(caught.value))
        if code in ("too_deep", "too_many_nodes", "string_too_long", "number_too_long", "float_number", "not_utf8"):
            assert len(loads) == before, code  # refused by the pre-scan, before any JSON structure exists
    lone = raw(VALID.replace('"agent"', '"agent","z":"\\ud800"'))
    assert code_of(lambda: W.decode_payload(lone, W.ToRuntime)) in ("frame_invalid", "frame_not_canonical")
    for bad in (to(4, CLOSE).model_copy(update={"v": "policyops.wire/v2"}),):
        text = json.dumps(json.loads(VALID) | {"v": bad.v}, sort_keys=True, separators=(",", ":"))
        assert code_of(lambda t=text: W.decode_payload(raw(t), W.ToRuntime)) == "frame_invalid"
    for field, value in (("seq", 0), ("seq", 2**31), ("session_id", "NOT-A-UUID")):
        text = json.dumps(json.loads(VALID) | {field: value}, sort_keys=True, separators=(",", ":"))
        assert code_of(lambda t=text: W.decode_payload(raw(t), W.ToRuntime)) == "frame_invalid", field
    lettered = UUID("abcdef01-2345-4678-9abc-def012345678")
    canonical = payload(to(4, CLOSE, session=lettered)).decode()
    upper = canonical.replace(str(lettered), str(lettered).upper())
    assert upper != canonical
    assert code_of(lambda: W.decode_payload(raw(upper), W.ToRuntime)) == "frame_not_canonical"
    unknown = VALID.replace('"close_session"', '"shutdown"')
    assert code_of(lambda: W.decode_payload(raw(unknown), W.ToRuntime)) == "frame_invalid"


# -- bounded encode accounting -----------------------------------------------------------------------------------------

def test_encode_accounting_refuses_aggregates_and_shapes_before_any_serialization(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Root's required correction: individually legal repeated references must not force a huge dump."""
    dumps: list[int] = []
    monkeypatch.setattr(W, "canonical_bytes", record(dumps, original_canonical))
    shared = ToolResult(call_id="c", content="x" * 32_000)  # one legal object, referenced many times

    def ended(appended: Any) -> Any:
        return build(W.FromRuntime, v=W.WIRE_VERSION, channel="agent", session_id=S, seq=3, reply_to=3,
                                             body=build(W.TurnEndedBody,
                                                 kind="turn_ended", outcome=build(TurnOutcome,
                                                     **{**dict(outcome()), "appended": appended})))
    cyclic: list[Any] = []
    cyclic.append(cyclic)
    cases = {
        "frame_too_large": ended((shared,) * 200),           # each legal; the aggregate is over the cap
        "too_many_nodes": ended((UserMessage(text="x"),) * 1_000_000),  # breadth refused before pushing
        "encode_invalid": ended(cyclic),
    }
    for code, frame in cases.items():
        assert code_of(lambda f=frame: W.encode_frame(f)) == code, code
    assert dumps == []  # nothing was serialized
    huge_int = build(W.ToRuntime, v=W.WIRE_VERSION, channel="agent", session_id=S, seq=10**10_000, body=CLOSE)
    assert code_of(lambda: W.encode_frame(huge_int)) == "number_too_long"
    shapes: list[Any] = [
        build(W.ToRuntime, v=W.WIRE_VERSION, channel="agent", session_id=S, seq=1, body={"kind": "x"}),
        build(W.ToRuntime, v=W.WIRE_VERSION, channel="agent", session_id=str(S), seq=1, body=CLOSE),
        build(W.ToRuntime, v=W.WIRE_VERSION, channel="agent", session_id=S, seq=1.0, body=CLOSE),
        build(W.ToRuntime, v=W.WIRE_VERSION, channel="agent", session_id=S, body=CLOSE),  # missing seq
        {"v": W.WIRE_VERSION},
        build(W.ToRuntime, v=W.WIRE_VERSION, channel="agent", session_id=S, seq=1,
                                    body=build(W.CloseSessionBody, kind="close_session", budget_ms=b"5")),
    ]
    for frame in shapes:
        assert code_of(lambda f=frame: W.encode_frame(f)) == "encode_invalid"
    assert dumps == []
    invalid_nested = build(W.ToRuntime,
        v=W.WIRE_VERSION, channel="agent", session_id=S, seq=2,
        body=build(W.UserTurnBody, kind="user_turn", turn=0, message=build(UserMessage,
            kind="user", text=""), budget_ms=5))
    assert code_of(lambda: W.encode_frame(invalid_nested)) == "encode_invalid"  # caught by the round trip
    deep: Any = (1,)
    for _ in range(40):
        deep = (deep,)
    # No declared field nests that deep, so a constructed deep nesting is refused by its declared type first; the
    # walk's depth guard remains defence in depth (the decoder's pre-scan depth refusal is tested above).
    assert code_of(lambda: W.encode_frame(ended(deep))) == "encode_invalid"
    long_text = build(W.ToRuntime,
        v=W.WIRE_VERSION, channel="agent", session_id=S, seq=2,
        body=build(W.UserTurnBody, kind="user_turn", turn=0, message=build(UserMessage,
            kind="user", text="y" * 400_001), budget_ms=5))
    assert code_of(lambda: W.encode_frame(long_text)) == "string_too_long"
    surrogate = build(W.ToRuntime,
        v=W.WIRE_VERSION, channel="agent", session_id=S, seq=2,
        body=build(W.UserTurnBody, kind="user_turn", turn=0, message=build(UserMessage,
            kind="user", text="bad\ud800"), budget_ms=5))
    assert code_of(lambda: W.encode_frame(surrogate)) == "encode_invalid"
    # Valid UUIDs, None fields and defaults encode normally.
    pending = PendingToolOutcome(call_id="c9", name="get_order", read_only=True)
    fine = frm(3, 3, W.TurnEndedBody(outcome=outcome(message=None, terminal="cancelled", pending=pending)))
    assert W.decode_payload(W.encode_payload(fine), W.FromRuntime) == fine


# -- the connection checker --------------------------------------------------------------------------------------------

def opened_connection() -> W.WireConnection:
    c = W.WireConnection(S)
    c.request(OPEN)
    c.receive(frm(1, 1, OPENED))
    return c


def test_a_full_conversation_walks_the_states_and_delivers_only_valid_replies() -> None:
    c = W.WireConnection(S)
    assert state(c) == "PREOPEN"
    assert c.request(OPEN).frame.seq == 1 and state(c) == "OPENING"
    assert isinstance(c.receive(frm(1, 1, OPENED)), W.Deliver) and (state(c), c.config) == ("OPEN_IDLE", CFG)
    assert c.request(TURN).frame.seq == 2 and state(c) == "TURN_OUTSTANDING"
    assert isinstance(c.receive(frm(2, 2, CALL)), W.Deliver) and state(c) == "AWAITING_TOOL"
    assert c.request(RETURN).frame.seq == 3 and state(c) == "TURN_OUTSTANDING"
    assert isinstance(c.receive(frm(3, 3, ENDED)), W.Deliver) and state(c) == "OPEN_IDLE"
    action = c.close(5)
    assert isinstance(action, W.Emit) and action.frame.seq == 4 and state(c) == "CLOSING"
    assert c.receive(frm(4, 4, CLOSED)) == W.Closed(acknowledged=True) and state(c) == "CLOSED"
    assert c.close(5) == W.NoOp("already_closed")
    assert code_of(lambda: c.request(TURN)) == "connection_closed"
    assert code_of(lambda: c.receive(frm(5, 4, CLOSED))) == "connection_closed"


def test_open_refusal_terminal_and_runtime_refusal_allow_only_the_cleanup_close() -> None:
    refused_open = W.WireConnection(S)
    refused_open.request(OPEN)
    refused_open.receive(frm(1, 1, REFUSED))
    terminal = opened_connection()
    terminal.request(TURN)
    terminal.receive(frm(2, 2, W.TurnEndedBody(outcome=outcome(message=None, terminal="budget"))))
    failed = opened_connection()
    failed.request(TURN)
    failed.receive(frm(2, 2, REFUSED))
    for connection, expected_state in ((refused_open, "OPEN_REFUSED"), (terminal, "TERMINAL"), (failed, "FAILED")):
        assert state(connection) == expected_state
        for body in (TURN, RETURN, OPEN):
            assert code_of(lambda c=connection, b=body: c.request(b)) == "unexpected_body"
        assert state(connection) == expected_state  # local misuse changes nothing
        assert isinstance(connection.close(5), W.Emit) and state(connection) == "CLOSING"


def test_a_close_before_any_open_is_a_local_no_op_and_repeated_closes_emit_nothing() -> None:
    c = W.WireConnection(S)
    assert c.close(5) == W.NoOp("never_opened") and state(c) == "CLOSED"
    d = opened_connection()
    assert isinstance(d.close(5), W.Emit)
    assert d.close(5) == W.NoOp("already_closing")
    assert W.WireConnection(S).close(0) == W.NoOp("never_opened")  # no frame is built, so no budget is checked
    e = opened_connection()
    assert code_of(lambda: e.close(0)) == "frame_invalid" and state(e) == "OPEN_IDLE"


def test_cleanup_close_discards_one_correlated_late_reply_and_refuses_anything_else() -> None:
    # Abandoned open (partially opened): one late session_opened is discarded, then the close reply.
    c = W.WireConnection(S)
    c.request(OPEN)
    close = c.close(5)
    assert isinstance(close, W.Emit) and close.frame.seq == 2
    assert isinstance(c.receive(frm(1, 1, OPENED)), W.Discard) and c.discarded == 1
    assert c.receive(frm(2, 2, CLOSED)) == W.Closed(acknowledged=True)
    # Abandoned turn: one late reply discarded; a second late reply is refused.
    d = opened_connection()
    d.request(TURN)
    d.close(5)
    assert isinstance(d.receive(frm(2, 2, CALL)), W.Discard)
    assert code_of(lambda: d.receive(frm(3, 2, ENDED))) == "reply_mismatch"
    assert (state(d), d.cleanup_uncertain) == ("CLOSED", True)
    # An uncorrelated body with a matching reply_to is not discarded.
    e = opened_connection()
    e.request(TURN)
    e.close(5)
    assert code_of(lambda: e.receive(frm(2, 2, OPENED))) == "reply_mismatch"
    # A refused close is recorded as cleanup uncertainty.
    f = opened_connection()
    f.close(5)
    assert f.receive(frm(2, 2, REFUSED)) == W.Closed(acknowledged=False) and f.cleanup_uncertain is True
    # A late turn_ended with a foreign config is never accepted, even for discarding.
    g = opened_connection()
    g.request(TURN)
    g.close(5)
    assert code_of(lambda: g.receive(frm(2, 2, W.TurnEndedBody(outcome=outcome(config="7" * 64))))) == \
        "config_mismatch"


@pytest.mark.parametrize(("frame", "code"), [
    (frm(2, 2, ENDED, session=uuid4()), "session_mismatch"),
    (frm(3, 2, ENDED), "sequence_mismatch"),
    (frm(2, 1, ENDED), "reply_mismatch"),
    (frm(2, 2, OPENED), "unexpected_body"),
    (frm(2, 2, CLOSED), "unexpected_body"),
    (frm(2, 2, W.TurnEndedBody(outcome=outcome(config="7" * 64))), "config_mismatch"),
    (frm(2, 2, W.TurnEndedBody(outcome=outcome(conversation=uuid4()))), "config_mismatch"),
], ids=["foreign-session", "skipped-seq", "stale-reply-to", "open-reply-to-turn", "close-reply-to-turn",
        "config", "conversation"])
def test_a_wrong_stale_or_foreign_reply_is_never_delivered_and_leaves_only_cleanup(frame: Any, code: str) -> None:
    c = opened_connection()
    c.request(TURN)
    assert code_of(lambda: c.receive(frame)) == code
    assert state(c) == "FAILED" and c.failure == code
    assert code_of(lambda: c.request(TURN)) == "unexpected_body"
    assert isinstance(c.close(5), W.Emit) and state(c) == "CLOSING"


def test_replies_without_a_request_and_out_of_order_sends_are_refused() -> None:
    idle = opened_connection()
    assert code_of(lambda: idle.receive(frm(2, 1, ENDED))) == "unexpected_body" and state(idle) == "FAILED"
    fresh = W.WireConnection(S)
    assert code_of(lambda: fresh.request(TURN)) == "unexpected_body" and state(fresh) == "PREOPEN"
    opening = W.WireConnection(S)
    opening.request(OPEN)
    assert code_of(lambda: opening.request(OPEN)) == "unexpected_body"  # one outstanding request
    assert code_of(lambda: W.WireConnection("s")) == "session_mismatch"  # type: ignore[arg-type]


def test_adapter_and_wire_sequences_map_exactly_and_check_their_ranges() -> None:
    assert [W.to_wire_seq(k) for k in (1, 2, 5)] == [2, 3, 6]
    assert [W.to_adapter_seq(w) for w in (2, 3, 6)] == [1, 2, 5]
    for bad in (0, -1, 2**31 - 1, True, 1.0):
        assert code_of(lambda b=bad: W.to_wire_seq(b)) == "sequence_mismatch"
    for bad in (1, 0, 2**31, True):
        assert code_of(lambda b=bad: W.to_adapter_seq(b)) == "sequence_mismatch"


# -- mutation sensitivity (capped) -------------------------------------------------------------------------------------

def assert_mutant(data: bytes, model: Any) -> None:
    try:
        decoded = W.decode_payload(data, model)
    except W.WireRefused:
        return
    assert W.encode_payload(decoded) == data  # a decoded mutant is exactly its own canonical bytes


def test_every_single_byte_mutation_of_a_tiny_frame_refuses_or_is_its_own_canonical_form() -> None:
    tiny = payload(frm(4, 4, CLOSED))
    assert len(tiny) < 200
    for index in range(len(tiny)):
        for flip in (0x01, 0x20, 0x80):
            mutated = bytearray(tiny)
            mutated[index] ^= flip
            assert_mutant(bytes(mutated), W.FromRuntime)
        assert_mutant(tiny[:index] + tiny[index + 1:], W.FromRuntime)


def test_seeded_mutations_of_larger_frames_refuse_or_are_their_own_canonical_form() -> None:
    rng = random.Random(20261106)  # noqa: S311 - deterministic mutation seeds, not cryptography
    for frame in (to(1, OPEN), frm(3, 3, ENDED)):
        data = payload(frame)
        for _ in range(300):
            mutated = bytearray(data)
            index = rng.randrange(len(mutated))
            if rng.random() < 0.7:
                mutated[index] ^= 1 << rng.randrange(8)
            elif rng.random() < 0.5:
                del mutated[index]
            else:
                mutated.insert(index, rng.randrange(256))
            assert_mutant(bytes(mutated), type(frame))


# -- schema shape and source isolation ------------------------------------------------------------------------------

def walk(node: Any, path: str, found: list[str]) -> None:
    if isinstance(node, dict):
        if node.get("additionalProperties") is True:
            found.append(f"{path}: open object")
        if node.get("type") == "number":
            found.append(f"{path}: number")
        if node.get("type") == "string" and not ({"maxLength", "pattern", "enum", "const"} & set(node)
                                                 or node.get("format") == "uuid"):
            found.append(f"{path}: unbounded string")
        for name in node.get("properties", {}):
            if name.lower() in HIDDEN:
                found.append(f"{path}: field {name}")
        for key, value in node.items():
            walk(value, f"{path}/{key}", found)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            walk(value, f"{path}/{index}", found)


def test_the_frame_schemas_are_closed_bounded_and_carry_no_hidden_or_privileged_field_names() -> None:
    """A field-name and shape check only: bounded visible content can still hold any characters."""
    for model in (W.ToRuntime, W.FromRuntime):
        found: list[str] = []
        walk(model.model_json_schema(), model.__name__, found)
        assert found == [], found


def test_the_wire_module_imports_only_stdlib_pydantic_and_contracts_and_does_no_io() -> None:
    tree = ast.parse(WIRE.read_text(encoding="utf-8"))
    modules = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | \
              {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert modules <= {"__future__", "collections", "dataclasses", "json", "re", "types", "typing", "uuid", "pydantic",
                       "policyops_contracts"}
    calls = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert not calls & {"open", "exec", "eval", "compile", "__import__"}


# -- review regressions (reviewer/draft-findings-1.md) ----------------------------------------------------------------

@pytest.mark.parametrize("kind", [[], {}, 1, None], ids=["array", "object", "number", "null"])
def test_a_malformed_discriminator_is_a_fixed_refusal_in_both_directions(kind: Any) -> None:
    for frame, model in ((to(4, CLOSE), W.ToRuntime), (frm(4, 4, CLOSED), W.FromRuntime)):
        document = json.loads(payload(frame))
        document["body"]["kind"] = kind
        data = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        assert code_of(lambda d=data, m=model: W.decode_payload(d, m)) == "frame_invalid"
    assert code_of(lambda: W.decode_payload(payload(to(4, CLOSE)), W.FromRuntime)) == "direction_mismatch"


def test_an_invalid_local_body_emits_nothing_and_consumes_no_sequence_number() -> None:
    c = W.WireConnection(S)
    bad_open = OPEN.model_copy(update={"budget_ms": 0})  # model_copy does not re-validate
    assert code_of(lambda: c.request(bad_open)) == "encode_invalid"
    assert (state(c), c.next_send, c.outstanding) == ("PREOPEN", 1, None)
    assert c.request(OPEN).frame.seq == 1  # the valid open still takes seq 1
    c.receive(frm(1, 1, OPENED))
    bad_turn = TURN.model_copy(update={"message": build(UserMessage, kind="user", text="")})
    assert code_of(lambda: c.request(bad_turn)) == "encode_invalid"
    assert (state(c), c.next_send) == ("OPEN_IDLE", 2)
    emit = c.request(TURN)
    assert emit.frame.seq == 2 and emit.payload == payload(emit.frame)  # the emitted bytes are the validated ones


def test_a_constructed_invalid_reply_is_never_delivered_and_commits_nothing() -> None:
    c = W.WireConnection(S)
    c.request(OPEN)
    forged = build(W.FromRuntime, v=W.WIRE_VERSION, channel="agent", session_id=S, seq=True, reply_to=True,
                                           body=build(W.SessionOpenedBody, kind="session_opened",
                                                                                     config_sha256="bad"))
    assert code_of(lambda: c.receive(forged)) == "frame_invalid"
    assert (state(c), c.config, c.next_recv) == ("FAILED", None, 1)
    assert isinstance(c.close(5), W.Emit) and state(c) == "CLOSING"  # cleanup only
    d = opened_connection()
    d.request(TURN)
    d.close(5)
    assert code_of(lambda: d.receive(forged)) == "frame_invalid" and (state(d), d.cleanup_uncertain) == ("CLOSED", True)


def test_an_oversized_backing_dict_is_refused_before_its_keys_are_touched(monkeypatch: pytest.MonkeyPatch) -> None:
    frame = to(4, CLOSE)
    frame.__dict__.update({f"k{i}": i for i in range(50_000)})
    built: list[int] = []
    monkeypatch.setattr(W, "set", record(built, set), raising=False)
    dumps: list[int] = []
    monkeypatch.setattr(W, "canonical_bytes", record(dumps, lambda model: b""))
    assert code_of(lambda: W.account(frame)) == "encode_invalid"
    assert built == [] and dumps == []
