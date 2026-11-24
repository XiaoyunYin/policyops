"""N10 arrival driver using HTTPX and the lean PolicyOps wire contracts."""

from __future__ import annotations

import argparse
import asyncio
from collections import defaultdict
from collections.abc import Awaitable, Callable, Iterable
from contextlib import AsyncExitStack, suppress
import ctypes
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
import hashlib
from hmac import compare_digest
from http import HTTPStatus
import ipaddress
import json
import math
from pathlib import Path
import platform
import random
import re
import socket
import ssl
import sys
import time
from typing import Any, TextIO
from urllib.parse import urljoin
from uuid import UUID, uuid5

import httpx

from policyops_contracts.digest import canonical_bytes
from policyops_contracts.errors import ErrorCode, ErrorEnvelope
from policyops_contracts.events import EventEnvelope
from policyops_contracts.proposal import ActionProposal


MARKER = "/api/v1/health/n10-load"
API = "/api/v1"
DEADLINE = 2.0
MAX_INFLIGHT = 64
MAX_RPS = 50
MAX_WORKFLOWS = 900
ROLES = {"alice": "analyst", "bob": "reviewer", "carol": "auditor"}
MIX = (
    ("case_list",) * 5
    + ("case_detail",) * 3
    + ("messages",) * 3
    + ("case_proposals",) * 2
    + ("proposal_detail",) * 5
    + ("run_snapshot",) * 2
)
TERMINAL = {"succeeded", "failed", "cancelled", "budget_exceeded"}
GENERATOR_CADENCE = 1.0
SEND_LAG_LIMIT = 0.005
WINDOWS_YIELD_LEAD = 0.002
LOOP_LAG_CADENCE = 0.1
STAGE_START_LEAD = 0.25
CANARY_RESOURCE = {
    "case_detail": "case", "messages": "case", "case_proposals": "case",
    "run_snapshot": "run", "proposal_detail": "proposal", "stream": "run",
}
# Closed codes emitted by the API error boundary, authentication and exercised services.
API_RULE_IDS = frozenset({
    "api.case_not_found", "api.consent_expired", "api.consent_required", "api.database_unavailable",
    "api.decision_outcome_unknown", "api.event_gap_resync_required", "api.event_position_ahead",
    "api.evidence_not_found", "api.expected_principal_required", "api.expected_workspace_required",
    "api.idempotency_key_required", "api.idempotency_mismatch", "api.internal", "api.invalid_cursor",
    "api.invalid_event_position", "api.invalid_expected_principal", "api.invalid_expected_workspace",
    "api.invalid_idempotency_key", "api.invalid_input", "api.invalid_limit", "api.invalid_precondition",
    "api.policy_changed", "api.precondition_required", "api.proposal_already_decided", "api.proposal_digest_mismatch",
    "api.proposal_expired", "api.proposal_invalid", "api.proposal_not_found", "api.proposal_not_presented",
    "api.proposal_superseded", "api.public_rate_limit", "api.read_integrity_conflict", "api.run_active",
    "api.run_not_found", "api.run_terminal", "api.separation_of_duties", "api.stale_version",
    "api.status_transition", "api.transaction_outcome_unknown", "auth.csrf", "auth.csrf_cookie", "auth.id_token",
    "auth.login_denied", "auth.login_state", "auth.membership", "auth.origin", "auth.principal_changed",
    "auth.provider", "auth.return_to",
    "auth.role", "auth.session", "auth.workspace", "auth.workspace_changed", "auth.workspace_required",
    "runtime.unconfigured", "server.not_started",
    *(f"api.http_{code.value}" for code in HTTPStatus if code >= 400),
})
Address = ipaddress.IPv4Address | ipaddress.IPv6Address


class Refused(ValueError):
    """Fixed, safe diagnostic for configuration, setup or the wrong-target guard."""


class Violation(ValueError):
    """Fixed, safe diagnostic for an unexpected response or violated invariant."""


def require(condition: bool, label: str) -> None:
    if not condition:
        raise Violation(label)


def address(value: str) -> Address:
    parsed = ipaddress.ip_address(value)
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped
    return parsed


def target(origin: str, deny_host: Iterable[str]) -> httpx.URL:
    url = httpx.URL(origin)
    host = url.host.lower().rstrip(".")
    denied = {name.strip().lower().rstrip(".") for name in deny_host}
    if not denied or "" in denied:
        raise Refused("at least one --deny-host hostname is required")
    if any(host == name or host.endswith("." + name) for name in denied):
        raise Refused("live hostname denied")
    if not host or url.userinfo or url.path != "/" or url.query or url.fragment or host != url.host:
        raise Refused("supply a canonical target origin")
    if url.scheme != "https" and (url.scheme != "http" or host not in ("127.0.0.1", "::1")):
        raise Refused("HTTPS is required outside the loopback pilot")
    return url


def loopback(url: httpx.URL) -> bool:
    return url.host in {"127.0.0.1", "::1"}


def approved_address(url: httpx.URL, deny_ip: Iterable[str], expect_ip: str | None = None) -> str:
    denied = {address(value) for value in deny_ip}
    if not denied:
        raise Refused("at least one --deny-ip address is required")
    if not loopback(url) and expect_ip is None:
        raise Refused("a non-loopback target requires --expect-ip with its IPv4 address")
    if expect_ip is not None:
        try:
            expected: Address = ipaddress.IPv4Address(expect_ip)
        except ipaddress.AddressValueError:
            raise Refused("--expect-ip must be a numeric IPv4 address") from None
        if loopback(url) and str(expected) != url.host:
            raise Refused("loopback expectation must match the loopback literal")
    else:
        expected = ipaddress.ip_address(url.host)
    answers = socket.getaddrinfo(url.host, url.port or (443 if url.scheme == "https" else 80), type=socket.SOCK_STREAM)
    resolved = {ipaddress.ip_address(str(row[4][0])) for row in answers}
    if not resolved or denied & {address(str(ip)) for ip in resolved}:
        raise Refused("target address was denied or absent")
    if resolved != {expected} or (not loopback(url) and any(row[0] != socket.AF_INET for row in answers)):
        raise Refused("target must resolve exclusively to the expected address")
    return str(expected)


class PinnedTransport(httpx.AsyncHTTPTransport):
    """Dial only the checked address, preserving Host and verified TLS SNI."""

    def __init__(self, url: httpx.URL, peer: str, tls: ssl.SSLContext) -> None:
        super().__init__(
            verify=tls,
            trust_env=False,
            limits=httpx.Limits(max_connections=164, max_keepalive_connections=64, keepalive_expiry=30),
        )
        self.url, self.peer = url, peer

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        outgoing = request.url
        if outgoing.userinfo or (outgoing.scheme, outgoing.host, outgoing.port) != (
            self.url.scheme,
            self.url.host,
            self.url.port,
        ):
            raise Refused("request left the checked origin")
        pinned = httpx.Request(
            request.method,
            request.url.copy_with(host=self.peer),
            headers=request.headers,
            stream=request.stream,
            extensions={**request.extensions, "sni_hostname": self.url.host},
        )
        return await super().handle_async_request(pinned)


async def check_marker(client: httpx.AsyncClient, token: str) -> bool:
    if not re.fullmatch(r"[a-f0-9]{64}", token):
        raise Refused("expected a 32-byte hex load token")
    response = await client.get(MARKER)
    try:
        payload = response.json() if response.status_code == 200 else {}
        present = payload.get("load_token")
        limiter = payload.get("limiter")
    except (ValueError, AttributeError):
        present, limiter = None, None
    if (
        not isinstance(present, str)
        or not compare_digest(present.encode(), token.encode())
        or type(limiter) is not bool
    ):
        raise Refused("load token missing or mismatched")
    return limiter


@dataclass(frozen=True)
class Stage:
    id: str
    w1: float
    w3: float = 0
    streams: int = 0
    batch: int = 0
    warmup: float = 60
    measured: float = 180
    drain: float = 90
    limiter: bool = False

    def __post_init__(self) -> None:
        if (
            not re.fullmatch(r"[a-z0-9-]+", self.id)
            or not all(math.isfinite(x) for x in (self.w1, self.w3, self.warmup, self.measured, self.drain))
            or not 0 < self.w1 <= MAX_RPS
            or not 0 <= self.w3 <= 1
            or self.streams not in (0, 10, 25, 50, 100)
            or self.batch not in (0, 1, 5, 20)
            or not 0 <= self.warmup <= 60
            or not 0 < self.measured <= 1800
            or not 0 < self.drain <= 90
            or sum(bool(value) for value in (self.w3, self.streams, self.batch)) > 1
            or ((self.w3 or self.streams or self.batch) and self.w1 != 2)
        ):
            raise Refused("stage exceeds the supported bounds")

    @property
    def arrivals_end(self) -> float:
        return self.warmup + self.measured

    @property
    def total(self) -> float:
        return self.arrivals_end + self.drain

    def phase(self, offset: float) -> str:
        if offset < 0:
            return "setup"
        if offset < self.warmup:
            return "warmup"
        return "measured" if offset < self.arrivals_end else "drain"


@dataclass(frozen=True)
class Slot:
    index: int
    offset: float
    route: str
    period: float
    choice: int


def schedule(stage: Stage, seed: int) -> list[Slot]:
    rng = random.Random(seed)  # noqa: S311 - reproducible traffic
    slots: list[Slot] = []
    routes: list[str] = []
    for index in range(math.ceil(stage.arrivals_end * stage.w1)):
        if index % 21 == 20:
            route = "inbox"
        else:
            if not routes:
                routes = list(MIX)
                rng.shuffle(routes)
            route = routes.pop()
        slots.append(Slot(index, index / stage.w1, route, 1 / stage.w1, rng.getrandbits(63)))
    for index in range(math.ceil(stage.arrivals_end * stage.w3)):
        slots.append(Slot(index, index / stage.w3, "workflow", 1 / stage.w3, rng.getrandbits(63)))
    for index in range(stage.batch):
        slots.append(Slot(index, stage.warmup, "workflow", stage.measured, rng.getrandbits(63)))
    return sorted(slots, key=lambda slot: slot.offset)


@dataclass
class Record:
    kind: str
    endpoint: str
    phase: str
    intended: float
    sent: float | None = None
    done: float | None = None
    status: int | None = None
    rule_id: str | None = None
    error: str | None = None
    correctness: bool = False
    workspace: str | None = None
    depth: int | None = None
    filtered: bool | None = None
    dispatch_lag: float | None = None


class Log:
    def __init__(self, output: TextIO, stage: Stage, start: float) -> None:
        self.output, self.stage, self.start = output, stage, start
        self.dispatch_lags: list[float] = []
        self.late_dispatches = 0
        self.abort_offset: float | None = None

    def now(self) -> float:
        return time.perf_counter() - self.start

    def write(self, row: dict[str, Any]) -> None:
        self.output.write(json.dumps(row, separators=(",", ":"), allow_nan=False) + "\n")

    def stop(self, abort: asyncio.Event, reason: str, *, correctness: bool = False) -> None:
        offset = self.now()
        if self.abort_offset is None:
            self.abort_offset = offset
        self.write({"kind": "abort", "reason": reason, "offset": offset, "correctness": correctness})
        abort.set()

    def record(self, row: Record, **fields: Any) -> None:
        if row.kind == "slot" and row.phase == "measured" and row.dispatch_lag is not None:
            self.dispatch_lags.append(row.dispatch_lag)
            self.late_dispatches += int(row.dispatch_lag > SEND_LAG_LIMIT)
        self.write({**asdict(row), **fields})


def sleep_until(when: float) -> None:
    time.sleep(max(0, when - time.perf_counter()))


async def wait_until(when: float) -> None:
    windows = sys.platform == "win32"
    yield_at = when - WINDOWS_YIELD_LEAD
    while (now := time.perf_counter()) < when:
        remaining = when - now
        if windows and now < yield_at:
            # Python 3.12 time.sleep uses a Windows waitable timer. Keep the coarse IOCP timeout off this path.
            await asyncio.to_thread(sleep_until, yield_at)
        else:
            await asyncio.sleep(remaining if not windows and remaining >= 0.001 else 0)


class MissedSlot(Exception):
    """The slot's dispatch window elapsed before the first send."""


def mark_send(slot: Slot, row: Record, log: Log) -> None:
    now = log.now()
    row.dispatch_lag = now - slot.offset
    if row.dispatch_lag > min(SEND_LAG_LIMIT, slot.period / 4):
        row.sent = None
        raise MissedSlot
    row.sent = now


async def dispatch(
    slots: list[Slot],
    log: Log,
    execute: Callable[[Slot, Record], Awaitable[None]],
    abort: asyncio.Event,
    *,
    cap: int = MAX_INFLIGHT,
) -> None:
    """Never queue a slot. Drop arrivals at the cap or after the dispatch window."""
    tasks: set[asyncio.Task[None]] = set()

    async def run(slot: Slot, row: Record) -> None:
        try:
            if abort.is_set():
                row.error = "aborted"
                return
            mark_send(slot, row, log)
            await execute(slot, row)
        except MissedSlot:
            row.error = "missed_slot"
        except (TimeoutError, httpx.TimeoutException):
            row.error = "deadline"
        except httpx.HTTPError as error:
            row.error = type(error).__name__
        except (Violation, ValueError, KeyError, TypeError, AttributeError) as error:
            row.error = str(error) if isinstance(error, Violation) else "invalid_response"
            row.correctness = True
            log.stop(abort, row.error)
        except asyncio.CancelledError:
            row.error = "cancelled_by_abort" if abort.is_set() else "drain_deadline"
            raise
        finally:
            row.done = log.now()
            log.record(row, index=slot.index)

    def completed(slot: Slot, row: Record, task: asyncio.Task[None]) -> None:
        tasks.discard(task)
        if task.cancelled() and row.done is None:
            row.error, row.done = "aborted" if abort.is_set() else "drain_deadline", log.now()
            log.record(row, index=slot.index)

    scheduled = 0
    try:
        for slot in slots:
            if abort.is_set():
                break
            row = Record("slot", slot.route, log.stage.phase(slot.offset), slot.offset)
            await wait_until(log.start + slot.offset)
            if abort.is_set():
                break
            scheduled += 1
            if len(tasks) >= cap:
                row.error = "overflow"
                row.done = log.now()
                row.dispatch_lag = row.done - slot.offset
                log.record(row, index=slot.index)
                continue
            task = asyncio.create_task(run(slot, row))
            tasks.add(task)
            task.add_done_callback(partial(completed, slot, row))
        if tasks and not abort.is_set():
            stop = asyncio.create_task(abort.wait())
            finished = asyncio.gather(*tasks)
            try:
                await asyncio.wait(
                    (finished, stop), timeout=max(0, log.stage.total - log.now()), return_when=asyncio.FIRST_COMPLETED
                )
            finally:
                stop.cancel()
                finished.cancel()
                with suppress(asyncio.CancelledError):
                    await stop
                with suppress(asyncio.CancelledError):
                    await finished
    finally:
        remaining = tuple(tasks)
        for task in remaining:
            task.cancel()
        if remaining:
            await asyncio.gather(*remaining, return_exceptions=True)
    if abort.is_set():
        for slot in slots[scheduled:]:
            row = Record("slot", slot.route, log.stage.phase(slot.offset), slot.offset, done=log.now(), error="aborted")
            log.record(row, index=slot.index)


async def follow(
    client: httpx.AsyncClient, method: str, url: str, data: dict[str, str] | None = None
) -> httpx.Response:
    # Same-origin only, including the form action. PinnedTransport also enforces this.
    for _ in range(10):
        response = await client.request(method, url, data=data)
        if response.is_error and response.url.path.startswith(API + "/"):
            status(Record("login", "dex_login", "setup", 0), response)
        if response.status_code not in (301, 302, 303, 307, 308):
            return response
        url = urljoin(str(response.url), response.headers["location"])
        if response.status_code == 303 or (method == "POST" and response.status_code in (301, 302)):
            method, data = "GET", None
    raise Refused("too many login redirects")


@dataclass
class Session:
    name: str
    workspace: str
    client: httpx.AsyncClient
    principal: str
    csrf: str

    @property
    def headers(self) -> dict[str, str]:
        return {"PolicyOps-Expected-Principal": self.principal, "PolicyOps-Expected-Workspace": self.workspace}

    @property
    def write_headers(self) -> dict[str, str]:
        return {**self.headers, "Origin": str(self.client.base_url).rstrip("/"), "X-CSRF-Token": self.csrf}


async def login(
    client: httpx.AsyncClient, name: str, workspace: str, expected: str, password: str, log: Log,
    allowed_workspaces: set[str],
) -> Session:
    # The same pinned Dex form parser used by the deployment verifier.
    from scripts.deploy_verify import LoginForm

    start = log.now()
    csrf_cookie = "__Host-policyops_csrf" if client.base_url.scheme == "https" else "policyops_csrf_local"
    response = await follow(client, "GET", API + "/auth/login")
    parser = LoginForm()
    parser.feed(response.text[:262144])
    if parser.action is None or response.status_code != 200:
        raise Refused("Dex login form unavailable")
    await follow(
        client,
        "POST",
        urljoin(str(response.url), parser.action),
        {**parser.fields, "login": name + "@example.invalid", "password": password},
    )
    csrf = client.cookies.get(csrf_cookie)
    if not csrf:
        raise Refused("Dex login did not establish a session")
    selected = await client.post(
        API + "/auth/workspace",
        json={"workspace_id": workspace},
        headers={"Origin": str(client.base_url).rstrip("/"), "X-CSRF-Token": csrf},
    )
    me = await client.get(API + "/me")
    for endpoint, result in (("workspace_select", selected), ("me", me)):
        if result.is_error:
            status(Record("login", endpoint, "setup", start), result)
    csrf = client.cookies.get(csrf_cookie)
    context = me.json()
    if (
        selected.status_code != 204
        or me.status_code != 200
        or not csrf
        or context.get("principal_id") != expected
        or context.get("workspace_id") != workspace
        or context.get("roles") != [ROLES[name]]
        or len(context["workspaces"]) != len(allowed_workspaces)
        or {item["workspace_id"] for item in context["workspaces"]} != allowed_workspaces
    ):
        raise Refused("fixture session context mismatch")
    log.record(
        Record("login", "dex_login", "setup", start, start, log.now(), me.status_code),
        principal=name,
        workspace=workspace,
    )
    return Session(name, workspace, client, expected, csrf)


@dataclass(frozen=True)
class Frame:
    event: str | None
    sequence: int | None
    data: str
    heartbeat: bool = False


class SSEParser:
    def __init__(self) -> None:
        self.fields: dict[str, str] = {}
        self.data: list[str] = []

    def feed(self, line: str) -> Frame | None:
        if line.startswith(":"):
            require(line == ": heartbeat", "unexpected_sse_comment")
            return Frame(None, None, "", heartbeat=True)
        if line:
            field, _, value = line.partition(":")
            if field == "data":
                self.data.append(value.removeprefix(" "))
            elif field in ("event", "id"):
                require(field not in self.fields, "duplicate_sse_field")
                self.fields[field] = value.removeprefix(" ")
            else:
                raise Violation("unexpected_sse_field")
            return None
        if not self.fields and not self.data:
            return None
        number = self.fields.get("id")
        if number is not None and not re.fullmatch(r"[0-9]{1,16}", number):
            raise Violation("sse_invalid_id")
        frame = Frame(self.fields.get("event"), int(number) if number is not None else None, "\n".join(self.data))
        self.fields.clear()
        self.data.clear()
        return frame


def advance(previous: int, frame: Frame) -> int:
    if frame.sequence is None:
        return previous
    require(frame.sequence > previous, "sse_duplicate_or_reorder")
    require(frame.sequence == previous + 1, "sse_gap")
    return frame.sequence


def status(row: Record, response: httpx.Response) -> ErrorEnvelope | None:
    row.status = response.status_code
    if response.is_success:
        return None
    row.error = "http_" + str(response.status_code)
    try:
        payload = response.json()
        rule = payload.get("rule_id") if isinstance(payload, dict) else None
        if rule is not None:
            row.rule_id = rule if isinstance(rule, str) and rule in API_RULE_IDS else "unrecognized"
        return ErrorEnvelope.model_validate_json(response.content)
    except ValueError:
        row.error, row.correctness = "invalid_error_envelope", True
        raise Violation(row.error) from None


def decode_event(data: str) -> tuple[dict[str, Any], str]:
    envelope = EventEnvelope.model_validate_json(data)
    return envelope.model_dump(mode="json"), hashlib.sha256(canonical_bytes(envelope.payload)).hexdigest()


def decode_read(route: str, response: httpx.Response, event_digests: dict[str, str]) -> dict[str, Any]:
    body = response.json()
    if not isinstance(body, dict):
        raise Violation("invalid_response")
    if route == "proposal_detail":
        ActionProposal.model_validate_json(json.dumps(body["proposal"]))
    if route == "run_snapshot":
        for event in [*body["events"], body["latest_review"], body["latest_stop"], body["latest_execution"]]:
            if event is not None:
                envelope = EventEnvelope.model_validate_json(json.dumps(event))
                digest = hashlib.sha256(canonical_bytes(envelope.payload)).hexdigest()
                require(event_digests.get(str(envelope.event_id)) == digest, "snapshot_event_digest_mismatch")
    return body


@dataclass(frozen=True)
class ReadRequest:
    path: str
    case: str | None = None
    run: str | None = None
    proposal: str | None = None
    version: int | None = None
    depth: int | None = None


ENTITY_TABLE = {
    "message_id": "messages", "consent_id": "consents", "approval_id": "decisions",
    "execution_id": "executions", "operation_id": "executions",
}
ID_ALIASES = {"customer_message_id": "message_id", "decision_id": "approval_id"}
WORKFLOW_EVENT_IDS = {"message_id", "event_id", "execution_id", "operation_id"}
UNSEEDED_IDS = {
    "evidence_id", "document_version_id", "order_id", "payment_method_id", "from_payment_method_id",
    "to_payment_method_id", "refund_payment_method_id", "item_id", "new_item_id", "item_ids", "new_item_ids",
    "product_id",
}
PRINCIPAL_FIELDS = {"principal_id", "entered_by"}
CUSTOMER_FIELDS = {"customer_user_id", "user_id", "resource_id"}
# The exercised FastAPI model schemas are checked against these handlers in the harness tests.
RESPONSE_ID_FIELDS = (
    ENTITY_TABLE.keys() | ID_ALIASES.keys() | UNSEEDED_IDS | PRINCIPAL_FIELDS | CUSTOMER_FIELDS
    | {"workspace_id", "case_id", "run_id", "proposal_id", "event_id", "initiated_by"}
    | {"correlation_id", "rule_id", "rule_ids"}  # closed diagnostic codes and correlation, not resource identities
)


class Workload:
    def __init__(self, manifest: dict[str, Any], sessions: list[Session], log: Log, abort: asyncio.Event) -> None:
        self.manifest, self.sessions, self.log, self.abort = manifest, sessions, log, abort
        self.demo = str(manifest["demo"])
        self.inventory = manifest["workspaces"]
        self.case_ids = {workspace: set(data["cases"]) for workspace, data in self.inventory.items()}
        self.proposals = {
            (row["proposal_id"], row["proposal_version"]): row
            for workspace in self.inventory.values()
            for row in workspace["proposals"]
        }
        self.proposal_versions: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for proposal in self.proposals.values():
            self.proposal_versions[proposal["proposal_id"]].append(proposal)
        self.sessions_by_name: dict[str, list[Session]] = defaultdict(list)
        for session in sessions:
            self.sessions_by_name[session.name].append(session)
        self.cursors: dict[tuple[str, bool], list[str | None]] = {}
        self.entities: dict[tuple[str, str], tuple[str, str | None, str | None]] = {}
        for workspace, inv in manifest.get("accounting", {}).items():
            for field, table in ENTITY_TABLE.items():
                for identifier, row in inv[table].items():
                    value = row["operation_id"] if field == "operation_id" else identifier
                    self.entities[field, value] = (workspace, row["case_id"], row.get("run_id"))
        for workspace, inv in self.inventory.items():
            for identifier, case in inv["messages"].items():
                self.entities["message_id", identifier] = (workspace, case, None)
            for identifier, run in inv["events"].items():
                self.entities["event_id", identifier] = (workspace, inv["runs"][run], run)

    def bind_new(self, field: str, identifier: str, session: Session, case: str, run: str) -> None:
        require(str(UUID(identifier)) == identifier and (field, identifier) not in self.entities, "new_id_mismatch")
        self.entities[field, identifier] = (session.workspace, case, run)

    def check_ids(self, body: Any, session: Session, request: ReadRequest, *, workflow: bool = False) -> None:
        inv = self.inventory[session.workspace]
        stack = [(body, request.case, request.run)]
        while stack:
            item, case, run = stack.pop()
            if isinstance(item, list):
                stack.extend((entry, case, run) for entry in item)
            if not isinstance(item, dict):
                continue
            require(item.get("workspace_id", session.workspace) == session.workspace, "workspace_mismatch")
            if isinstance(item.get("scope"), dict):
                case, run = item["scope"].get("case_id", case), item["scope"].get("run_id", run)
            found = item.get("case_id", case)
            if found is not None:
                require(
                    found in self.case_ids[session.workspace] and (request.case is None or request.case == found),
                    "case_mismatch",
                )
                case = found
            found = item.get("run_id", run)
            if found is not None:
                require(
                    found in inv["runs"]
                    and (case is None or inv["runs"][found] == case)
                    and (request.run is None or request.run == found),
                    "run_mismatch",
                )
                run = found
            if "proposal_id" in item:
                versions = self.proposal_versions[item["proposal_id"]]
                require(
                    any(
                        proposal["workspace_id"] == session.workspace
                        and item.get("proposal_version", proposal["proposal_version"]) == proposal["proposal_version"]
                        and (case is None or proposal["case_id"] == case)
                        and (run is None or proposal["run_id"] == run)
                        and item.get("action_digest", proposal["action_digest"]) == proposal["action_digest"]
                        for proposal in versions
                    ),
                    "proposal_mismatch",
                )
            if "initiated_by" in item:
                require(run in inv["run_principals"] and inv["run_principals"][run] == item["initiated_by"],
                        "initiator_mismatch")
            for field, identifier in item.items():
                if field.endswith(("_id", "_ids")):
                    require(field in RESPONSE_ID_FIELDS, "unhandled_response_id")
                if identifier is None:
                    continue
                kind = ID_ALIASES.get(field, field)
                if kind in ENTITY_TABLE or kind == "event_id":
                    owner = self.entities.get((kind, identifier))
                    if owner is None and workflow and kind in WORKFLOW_EVENT_IDS:
                        # The checker must reconcile the exact canonical SSE payload with this run's rows.
                        require(case is not None and run is not None, "unbound_workflow_event")
                        continue
                    require(
                        owner is not None and owner[0] == session.workspace
                        and (case is None or owner[1] == case)
                        and (run is None or owner[2] is None or owner[2] == run),
                        f"{kind}_mismatch",
                    )
                elif kind in PRINCIPAL_FIELDS:
                    require(identifier in self.manifest["principals"].values(), "principal_mismatch")
                elif kind in CUSTOMER_FIELDS:
                    require(identifier == self.manifest["customer_user_id"], "customer_mismatch")
                elif kind in UNSEEDED_IDS:
                    raise Violation("unseeded_reference")
            stack.extend((value, case, run) for value in item.values() if isinstance(value, dict | list))

    async def verify(
        self, route: str, response: httpx.Response, session: Session, request: ReadRequest,
        *, consent_message: str | None = None,
    ) -> dict[str, Any]:
        if route in {"proposal_detail", "run_snapshot"}:
            body = await asyncio.to_thread(
                decode_read, route, response, self.inventory[session.workspace]["event_digests"],
            )
        else:
            body = decode_read(route, response, {})
        if route in {"case_list", "messages", "case_proposals", "inbox"}:
            require(isinstance(body["items"], list), "invalid_page")
            identifiers = {
                "case_list": "case_id",
                "messages": "message_id",
                "case_proposals": "proposal_id",
                "inbox": "proposal_id",
            }
            require(all(identifiers[route] in item for item in body["items"]), "invalid_page_item")
        if route == "case_detail":
            require(body["case_id"] == request.case, "case_mismatch")
        if route == "proposal_detail":
            proposal = body["proposal"]
            require(
                proposal["proposal_id"] == request.proposal
                and proposal["proposal_version"] == request.version
                and proposal["scope"]["case_id"] == request.case
                and "action_digest" in proposal,
                "proposal_mismatch",
            )
            if consent_message is not None and request.case is not None and request.run is not None:
                consent = body["consent"]
                require(
                    consent["customer_message_id"] == consent_message
                    and consent["entered_by"] == self.manifest["principals"]["alice"],
                    "consent_not_bound",
                )
                self.bind_new("consent_id", consent["consent_id"], session, request.case, request.run)
        if route == "run_snapshot":
            require(body["run"]["run_id"] == request.run and body["run"]["case_id"] == request.case, "run_mismatch")
        self.check_ids(body, session, request)
        return body

    async def prepare(self) -> None:
        for workspace in self.inventory:
            session = next(s for s in self.sessions if s.workspace == workspace)
            for filtered in (False, True):
                cursors: list[str | None] = [None]
                for _ in range(7):
                    response = await session.client.get(
                        API + "/cases",
                        headers=session.headers,
                        params={
                            "limit": 25,
                            **({"status": "open"} if filtered else {}),
                            **({"cursor": cursors[-1]} if cursors[-1] else {}),
                        },
                    )
                    if response.status_code != 200:
                        status(Record("http", "case_list", "setup", self.log.now()), response)
                        raise Refused("could not precompute case page cursors")
                    body = await self.verify("case_list", response, session, ReadRequest("/cases"))
                    if body["next_cursor"] is None:
                        break
                    cursors.append(body["next_cursor"])
                self.cursors[workspace, filtered] = cursors

    @staticmethod
    def read_slot(slot: Slot, session: Session, inv: dict[str, Any]) -> ReadRequest:
        rng = random.Random(slot.choice)  # noqa: S311 - reproducible fixture selection
        case = rng.choice(inv["browse"])
        if slot.route == "case_detail":
            return ReadRequest(f"/cases/{case}", case)
        if slot.route == "messages":
            return ReadRequest(f"/cases/{case}/messages?limit=25", case)
        if slot.route == "case_proposals":
            case = rng.choice(inv["proposal_cases"])
            return ReadRequest(f"/cases/{case}/proposals?limit=25", case)
        if slot.route == "proposal_detail":
            row = rng.choice(inv["browse_proposals"])
            return proposal_request(row)
        if slot.route == "run_snapshot":
            run = rng.choice(inv["browse_runs"])
            return ReadRequest(f"/runs/{run}/snapshot?tail=25", inv["runs"][run], run)
        if slot.route == "inbox":
            return ReadRequest("/approvals?limit=25")
        raise Violation("unrecognized_read_route")

    async def request(
        self,
        session: Session,
        request: ReadRequest,
        row: Record,
        *,
        method: str = "GET",
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        if row.sent is None:
            row.sent = self.log.now()
        remaining = row.intended + DEADLINE - self.log.now()
        async with asyncio.timeout(max(0, remaining)):
            response = await session.client.request(
                method, API + request.path, json=body, headers={**session.headers, **(headers or {})}
            )
        status(row, response)
        return response

    async def read(self, slot: Slot, row: Record) -> None:
        readers = self.sessions_by_name["bob"] if slot.route == "inbox" else self.sessions
        session = readers[slot.choice % len(readers)]
        if slot.route == "case_list":
            filtered = bool(slot.choice & 1)
            cursors = self.cursors[session.workspace, filtered]
            depth = (slot.choice >> 1) % len(cursors)
            path = "/cases?limit=25" + ("&status=open" if filtered else "")
            if cursors[depth]:
                # The server issues URL-safe opaquely encoded cursor values.
                path += "&" + str(httpx.QueryParams({"cursor": cursors[depth]}))
            request = ReadRequest(path, depth=depth)
        else:
            request = self.read_slot(slot, session, self.inventory[session.workspace])
        row.workspace, row.depth = session.workspace, request.depth
        row.filtered = "&status=open" in request.path if request.depth is not None else None
        mark_send(slot, row, self.log)
        response = await self.request(session, request, row)
        if response.status_code == 200:
            await self.verify(slot.route, response, session, request)
        else:
            row.error = row.error or "unexpected_status"

    async def subrequest(
        self,
        session: Session,
        request: ReadRequest,
        route: str,
        origin: Record,
        *,
        method: str = "GET",
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        expected: tuple[int, ...] = (200,),
        arrival: Slot | None = None,
        decisions: list[int | None] | None = None,
    ) -> httpx.Response:
        if arrival is not None:
            mark_send(arrival, origin, self.log)
        row = Record("http", route, origin.phase, self.log.now())
        try:
            response = await self.request(session, request, row, method=method, body=body, headers=headers)
            if row.status in expected:
                row.error = None
            elif row.error is None:
                row.error = "unexpected_status"
            return response
        except (TimeoutError, httpx.TimeoutException):
            row.error = "deadline"
            raise
        except httpx.HTTPError as error:
            row.error = type(error).__name__
            raise
        finally:
            if decisions is not None:
                decisions.append(row.status)
            row.done = self.log.now()
            self.log.record(row, case_id=request.case, workspace=session.workspace)

    async def canaries(self, *, measured: bool = False) -> None:
        foreign = self.manifest["canary"]
        foreign_ids = set(self.manifest.get("foreign_ids", ()))
        foreign_ids.update(foreign[key] for key in ("workspace_id", "case_id", "run_id", "proposal_id"))
        resources = {
            "case_detail": f"/cases/{foreign['case_id']}",
            "messages": f"/cases/{foreign['case_id']}/messages",
            "case_proposals": f"/cases/{foreign['case_id']}/proposals",
            "run_snapshot": f"/runs/{foreign['run_id']}/snapshot",
            "proposal_detail": proposal_request(foreign).path,
            "stream": f"/runs/{foreign['run_id']}/events",
        }
        sessions = self.sessions
        phase = "setup"
        if measured:
            phase = "measured"
            sessions = [next(s for s in sessions if s.workspace == self.demo and s.name == "alice")]
            resources = {name: resources[name] for name in ("case_detail", "stream")}
        for session in sessions:
            for route, path in resources.items():
                row = Record("canary", route, phase, self.log.now())
                # Stream headers first in case a broken isolation layer returns a live stream.
                try:
                    row.sent = self.log.now()
                    async with session.client.stream("GET", API + path, headers=session.headers, timeout=2) as response:
                        row.status = response.status_code
                        error = None
                        if response.is_error:
                            await response.aread()
                            error = status(row, response)
                        require(row.status == 404, "foreign_resource_visible")
                        resource = CANARY_RESOURCE[route]
                        require(
                            error is not None and error.code == ErrorCode.NOT_FOUND and not error.retryable
                            and error.rule_id == f"api.{resource}_not_found" and error.detail == f"No such {resource}."
                            and str(error.correlation_id) not in foreign_ids,
                            "invalid_canary_error",
                        )
                        row.error = None
                except Violation as error:
                    row.error, row.correctness = str(error), True
                    raise
                except httpx.HTTPError as error:
                    row.error = type(error).__name__
                    raise
                finally:
                    row.done = self.log.now()
                    self.log.record(row, workspace=session.workspace, principal=session.name)

    async def stream(
        self,
        session: Session,
        case: str,
        run: str,
        until: float,
        origin: Record,
        *,
        workflow: bool = False,
        stream_id: str | None = None,
    ) -> str | None:
        sequence, first, reconnects = 0, True, 0
        opened, last_heartbeat = self.log.now(), None
        receipt: str | None = None
        terminal: str | None = None
        key = stream_id or run
        path = API + f"/runs/{run}/events"
        request = ReadRequest(path, case, run)
        try:
            async with asyncio.timeout(max(0, until - opened)):
                while not self.abort.is_set():
                    parser = SSEParser()
                    headers = {**session.headers, "Last-Event-ID": str(sequence)}
                    started = self.log.now()
                    phase = origin.phase if workflow else self.log.stage.phase(started)
                    async with session.client.stream("GET", path, headers=headers) as response:
                        row = Record("stream", "headers", phase, started, started, self.log.now(), response.status_code)
                        try:
                            if response.status_code != 200:
                                await response.aread()
                                status(row, response)
                                row.error = row.error or "unexpected_status"
                        finally:
                            self.log.record(row, run_id=run, stream_id=key)
                        if response.status_code != 200:
                            return None
                        require(
                            response.headers.get("content-type", "").startswith("text/event-stream"), "sse_content_type"
                        )
                        async for line in response.aiter_lines():
                            frame = parser.feed(line)
                            if frame is None:
                                continue
                            now = self.log.now()
                            phase = origin.phase if workflow else self.log.stage.phase(now)
                            if frame.heartbeat:
                                if last_heartbeat is not None:
                                    self.log.record(
                                        Record(
                                            "stream", "heartbeat_gap", phase, last_heartbeat, last_heartbeat, now, 200
                                        ),
                                        run_id=run,
                                        stream_id=key,
                                    )
                                last_heartbeat = now
                                continue
                            if frame.event == "reconnect" and frame.sequence is None:
                                require(json.loads(frame.data) == {}, "invalid_sse_control")
                                break
                            next_sequence = advance(sequence, frame)
                            require(frame.sequence is not None, "unexpected_sse_control")
                            event, digest = await asyncio.to_thread(decode_event, frame.data)
                            require(
                                event["sequence"] == next_sequence
                                and "event_id" in event
                                and frame.event == event["payload"]["type"],
                                "sse_event_mismatch",
                            )
                            require(
                                event["scope"] == {"workspace_id": session.workspace, "case_id": case, "run_id": run},
                                "sse_scope_mismatch",
                            )
                            self.check_ids(event, session, request, workflow=workflow)
                            sequence = next_sequence
                            self.log.write(
                                {
                                    "kind": "event",
                                    "stream_id": key,
                                    "run_id": run,
                                    "case_id": case,
                                    "workspace": session.workspace,
                                    "sequence": sequence,
                                    "event_id": event["event_id"],
                                    "phase": phase,
                                    "payload_sha256": digest,
                                }
                            )
                            if first:
                                self.log.record(
                                    Record("stream", "first_event", phase, opened, opened, now, 200),
                                    run_id=run,
                                    stream_id=key,
                                )
                                first = False
                            payload = event["payload"]
                            if payload["type"] == "execution.changed" and payload.get("outcome") == "committed":
                                receipt = payload["receipt_sha256"]
                            if payload["type"] == "review.outcome" and payload.get("reason") == "review_rejected":
                                receipt = "rejected"
                            if payload["type"] == "run.state_changed" and payload["current"] in TERMINAL:
                                terminal = payload["current"]
                                break
                    if terminal:
                        require(workflow, "hold_run_became_terminal")
                        return receipt
                    reconnects += 1
                    self.log.record(
                        Record("stream", "reconnect", phase, started, started, self.log.now(), 200),
                        run_id=run,
                        stream_id=key,
                    )
                    await asyncio.sleep(0.25)
        except (TimeoutError, httpx.ReadTimeout):
            if not workflow and self.log.now() < until - 0.1:
                self.log.record(
                    Record(
                        "stream",
                        "connection_error",
                        self.log.stage.phase(self.log.now()),
                        opened,
                        opened,
                        self.log.now(),
                        error="sse_timeout",
                    ),
                    run_id=run,
                    stream_id=key,
                )
            return None
        except httpx.HTTPError as error:
            self.log.record(
                Record(
                    "stream",
                    "connection_error",
                    self.log.stage.phase(self.log.now()),
                    opened,
                    opened,
                    self.log.now(),
                    error=type(error).__name__,
                ),
                run_id=run,
                stream_id=key,
            )
            return None
        except (Violation, ValueError, KeyError, TypeError, AttributeError) as error:
            if workflow:
                raise
            self.log.record(
                Record(
                    "stream",
                    "sequence",
                    self.log.stage.phase(self.log.now()),
                    opened,
                    opened,
                    self.log.now(),
                    error=str(error) if isinstance(error, Violation) else "invalid_sse_frame",
                    correctness=True,
                ),
                run_id=run,
                stream_id=key,
            )
            self.log.stop(self.abort, "invalid_sse_frame")
            return None
        finally:
            self.log.write(
                {
                    "kind": "stream_end",
                    "phase": self.log.stage.phase(self.log.now()),
                    "stream_id": key,
                    "run_id": run,
                    "case_id": case,
                    "workspace": session.workspace,
                    "finished": self.log.now(),
                    "sequence": sequence,
                    "reconnects": reconnects,
                    "workflow": workflow,
                }
            )
        return None

    async def workflow(self, slot: Slot, origin: Record) -> None:
        fixture = self.manifest["writes"][slot.index]
        analyst = next(s for s in self.sessions_by_name["alice"] if s.workspace == self.demo)
        reviewers = [s for s in self.sessions_by_name["bob"] if s.workspace == self.demo]
        bob, race_bob = reviewers
        case, run, mode = fixture["case_id"], fixture["run_id"], fixture["control"]
        bound = proposal_request(fixture)
        key = str(uuid5(UUID(case), "n10-consent"))
        write: dict[str, Any] = {
            "kind": "write",
            "phase": origin.phase,
            "index": slot.index,
            "case_id": case,
            "run_id": run,
            "control": mode,
            "consent_status": None,
            "decisions": [],
        }
        # The decision API's replay identity is its sealed request and same reviewer. The message API has a key.
        try:
            if mode not in STALE:
                message = ReadRequest(f"/cases/{case}/messages", case, run)
                payload = {"source": "operator_entered_customer", "text": "Yes, I confirm."}
                headers = {
                    **analyst.write_headers,
                    "Idempotency-Key": key,
                    "If-Match": '"' + str(fixture["case_version"]) + '"',
                }
                response = await self.subrequest(
                    analyst, message, "consent", origin, method="POST", body=payload, headers=headers, expected=(201,),
                    arrival=slot,
                )
                write["consent_status"] = response.status_code
                if response.status_code != 201:
                    origin.status, origin.error = response.status_code, "consent_failed"
                    return
                body = response.json()
                message_id = body["message"]["message_id"]
                require(
                    body["case"]["case_id"] == case
                    and body["message"]["case_id"] == case
                    and body["message"]["entered_by"] == analyst.principal
                    and body["case"]["version"] == fixture["case_version"] + 1,
                    "consent_binding_mismatch",
                )
                self.bind_new("message_id", message_id, analyst, case, run)
                self.check_ids(body, analyst, message)
                write["message_id"] = message_id
                if mode == "replay":
                    replay = await self.subrequest(
                        analyst,
                        message,
                        "consent_replay",
                        origin,
                        method="POST",
                        body=payload,
                        headers=headers,
                        expected=(201,),
                    )
                    write["consent_replay_status"] = replay.status_code
                    write["consent_replay_equal"] = replay.content == response.content
                    require(
                        replay.status_code == 201
                        and replay.headers.get("idempotent-replayed") == "true"
                        and write["consent_replay_equal"],
                        "consent_replay_mismatch",
                    )
            response = await self.subrequest(
                bob, bound, "bound_proposal", origin, arrival=slot if mode in STALE else None,
            )
            if response.status_code != 200:
                origin.status, origin.error = response.status_code, "bound_proposal_failed"
                return
            body = await self.verify("proposal_detail", response, bob, bound, consent_message=write.get("message_id"))
            if mode not in STALE:
                write["consent_id"] = body["consent"]["consent_id"]
            if mode == "expired":
                require(
                    body["row_status"] == "presented" and body["presentation"] is not None
                    and body["state"] == "expired",
                    "expired_fixture_not_presented",
                )
            choice = "reject" if mode == "reject" else "approve"
            decision_body: dict[str, Any] = {
                "proposal_version": bound.version,
                "action_digest": fixture["action_digest"],
                "decision": choice,
                "reason": "Fictional load approval.",
            }
            decision_path = ReadRequest(f"/proposals/{bound.proposal}/decision", case, run)
            acknowledged: list[float] = []

            async def decide(session: Session, body: dict[str, Any], route: str) -> httpx.Response:
                response = await self.subrequest(
                    session,
                    decision_path,
                    route,
                    origin,
                    method="POST",
                    body=body,
                    headers=session.write_headers,
                    expected=(200, 201, 409),
                    decisions=write["decisions"],
                )
                if response.status_code in (200, 201):
                    result = response.json()
                    require(
                        result["proposal_id"] == bound.proposal
                        and result["proposal_version"] == bound.version
                        and result["action_digest"] == fixture["action_digest"]
                        and result["decision"] == choice
                        and result["principal_id"] == session.principal
                        and result["consent_id"] == write.get("consent_id")
                        and result["scope"] == {"workspace_id": session.workspace, "case_id": case, "run_id": run},
                        "decision_binding_mismatch",
                    )
                    if response.status_code == 201:
                        self.bind_new("approval_id", result["approval_id"], session, case, run)
                    self.check_ids(result, session, decision_path)
                    write["approval_id"] = result["approval_id"]
                if response.status_code == 201:
                    acknowledged.append(self.log.now())
                return response

            if mode == "race":
                # Same fixture principal, distinct sessions and conflicting requests so the losing attempt is a 409.
                first, second = await asyncio.gather(
                    decide(bob, decision_body, "decision"),
                    decide(race_bob, {**decision_body, "reason": "Concurrent fictional review."}, "decision"),
                    return_exceptions=True,
                )
                if isinstance(first, BaseException):
                    raise first
                if isinstance(second, BaseException):
                    raise second
                require(sorted((first.status_code, second.status_code)) == [201, 409], "decision_race_mismatch")
                origin.status = 201
            else:
                decision = await decide(bob, decision_body, "decision")
                origin.status = decision.status_code
                if mode in STALE:
                    reason = {
                        "expired": "api.proposal_expired",
                        "superseded": "api.proposal_superseded",
                        "unconsented": "api.consent_required",
                    }[mode]
                    require(
                        decision.status_code == 409 and decision.json().get("rule_id") == reason,
                        "stale_decision_not_refused",
                    )
                    write["stale_rule_id"] = reason
                    return
                if decision.status_code != 201:
                    origin.error = "decision_failed"
                    return
                if mode == "replay":
                    replay = await decide(bob, decision_body, "decision_replay")
                    write["decision_replay_equal"] = replay.content == decision.content
                    require(
                        replay.status_code == 200
                        and replay.headers.get("idempotent-replayed") == "true"
                        and write["decision_replay_equal"],
                        "decision_replay_mismatch",
                    )
            ack = acknowledged[0]
            outcome = await self.stream(bob, case, run, self.log.stage.total, origin, workflow=True)
            if self.abort.is_set():
                raise asyncio.CancelledError
            if not outcome:
                origin.error = "terminal_receipt_missing"
            else:
                write["receipt"] = outcome
                if choice == "approve":
                    self.log.record(
                        Record("timing", "approval_to_terminal", origin.phase, ack, ack, self.log.now(), 200),
                        case_id=case,
                        choice=choice,
                    )
        finally:
            if origin.sent is not None:
                self.log.write(write)

    async def execute(self, slot: Slot, row: Record) -> None:
        if slot.route == "workflow":
            await self.workflow(slot, row)
        else:
            await self.read(slot, row)


STALE = {"expired", "superseded", "unconsented"}


def proposal_request(row: dict[str, Any]) -> ReadRequest:
    identifier, version = row["proposal_id"], row["proposal_version"]
    return ReadRequest(f"/proposals/{identifier}?version={version}", row["case_id"], row["run_id"], identifier, version)


def cpu_ticks() -> tuple[int, int]:
    if platform.system() == "Windows":
        from ctypes import wintypes

        idle, kernel, user = (wintypes.FILETIME() for _ in range(3))
        kernel32 = getattr(ctypes, "windll").kernel32  # noqa: B009 - available on Windows only
        if not kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
            raise Refused("could not sample generator CPU")
        ticks = [(value.dwHighDateTime << 32) | value.dwLowDateTime for value in (idle, kernel, user)]
        return ticks[1] + ticks[2], ticks[0]
    with Path("/proc/stat").open(encoding="ascii") as source:
        ticks = [int(value) for value in source.readline().split()[1:9]]
    return sum(ticks), ticks[3] + ticks[4]


def percentile(values: Iterable[float], quantile: float) -> float | None:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * quantile) - 1)] if ordered else None


async def monitor(workload: Workload, client: httpx.AsyncClient) -> None:
    log, abort = workload.log, workload.abort
    previous = cpu_ticks()
    readiness_losses, next_probe = 0, 0.0
    # Keep CPU sampling and the JSONL flush off the integer-second arrival boundaries.
    sample_at = GENERATOR_CADENCE + 0.0625
    probe: asyncio.Task[bool] | None = None
    loop_lags: list[float] = []

    async def measure_loop_lag() -> None:
        when = log.start + LOOP_LAG_CADENCE
        while not abort.is_set():
            await wait_until(when)
            now = time.perf_counter()
            loop_lags.append(max(0.0, now - when))
            when = now + LOOP_LAG_CADENCE

    async def ready() -> bool:
        try:
            response = await client.get(API + "/health/ready", timeout=2)
            if response.status_code == 429 and log.stage.limiter:
                error = status(Record("http", "readiness", "setup", log.now()), response)
                return error is not None and error.rule_id == "api.public_rate_limit"
            # The Compose readiness probe has a separate health status schema.
            return response.status_code == 200
        except Violation:
            log.stop(abort, "invalid_error_envelope", correctness=True)
            return False
        except (httpx.HTTPError, ValueError, AttributeError):
            return False

    lag_probe = asyncio.create_task(measure_loop_lag())
    try:
        while log.now() < log.stage.total and not abort.is_set():
            await wait_until(log.start + sample_at)
            now = log.now()
            sample_at += GENERATOR_CADENCE * max(1, math.floor((now - sample_at) / GENERATOR_CADENCE) + 1)
            current = cpu_ticks()
            total, idle = (a - b for a, b in zip(current, previous, strict=True))
            previous = current
            if total <= 0:
                log.stop(abort, "generator_cpu_unavailable")
                break
            cpu = 100 * (total - idle) / total
            dispatched = len(log.dispatch_lags)
            p99_over_limit = math.ceil(dispatched * 0.99) > dispatched - log.late_dispatches
            phase = log.stage.phase(now)
            log.write(
                {
                    "kind": "generator",
                    "phase": phase,
                    "offset": now,
                    "cpu_percent": cpu,
                    "measured_dispatches": dispatched,
                    "dispatch_lag_over_5ms": log.late_dispatches,
                    "event_loop_lag_samples": len(loop_lags),
                    "event_loop_lag_max_s": max(loop_lags, default=None),
                }
            )
            loop_lags.clear()
            if cpu > 50 or (dispatched >= 100 and p99_over_limit):
                log.stop(abort, "generator_cpu" if cpu > 50 else "generator_send_lag")
            if probe is not None and probe.done():
                ok = probe.result()
                probe = None
                readiness_losses = 0 if ok else readiness_losses + 1
                log.write({"kind": "readiness", "offset": now, "ok": ok})
                if readiness_losses >= 2:
                    log.stop(abort, "repeated_readiness_loss")
            if probe is None and now >= next_probe and not abort.is_set():
                probe = asyncio.create_task(ready())
                next_probe = now + 5
            log.output.flush()
    finally:
        lag_probe.cancel()
        with suppress(asyncio.CancelledError):
            await lag_probe
        if probe is not None:
            probe.cancel()
            with suppress(asyncio.CancelledError):
                await probe


def dataset_fingerprint(manifest: dict[str, Any]) -> str:
    inventories = {}
    for ws, inv in manifest["workspaces"].items():
        inventory = {key: value for key, value in inv.items()
                     if key not in {"events", "event_digests", "messages", "proposals", "browse_proposals"}}
        if "dataset" not in inv:
            inventory["messages"] = inv["messages"]
        for key in ("proposals", "browse_proposals"):
            inventory[key] = [{k: v for k, v in row.items() if k != "action_digest"} for row in inv[key]]
        inventories[ws] = inventory
    logical = {
        "seed": manifest["seed"],
        "principals": list(manifest["principals"].items()),
        "customer": manifest["customer_user_id"],
        "workspace_order": list(manifest["workspaces"]),
        "inventories": inventories,
        "canary": manifest["canary"],
        "foreign_dataset": manifest.get("foreign_dataset"),
        "counts": manifest["counts"],
        "writes": [
            {key: row[key] for key in ("case_id", "run_id", "proposal_id", "proposal_version", "control",
                                       "case_version", "simulator_version")}
            for row in manifest["writes"]
        ],
    }
    return hashlib.sha256(json.dumps(logical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


async def experiment(
    args: argparse.Namespace, url: httpx.URL, stage: Stage, manifest: dict[str, Any], output: TextIO,
) -> int:
    peer = approved_address(url, args.deny_ip, args.expect_ip)
    token = args.token_file.read_text(encoding="ascii").strip()
    tls = ssl.create_default_context(cafile=str(args.ca_file) if args.ca_file else None)
    if sys.platform == "win32" and not args.ca_file:
        # Preserve system validation for locally installed trust anchors on the workstation.
        tls.load_default_certs()
    seed = args.seed if args.seed is not None else manifest["seed"]
    slots = schedule(stage, seed)
    write_slots = sum(slot.route == "workflow" for slot in slots)
    if manifest["v"] != 2 or not 0 <= write_slots <= MAX_WORKFLOWS or len(manifest["writes"]) != write_slots:
        raise Refused("manifest write cohort must match the scheduled workflow count")
    start_utc = datetime.now(UTC)
    log = Log(output, stage, time.perf_counter())
    abort = asyncio.Event()
    log.write(
        {
            "kind": "meta",
            "v": 1,
            "stage": asdict(stage),
            "profile_sha256": hashlib.sha256(args.profile.read_bytes()).hexdigest(),
            "seed": seed,
            "environment": args.environment,
            "run": args.run,
            "setup_utc": start_utc.isoformat(),
            "counts": manifest["counts"],
            "manifest_sha256": hashlib.sha256(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "generator_cadence_s": GENERATOR_CADENCE,
            "event_loop_lag_cadence_s": LOOP_LAG_CADENCE,
            "scheduler": (
                {"wait": "windows_waitable_timer_then_yield", "yield_lead_s": WINDOWS_YIELD_LEAD}
                if sys.platform == "win32" else {"wait": "asyncio_sleep"}
            ),
            "target_sha256": hashlib.sha256((str(url) + peer).encode()).hexdigest(),
            "dataset_sha256": dataset_fingerprint(manifest),
        }
    )
    async with AsyncExitStack() as stack:
        transport = await stack.enter_async_context(PinnedTransport(url, peer, tls))

        async def new_client() -> httpx.AsyncClient:
            return await stack.enter_async_context(
                httpx.AsyncClient(base_url=url, transport=transport, timeout=httpx.Timeout(2, read=25), trust_env=False)
            )

        control = await new_client()
        before = log.now()
        if await check_marker(control, token) != stage.limiter:
            raise Refused("target limiter configuration does not match the stage")
        log.write({"kind": "target", "token_probe_seconds": log.now() - before})
        # Avoid printing credentials or keeping cookie jars on disk.
        sessions = []
        for workspace in manifest["workspaces"]:
            for name in ROLES:
                copies = 2 if workspace == manifest["demo"] and name == "bob" and write_slots else 1
                for _ in range(copies):
                    t0 = time.perf_counter()
                    password = (args.password_dir / name).read_text(encoding="utf-8").strip()
                    sessions.append(
                        await login(
                            await new_client(), name, workspace, manifest["principals"][name],
                            password, log, set(manifest["workspaces"]),
                        )
                    )
                    await wait_until(t0 + 1)
        log.write({"kind": "sessions", "principals": len(ROLES), "sessions": len(sessions)})
        workload = Workload(manifest, sessions, log, abort)
        await workload.canaries()
        await workload.prepare()
        held = [
            (run, inv["runs"][run], workspace) for workspace, inv in workload.inventory.items() for run in inv["hold"]
        ]
        if stage.streams > len(held):
            raise Refused("there are too few hold runs")
        # Randomize the hold cohort with the same seed, independent of the arrival schedule.
        random.Random(seed).shuffle(held)  # noqa: S311 - reproducible stream selection
        log.start = time.perf_counter() + STAGE_START_LEAD
        now = datetime.now(UTC) + timedelta(seconds=STAGE_START_LEAD)
        validity = [
            {
                "case_id": row["case_id"],
                "control": row["control"],
                "seconds": (datetime.fromisoformat(row["expires_at"]) - now).total_seconds(),
            }
            for row in manifest["writes"]
        ]
        if any(
            row["seconds"] >= 0 if row["control"] == "expired" else row["seconds"] < stage.total
            for row in validity
        ):
            raise Refused("write wave has insufficient remaining validity")
        log.write({"kind": "stage_start", "utc": now.isoformat(), "write_validity": validity})
        output.flush()

        async def hold(index: int, run: str, case: str, workspace: str) -> None:
            session = [s for s in sessions if s.workspace == workspace][index % len(ROLES)]
            await workload.stream(
                session, case, run, stage.total, Record("stream", "hold", "warmup", 0), stream_id=f"hold-{index}"
            )

        async def open_holds() -> None:
            # Let the first W1 slot dispatch before opening a whole hold cohort.
            await wait_until(log.start + 0.01)
            async with asyncio.TaskGroup() as connections:
                for index, (run, case, workspace) in enumerate(held[: stage.streams]):
                    connections.create_task(hold(index, run, case, workspace))

        async def check_under_load() -> None:
            if stage.limiter:
                return
            try:
                await asyncio.wait_for(abort.wait(), timeout=stage.warmup + stage.measured / 2 - log.now())
                return
            except TimeoutError:
                pass
            try:
                await workload.canaries(measured=True)
            except (Violation, httpx.HTTPError):
                log.stop(abort, "under_load_canary")

        async with asyncio.TaskGroup() as tasks:
            monitoring = tasks.create_task(monitor(workload, control))
            tasks.create_task(check_under_load())
            holding = tasks.create_task(open_holds()) if stage.streams else None
            await dispatch(slots, log, workload.execute, abort)
            if not abort.is_set():
                # Continue sampling through the declared drain even if client work has already completed.
                await monitoring
            if abort.is_set():
                if holding is not None:
                    holding.cancel()
                monitoring.cancel()
        lag = percentile(log.dispatch_lags, 0.99)
        if not abort.is_set() and (lag is None or lag > SEND_LAG_LIMIT):
            log.stop(abort, "generator_send_lag")
        log.write(
            {
                "kind": "stage_end", "utc": datetime.now(UTC).isoformat(), "aborted": abort.is_set(),
                "abort_offset": log.abort_offset, "send_lag_p99": lag,
            }
        )
    return int(abort.is_set())


def read_stage(path: Path, name: str, rate: float | None, workflow_rate: float | None = None) -> Stage:
    profile = json.loads(path.read_bytes())
    if profile["version"] != 1:
        raise Refused("unsupported load profile version")
    stage = next((item for item in profile["stages"] if item["id"] == name), None)
    if stage is None:
        raise Refused("stage is absent from profile")
    if (stage.get("w1") is None) != (rate is not None):
        raise Refused("supply --rate only for a profile with a coordinator-selected W1 rate")
    if workflow_rate is not None and (not name.startswith(("fix-", "repeat-")) or rate != 2):
        raise Refused("a coordinator-selected workflow rate requires a fix/repeat profile at 2 W1 rps")
    specification = Stage(
        **{
            **profile.get("defaults", {}),
            **stage,
            **({"w1": rate} if rate is not None else {}),
            **({"w3": workflow_rate} if workflow_rate is not None else {}),
        }
    )
    measured_w1 = sum(
        slot.route != "workflow" and specification.phase(slot.offset) == "measured"
        for slot in schedule(specification, 0)
    )
    if measured_w1 < 100:
        raise Refused("the send-lag p99 gate requires at least 100 measured W1 slots")
    return specification


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--target", required=True)
    cli.add_argument("--deny-host", action="append", required=True, help="Repeat for every live hostname")
    cli.add_argument("--deny-ip", action="append", required=True, help="Repeat for every live address")
    cli.add_argument("--expect-ip", help="Privately recorded IPv4 address for a non-loopback target")
    cli.add_argument("--token-file", required=True, type=Path)
    cli.add_argument("--rtt-only", action="store_true", help="After the guard, sample TCP connect time without load")
    cli.add_argument("--password-dir", type=Path, help="Directory with alice, bob, carol files")
    cli.add_argument("--ca-file", type=Path)
    cli.add_argument("--manifest", type=Path)
    cli.add_argument("--profile", type=Path)
    cli.add_argument("--stage")
    cli.add_argument("--rate", type=float)
    cli.add_argument("--workflow-rate", type=float)
    cli.add_argument("--seed", type=int)
    cli.add_argument("--run", help="Unique trial label, for example w1-08-a1")
    cli.add_argument("--environment", choices=("workstation", "lightsail"))
    cli.add_argument("--output", type=Path, required=True)
    return cli


async def record_rtt(args: argparse.Namespace, url: httpx.URL) -> int:
    if url.scheme != "https":
        raise Refused("RTT recording requires a guarded HTTPS target")
    peer = approved_address(url, args.deny_ip, args.expect_ip)
    tls = ssl.create_default_context(cafile=str(args.ca_file) if args.ca_file else None)
    async with httpx.AsyncClient(
        base_url=url, transport=PinnedTransport(url, peer, tls), timeout=2, trust_env=False
    ) as client:
        await check_marker(client, args.token_file.read_text(encoding="ascii").strip())
    samples = []
    for _ in range(5):
        start = time.perf_counter()
        async with asyncio.timeout(2):
            _, writer = await asyncio.open_connection(peer, url.port or 443)
            samples.append(time.perf_counter() - start)
            writer.close()
            await writer.wait_closed()
        await asyncio.sleep(0.3)
    with args.output.open("x", encoding="utf-8", newline="\n") as output:
        json.dump({"kind": "tcp_connect", "utc": datetime.now(UTC).isoformat(), "samples_s": samples}, output)
    return 0


def main() -> int:
    cli = parser()
    args = cli.parse_args()
    try:
        url = target(args.target, args.deny_host)
        if args.rtt_only:
            return asyncio.run(record_rtt(args, url))
        if not all((args.password_dir, args.manifest, args.profile, args.stage, args.run, args.environment)):
            cli.error("load requires --password-dir, --manifest, --profile, --stage, --run and --environment")
        if args.environment == "workstation" and not loopback(url):
            raise Refused("the workstation pilot requires a loopback target")
        if args.environment == "lightsail" and url.scheme != "https":
            raise Refused("Lightsail trials require HTTPS")
        stage = read_stage(args.profile, args.stage, args.rate, args.workflow_rate)
        manifest = json.loads(args.manifest.read_bytes())
        with args.output.open("x", encoding="utf-8", newline="\n") as output:
            setup_utc = datetime.now(UTC).isoformat()
            try:
                return asyncio.run(experiment(args, url, stage, manifest, output))
            except Exception as error:
                if output.tell() == 0:
                    output.write(json.dumps({
                        "kind": "meta", "v": 1, "stage": asdict(stage), "environment": args.environment,
                        "seed": args.seed if args.seed is not None else manifest.get("seed", 0),
                        "run": args.run, "setup_utc": setup_utc,
                    }) + "\n")
                output.write(
                    json.dumps(
                        {
                            "kind": "abort",
                            "reason": str(error) if isinstance(error, Refused | Violation) else type(error).__name__,
                            "correctness": isinstance(error, Violation),
                        }
                    )
                    + "\n"
                )
                raise
    except Exception as error:
        print(str(error) if isinstance(error, Refused | Violation) else type(error).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
