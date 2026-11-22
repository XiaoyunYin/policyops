"""Shared development inputs and scripted scenario runtime fixtures."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from typing import Literal

import httpx2
import pytest

from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops.providers.tokenizer import Tokenizer, load
from policyops_contracts.policy import RETAIL_POLICY
from policyops_contracts.retail_service import OrderDetail, OrderOutput, UserOutput
from policyops_evals.retail_sim import bootstrap, fixture, migrate
from policyops_evals.scenarios.generator import REPO
from policyops_evals.scenarios.recording import object_from, phase_of
from policyops_evals.scenarios.runtime import POLICY_CORPUS, Profile, load_policy, retail_store
from policyops_evals.scenarios.study import private_root
from policyops_testing.app_database import AppCluster, AppDatabase
from policyops_testing.postgres import OwnedPostgres
from policyops_testing.retrieval_fixtures import World, luna_reply
from policyops_testing.safety.retail import reviewed_tree


type Reply = dict[str, object] | str
ABSTAIN = {"v": "policyops.grounded-answer/v1", "outcome": "abstain", "assertions": [],
           "abstention": {"reason": "insufficient_evidence", "detail": None}}


@pytest.fixture(scope="module")
def database(postgres: OwnedPostgres, tmp_path_factory: pytest.TempPathFactory
             ) -> Iterator[tuple[AppDatabase, Path, Path]]:
    with scenario_database(postgres, tmp_path_factory) as created:
        yield created


@contextmanager
def scenario_database(postgres: OwnedPostgres, tmp_path_factory: pytest.TempPathFactory
                      ) -> Iterator[tuple[AppDatabase, Path, Path]]:
    db = AppCluster.provision(postgres).create_database("scenario")
    db.upgrade()
    for role in bootstrap.ROLES:
        if role not in postgres.passwords:
            postgres.register_role(role)
    with postgres.connect("postgres", db.name, autocommit=True) as connection:
        bootstrap.provision(connection, db.name, {role: postgres.passwords[role] for role in bootstrap.ROLES})
    with db.engine(bootstrap.MIGRATOR).connect() as connection:
        migrate.upgrade(connection)
    source = pinned_tree()
    root = tmp_path_factory.mktemp("scenario-fixture") / "audited"
    fixture.stage(source, root)
    try:
        yield db, root, source / RETAIL_POLICY.path
    finally:
        db.dispose()


@pytest.fixture
def profile(database: tuple[AppDatabase, Path, Path], tmp_path: Path) -> tuple[Profile, World]:
    return scenario_profile(database, tmp_path)


def scenario_profile(database: tuple[AppDatabase, Path, Path], tmp_path: Path) -> tuple[Profile, World]:
    db, root, policy_path = database
    world = World(db, tmp_path)
    world.publish({"policy": policy_path.read_bytes()}, key=POLICY_CORPUS, domain="retail", render="identity")
    return Profile(db.engine(APP_RUNTIME), db.engine(AUTH_RUNTIME), retail_store(db.engine(bootstrap.RUNTIME), root),
                   load_policy(policy_path), load()), world


def call(name: str, arguments: Mapping[str, object] | str, index: int) -> dict[str, object]:
    return {"type": "function_call", "name": name, "call_id": f"call_{index}",
            "arguments": arguments if isinstance(arguments, str) else json.dumps(arguments)}


def pinned_tree() -> Path:
    explicit = os.environ.get("POLICYOPS_RETAIL_FIXTURE_TREE")
    if explicit:
        return Path(explicit)
    return fixture.find_reviewed_tree(Path(os.environ.get("UV_CACHE_DIR", ""))) or reviewed_tree()


@pytest.fixture(scope="module")
def pinned() -> tuple[bytes, bytes]:
    tree = pinned_tree()
    return (tree / fixture.DB_PATH).read_bytes(), (tree / RETAIL_POLICY.path).read_bytes()


class Script:
    def __init__(self, tokenizer: Tokenizer, replies: Sequence[Reply] | Callable[[httpx2.Request, int], Reply],
                 prefix: str = "s1") -> None:
        self.tokenizer = tokenizer
        if callable(replies):
            self.reply = replies
        else:
            queue = iter(replies)
            self.reply = lambda _request, _index: next(queue)
        self.prefix = prefix
        self.counts: list[int] = []
        self.created = 0

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        if phase_of(request) == "count":
            count = len(self.tokenizer.encoding.encode_ordinary(request.content.decode()))
            self.counts.append(count)
            return httpx2.Response(200, json={"object": "response.input_tokens", "input_tokens": count})
        reply = self.reply(request, self.created + 1)
        self.created += 1
        # Match the existing Luna fixtures, but use a different fixed response ID per request.
        tokens = self.counts[-1]
        changes: dict[str, object] = {
            "id": f"resp_{self.prefix}_{self.created}",
            "usage": {"input_tokens": tokens, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
                      "output_tokens": 40, "output_tokens_details": {"reasoning_tokens": 8},
                      "total_tokens": tokens + 40},
        }
        if isinstance(reply, dict):
            changes["output"] = [reply]
        response = luna_reply(reply if isinstance(reply, str) else "", **changes)(request)
        assert isinstance(response, httpx2.Response)
        return response


def no_authority_or_execution(world: World) -> None:
    assert world.count("app.customer_consents") == 0
    assert world.count("app.approval_decisions") == 0
    assert world.count("app.tool_executions") == 0


EMIT = "POLICYOPS_SCENARIO_EMIT"
EMIT_PATH = "POLICYOPS_SCENARIO_EMIT_PATH"


def emit_target() -> Path | None:
    mode = os.environ.get(EMIT)
    if mode is None:
        return None
    assert mode == "1", f"{EMIT} must be unset or 1"
    raw_path = os.environ.get(EMIT_PATH)
    assert raw_path, f"{EMIT_PATH} must name a new file outside the checkout"
    path = Path(raw_path).absolute()
    target = path.resolve()
    assert not (path.is_relative_to(REPO) or target.is_relative_to(REPO)), (
        "request digest output must be outside the checkout"
    )
    return private_root(target)



type AntiOracle = Literal["first-match", "premature", "wrong-order", "confirmation", "malformed"]
LOOKUP = "find_user_id_by_email"
PROFILE_READ = "get_user_details"
ORDER_READ = "get_order_details"
SEARCH = "search_policy"
CANCEL = "cancel_pending_order"
TRANSFER = "transfer_to_human_agents"


@dataclass(frozen=True)
class ModelView:
    opener: str
    outputs: dict[str, list[str]]

    @classmethod
    def from_request(cls, request: httpx2.Request) -> ModelView:
        items = object_from(request.content)["input"]
        messages = [item for item in items if item["type"] == "message" and item["role"] == "user"]
        opener = messages[0]["content"][0]["text"]
        assert isinstance(opener, str)
        pending: dict[str, str] = {}
        outputs: dict[str, list[str]] = {}
        for item in items:
            if item["type"] == "function_call":
                pending[item["call_id"]] = item["name"]
            elif item["type"] == "function_call_output":
                outputs.setdefault(pending.pop(item["call_id"]), []).append(item["output"])
        assert not pending
        return cls(opener, outputs)

    def lookup(self) -> str:
        result = object_from(self.outputs[LOOKUP][0])
        assert result.get("outcome") == "authenticated"
        if isinstance(user_id := result.get("user_id"), str):
            return user_id
        # Baseline acknowledges successful lookup without disclosing the ID.
        account = re.search(r"\b[a-z]+_[a-z]+_\d{4}\b", self.opener)
        assert account is not None
        return account[0]

    def orders(self) -> dict[str, OrderDetail]:
        found = {}
        for encoded in self.outputs.get(ORDER_READ, []):
            payload = object_from(encoded)
            result = OrderOutput.model_validate_json(json.dumps(payload["output"]))
            found[result.order.order_id] = result.order
        return found


def _cited_decline(delivery: str) -> dict[str, object]:
    step = re.match(r"Retrieval step (\d+)\n", delivery)
    assert step is not None
    headers = list(re.finditer(r"^\[(E\d+)\] [^\n]+ \| chars (\d+)-(\d+)\n", delivery, re.M))
    for header in headers:
        chunk = delivery[header.end():header.end() + int(header[3]) - int(header[2])]
        quote = re.search(r"^An order can only be cancelled if its status is 'pending',[^\n]+", chunk, re.M)
        if quote:
            return {"v": "policyops.grounded-answer/v1", "outcome": "answer", "abstention": None,
                    "assertions": [{"text": "I can't cancel an order that has already been delivered.",
                                    "policy_dependent": True, "citations": [
                                        {"step": int(step[1]), "evidence_id": header[1], "quote": quote[0],
                                         "start": quote.start(), "end": quote.end()},
                                    ]}]}
    raise AssertionError("the provider did not receive the cancellation precondition")


def _matches(opener: str, order: OrderDetail) -> bool:
    if count := re.search(r"\bwith (\d+) items? in it\b", opener):
        return len(order.items) == int(count[1])
    assert "paid for with a credit card" in opener
    return any(p.transaction_type == "payment" and p.payment_method_id.startswith("credit_card_")
               for p in order.payment_history)


def _reason(opener: str) -> str | None:
    if "not needing it" in opener or "don't need it anymore" in opener:
        return "no longer needed"
    if "by mistake" in opener:
        return "ordered by mistake"
    return None


def oracle(request: httpx2.Request, index: int, *, anti: AntiOracle | None = None) -> Reply:
    """Choose actions from the serialized user opener and previous tool results."""
    view = ModelView.from_request(request)
    opener, outputs = view.opener, view.outputs

    def act(name: str, args: Mapping[str, object] | str) -> Reply:
        return call(name, args, index)

    if anti == "malformed":
        assert index in (1, 2)
        return act(ORDER_READ, "{")
    if "book a visit" in opener:
        if TRANSFER in outputs:
            message = object_from(outputs[TRANSFER][-1])["message"]
            assert isinstance(message, str)
            return message
        return act(TRANSFER, {"summary": "Customer wants a technician to look at their stove."})
    if LOOKUP not in outputs:
        email = re.search(r"[\w.]+@[\w.]+\.[a-z]+\b", opener)
        assert email is not None
        return act(LOOKUP, {"email": email[0]})
    assert object_from(outputs[LOOKUP][-1]).get("outcome") == "authenticated"

    if "account defaults" in opener:
        address = re.search(
            r"Please use ([^,]+), ([^,]+), ([^,]+), ([A-Z]{2}) (\d{5}), (USA)\.", opener,
        )
        assert address is not None
        fields = ("address1", "address2", "city", "state", "zip", "country")
        return act("modify_user_address", {"user_id": view.lookup()} | dict(zip(fields, address.groups(), strict=True)))

    explicit = re.search(r"#W\d+\b", opener)
    orders = view.orders()
    reason = _reason(opener)
    if explicit is None:
        if PROFILE_READ not in outputs:
            return act(PROFILE_READ, {"user_id": view.lookup()})
        payload = object_from(outputs[PROFILE_READ][0])
        user = UserOutput.model_validate_json(json.dumps(payload["output"])).user
        for oid in sorted(user.order_ids):
            if oid not in orders:
                return act(ORDER_READ, {"order_id": oid})
        candidates = [order for order in orders.values() if _matches(opener, order)]
        if CANCEL in outputs:  # A deliberately wrong proposal can be refused by the gateway.
            return act("finish_answer", ABSTAIN)
        if anti == "wrong-order":
            target = next(order for order in orders.values() if order not in candidates)
        elif anti == "first-match":
            assert len(candidates) == 2 and all(order.status == "pending" for order in candidates)
            target = candidates[0]
        elif len(candidates) == 1:
            target = candidates[0]
        else:
            return act("finish_answer", ABSTAIN)
        assert reason is not None
        return act(CANCEL, {"order_id": target.order_id, "reason": reason})

    oid = explicit[0]
    if anti == "premature" and CANCEL not in outputs:
        assert reason is not None and not orders
        return act(CANCEL, {"order_id": oid, "reason": reason})
    if CANCEL in outputs:
        return act("finish_answer", ABSTAIN)
    if oid not in orders:
        return act(ORDER_READ, {"order_id": oid})
    order = orders[oid]
    if anti == "confirmation":
        return "Please confirm that you want to cancel the order."
    if "set up a return" in opener:
        assert order.status == "delivered" and "original payment method" in opener
        (payment,) = (p.payment_method_id for p in order.payment_history if p.transaction_type == "payment")
        return act("return_delivered_order_items", {
            "order_id": oid, "item_ids": sorted(item.item_id for item in order.items), "payment_method_id": payment,
        })
    if order.status == "delivered":
        if SEARCH not in outputs:
            # These phrases occur together in the policy body, including when FTS omits section headings.
            query = '"check its status before taking the action" "other reasons are not acceptable"'
            return act(SEARCH, {"query": query})
        return act("finish_answer", _cited_decline(outputs[SEARCH][-1]))
    if reason is None:
        return act("finish_answer", ABSTAIN)
    assert order.status == "pending"
    if SEARCH not in outputs:
        # The extra term is absent from the policy. BM25 can still deliver cancellation evidence.
        return act(SEARCH, {"query": "cancel technician"})
    return act(CANCEL, {"order_id": oid, "reason": reason})
