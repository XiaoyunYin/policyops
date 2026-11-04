"""Pinned retail policy identity and the clause-to-rule table.

Clauses are anchored by 1-based line ranges in the pinned upstream
`data/tau2/domains/retail/policy.md` and the SHA-256 of those exact lines (UTF-8,
joined by "\\n"); the policy text itself is not copied here. The evaluator
command `policyops-evals data policy-trace` checks every anchor against the
pinned bytes. Interpretations are PolicyOps paraphrases.

Enforcement classes:
  deterministic  checked by policyops.domain rules before a proposal is accepted
  presentation   satisfied only by the server-rendered confirmation content
  protocol       enforced on the agent step sequence
  escalate       outside the supported scope: refuse the action and hand off
  not_codified   recorded, not enforced by code (with the reason)
"""

from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from policyops_contracts.base import WireModel
from policyops_contracts.retail import ToolName
from policyops_contracts.scalars import GitObjectId, Sha256Hex, ShortText, Slug


Enforcement = Literal["deterministic", "presentation", "protocol", "escalate", "not_codified"]


class PolicyRef(WireModel):
    source_commit: GitObjectId
    path: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    sha256: Sha256Hex


class PolicyRule(WireModel):
    rule_id: Slug
    line_start: Annotated[int, Field(ge=1)]
    line_end: Annotated[int, Field(ge=1)]
    clause_sha256: Sha256Hex
    enforcement: Enforcement
    tools: tuple[ToolName, ...] = ()
    interpretation: ShortText
    ambiguity: ShortText | None = None


RETAIL_POLICY = PolicyRef(
    source_commit="19f13ea3f5fba8b4c4d272d1353590f29dc53062",
    path="data/tau2/domains/retail/policy.md",
    sha256="2c9652afbce57d6e087768d37cda64d31c53d50b3e3225cfdb791bac66466467",
)

_W = ToolName
_ITEMS = (_W.MODIFY_PENDING_ORDER_ITEMS,)
_EXCHANGE = (_W.EXCHANGE_DELIVERED_ORDER_ITEMS,)
_ORDER_WRITES = (_W.CANCEL_PENDING_ORDER, _W.MODIFY_PENDING_ORDER_ADDRESS, _W.MODIFY_PENDING_ORDER_PAYMENT,
                 _W.MODIFY_PENDING_ORDER_ITEMS, _W.RETURN_DELIVERED_ORDER_ITEMS, _W.EXCHANGE_DELIVERED_ORDER_ITEMS)
_ALL_WRITES = (*_ORDER_WRITES, _W.MODIFY_USER_ADDRESS)


def _rule(rule_id: str, lines: tuple[int, int], digest: str, enforcement: Enforcement, tools: tuple[ToolName, ...],
          interpretation: str, ambiguity: str | None = None) -> PolicyRule:
    return PolicyRule(rule_id=rule_id, line_start=lines[0], line_end=lines[1], clause_sha256=digest,
                      enforcement=enforcement, tools=tools, interpretation=interpretation, ambiguity=ambiguity)


RETAIL_RULES: tuple[PolicyRule, ...] = (
    _rule("scope.supported_requests", (3, 8), "adb745262a0d2ecf60ef3055f12043a9dc63445646936e39ea9ab332fbd86756",
          "escalate", (), "Only cancel/modify pending orders, return/exchange delivered orders, change the default "
          "address and own-account information are in scope; other requests are refused or handed off."),
    _rule("user_address.supported", (7, 7), "2e96467670c66bf1fcb0699053272aae92abffec67954ce8aaf45a1565200fa3",
          "deterministic", (_W.MODIFY_USER_ADDRESS,), "The bound customer's default address may be changed."),
    _rule("auth.lookup_required", (10, 10), "07b97e5b3205eb45429a4e537cc352ce82ee6a359f6a7095f47f16cd5f04f5a9",
          "deterministic", (_W.FIND_USER_ID_BY_EMAIL, _W.FIND_USER_ID_BY_NAME_ZIP),
          "Authenticate by email or name+ZIP lookup in this conversation, even if a user ID is offered; only a "
          "lookup returning the case's bound customer authenticates."),
    _rule("auth.reads_after_authentication", (12, 12),
          "9b572da2a8e9046a8c0139773c1f817950aef2094dbbdcaf1c6a37488ab9c0d3", "deterministic",
          (_W.GET_USER_DETAILS, _W.GET_ORDER_DETAILS, _W.GET_PRODUCT_DETAILS, _W.GET_ITEM_DETAILS,
           _W.LIST_ALL_PRODUCT_TYPES),
          "Profile, order and product reads are allowed only after authentication."),
    _rule("scope.single_customer", (14, 14), "35c4f291b47c698f2ff3d47df5bee971f7fb9326218b5d2edb1882acd7a98603",
          "deterministic", (_W.GET_USER_DETAILS, _W.GET_ORDER_DETAILS, *_ALL_WRITES),
          "Every user, order and payment method used must belong to the bound customer; others are denied."),
    _rule("consent.explicit_yes", (16, 16), "8006d0c4fea14bf6cf28c2c7ff8a296df4b75a96d48e304241f149f489eb4779",
          "presentation", _ALL_WRITES,
          "Every write needs the exact server-rendered action details shown and a later explicit customer yes "
          "bound to that presentation; staff approval is separate.",
          "The policy lists cancel/modify/return/exchange; PolicyOps also applies it to default-address changes."),
    _rule("grounding.no_fabrication", (18, 18), "b79facae907c653d79fd9d6597fc9271e8971d4819261d0a5ce98f8cce267c3e",
          "not_codified", (), "No invented information or subjective advice; checked later by citation validation "
          "and rubric, not by these rules."),
    _rule("protocol.one_action_per_turn", (20, 20), "282756cc14a8799b2d9c041d7fce685c5c96a49b98d1107663b899fb54c500b3",
          "protocol", (), "Each agent step is exactly one tool call or exactly one customer message."),
    _rule("policy.deny_violations", (22, 22), "1c0d6976edd113a686e268068143cd33bd6a15c077678f5528eb342623477d01",
          "deterministic", _ALL_WRITES, "A failed precondition denies the action; it is never retried around."),
    _rule("escalation.transfer", (24, 24), "20d98bbdb1017e4f5d361612717fff09c069044ad50c08252389d662343d3c3c",
          "protocol", (_W.TRANSFER_TO_HUMAN_AGENTS,),
          "Hand off only when out of scope: transfer tool call, then the exact handoff message as the next step."),
    _rule("time.est_database", (28, 28), "e202dde1c02004c4feb7368ec9da2237b0d858f8b41a43b87d42867566c7a4cc",
          "not_codified", (), "The pinned retail DB has no timestamp fields; application times are UTC.",
          "If upstream adds EST times, they map to fixed UTC-05:00, not a daylight-saving zone."),
    _rule("ids.product_item_distinct", (62, 62), "c723aee9877606d77f121b092a1e78457145dd9cf54184f643e53f28ebccb4f6",
          "deterministic", (_W.GET_PRODUCT_DETAILS, _W.GET_ITEM_DETAILS, *_ITEMS, *_EXCHANGE),
          "Product and item IDs are separate typed fields; an item must belong to the stated product."),
    _rule("status.actionable", (82, 82), "4406f95fbd2a4b4227b693f01f3a1082f03c4c71d2b541cfb323e6d9260b38c8",
          "deterministic", _ORDER_WRITES, "Order writes apply only to pending or delivered orders."),
    _rule("orders.modify_exchange_once", (84, 84), "2dfbdc114a29370a0522663e7482bf05703da35b64f7e315095190b08d45ddd2",
          "deterministic", (_W.MODIFY_PENDING_ORDER_ADDRESS, _W.MODIFY_PENDING_ORDER_PAYMENT, *_ITEMS, *_EXCHANGE),
          "Each modify tool and the exchange tool succeeds at most once per order (per tool), checked against "
          "recorded successful executions rather than inferred from status.",
          "Read as once per tool; dev reference workflows change address then items on one order. A combined "
          "one-modification reading is not adopted."),
    _rule("cancel.pending_only", (88, 88), "be51712775959c77490aebe9ae1f231b71477d3760cbd09fff9a338e6a74f9d2",
          "deterministic", (_W.CANCEL_PENDING_ORDER,), "Cancel requires status pending."),
    _rule("cancel.order_and_reason", (90, 90), "85f927e412a03491b5d0882d861c7e480905cd161417609edc64db1766cab65d",
          "deterministic", (_W.CANCEL_PENDING_ORDER,),
          "Exact order ID and one of the two allowed reasons; any other reason is denied."),
    _rule("cancel.effect", (92, 92), "b0c21f985c4bf70ce249a6b9c0631c04d7fffcd032ae73bc329b0c8317ee7a39",
          "presentation", (_W.CANCEL_PENDING_ORDER,),
          "Shown effect: status cancelled; each payment refunded, gift cards immediately, others in 5 to 7 "
          "business days."),
    _rule("modify.pending_only", (96, 96), "7fcf31ced38fe41507b1ab8dddaafec0ba0ba73b52311c7e480c35cee8e7ac98",
          "deterministic", (_W.MODIFY_PENDING_ORDER_ADDRESS, _W.MODIFY_PENDING_ORDER_PAYMENT, *_ITEMS),
          "Order modifications require status exactly pending."),
    _rule("modify.allowed_fields", (98, 98), "bb28a8928fc08f995a463d023ab58b2cb70d403cf5b213795badab9bf34e19b9",
          "escalate", (), "Only shipping address, payment method and item options may change; anything else is "
          "out of scope."),
    _rule("payment.single_different_method", (102, 102),
          "63ae0e7393dc28cc6b06eab09b882b67f00233da19c876a362f08af6f8ecf867", "deterministic",
          (_W.MODIFY_PENDING_ORDER_PAYMENT,),
          "Exactly one new method, owned by the customer and different from the order's single payment.",
          "Orders whose history is not exactly one payment are escalated."),
    _rule("payment.gift_card_covers_total", (104, 104),
          "92423ce544bf620cefffa2c8e9771280b5f0f1196cda38eeeef33116a8ba412f", "deterministic",
          (_W.MODIFY_PENDING_ORDER_PAYMENT,), "A new gift card must hold at least the order total."),
    _rule("payment.effect", (106, 106), "2e8b8fcd06b1b7ba77d3d7ab1c2337667f4e13615b20d4dc5cf2de58718ac590",
          "presentation", (_W.MODIFY_PENDING_ORDER_PAYMENT,),
          "Shown effect: status stays pending; the original method is refunded immediately if a gift card, "
          "otherwise in 5 to 7 business days."),
    _rule("items.once_and_all_items", (110, 110), "11f2f187fdddce12aea8b338de5dea522e0a397a948692d520caca3c946b38ae",
          "presentation", _ITEMS,
          "One-time action: the confirmation states it can be done once and asks the customer to confirm all "
          "items are included; the resulting status is pending (item modified).",
          "Policy prose spells the status 'pending (items modifed)'; the executable value is used."),
    _rule("items.same_product_other_option", (112, 112),
          "cd83aecf1d2060a28ae1771d56333fd561205bf105e97ce4e3bf8a7e9f40e99b", "deterministic", _ITEMS,
          "Each new item is an available variant of the same product with a different item ID.",
          "The pinned simulator applies the last replacement's price and options to every modified item, so "
          "modifications with more than one distinct replacement variant escalate."),
    _rule("items.price_difference_method", (114, 114),
          "568fa8e61b096db7520d6c40f1457d25544b26fb3ad5bb31dbdf7551bb2ecf10", "deterministic", _ITEMS,
          "A customer payment method settles the difference; a gift card must cover a positive difference."),
    _rule("return.delivered_only", (118, 118), "ed1a8b666bade33eaff7d1427b63174036a4023050058b553939dc268be2296b",
          "deterministic", (_W.RETURN_DELIVERED_ORDER_ITEMS,), "Return requires status delivered."),
    _rule("return.order_and_items", (120, 120), "55f30c452733263a926507dbc0f877b111f7ada0838c6ec5a686dce1fa62407f",
          "deterministic", (_W.RETURN_DELIVERED_ORDER_ITEMS,),
          "Exact order ID and an item list that the order contains, counting duplicates."),
    _rule("return.refund_method_required", (122, 122),
          "fbeb12565000d65565e83a0a83ac5050a0ce24879951e5ce55bc649476b0643f", "deterministic",
          (_W.RETURN_DELIVERED_ORDER_ITEMS,), "A refund payment method must be named."),
    _rule("return.refund_destination", (124, 124), "096488a16ac30cc5bdd42ce7a2c48365e33800c2fc9de4b891883eba2bf24e75",
          "deterministic", (_W.RETURN_DELIVERED_ORDER_ITEMS,),
          "Refund goes to the original payment method or one of the customer's existing gift cards."),
    _rule("return.effect", (126, 126), "02caf3b3fc3900e965ef38c541b94d6aa585fb6e3d6861e2297129413a8d5d78",
          "presentation", (_W.RETURN_DELIVERED_ORDER_ITEMS,),
          "Shown effect: status return requested, the returned items, their purchase-price total and the refund "
          "destination; upstream computes no refund amount."),
    _rule("exchange.delivered_only_all_items", (130, 130),
          "fc134f759d49da4a0287e5892abf5c61ab44068861f1b19064887e966060dbc1", "deterministic", _EXCHANGE,
          "Exchange requires status delivered; the confirmation asks the customer to confirm all items are "
          "included."),
    _rule("exchange.same_product_other_option", (132, 132),
          "e5a1e8d4c8d4d9671d99b83651b93911af5fdd377e6b9abfb559edebde974da4", "deterministic", _EXCHANGE,
          "Each new item is an available variant of the same product with a different item ID."),
    _rule("exchange.price_difference_method", (134, 134),
          "568fa8e61b096db7520d6c40f1457d25544b26fb3ad5bb31dbdf7551bb2ecf10", "deterministic", _EXCHANGE,
          "A customer payment method settles the difference; a gift card must cover a positive difference."),
    _rule("exchange.effect", (136, 136), "adc0923e7fd4155456970b310ed94cd04ce267fea3be62d50c6e1da119408c69",
          "presentation", _EXCHANGE, "Shown effect: status exchange requested; no new order is placed."),
)
RULES_BY_ID = {rule.rule_id: rule for rule in RETAIL_RULES}
