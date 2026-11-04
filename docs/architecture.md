# Architecture: retail contracts and domain rules

This page describes what is implemented so far. The application database (schema, roles, migrations) is described
in [database.md](database.md); HTTP handlers, the agent runtime, the retail simulator and the web UI are later work. The contracts and rules below are pure, typed and tested, but they do not by
themselves authorize anything at runtime.

## Packages

| Package | Contents | Depends on |
|---|---|---|
| `packages/policyops_contracts` | Wire contracts (Pydantic, strict, frozen, unknown fields rejected), the pinned retail policy rule table, server-rendered confirmation text, canonical digests, JSON Schema export | Pydantic, standard library |
| `packages/policyops/.../domain` | Deterministic rules: write preconditions and exact effects, proposal sealing, consent and approval decisions, customer session, agent step protocol, role matrix, synthetic examples | `policyops_contracts` only (no HTTP, database, orchestration or provider SDK) |
| `evals` | Evaluator: pinned upstream data, splits, the retail calibration allowlist, metadata-only demo seeds, policy-trace and server-only seed bindings | `policyops_contracts`, pinned tau2; never the application package |

Contract wire version: `CONTRACTS_SCHEMA_VERSION = "0.2.0"` (the 0.1.0 `WireModel` base is unchanged).
Generated JSON Schemas are in `packages/policyops_contracts/schemas/`; fictional examples are in
`packages/policyops_contracts/examples/`. Both are regenerated and compared byte for byte by the tests:

```powershell
python -B scripts/devenv.py uv run --frozen python -B -m policyops_contracts.schema_export --check packages/policyops_contracts/schemas
python -B scripts/devenv.py uv run --frozen python -B -m policyops.domain.examples --check packages/policyops_contracts/examples
```

## Retail scope and policy traceability

Tool calls mirror the pinned upstream retail toolkit (tau2 `19f13ea3`): 7 read tools, 7 write tools, `calculate` and
`transfer_to_human_agents`, with upstream argument names and ID formats. Order statuses use the executable upstream
values, including `pending (item modified)`; the policy prose misspells it `pending (items modifed)`.

`policyops_contracts.policy.RETAIL_RULES` maps 34 policy clauses to enforcement classes:
22 deterministic, 6 presentation, 2 protocol, 2 escalate and 2 not codified. Each clause is anchored by its line
range in the pinned `policy.md` and the SHA-256 of those exact lines, so no policy text is copied.
`policyops-evals data policy-trace --acquired <fetch>` verifies every anchor against the pinned bytes and lists the
policy lines no rule cites (data-model prose).

Interpretations worth knowing:

- **One-shot tools.** The clause "exchange or modify order tools can only be called once per order" is read *per
  tool*: each of address change, payment change, item modification and exchange succeeds at most once per order.
  Dev reference workflows change the address and then the items of the same order, which a single
  "one modification in total" reading would forbid. Repetition is checked against a supplied
  `OrderOperationHistory` (execution records, later tasks), not inferred from status. Incomplete history escalates.
- **Policy rules upstream does not enforce in code** become deterministic rules here: authenticate by lookup even if a
  user ID is offered; one customer per conversation; a different item option for modifications and exchanges; and an
  explicit "yes" before any write. The confirmation rule is applied to default-address changes too.
- **Calculator.** Upstream evaluates `calculate` expressions after only a character check. The contract accepts only
  `+ - * /`, unary signs, parentheses and bounded finite numbers, validated on the syntax tree without evaluation.
  Its result is never exact-money evidence.
- **Out of scope** requests and unspecified situations escalate: missing snapshots, unexpected payment history, or an
  original payment method that is not in the profile. Escalation never certifies an action.

## Known pinned-source behaviour (simulator parity)

The previews are the *expected* effects on supplied facts. Where the pinned upstream tool is known to produce
something else, the preview either escalates or says only what the tool records:

- `modify_pending_order_items` applies the price and options of the **last** replacement variant to every modified
  item. A modification with more than one distinct replacement variant therefore escalates. Several old items
  replaced by one variant are previewed normally.
- `modify_pending_order_items` stores the price difference as an unrounded float (for example `14.249999999999943`),
  which is not exact-money compatible.
- `exchange_delivered_order_items` only records the request (sorted item lists, payment method, rounded difference).
  It makes no payment or refund, so the exchange confirmation says it records a quoted difference and that no charge
  or refund is made by the request. Exchange previews keep the requested item pairs and multiplicity.

Validating the simulator's actual state change and exact-money conversion against the approved effect, before
committing a snapshot and receipt, belongs to T16. A mismatch must not produce a success receipt.

## Customer, consent and approval

- **Binding versus authentication.** A seeded case has a server-only `CaseCustomerBinding` (scope). A
  `CustomerAuthentication` is created only when an email or name+ZIP lookup in the run returns that same customer. A
  different customer is a mismatch to deny and audit; nothing rebinds a case. Reads (other than lookups, `calculate`
  and transfer) wait for authentication, and every user, order and payment method must belong to the bound customer.
- **Proposal.** `ActionProposal` binds under one SHA-256 `action_digest`:
  - workspace/case/run scope and the bound customer;
  - proposal ID, version and intent digest;
  - the typed write call;
  - the computed effect and the exact server-rendered text shown for it;
  - the policy version and the rules checked;
  - resource versions (user, order, product) and evidence versions;
  - creation and expiry (at most 15 minutes).

  Construction and deserialization re-check that the effect matches the call (item order and multiplicity
  included), that the text is the rendering of the effect, and that the digest matches. Effects also carry their
  derivable invariants:
  - status pairs per action kind;
  - price differences equal to the listed price changes;
  - a different item for every change;
  - return totals equal to the listed item prices;
  - a different payment method, with refund timing that follows the original method.

  A self-consistent record is still not proof of current business state. Money is integer minor units: upstream
  floats convert exactly or are rejected (bool, NaN, infinities, strings and more than two decimals), using integer
  arithmetic that the thread's decimal context cannot change. Item modification and exchange texts state the one-time
  nature and ask the customer to confirm the list contains every item.
- **Customer consent** comes only from a customer message, simulated or operator-entered (the operator is
  recorded). It must follow the presentation of the exact proposal version, in time order: proposal, then
  presentation, then customer message, then now. Evidence dated in the future, or a presentation older than its
  proposal, is never consent. The reply must be an explicit affirmation from a small fixed set. Hedged, conditional
  or combined replies ask again; no model judges a reply. Consent is current from its confirmation until the earlier
  of the proposal expiry and 15 minutes. Any new proposal version or changed resource version invalidates it.
- **Staff approval** is a separate record by a principal with the reviewer role (admin alone is not enough). That
  principal cannot be the operator who typed the consent message. Approval is decided after the consent is confirmed,
  is not current before its decision time, and expires no later than the consent and the proposal. Lifetimes are
  checked by subtraction and computed expiries are capped at the largest representable UTC time, so extreme dates
  yield validation results instead of overflow errors. `ready_to_execute` checks mutual consistency and chronology at
  one instant; persistence, execution-time rechecks and idempotent execution are later tasks.

## Agent protocol, events and errors

Each retail agent step is exactly one tool call or exactly one customer message. A transfer must be followed, as the
next step, by the exact handoff message, which ends the conversation. Run event payloads have no free-form text
fields: IDs, digests, enumerated codes and timestamps only, under a versioned envelope. A tool event's read/write kind
must match the tool. Errors are an envelope with a stable code, bounded free-text detail, optional rule ID,
correlation ID and retryability; the replayable error event carries the code and IDs, not the detail.

Length bounds and control-character rejection are not a text-safety guarantee. Bounded text can still contain HTML,
prompt text, personal data or secrets. Rendering must escape it, logging must redact it, and services must control
where it comes from.

## Roles

| Action | analyst | reviewer | admin | auditor |
|---|---|---|---|---|
| View case | yes | yes | yes | yes |
| Create case, staff note, operator customer turn, start/cancel run | yes | yes | yes | no |
| Decide proposal | no | yes | no | no |
| Manage membership | no | no | yes | no |
| Read audit and evaluation summaries | no | yes | yes | yes |

## Dev calibration allowlist and demo seeds

`evals/manifests/tau2-19f13ea3/retail-calibration.json` is rebuilt from the committed T03 manifests by
`policyops-evals data calibration --check` and validated by `check-manifests`. The official 64-dev / 50-holdout split
is unchanged. Excluded from demos, smoke runs and tuning are 18 dev tasks:

- 12 with a held-out scenario neighbour at Jaccard ≥ 0.7;
- 3 with open upstream issues;
- 9 whose reference actions raise during replay.

That leaves 46. Tags come from the dev replay: 44 `mutation` (the reference actions changed the database without
errors) and 2 `read_only` (24, 57). Each seed carries only a neutral label (`Retail demo <id>`), the tag and the
allowlist digest. Tags, seeds and bindings are operator and server metadata; the runtime task view stays limited to
domain, task ID, split and purpose.

`policyops-evals data seed-bindings --acquired <fetch> --out <private dir>` derives the server-only customer binding
for each seed and writes it outside the repository; it is never committed. The binding comes from the reference
identity lookup or the owner of the resources the reference actions name, using read-only upstream calls on the
pinned DB. It currently yields 44 bindings; tasks 24 and 57 name no customer and are reported unavailable.
