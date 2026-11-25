# Architecture: retail contracts and domain rules

This page describes the implemented contracts, services and runtime boundaries. The application database (schema, roles, migrations) is described
in [database.md](database.md), and OIDC/session authentication handlers and role dependencies in
[authentication.md](authentication.md). The case/message and review APIs, bounded investigation graph, approval continuation,
execution/reconciliation services and web UI are implemented. The default Compose demo leaves
model-driven investigation unconfigured and verifies a deterministic proposal through real
consent, approval and execution. See [operations](operations.md) and [evaluation](evaluation.md)
for the measured scope. Pure contracts do not authorize a runtime action; services establish
current authority and database roles constrain persistence.

## Packages

| Package | Contents | Depends on |
|---|---|---|
| `packages/policyops_contracts` | Wire contracts (Pydantic, strict, frozen, unknown fields rejected), the pinned retail policy rule table, server-rendered confirmation text, canonical digests, JSON Schema export | Pydantic, standard library |
| `packages/policyops/.../domain` | Deterministic rules: write preconditions and exact effects, proposal sealing, consent and approval decisions, customer session, agent step protocol, role matrix, synthetic examples | `policyops_contracts` only (no HTTP, database, orchestration or provider SDK) |
| `evals` | Evaluator: pinned upstream data, splits, the retail calibration allowlist, metadata-only demo seeds, policy-trace and server-only seed bindings | `policyops_contracts`, pinned tau2, local `policyops` for composition of minimal agent/ports, bounded providers, budgets and evaluation persistence only; application code never imports tau2 |

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
  `OrderOperationHistory` (the execution ledger), not inferred from status. Incomplete history escalates.
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

The retail simulator validates the actual state change and exact-money conversion against the approved
effect before committing a snapshot and receipt. A mismatch produces no success receipt.

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
  one instant; persisted authority, execution-time rechecks and the operation ledger enforce the runtime path.

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
| Create case, change case status, staff note, operator customer turn, start/cancel run | yes | yes | yes | no |
| Decide proposal | no | yes | no | no |
| Manage membership | no | no | yes | no |
| Read audit and evaluation summaries | no | yes | yes | yes |

## Case and message API

Routes under `/api/v1` (`policyops.api.cases`, service `policyops.services.cases`). Every route needs a session
with a selected workspace and runs in that workspace's row-level-security scope, so another workspace's case is
`404 api.case_not_found`, like an unknown ID.

| Route | Action | Notes |
|---|---|---|
| `GET /cases?status=&cursor=&limit=` | view case | newest first by immutable `(created_at, id)`; `limit` 1–100, default 50 |
| `POST /cases` | create case | body `{"scenario": "retail"}`; the case starts `open`, version 1, no bound customer |
| `GET /cases/{id}` | view case | `ETag` is the strong case version, for example `"3"` |
| `PATCH /cases/{id}` | change case status | body `{"status": ...}`; `If-Match` required |
| `GET /cases/{id}/messages?after_sequence=&limit=` | view case | sequence order; `limit` 1–200, default 50 |
| `POST /cases/{id}/messages` | staff note or operator customer turn | body `{"source", "text"}`; `If-Match` required |

- **Provenance is server-owned.** The browser may send only `staff_note` or `operator_entered_customer`. Actor,
  workspace, IDs, times, sequence and digests are set by the server. Unknown body fields are refused. Customer
  binding stays a trusted seed path. `scenario` reports the stored value; the API itself creates only retail
  cases.
- **Status.** A pure table allows `open → in_progress → resolved → closed` and `resolved → in_progress`;
  `closed` is terminal and anything else is `409 api.status_transition`. Asking for the current status is a no-op:
  no version change and no audit row.
- **Versions.** A status change and a message append each advance the case version (and `updated_at`). The
  append does it under the same row lock that allocates the sequence. Two operators posting against the same
  version conflict: one wins and the other gets `409 api.stale_version` and must reload.
- **Idempotency.** Every write needs an `Idempotency-Key` (8–128 of `A-Za-z0-9._~-`); a missing key is
  `400 api.idempotency_key_required`. Keys are scoped by workspace, principal and operation. The request is
  reduced to a typed, versioned intent (path IDs, body and expected version), and its SHA-256 is stored with the
  original successful status, body and ETag in one transaction with the change and its audit row. A retry with
  the same intent gets that original response, byte for byte, with `Idempotent-Replayed: true`, even after later
  changes and even with its old `If-Match`. A different intent for the key is `409 api.idempotency_mismatch`.
  Concurrent requests with one key wait on a transaction-scoped advisory lock, so exactly one change happens. A
  failed attempt stores nothing and the key can be retried. Replay happens only after the current role is
  rechecked (after the lock wait) and the case is visible in the selected workspace. Stored responses do not
  expire; any later retention policy must keep the replay guarantee.
- **Preconditions.** `If-Match` must be one strong case ETag. Missing is `428 api.precondition_required`;
  malformed (weak, `*`, lists, zero, out of range) is `422 api.invalid_precondition`.
- **Pagination.** The queue cursor is untrusted data, not a capability: a strictly typed, canonical, base64url
  document bound to the workspace and the status filter; anything else is `422 api.invalid_cursor`. Each page
  reads live rows strictly after the cursor's `(created_at, id)` position. A case inserted later appears on a
  later page only if its `(created_at, id)` sorts after that position: one with a newer `created_at` (the usual
  case) does not, but one with the same `created_at` and a smaller `id`, or an older `created_at` from a clock
  that moved back, does. A case whose status changes between pages can be missed by, or appear later in, a
  status filter. There is no snapshot across pages.
- **Bounds and errors.** Bodies are bounded to 64 KiB as received (`BodyLimit`, a pure ASGI pre-read). A larger
  declared length is refused before reading; otherwise reading stops at the chunk that passes the limit (`413`).
  A malformed or repeated `Content-Length` is `400`. Message text is 1–4000 code points; newline and tab are
  allowed, other control characters (C0, DEL and C1) are not, and it must be encodable Unicode (a lone surrogate
  is `422`). Errors use the standard envelope without
  echoing input. Responses are `no-store` with `Referrer-Policy: no-referrer`.
- **Refusal order.** Body limits and undecodable (`400`) or malformed JSON (`422`) are refused while reading the
  body, before authorization. Authorization then precedes body-model validation, header parsing, idempotency
  lookup and the service.
- **Audit.** Each successful create, status change and message post appends one actor-attributed audit row
  (`case.created`, `case.status_changed`, `case.message_posted`). Replays and no-ops add none.

The OpenAPI document `packages/policyops/openapi/v1.json` is exported from the served route composition, without
a runtime, settings or database (`python -m policyops.api.openapi --check FILE`). Requirements that PolicyOps
dependencies enforce (session cookie, CSRF token and Origin, the required `PolicyOps-Expected-Principal` and
`PolicyOps-Expected-Workspace` headers on the 16 workspace-bound operations, `Idempotency-Key`, `If-Match`,
cookie-setting responses) and every error status are documented explicitly with the error envelope. The expected
context is a refusal precondition (409 `context_changed`), never a selector; see
[authentication](authentication.md#expected-context-cross-tab-binding). FastAPI's default
validation-error body is refused because the API never returns it. `apps/web/src/api/schema.d.ts` is generated
from it by `scripts/api_types.py` with openapi-typescript 7.13.0, in an isolated, exactly locked generator project
(`scripts/api-types`). openapi-typescript 7.13.0 declares a TypeScript 5 peer, while the web app uses TypeScript 6,
so the generator has its own TypeScript 5.9.3 instead of changing the web toolchain. The generator gets the
parsed document with only local references, an explicit Redocly configuration (no `redocly.yaml` discovery, no
tokens), a minimal environment and closed proxies. The tests check real HTTP responses against the document and
compile real bodies against the generated types.

## Runs, leased jobs and event streaming

Packages: `policyops.runtime` (lease clock, runtime specs, worker, outbox dispatcher), `policyops.persistence.runs`,
`policyops.services.runs` and `policyops.api.runs`.

| Route | Action | Notes |
|---|---|---|
| `POST /cases/{id}/runs` | start run | body `{"mode": "workbench"}`; `Idempotency-Key` and strong case `If-Match`; 202 with `Location` and `ETag` |
| `GET /runs/{id}` | view case | `ETag` is the run version |
| `POST /runs/{id}/cancel` | cancel run | `Idempotency-Key`; no version precondition |
| `GET /runs/{id}/events` | view case | server-sent events; `Last-Event-ID` or `?after=` |

- **Start.** It takes the case-API idempotent write path (replay of the original 202, 409 for a changed intent). Then,
  under the case lock, it rechecks the current role and the case version, and allows at most one active workbench
  run per case (`409 api.run_active`, also enforced by a partial unique index). It creates, in one transaction:
  - the run, bound to the case version, the initiating principal and the frozen server runtime spec (its real
    graph, prompt and config digests);
  - its first event and outbox intent;
  - its execute job;
  - an audit row.

  Mode, digests, times and fences are all server-owned.
- **Runtime configuration.** An investigation runtime can be composed with
  `build_investigation_spec` and installed in the API/worker catalog. The default served API
  and Compose demo leave it unconfigured: a fresh start returns `503 runtime.unconfigured`
  before any write. The packaged worker still handles review continuations and reconciliation.
  Scripted executors and fixed clocks are refused outside the test environment.
- **Time authority.** Leases, deadlines and run/job/event times come from PostgreSQL `clock_timestamp()`. It is read
  after the locks a decision depends on: `now()` is the transaction start, and would still accept a lease that
  expired while the transaction waited for a lock. A test proves this boundary.
- **Lock order.** Everywhere: idempotency key → case → run → job → outbox rows. A heartbeat takes only the job lock.
  No transaction spans an executor call, a sleep, an SSE yield or a human wait.
- **Discovery and claims.** The worker discovers candidate jobs (due queued jobs and expired leases) as the narrow
  `policyops_worker_discovery` role, which reads only scheduling metadata. It then claims as the app runtime in the
  job's workspace, with `SKIP LOCKED` on the run and then the job. Before any work it rechecks, in that order:
  - the job kind and its allowed run states; investigation execution, review continuation and
    outcome projection have separate handlers and authorization;
  - the deadlines and the remaining attempts;
  - the spec matching all three digests;
  - the initiator's current START_RUN permission, checked at every claim (each attempt). An ended browser
    session does not stop authorized background work. A revoked membership stops the next claim, but it does
    not interrupt an executor already running under a claim; cancellation and the lease fences do that.
- **Fencing.** A claim sets a new stable `claim_id` and increments the run's `generation`; heartbeats extend the
  lease without changing either. Every worker write (event, state, finish, release) locks the run and then the job,
  and verifies all of the following, failing closed otherwise (`Fenced`):
  - the claim ID and owner;
  - the generation;
  - an unexpired lease (so an expired claim that nobody has reclaimed yet cannot write either);
  - both deadlines;
  - a non-terminal state.

  Cancellation and reclaiming change the generation, which fences out any earlier claim.
- **Dead letters and retries.** Attempts are counted at claim, so a killed worker's attempt counts. Typed codes:
  `executor_unavailable`, `initiator_not_authorized`, `max_attempts`, `deadline_exceeded`, `run_not_runnable`
  and `unsupported_job_kind`; `run_cancelled` and `run_failed` mark finished jobs.
  - Transient outcomes are released with bounded exponential backoff.
  - When no retry slot is left before the deadline, the job is dead-lettered instead of being scheduled at it.
  - A failed run gets an `error.raised` event with an error code and rule ID.
  - Logs carry codes, IDs and exception type names, never exception text.
- **Cancel** is a desired-state action. Under the run, then job, locks, it moves an active run to `cancelled`,
  increments the generation, finishes the job, and appends the event, outbox intent and audit row together. A
  terminal run is returned unchanged with no event. Cancellation cannot undo a remote commit; the ledger continues reconciliation and reports late receipts.
- **Events and outbox.**
  - **Allocation.** Sequences come from the run's durable `event_highwater` under the run lock, never
    `MAX(sequence) + 1`, so a retired sequence is never reissued.
  - **Retention floor.** `event_retention_floor` is the last retired sequence (0 = none). There is no automatic
    purge, and the runtime cannot move the floor.
  - **Outbox.** Each event writes an outbox intent in the same transaction. The dispatcher publishes the intents
    for one workspace with a single `pg_notify('policyops_run_events', '')` and sets `delivered_at` in the same
    transaction. `delivered_at` therefore means "publication committed", not "a client received it", and
    identical wake-ups coalesce.
  - **Payload.** The notification payload is empty, because every session of the same database can LISTEN.
    Polling the durable events is the correctness path.
  - **Other topics.** Rows of other topics are left undelivered and cannot starve discovery.
- **Stored events** are decoded only when their schema version is supported and their payload is a valid typed
  event of the stored type. Anything else is streamed in its place as `event: unsupported`, carrying only its
  identifiers; its content is never relabelled or completed.
- **Event stream (SSE).**
  - **Frames.** `id: <sequence>`, `event: <type>`, `data: <EventEnvelope JSON>`. Control frames (`: heartbeat`,
    `event: resync`, `event: reconnect`) carry no `id`.
  - **Position.** `Last-Event-ID` takes precedence over `?after=`, and only the selected value is validated:
    digits only, 0 allowed.
  - **Refused before any headers are sent:** malformed (`422 api.invalid_event_position`), ahead of the high-water
    mark (`422 api.event_position_ahead`), below the floor (`409 api.event_gap_resync_required`), or a foreign run
    (404).
  - **Each poll** rechecks the session and current membership, then reads one bounded batch in a short
    transaction. A revocation ends the stream with no further data.
  - **End.** The stream ends after a terminal run's last event, or at the maximum lifetime with `reconnect`. The
    lifetime is checked before every event, so a full batch or a slow reader cannot extend it.
  - **Delivery deadline.** Independently, the outermost `StreamDeadline` middleware cuts the whole response off at
    `max_lifetime + delivery_grace`, including a send stalled by a client that stopped reading. No further frame is
    sent, so no ID is invented, and the client reconnects from its last received ID.

Limits:
- The default Compose demo does not install model-driven investigation. The graph is separately
  composed and tested; the packaged worker executes review and recovery jobs.
- Real-process and Compose kill/restart checks cover selected windows, not every crash boundary.
- Cross-database clock skew does not apply, because the database clock is the only authority.
- A job kind that some worker does not support is dead-lettered by that worker, so new kinds must ship only after
  every worker supports them.
- **Stream cancellation and in-flight polls.** When the stream is cancelled (the delivery deadline, a disconnect),
  a session check or database poll that is already running (including the initial authorization and preflight
  snapshot before any headers are sent) is abandoned, not interrupted. Its worker thread
  finishes the query, ends its short transaction and returns the connection to the pool. Until then it holds that
  connection and a thread. Runtime transactions configure finite statement/lock/idle timeout profiles, but these are per operation
  and do not prove total socket or cleanup deadlines. The HTTP response itself still ends at the deadline.
- **What the deadline covers.** The delivery deadline and the stalled-send behaviour were tested at the ASGI level
  (including the composed app over real PostgreSQL), not with a stalled physical socket or behind a reverse proxy.

<a id="proposal-review-t18"></a>

## Proposal review

Packages: `policyops.services.proposals` (creation, presentation and customer reply), `policyops.services.decisions`
(staff decisions), `policyops.services.proposal_views` (views, derived state, cursors), `policyops.api.proposals`
(routes), and `policyops.gateway.stores` (`PgDecisionStore` and `PgEvidencePort`, the precheck's persisted authority
records). Pure rules are in `policyops.domain` (`retail_rules.propose`, `consent_rules`, `approval_rules`).

| Route | Required permission | Notes |
|---|---|---|
| `GET /approvals?cursor=&limit=` | decide proposal | Reviewer inbox: presented versions with a consent current now and no decision, oldest first by `(created_at, id)` |
| `GET /cases/{id}/proposals?cursor=&limit=` | view case | Every version in the case with its derived state; bounded and paginated |
| `GET /proposals/{id}?version=` | view case | One version (the latest by default), exactly as sealed, with presentation, consent, decision, derived state and server time |
| `POST /proposals/{id}/decision` | decide proposal | Approve or reject one exact version; CSRF and Origin checked |

No route creates, presents, collects consent for or executes a proposal. Creation and presentation are internal investigation operations; customer replies enter through the
case message API. Decision jobs continue into execution/reconciliation and deterministic outcome projection.

**Sealing and binding.**
- `propose` seals an `ActionProposal` once, under one `action_digest`: its scope and customer, the typed write call,
  the computed effect and exact text, the policy version, resource and evidence versions, and an expiry of at most
  15 minutes. Reads re-validate the stored body and compare its digest with the row.
- Creation takes its locks first (case, then corpora `FOR SHARE` for evidence, then run), then reads the clock. It
  checks that the case is bound to the scope's customer, that the run is not terminal and that a lookup
  authentication exists. Intake refuses an invalid call, more than 32 evidence references, duplicate citation IDs or
  a rationale outside 1–1000 characters before any transaction work. Nothing is written on refusal.
- A new version of the same intent in a case supersedes its active versions in the same transaction, so at most one
  version per (case, intent) is presented. Statuses only move forward (database trigger), so a superseded version
  never regains authority.
- `present` stores the exact text as one agent message with a presentation record and run events. A text that does not
  fit one 4000-character case message is refused (`presentation.message_limit`); it is never truncated or split.

**Consent and approval are separate records.**
- Customer consent comes only from a customer message after the presentation of that exact version (see
  **Customer, consent and approval**). Hedged replies ask again. Consent is current from confirmation until the earlier
  of the proposal's expiry and 15 minutes.
- A staff decision (`DecisionService.decide`) takes its locks in this order: run, then proposal row, then the
  principal's active memberships (`FOR SHARE`). The reviewer role is required before any replay, and an admin without
  it gets 403. The request's `action_digest` must equal the sealed one, or the response is 409. A new decision also
  needs a presented, unexpired version and policy, and a current consent (rejection needs one too). The operator who
  typed the consent cannot decide it (403 `api.separation_of_duties`). Its expiry is the minimum of the proposal expiry,
  the consent expiry and the decision time plus 15 minutes.
- Responses: `201` with the immutable `ApprovalDecision` for a new decision; `200` with `Idempotent-Replayed: true` and
  the original canonical record for an identical request by the same reviewer. Identity here means the same reviewer,
  proposal version, `action_digest`, decision and reason, not raw HTTP body byte equality: the returned canonical record
  bytes are identical. For a new decision, `409` covers any other request on a decided version, a superseded or expired
  version, or a missing consent. Replay is different: an identical persisted request still answers after its version
  expires, is superseded or its run ends, provided the reviewer's current role and membership and the digest still pass.
  The presentation, status, policy, expiry and current-consent checks apply to new decisions only. There is no
  `Idempotency-Key`: the natural key `(proposal_id, proposal_version)` and that identity are the rule.
- **Unknown outcome.** An exception raised by COMMIT after the decision body completed becomes
  `DecisionCommitUnknown`, returned as `503 api.decision_outcome_unknown` with `retryable: true`. It is never reported as
  success. The recovery is to resend the identical request: it replays the original if the first attempt committed.
  Lock waits and COMMIT are synchronous and have no hard wall-clock interruption, so an acknowledged decision can
  already be past its own expiry when the response arrives.
- A new decision appends one `approval.decided` run event and one audit row. The decision transaction queues a durable review continuation; it sends no business mutation.
  The execution precheck re-collects facts and refuses a stale approval.

**Reads.**
- Derived state (`awaiting_presentation`, `awaiting_consent`, `awaiting_decision`, `approved`, `approval_expired`,
  `rejected`, `superseded`, `expired`) is computed per read from persisted records and one clock reading, and never
  written. `approved` means only that a bound, unexpired decision exists.
- The detail is mutable derived state over an immutable version, so it has no `ETag` or conditional read. The binding a
  client needs is the decision's `action_digest`.
- Lists are bounded (`limit` 1–100, default 50) and use a canonical cursor bound to the workspace and the list (`inbox`
  or one case). An invalid cursor is 422. A cursor is untrusted pagination data, not a capability, and row-level security
  still bounds every row.

**Evidence currentness.** At create and when the execution precheck is invoked, `evidence_status` locks the cited corpora `FOR SHARE`
in sorted key order and re-reads each citation: version digest, active generation, ready generation and an active
document version. A mismatch is `stale_evidence`, and contradictory signals are `evidence_inconsistent`. If the active
pointer names a generation that is not ready, row-level security hides its chunks from the runtime role, so its
citations are not found and are refused as stale; the refusal does not separate this case from other missing citations. The port `PgEvidencePort.is_current` has no run argument, so it cannot recheck run
provenance; provenance is checked at creation and preserved by the sealed proposal. Currentness says nothing about
whether a cited text is true or supports a claim.

**Limits.**
- A decision approves one exact sealed version. It is a staff record, separate from the customer's consent, and it does
  not by itself execute anything. Resource versions are not re-read at decision time (that would need the retail
  service); the execution precheck re-collects facts and refuses a stale approval.
- Commit and lock waits have no hard wall-clock interruption (see the unknown-outcome note above).
- The tests that exercise these paths are `tests/unit/test_proposal_review.py`, `tests/unit/test_decision_service.py`,
  `tests/integration/test_proposal_api.py`, `tests/integration/test_proposal_decisions.py` and
  `tests/integration/test_proposal_evidence.py`; the integration cases run in the Ubuntu PostgreSQL CI job.

## Model configuration and usage budgets

`policyops.budget` (budget) holds the allowed models, their dated prices, the cost calculator, the actor configuration,
the usage ledger rules and the offline evaluation preflight. It imports no provider SDK or HTTP framework and makes
no provider call itself. The provider adapters (see "Provider adapters" below) account for every physical request
they make through this ledger. The configured investigation and evaluation runtimes call them through the same bounded ports.
Dated compatibility smokes below are separate from [model-quality studies](evaluation.md).

- **Price snapshot.** `pricing.2026-11-05.v1` holds standard first-party text-token rates per million tokens, read
  on 2026-11-05 from the providers' public model, pricing and prompt-caching pages (listed in `prices.SOURCES`).
  These are dated evidence, not a claim about any account's access or invoices.
  - A request is priced at the tier of its **whole prompt**, cache reads and writes included. Haiku 5.5 is short up
    to 100000 prompt tokens. Luna is short up to 272000, the recorded reading of "more than 272K"; its long rates are
    the documented multipliers (input and cache x2, output x1.5), written out.
  - Cache writes have a rate per lifetime: OpenAI 30m and 12h, Anthropic 5m and 1h.
  - Reasoning tokens are part of the billed output and are never added again.
  - Every amount is an exact `Decimal`; nothing is rounded or truncated.
- **Registry.** Only the listed models, efforts and cache modes are allowed, and there is no fallback. Luna allows
  effort `low` or `none`; Haiku allows `low`; the embedding model allows 1536 dimensions. Embeddings have their own
  request limits from the provider's documentation (8192 tokens per input, 300000 tokens and 2048 inputs per
  request, no empty input); chat effort, output and cache settings do not apply to them.
- **Cache mode `none` is a contract with the request serializer.** It is reserved as ordinary input only, which is
  valid only if the request really disables caching. For OpenAI, omitting the cache options does not disable it:
  implicit caching writes at the 30m lifetime. The provider adapters (below) implement the contract: OpenAI requests
  send `prompt_cache_options.mode = "explicit"` with no breakpoints, and Anthropic requests carry no cache markers
  and no replayed thinking. `registry.CACHE_NONE_CONTRACT` keeps its recorded per-provider descriptor unchanged (its
  Anthropic text still says "unverified", as written before any live run). It is part of every actor configuration
  digest, so it is not rewritten.
- **Actors and caps.**
  - Defaults: agent, simulator and reranker use Luna with low effort; the judge uses Haiku with low effort; the
    embedding model is called at 1536 dimensions.
  - Chat requests are capped at 16000 input and 2048 output tokens. The embedding actor reserves at most 8192 tokens
    and 64 inputs per request.
  - A workbench run gets 12 calls and $0.05, counting every request of every actor. An evaluation scenario gets
    $0.20, an invocation $5, and a study $5 unless its manifest declares another finite ceiling.
  - A non-run operation (including ingestion) gets its own finite budget: 64 calls and $0.05.
  - `BudgetSettings` reads optional `POLICYOPS_BUDGET_*` overrides from the environment only. A variable that is
    present must be valid (an empty value is refused, never treated as the default), and every value is checked
    against the registry and the caps.
- **Reservations (decision D4).** An attempt reserves its actor's worst case before it is sent: the highest tier its
  admitted maximum prompt can reach, every prompt token written cold at the configured cache lifetime, plus the
  maximum output. The default chat reservation is $0.002624, the embedding one $0.00016384. Settlement prices the
  actual usage at the attempt's own price revision. One revision names one price table; installing a second,
  different table under the same revision is refused.
- **Ledger.** One accounted provider request is one usage attempt; a retry is a new attempt. `Ledger` applies the
  same rules to the app store (workspace RLS) and the evaluation store (eval runtime), over static SQL.
  - `reserve` holds the worst case and one call slot in **every** applicable scope, in one transaction. The scopes
    come from a canonical binding and never from a caller's list: a run, an operation, or a study with an invocation
    and a scenario.
  - A scope is created on first use with the server's caps. Recreating it with the same caps is a replay and with
    different caps a conflict, so a new attempt ID or a restarted process cannot reset a budget.
  - The same attempt ID with the same intent is a replay; a different actor configuration or operation is a
    conflict. The intent includes the digest of the full actor configuration, so an effort change is a different
    intent even when it prices the same.
  - `begin_dispatch` moves reserved → dispatching in a committed transaction before any I/O, and consumes the call
    slot for good. Only the caller that makes that transition gets `DispatchGranted`. Every other caller gets
    `DispatchRefused` with a reason: the attempt is already past `reserved`, a scope is overrun, or the run is no
    longer active.
  - `release` is allowed only from `reserved`. Nothing that may have been sent is ever released.
  - `mark_unresolved` keeps the conservative hold when usage is unknown, and never downgrades a settled attempt.
  - `settle` moves the hold to spent at the true cost. If the cost exceeds the reservation, the attempt and every
    scope it charges become `overrun`, which blocks new holds and dispatches there. Settlement is still recorded
    after a run is cancelled; it authorizes nothing else.
  - App settlement also writes one `usage_events` row for the attempt. Reusing a provider request ID that already
    belongs to another attempt is a conflict that keeps the hold.
  - Lock order: the run row (`FOR SHARE`, for reserve and dispatch only), then the scopes by (kind rank, ID), then
    the attempt. Release, dispatch and settle first read the attempt's immutable bindings without a lock. Times come
    from the database clock, read after the locks, and no transaction spans provider I/O.
- **Preflight.** `budget.preflight` checks a typed study manifest offline. For each actor it takes the request
  bounds, the logical calls per scenario, the repairs per logical call (at most 1) and the retries per request.
  - Attempts per logical call are `(1 + repairs) x (1 + retries)`, because a repair request can be retried too.
  - The worst cases are totalled per scenario, invocation and study and checked against the caps.
  - With a ledger snapshot, the study's persisted spend and **all** of its holds (active and unresolved) count, its
    persisted caps must equal the manifest's, and an overrun study is reported as `blocked_by_overrun`. Without a
    snapshot the prior spend is `unverified`, never zero.
  - `authorizes_paid_execution` is always `false`: runtime reservations remain the authority.
- **Limits.**
  - No exactly-once external billing is claimed. A grant is a ledger decision; the adapter that honours it, and
    that disables implicit SDK retries, is provider's.
  - Run-bound accounting also validates the current investigation claim at admission, including a
    recheck after lock waits. Already admitted remote work cannot be recalled by a later fence.
  - Active time is enforced by the runtime, separately from ledger money/call admission.
  - The overrun block has no operator reset.
- **Provider extensions (revision 0007):** every new attempt is intent version 2 and binds the request fingerprint. It
  needs exactly one admitted count before `begin_dispatch`, and a contract block (separate from the monetary overrun)
  stops new holds, counts and dispatches in every charged scope. Version 1 attempts from 0006 can still settle or be
  released, but never dispatch.

## Provider adapters

`policyops.providers` turns a provider-neutral `ModelRequest` (`policyops_contracts.model`, pydantic only) into one
exact OpenAI Responses or Anthropic Messages request. It sends that request through the official SDKs, pinned
exactly (`openai` 3.40.0, `anthropic` 2.3.0, the newest version before the lock's supply-chain cutoff), and accounts
for every physical request in the usage ledger.

**Compatibility smoke history (2026-11-05).** All of it was user-approved and capped, with one count and one inference per
case, no automatic retries and no fallback. Every case ran at low effort with cache mode `none`: Luna on the default
tier, and Haiku on `standard_only` with thinking disabled.

1. **First smoke** (source at commit `93afd3b`, a persisted USD 0.01 cap):
   - **OpenAI.** The text, required-tool and structured-output cases were verified, with known usage.
   - **Anthropic.** The three count requests were accepted, but the three inference requests returned HTTP 400.
     They have no result or usage, and their holds stay unresolved.
2. **Diagnostic.** One separately approved resend of the unchanged Haiku text request (one count, one inference, no
   retry) also returned HTTP 400, and its hold stays unresolved too.
   - It recorded only a closed error category: `invalid_request_error`, naming the parameter `speed`, with no
     indicator such as a spend limit or credit balance.
   - The full message was not retained. This implicates the explicit `speed` field; it does not establish the
     provider's whole reasoning.
3. **Repair.** Commit `0a91c03` makes the Anthropic request omit `speed`, which keeps the standard default (below).
   The OpenAI request and count bytes, and every count body, are unchanged; tests prove this byte for byte.
4. **Fixed-source Haiku smoke** (source at commit `0a91c03`, a new study with a USD 0.002 cap and 3 calls): the
   text, required-tool and streamed structured-output cases were all verified. Each had known usage, one settled
   attempt, confirmed cleanup and the returned model `claude-haiku-5-5`. The study settled completely, with nothing
   held and no contract block.

**Which evidence each provider rests on.** The OpenAI results come from the first smoke on the earlier source and
were **not** rerun on `0a91c03`. They carry over because the request and count bytes are proven unchanged. The Haiku
results come only from the fixed-source smoke. No call used an automatic retry. The earlier failures and their
unresolved holds are preserved, not erased or reset.

| Provider / model | Case | Live result | Official count | Reported input | Reported output |
|---|---|---|---|---|---|
| OpenAI `gpt-6-luna` | text | verified | 30 | 30 | 10 |
| OpenAI `gpt-6-luna` | required tool | verified | 152 | 152 | 19 |
| OpenAI `gpt-6-luna` | streamed structured | verified | 71 | 71 | 26 |
| Anthropic `claude-haiku-5-5` | text | verified | 37 | 37 | 10 |
| Anthropic `claude-haiku-5-5` | required tool | verified | 547 | 547 | 40 |
| Anthropic `claude-haiku-5-5` | streamed structured | verified | 280 | 280 | 33 |

**What the table shows.** On these six small requests the official count equalled the reported input. The ledger
amounts priced from the dated local price table were USD 0.0000528 for the three OpenAI cases and USD 0.0001279 for
the three Haiku cases. These are local calculations, not reconciled provider invoices. The results cover one tested
account per provider (separate vendor accounts), one date and one configuration. They are not evidence of model
quality, general counting accuracy, performance or a universal capability.

Earlier, separately documented project work made count-only provider requests that did not use these adapters.

**What the offline tests cover.** They exercise the request boundary, the response mapping and the accounting over
a scripted mock transport. Neither they nor the smoke are evidence of model quality, general counting accuracy or
price.

- **Preparation** (`serialize.prepare`): every local check runs before anything is reserved: the registry, the
  implemented provider contract (`contract.py`), schema registration, history consistency and the output limit.
  - The result keeps the request as canonical body **bytes**, integer-only and strict.
  - `request_sha256` hashes the contract version, method, host, path, version headers and body. Keys and auth
    headers are never part of it, or of anything stored or logged.
- **Wire contract:**
  - **Luna:** effort `low`, `service_tier="default"`, `store=false`, no parallel tool calls, `truncation="disabled"`.
    Cache `none` sends `prompt_cache_options.mode=explicit` with no breakpoints. Cache `30m` sends implicit mode
    with a 30-minute TTL. The adapter refuses requests for `12h`. If OpenAI reports a 12-hour write with
    otherwise priceable usage, the adapter settles it at the 12-hour rate and blocks the run.
  - **Haiku:** `thinking={"type": "disabled"}` with `output_config.effort="low"`, `standard_only` tier,
    no `speed` field (optional; omitting it keeps the standard default, and some models refuse any `speed` value
    without a beta header), no sampling parameters, no `inference_geo`. A returned `usage.speed` other than standard
    still holds and blocks. Only cache `none` is implemented: no cache
    markers, no replayed thinking and no per-message effort change.
- **Identity on the wire** (`transport.BoundedTransport`): each count and each request gets a fresh SDK client
  (`max_retries=0`, explicit timeout) over a fresh `httpx2.AsyncClient` (`trust_env=False`, no redirects). Its
  transport lets exactly one request through, and only if all of these hold:
  - the method, fixed host and path, and the fixed `Host`;
  - JSON content type, a `Content-Length` matching the body, no duplicated header and only allowlisted header
    names;
  - the pinned version headers and exactly the expected bearer credential (compared in constant time);
  - a body that re-encodes canonically to the bound bytes.

  Responses must be uncompressed and stay within the request's immutable `ResponseBounds`: for chat, 1 MiB and
  64 KiB per line (every line of every chunk, so SSE lines too); for embeddings (ingestion), 4 MiB with no line bound, a
  non-SSE JSON body only. A client is refused while any
  `OPENAI_*` / `ANTHROPIC_*` environment variable other than the API key's is set; only the names are checked.
- **Counting** is required: one supported count per attempt, over the full projection of the same prepared request
  (instructions/system, messages, tools, output format, effort/thinking). The count is claimed in the ledger before
  the call and never retried.
  - It admits the request only if `tokens + max(10%, 256)` fits the actor's maximum prompt, and `begin_dispatch`
    re-checks that itself.
  - A known prompt larger than the count plus that headroom settles and blocks (`count_underestimate`).
  - Count units are finite per scope and never returned.
- **Usage evidence** (`results.py`):
  - **OpenAI** `input_tokens` includes both cache reads and writes. Reads plus writes above that total are
    `usage_inconsistent`. When writes are nonzero or a split is present, both TTL counts in
    `input_tokens_details.cache_write_tokens_details` must be valid and sum to `cache_write_tokens`. Each bucket
    uses its own rate. Missing or malformed TTL counts (`cache_ttl_unknown`) and a split that disagrees with the
    write total (`cache_split_mismatch`) leave usage unpriced and held.
  - **Anthropic** `input_tokens` excludes cache reads and writes. Add them to get the whole prompt. The 5m/1h split
    must account for the creation total.
  - **Known, fully priced usage settles exactly**, whatever the answer's outcome.
  - **A known contract mismatch** settles the exact bill and contract-blocks every charged scope; the result becomes
    a `contract_gap` with no payload. For OpenAI, any read or write under cache `none` blocks after settlement
    (`cache_write_under_none` if there are writes, `cache_read_under_none` for reads alone). Otherwise a reported
    12-hour write blocks as `cache_ttl_unrequested`. Other examples include a prompt above the admitted maximum,
    output above `max_output_tokens`, and a thinking block.
  - **Unpriceable evidence** stays unresolved with its hold and a small allowlisted diagnostic, and is blocked the
    same way; no bill or TTL is invented. Examples: no TTL split, a non-standard tier, speed or geo, a returned model
    ID outside the explicit confirmed list, malformed counts.
  - **Missing usage** stays unresolved, with no block. OpenAI's `total_tokens` must equal input plus output;
    a missing or malformed total stays unresolved and blocked as `usage_malformed`, a contradictory one as
    `usage_inconsistent`, and no corrected total is invented. Anthropic's streamed cumulative counters must never
    decrease or be malformed; otherwise the usage is unknown and blocked (`usage_inconsistent`), never resolved by
    picking one value. A malformed response envelope (an `output` or `content` that is not an array) is a
    payload-free `failed`, while its known bill still settles.
  - **Unreported reasoning** (informational, inside the output) is recorded as unreported (null), never as an
    observed zero. Settlements that report it keep their exact original (v1) digest. The legacy `usage_events` column
    cannot hold null, so it stores 0 there, while the attempt's canonical usage (v2) keeps null.
  - **The evidence comes first.** The usage evidence is computed before the result, so a result that cannot be
    represented never loses it. Overlong metadata, invalid Unicode or an oversized payload become a typed,
    payload-free outcome, while the bill still settles or the hold and block are still recorded.
- **Results:** a `ModelResult` is `completed`, `structured`, `refused`, `truncated`, `invalid_output`,
  `contract_gap` or `failed`.
  - Structured answers and tool arguments are parsed strictly, numbers as exact decimals. They are validated
    locally with the pinned `jsonschema` 4.26.0 (Draft 2020-12, integers are integral numbers and never bools) against
    the **full domain schema**. The provider sees only a documented wire projection.
  - `pattern` is matched by pydantic-core's linear-time Rust regex engine, never Python's backtracking `re`, so an
    untrusted value cannot stall the deadline. Lookaround and backreferences are refused at registration. Matching is
    a search, and `\d` includes Unicode digits, exactly as the retail DTOs themselves validate.
  - `tools.to_agent_step` accepts exactly one tool call validated by the retail DTO, or one message; it is still
    only a proposal.
- **Calls** (`calls.call`, async; `call_sync` for worker threads):
  - the per-attempt sequence is prepare, reserve, count, dispatch, one SDK call, then settle or hold;
  - a retryable failure is retried as a new attempt (`retries_per_request`, default 1), and there is at most one
    repair for `invalid_output`;
  - there is no model fallback;
  - one absolute deadline covers everything, with an absolute cap per count or request (60 s by default) that also
    stops a stream that keeps trickling bytes;
  - after a dispatch grant, an attempt is never released;
  - only the caller that created an attempt touches it, so a duplicate or restarted caller changes nothing;
  - an unexpected exception after a grant still leaves the attempt unresolved;
  - a count or request client whose close could not be confirmed within its bound is listed in
    `CallReport.cleanup_unconfirmed`, and its bill is unaffected.
- **Capability record** (`capability.py`): the factory returns an unpopulated template whose live cells are all
  `not_run`, whatever has been observed. The dated compatibility results are the matrix under **Compatibility smoke history**
  above. The record's smoke manifest is **preliminary data only** (`preliminary_not_enforceable`). It is not an
  executable or approved plan, and no live run happens without a separately reviewed driver and explicit approval.
- **Limits:**
  - **Narrow capability evidence:** the count-versus-usage compatibility matrix is limited to the six dated
    smoke cases above; later model studies are reported separately in [evaluation](evaluation.md).
  - **Worker fencing:** stale count/dispatch claims and active-time admission are handled by the
    composed runtime, not by an SDK timeout alone.
  - **Cancellation:** a provider may keep generating after a local cancel; the hold stays.
  - **Unimplemented modes:** the Anthropic positive cache modes and OpenAI 12h are refused, not implemented.

## Embedding foundation

The embedding foundation accounts for and caches exact texts with `text-embedding-3-small` at 1536
dimensions. Its callers are operator-run ingestion (see **Corpus ingestion**) and the
retrieval step's run-bound query embedding (see **Retrieval steps**), including configured
investigation. One bounded live compatibility smoke on 2026-11-05 is described under **Limits** below.

**Local counting** (`providers/tokenizer.py`). Embedding inputs are counted with cl100k_base, the encoding tiktoken
0.14.0 maps to this model:
- The vocabulary is pre-provisioned, never downloaded by the application. `scripts/fetch_tokenizer_vocab.py`
  places the one pinned official file under `$POLICYOPS_TEMP_DIR/tokenizers/`, checked against the SHA-256 that
  tiktoken's `openai_public.py` names. A missing or different file fails closed, and tiktoken's own downloading
  factories are never called.
- The pattern and special tokens are pinned constants, compared in a test with the installed tiktoken source,
  identified by the hash of its text with line endings normalized to LF (the wheels install platform line endings).
  The installed tiktoken version is checked when the vocabulary is loaded.
- Before encoding, every input is bounded (32,768 code points, 65,536 UTF-8 bytes, no NUL or lone surrogate) and
  split with the pinned pattern; every actual regex piece, whitespace included, must be at most 1,024 UTF-8 bytes.
  That bounds the per-piece merge work. Encoding is synchronous and no timeout interrupts it; the measured worst
  admitted inputs take milliseconds on development hardware, which is a measurement, not a guarantee.
- The count is recorded in the ledger with source `local.tiktoken-cl100k`. There is no embedding count endpoint and
  no count request. In the one live smoke below the local total (42) equalled the provider's `prompt_tokens`; that is
  a single small sample, not general equality.

**The request** (`providers/embeddings.py`, `embedding_contract.py`). The body is exactly `{"model", "input",
"dimensions": 1536, "encoding_format": "float"}`, fingerprinted like a chat request. `encoding_format` is always
explicit: omitted, the SDK would request base64 and decode it in its parser, which this code never calls. The request
goes once through the real SDK (`with_raw_response`, no retries) over the same `BoundedTransport` as chat, with the
embedding bounds. The transport is owned from the moment it is acquired, and closed on every failure path. A
complete body is handed to the caller as soon as it has arrived, before any stream or client close is awaited, so a
timeout or cancellation during cleanup cannot lose a known bill.

**Validation.** The body is parsed by an embedding-local bounded parser (the shared chat parser is unchanged):
- a one-cursor precheck with anchored matches only (linear; at most 1,024 strings of 4 KiB, 256 containers, depth
  8);
- numeric literals longer than 24 characters, `NaN`, `Infinity` and duplicate keys become markers confined to
  their subtree, and taint the document;
- billing (`model`, `prompt_tokens`, `total_tokens`) is read first and must be present, unique and strictly typed;
- vectors are usable only from an untainted document: unique contiguous `int` indexes and 1536 finite numbers each,
  rounded to float32 (overflow refused), not all zero after rounding. Norms are kept as a diagnostic only.

| Response | Ledger | Cache |
|---|---|---|
| unparseable, or billing missing or malformed | unresolved, hold kept | none |
| `prompt_tokens` ≠ `total_tokens` | unresolved, hold kept, blocked | none |
| another model than requested | unresolved, hold kept, blocked | none |
| consistent usage ≠ local count | the actual bill settled, blocked | none |
| billing valid, vectors invalid | the actual bill settled | none |
| everything valid | settled | the vectors |

**Jobs** (`providers/embedding_calls.py`, `persistence/embeddings.py`, revision `0009`):
- A job is identified by `(workspace, purpose, subject_key)` and binds the full intended ordered input set, the
  request configuration and the tokenizer. Any other identity for the same subject is a conflict.
- Planning (one transaction) stores every input and a frozen plan of the distinct inputs not already cached: at most
  64 inputs, 8,192 local tokens and 262,144 UTF-8 input bytes per request (a new batch starts before an input that
  would cross any of the three). Each batch's ledger attempt is `uuid5(job, operation)`, with the full
  batch digest in the operation. Resume never re-batches; an all-cached or empty job makes no request. A batch whose
  inputs all became cached before it reserved anything is satisfied from the cache.
- The job has an immutable deadline (`caps.active_seconds` from its creation, on the database clock); a caller's
  deadline is clamped to it and to `caps.active_seconds`, and a restart cannot extend it. Preparation has its own
  60-second bound.
- Before anything is reserved: the ledger must be the app ledger of the store's workspace on the same engine, the
  credential must be configured with no ambient SDK setting, and every unreserved batch must fit the operation
  scope's remaining USD (after spend and every outstanding hold), calls and counts.
- Per batch, the ledger's single-winner `claim_count` and `begin_dispatch` are the only permission to send. A batch
  lease with a fence governs job advancement only. A late response is always published and settled, even after its
  lease moved on; the next owner reconciles the batch from that attempt's own evidence, never from another
  attempt's cached vector. A dispatched attempt without evidence is `orphaned`: its hold stays and nothing is resent
  (reissue is a later, explicitly authorized operation). Only the process whose own local count was rejected
  releases a reservation.
- Publication of evidence and vectors is one transaction, checked against the stored batch, the job's request
  configuration and the ledger attempt; evidence is first-write-wins and a cached vector is never replaced. A
  database failure is retried at most three times, never with a second request; the bill is settled either way.
- Run-bound query jobs (retrieval): a job of purpose `query` is always run-bound (`job_binding`): exactly one input and the
  subject `query.<run_id>.<step>`, charged to that run's shared budget scope. `run_job(run_id=...)` checks the binding
  against the job's immutable identity (`BindingMismatch` otherwise, before any write) and that the run is visible in
  the caller's workspace and active (`EmbeddingStore.run_is_active`) before planning, cache use or terminal
  reconciliation; otherwise the report is `blocked` with reason `run_not_active`, no job and no write. There is no
  operation-scope preflight for a run-bound job: the ledger's atomic run-scope reservation is the only admission, and
  its run lock and active checks stay authoritative. Every other job keeps its operation binding and behavior
  unchanged (`run_id` must then be absent). A run that turns inactive after the check can still be answered from the
  cache (read-only, no spend).

**Limits.**
- The default operation caps (64 calls, USD 0.05) and the 180-second active window bound one job; larger jobs need
  explicitly larger server caps.
- **Live compatibility smoke (2026-11-05).** One user-approved, capped request to OpenAI `text-embedding-3-small`
  (float, 1536 dimensions) ran against accepted commit `3a037abb`. The logical job had four ordered input positions:
  three distinct short synthetic texts (ASCII, Unicode, CRLF plus tab) and one duplicated position. Deduplication
  sent the three unique inputs in one physical provider request, with no provider count request and no retries; the
  provider returned three vectors, stored as three cache entries and mapped back to the four ordered positions. Local
  counts of 14 + 16 + 12 = 42 equalled the returned `prompt_tokens` and `total_tokens` (42) on this sample only. The
  ledger settled USD 0.00000084 with nothing held (operation cap USD 0.001, worst-case reservation USD 0.00000256).
  This is the cost of this smoke, not a statement about retrieval quality, model quality, cache savings or
  performance, and it is not an evaluation. The earlier dated Luna and Haiku evidence and their recorded holds are
  unchanged. Configured investigation uses query embedding; the ingestion command and retrieval step are described under **Corpus ingestion** and **Retrieval steps** and do not extend this smoke. The
  external smoke ran under a 300-second child supervisor with a bounded cleanup grace; that is not a production
  deadline proof, and the database-wait bullet at the end of this list still applies.
- A synthetic maximum
  batch (64 x 1536 numbers of 24 characters, two-space indentation) measures about 3.3 MB; deeper indentation could
  exceed the enforced 4 MiB bound, and a response above it is refused with its hold kept.
- Cache entries and evidence are never deleted at runtime; there is no retention policy yet.
- The job deadline does not bound database waits: the ledger and store transactions are synchronous, runtime statement/lock/idle timeouts apply per operation, while socket and commit waits
  still prevent a universal wall-clock bound. The deadline
  is checked again afterwards; a blocked wait sends nothing.

## Corpus ingestion

The ingestion implementation in `policyops.retrieval` (`sources.py`, `parse.py`, `corpus.py`, `ingest.py`, `cli.py`) and
`persistence/corpora.py` on revision `0010` ([database.md](database.md)) import one corpus into one workspace as a
new, atomically activated generation. **Status: implemented and verified locally** (Windows with Docker Desktop: the application suite with
1,149 default and 415 PostgreSQL cases, the evaluator suite with 168 cases of which 35 use PostgreSQL, strict lint
and type checks, and a genuine populated pre-ingestion dump upgraded to `0010`); hosted and Linux CI have not been
run. It is an operator-run command: the process holds
database credentials, so there is no principal or membership check (like the synthetic importer), and there is no
HTTP endpoint or worker; retrieval over its generations is the internal component under **Retrieval steps**. The one-request embedding smoke under **Limits** above remains the
only live embedding evidence; nothing here is a corpus-scale, quality, savings or performance result.

**Source manifest and reading** (`sources.py`). `policyops.ingest-manifest/v1` is committed metadata only: per
corpus a sorted, finite list of documents (key, repository path, Git blob, SHA-256, size), the license scope, the
pinned render and the digest of the sorted rendered bodies. `evals/manifests/tau2-19f13ea3/ingest-corpora.json`
holds `tau2-banking-knowledge` (698 documents, render `tau2-banking/v1`) and `tau2-retail-policy` (1 document,
render `identity`). It is derived from the committed data-audit manifests by the evaluator-owned
`policyops_evals.ingest_manifest` (`--check` compares, `--manifests DIR` selects the input); the application never
imports the evaluator. The caller supplies the manifest's exact bytes with their SHA-256. Before any database write or
provider call:

- the manifest is strictly parsed (unknown fields, duplicate keys and non-finite numbers refused; at most 2,000
  documents and 16 MiB of raw bytes per corpus, 4 MiB per file);
- every path is a safe relative POSIX path under an acquisition root (for `data fetch --dest D`, the root is
  `D/tree`) that is itself free of links; each component is checked and the joined path must equal its strict
  resolution inside the root;
- each file is read bounded by its declared size and its size, SHA-256 and Git blob SHA-1 must all match; the bytes
  must be strict UTF-8 without a BOM, and the rendered body non-empty, at most 4 MiB and free of NUL and lone
  surrogates;
- the rendered-list digest must equal the manifest's value. A refusal refuses the whole corpus.

The check-then-open sequence guards ordinary aliasing, not an attacker replacing files during the read.

**Parser** (`parse.py`, `policyops.md/v1`, chunk configuration `chunk.cl100k-512-nooverlap/v1`). A deterministic
function of the body, the versions and the token counter. Offsets are code-point indexes and a chunk's text is
exactly `body[start:end]`: CRLF, tabs and Unicode are never normalized. `\n` is the only line terminator. Headings
are ATX only; fenced code (a CommonMark subset) keeps its headings as text; a section runs from a heading to the next
heading of any level, so a parent never repeats its children. Paragraphs and whole fenced blocks are packed greedily
without overlap while the exact submitted embedding input (heading path, blank line, text) counts at most 512
cl100k_base tokens and the span at most 20,000 code points. An oversized paragraph is split at sentences, and an
oversized sentence or fence is hard split by bisection. Prefix counts are not assumed monotone, so a split is
feasible and deterministic, not maximal, and at most 18 counts are made per split; a position where not even one
code point is feasible, or a heading path over 500 code points, is a named, bounded refusal.

**Identities** (`corpus.py`). A document's identity is its `source_uri` from the corpus domain and document key, with
no source commit, and a source identity owned by another corpus is refused. Each generation records the revision,
path, Git blob and raw digest of its members, while an immutable document version is identified by its rendered-body
digest: changed content creates a new version numbered after the document's latest, and a body that matches an
existing version of that document reuses it even when the revision, path or blob differs (a candidate whose stored
body does not have its recorded digest refuses the publication). A chunk's `sha256` is a composite digest over parser and chunk versions, source identity, version digest,
offsets, heading path, section metadata and the plain text digest, so repeated text at other positions keeps distinct
identities; the plain text digest is stored and verified separately. The embedding input digest is the cache key and
is independent of document and position. The expected set (header, every member document including those without chunks,
such as heading-only or whitespace-only bodies, and every chunk) has one digest; an empty body is refused at reading; the generation key binds it to the header, and a key equal to the active generation's is a
repeat that changes no row and makes no call. At most 10,000 chunks and 64 MiB of bodies are accepted so that the
publish transaction is bounded.

**Modes and the paid gate** (`ingest.py`, `cli.py`).

| Invocation | Effect |
|---|---|
| default | Read-only plan: verifies, parses, compares with the active generation, looks up the cache and any existing job, and estimates the remaining work. No write, reservation, credential read or request |
| `--execute` | Writes allowed. Publishes locally when every input is cached, or when an existing job is settled |
| `--execute --paid` with `--model --dimensions --max-usd --max-calls --max-input-tokens --max-seconds` | The only way to embed misses. Every flag is required (no defaults), model and dimensions must equal the configured actor (`text-embedding-3-small`, 1536), and the caps are bounded by USD 1.00, 1,000 calls, 5,120,000 local tokens and 3,600 seconds |

Caps without `--paid`, or `--paid` without `--execute`, are usage refusals. The preflight runs over the complete
remaining miss plan before any credential read, reservation or request: batches times the worst-case reservation
within `--max-usd`, batches within `--max-calls`, the frozen plan's **total** local tokens within
`--max-input-tokens`, and batches times (30-second attempt plus 10-second settlement margin) within `--max-seconds`
and the job's remaining window. The caps are also the ledger configuration used for admission, so recorded caps are the
enforced ones. The token ceiling is a cumulative job budget: a resume counts every frozen batch, attempted or not, so
a lower ceiling cannot ignore work already planned, and a larger one does not widen the effective budget. When provider
work remains, a resume whose caps or window differ from the stored job and scope is refused
(`resume_configuration_changed`); there is never a second job or a reissue. `OPENAI_API_KEY` is read only after the preflight passed. An expired incomplete job, an
unresolved hold or a missing vector is reported (`embedding_incomplete`) with accounting and cache preserved; a job
that is already settled (complete, or every batch published or satisfied by the cache with nothing held) is published
from the cache without a provider call, credential read or deadline change even after its window elapsed. That
cache-only publication is local: it needs no paid caps and does not validate a changed paid budget that it does not
use.

**Publish** (`CorpusStore.publish`). One bounded transaction as `policyops_app_runtime` inside the workspace scope
(the store verifies at construction that its engine authenticates as that role), with no provider or file I/O:

1. create or lock the corpus row `FOR UPDATE` and compare it with the import's snapshot (compare-and-swap, including
   the no-corpus case); a difference is `StaleActivation`, exit 4, with nothing written;
2. insert or reuse documents and versions (only the one reuse candidate per document is read and hashed; a candidate
   whose body does not have the expected digest refuses the publication and is never rewritten);
3. insert the `building` generation, its membership and its chunks with their cached vectors;
4. retire the previous ready generation, make the new one ready and move the pointer;
5. read back through the unchanged ready-only chunk policy and verify the exact expected set (counts, every member's
   body digest and source identity, every chunk slice against its version body, text digest, composite identity and
   vector against its cache entry, and the recomputed expected-set digest). Any difference rolls everything back.

A failed or interrupted import leaves the previous generation active; failed jobs keep their accounting and cache.
Step 5 partly re-reads values this process just wrote: it catches database-side differences, and is not an
independent oracle. The `0010` guards independently prevent later rows in a published generation. Runtime SQL statements, lock waits and idle transactions have configured finite timeout profiles. Synchronous
SQL can still delay cancellation, so no total wall-clock bound on publication is claimed,
and no duration, row or byte measurements of a real corpus import are reported here.

**Citation read** (`CorpusStore.resolve_citation_text`). A narrow typed read port returns the cited span from the
immutable version body, with the checks actually performed: the run matches the citation's trace, the version's
actual body digest equals its recorded digest, and the span lies within the version (at most 20,000 code points). For
a corpus generation it also checks that the version is a member of the trace's generation and reports chunk
containment as a write-time guard; for a legacy generation it reports `version_in_generation` as
`not_recorded_legacy`. This is not authorization (the service must already have checked run and case access) and does
not show that a span supports any claim; the configured investigation uses the recorder under **Reranking and citation grounding** to create citation rows. The write-time guard still requires a cited chunk to be in a ready generation at insertion; a retrieval trace records the generation it read, and when an activation makes a citation insertion stale, the caller must re-retrieve in a new step rather than reuse the retired snapshot as current evidence; the citation recorder described under **Reranking and citation grounding** writes new rows only for current-generation evidence.

**Scripted full-manifest measurement.** One local run imported the full committed manifest into a fresh workspace
on real PostgreSQL as `policyops_app_runtime`, through the real SDK path over a scripted transport (synthetic
credentials and deterministic synthetic vectors; no provider HTTP): 699 documents (698 banking, 1 retail policy),
2,963 chunks and 2,957 distinct embedding inputs (2,945 banking and 12 retail), published as one generation per
corpus with 48 scripted requests (47 and 1). The tables then held 699 documents, 699 versions, 2 generations, 699
memberships, 2,963 chunks, 2,957 cache entries and 48 usage attempts. The banking publish transaction took 4.17 s
(its corpus-row lock was held for 4.16 s, mostly verification) and the retail one 0.06 s, on one machine in one
observation: that is not a speed or capacity claim. The 6 duplicate occurrences (five repeated banking input strings)
are why chunks exceed distinct inputs; their roughly 246 tokens are a count difference, not a measured saving. The
serialized vector text recorded (about 95 MB) is not database storage (relation sizes were measured separately) and
not billable input. Vectors, prices and usage are synthetic; no retrieval quality or live-embedding result follows.

**Operator output.** One JSON object on stdout with the outcome, counts, digests, estimate and caps (never document
text or secrets). Exit codes: 0 planned, unchanged or activated; 1 verification failure or unexpected error (type
only); 2 refused; 3 embedding incomplete; 4 stale activation. The connection uses the libpq environment, and the role
must be `policyops_app_runtime`.

**Structural (archive-derived) profile.** A second ingest profile (`--profile structural`) sits alongside the Markdown
one. It accepts a bounded, hash-verified title-run passages JSONL and a metadata manifest, such as the MultiDoc2Dial
materialization from `policyops_evals.datasets.multidoc2dial`. Each passage becomes one document with one complete chunk,
keeping its heading, body and original domain/document/offset mapping. The profile refuses more than 5,000 passages or
any chunk over 20,000 code points or 8,192 embedding tokens; it never truncates. Generation identities bind the
profile's parser and chunk versions, the derivation Git identity and the archive provenance, so a Git field never claims
an upstream dataset commit. The existing cache, runtime-role/RLS verification, staged activation and FTS/dense/RRF/rerank
semantics are reused unchanged; ranked documents are passages. Migration `0017` raises the per-generation document and
ordinal bounds to 5,000 for this profile. Its downgrade refuses, without changing data, while larger generations exist.
`--offline-preflight` reports the empty-cache plan and checks explicit caps without a database or provider call.

## Retrieval steps

retrieval: an internal, programmatic retrieval step (`policyops.retrieval` `search.py`, `rank.py`, `counting.py`; `persistence/retrieval.py`; `policyops_contracts/retrieval.py`) on revision `0011`. It has been exercised on synthetic fixture corpora with synthetic vectors and scripted transport, and verified locally on Windows with Docker Desktop (lint, type checks, the application default and PostgreSQL suites, the evaluator default suite, the scanner and static checks), and its PostgreSQL cases run in hosted CI. The configured investigation adapter calls it; the default Compose stack leaves investigation unconfigured; the optional rerank stage and the citation grounding that build on it are described under **Reranking and citation grounding**, and it makes no quality, latency or cost claim.

**Request.** A step names one corpus, a run, a caller-owned step number (0-9999), a query, an optional document allowlist and a versioned configuration. The query is 1-2000 code points of text without control characters other than tab and line breaks and at most 1024 local cl100k tokens, counted as an embedding input. The allowlist has at most 32 sources and must lie inside the corpus. The configuration (`policyops.retrieval-config/v2`) holds the mode, the documents kept per branch (default 20, at most 50), chunks per document (default 2, at most 3), `rrf_k` (default 60), `max_chunks` (default 6, at most 16), `max_evidence_tokens` (default 4096, at most 16,000), `full_policy_max_chunks` (default 16), `max_admission_attempts` (default 64), the dense policy, the FTS configuration, the evidence format and the embedding model and dimensions. Configuration values are strict integers and enumerations, scores are decimal strings and there are no free dictionaries; query vectors and stored vectors remain floats. The step's identity is its run and step number. Its request fingerprint is the SHA-256 of the query digest, the scope digest and the configuration digest (the retrieval intent and trace never store the raw query text; the query embedding job, as a foundation job, persists its input text in `app.embedding_job_inputs`, a tenant-scoped, forced-RLS table with select and insert only, so that the paid job can be recovered durably). The calling service must already have authorized the run, case and corpus; this component still enforces its own tenant, corpus, run, model, dimension and state relationships.

**Modes and snapshot.** One `REPEATABLE READ READ ONLY` snapshot reads the corpus pointer, the active generation and its embedding configuration, both branches and the bounded candidate texts, so an activation cannot mix generations or hide chunks mid-step. Lexical search uses `websearch_to_tsquery('english', ...)` and `ts_rank_cd(..., 32)` (a query that yields an empty tsquery is reported as `empty_query`, not an error); dense search uses exact cosine distance (`<=>`, sequential, at most 10,000 chunks per generation). Each branch keeps the best chunk per document, the top documents (default 20) ordered by score then `source_uri` in byte order, and their best chunks. Fusion sums `1/(k + rank)` with `fractions.Fraction` and orders by RRF value, best single-branch rank, `source_uri`, then document ID; equal ranks put lexical first. A lexical score is never compared with a distance. The `full_policy` mode is for a corpus of the retail domain only (another domain is refused as `full_policy_not_supported`): it reads every chunk if there are at most `full_policy_max_chunks`, otherwise refuses before loading any text.

`Retriever` and its snapshot accept three typed `lexical_mode` values:

- `all_terms` remains the default: `websearch_to_tsquery` preserves web-search operators and phrases, ranked by `ts_rank_cd(..., 32)`.
- `any_terms` ORs distinct English lexemes and uses the same ranker, allowing conversational queries to match passages containing only some terms.
- `bm25` uses that same OR candidate set and English normalization, with exact Okapi BM25 over the active generation's stored `chunks.tsv`. It exists because `ts_rank_cd` lacks collection IDF and BM25 length normalization: a broad OR query can otherwise rank common lexemes too highly and weaken RRF's lexical signal.

For each distinct query lexeme `t`, BM25 adds
`ln(1 + (N - df(t) + 0.5) / (df(t) + 0.5)) * tf(t,d) * (k1 + 1) / (tf(t,d) + k1 * (1 - b + b * dl(d) / avgdl))`.
The fixed, untuned constants are **k1 = 1.2, b = 0.75**; IDF is the positive Lucene form. `N` counts all chunks in the generation, `df` counts chunks containing the lexeme, `tf` counts its retained positions, and `dl` sums retained position counts across all lexemes (not distinct lexemes or the largest position). `avgdl` covers every chunk, including zero-length vectors. Allowlisting restricts candidates, not collection statistics. Repeating a normalized query term does not multiply its contribution.

One bounded SQL statement computes all query-term dfs using `tsv @@ single_lexeme_tsquery` predicates. **GIN acceptance remains blocked:** PostgreSQL 17's [`ts_match_vq` catalog entry](https://github.com/postgres/postgres/blob/REL_17_STABLE/src/include/catalog/pg_proc.dat) is not leakproof, and the [planner rejects index conditions that cannot move before security restrictions](https://github.com/postgres/postgres/blob/REL_17_STABLE/src/backend/optimizer/path/indxpath.c). With the current forced chunk RLS policy, source inspection therefore predicts generation scans rather than use of `chunks_tsv`; the runtime plan test must confirm this before accepting the strict GIN requirement. This draft preserves RLS and makes no catalog changes. Every matching chunk is scored before the existing per-document best-chunk selection and `branch_documents` limit. Ties retain the source URI, document ID, span and chunk ID order described above. The generation is bounded to 10,000 chunks; larger BM25 generations refuse. A store keeps at most one workspace-local `(generation ID, N, avgdl)` tuple, reused only after the snapshot verifies that exact ready generation. Immutable generations make reuse safe; concurrent misses may recompute. There is no schema change, migration or new SQL timeout: all work uses the existing read-only repeatable-read snapshot and retrieval statement limits. `scripts/bm25_latency_probe.py` compares full cached and recomputed snapshots on the manifest's dev queries, with paired score equality, nearest-rank p50/p95 and refusals reported separately; real-generation measurements and the final cache decision belong to coordinator evidence.

PostgreSQL parses bound query text and quotes each lexeme before OR composition; raw text never becomes SQL or query operators. Both OR modes refuse above 64 distinct normalized lexemes with `lexical_query_too_many_lexemes`; app requests return `query_too_long` with that detail, and QA slots record the failure. Nothing is truncated. Empty/stopword queries return an empty lexical branch. Non-default app fingerprints prevent cross-mode replay; existing default app and QA study/arm digests stay unchanged (QA omits `all_terms` from canonical serialization). The runner forwards the mode to both FTS-only and RRF lexical snapshots.

This is exact BM25 over PostgreSQL's retained English vectors, rather than a reproduction of the paper's Lucene analyzer. English stemming, stopword removal and tokenization can differ from Lucene. PostgreSQL [clamps positions above 16,383 and merges duplicate positions](https://www.postgresql.org/docs/17/datatype-textsearch.html); it also retains [at most 255 positions per lexeme (measured on the pinned PostgreSQL 17 image; the documentation describes the limit as 256)](https://www.postgresql.org/docs/17/textsearch-limitations.html). BM25 counts the surviving positions as stored, so capped vectors underestimate original term frequency and length; it cannot reconstruct lost occurrences. Stopword positions are not included in length. These limits and preprocessing differences constrain comparisons to upstream BM25 results.

The descriptive dev config `g1-dev-retrieval-v3.json` retains v1/v2 as historical records. It pairs BM25 and RRF(BM25) with dense and `any_terms` across history-four and last-user-turn profiles, plus RRF(any_terms/history) for continuity. Two additional lexical any-terms arms make both within-study BM25-versus-any comparisons possible. This dev study does not select on sealed data or establish upstream protocol equivalence.

**Exclusions.** The dense branch skips and counts chunks of the generation whose stored vector is missing or whose cosine distance to the query vector is NaN (a zero vector gives NaN), reported as `dense_nan_distance`; this count covers the whole generation, not only the allowlist. Chunks longer than 20,000 code points (already barred by a table CHECK, so expected to be zero) are filtered from every branch and counted as `text_oversized`. Candidate assemblies the evidence counter refuses are skipped and counted as `count_refused`. These counters do not claim that every stored chunk vector has been validated.

**Evidence format and budget.** Evidence blocks are `[E{n}] {source_uri} version {v} | {heading} | chars {start}-{end}`, a line break and the verbatim chunk text, joined by a blank line (`policyops.evidence-format/v1`). The `E{n}` list is the delivery map, never parsed from text; source URIs, headings and texts are untrusted and may contain fake markers, URLs or instructions, and the delimiter is not prompt-injection-proof. Ranked delivery takes the better-ranked branch's chunks first and at most `chunks_per_document` per document in a first pass, then the remainder, and counts the entire concatenated string against `max_evidence_tokens` on every admission (blocks are admitted only if the whole string still fits and fewer than `max_chunks` are delivered), skipping non-fits, never truncating, with a bounded number of attempts. The retail-domain `full_policy` control delivers every chunk if the whole string fits the same token budget, or refuses. Counting uses a retrieval-specific adapter (`counting.py`) over the same pinned cl100k vocabulary, pattern and identity, with its own whole-assembly bounds (at most 384,200 code points and four times that many UTF-8 bytes), strict UTF-8, no NUL, and the foundation's per-regex-piece bound, because the embedding tokenizer's 32,768-code-point input ceiling would wrongly refuse feasible evidence. The foundation tokenizer and its limits are unchanged. Adjacent-context expansion is deferred to development tuning (retrieval study).

**Query embedding.** A dense or hybrid step uses one run-bound foundation job (see **Embedding foundation**, run-bound query jobs): subject `query.<run_id>.<step>`, exactly one input, the run's shared budget scope, the per-workspace cache and a frozen job without ambiguous reissue. The step's own job is authoritative: an unsettled job is not bypassed by a vector that another job cached. The cached vector must have 1536 finite values and be non-zero after float32 rounding, otherwise the step refuses as `query_vector_invalid`. Availability outcomes (`budget`, `unresolved`, `vectors_invalid`, `job_unsettled`, `missing_vector`) make a hybrid step lexical-only, flagged in the result and trace, when `dense_policy = "lexical_fallback"` (the default), and refuse as `embedding_unavailable` under `refuse`; mode `dense` always refuses. Cancellation, an expired deadline, a lease held elsewhere past a bounded wait (`step_in_progress`) and binding, identity, contract or configuration failures never become a lexical success; there is no model fallback and no reissue.

**Intent, trace and replay (revision `0011`).** For a new step, a short transaction first checks that the run is active (read `FOR SHARE`) and the corpus has an active generation, resolves the allowlist and measures the configuration's worst-case trace payload in the database (a configuration whose measured worst case exceeds the column limits with a 10% margin is refused as `config_trace_too_large`), and then inserts the immutable `(workspace, run, step)` intent holding the request fingerprint. A stored intent with a different fingerprint is `step_conflict`, with no provider work. The trace has a deterministic ID and typed, bounded JSON (no raw query text in the trace); if it cannot be written the step refuses as `trace_unavailable` while settled or held billing stays in the ledger. An existing completed trace replays read-only, whatever the run's state now and even after the corpus changed, by rebuilding the evidence from the immutable version bodies and spans and re-verifying the body, evidence-text and payload digests (`replay_integrity` on a mismatch); a trace without a matching intent, or with an unsupported payload, is refused as `replay_unsupported`. A concurrent trace insert conflict rereads and verifies the stored trace; the result is then `replayed: true` because it is the stored trace, while its `provider_requests` still counts the embedding request this invocation made before it lost the race (a later audit replay reports zero). Results carry constant `current_policy_validated: false`, `claim_support_validated: false` and `caller_authorized_scope: required`, and `generation_current` is only whether the generation was still the pointer at the last observation, never current-policy proof. Every new step needs an active run, a present corpus and an immutable intent.

**Deadline.** The deadline is checked at the explicit service phase boundaries and again before any result, new or replayed, is returned; it is not checked inside each nested lookup of the query-vector phase or inside the snapshot's SQL. A synchronous SQL call is not interrupted by it and may continue until control returns to the service; a step whose deadline has passed by the next boundary returns `deadline_passed`, never a result. Work already committed (an intent, a settled embedding, a written trace) is kept, never rolled back or reissued, so a later timely retry of the same step replays the trace or reuses the vector without a new call.

**Failure and crash behavior.** Before the intent commits nothing persists. After the intent and before any embedding, a retry proceeds to the embedding phase (it reuses a cached vector or runs the step's job). Once the embedding evidence, the publication of the vector to the cache and the settlement have all completed but the trace has not been written, a retry reuses the cached vector with zero provider requests and writes the trace. A crash or an ambiguous outcome after dispatch can instead leave an unresolved foundation hold: the step then refuses or falls back according to the dense policy, and the request is never reissued automatically. After the trace, a retry replays. A changed valid request is never accepted or reissued under an old step: on the completed-trace path the stored request fingerprint conflicts (`step_conflict`), and on the active-intent path the stored intent conflicts (`step_conflict`). The new-step path first requires an active run, so a retry of an incomplete step whose run has since become terminal is refused as `run_not_active` before any conflict is evaluated.

**Limits.**
- The tests use synthetic fixture corpora, synthetic vectors, synthetic credentials and a scripted provider transport. A passing semantic fixture shows mechanics, not retrieval quality, and no real-corpus query result exists.
- The local retrieval budget counts cl100k tokens of the formatted evidence string. It is not a provider token count and not the size of any serialized model prompt; provider request tokens and live limits are measured separately with the providers' counting (see the token notes in the data provenance page).
- SQL transactions (intent, snapshot, size measurement, trace insert) are not interrupted by deadlines and runtime transactions set finite statement, lock and idle-in-transaction timeouts; provider awaits (the embedding request and, when enabled, the rerank request) can be cancelled, while synchronous SQL remains non-interruptible. No hard wall-clock bound is claimed.
- Intent rows are permanent per run and step. Live dense search is exact and linear in generation size. The [N16 protocol](performance.md#n16-filtered-hnsw-protocol) benchmarks HNSW on a disposable table. The 4,110-passage MultiDoc2Dial corpus uses exact search. Reranking is optional and off by default. Entailment validation is outside the retrieval step.

## Reranking and citation grounding

grounding: internal, programmatic additions to retrieval (`policyops.retrieval` `rerank.py` and `grounding.py`, `persistence/citations.py`, `policyops_contracts/grounding.py` and `retrieval.py`). There is no new migration: citations use the existing `app.citations` table, grants, row-level security and the ready-generation insert guard. It has been exercised on synthetic fixture corpora with scripted provider transports and a local runtime PostgreSQL, with an independent functional review of the internal component. The configured investigation adapter calls it, and it makes no real-provider, quality, saving or latency claim.

**Rerank (optional, off by default).** A step reranks only when its configuration carries a rerank section **and** its `Retriever` was built with reranking enabled. The production adapter is built by the `Retriever` from its own verified ledger, providers factory and workspace, never injected, and a test port must declare itself test-only and is refused outside the test environment. After the snapshot closes, the first `documents` fused documents (default and maximum 20, at least 2) in baseline order get server-assigned labels `D01…`, and the server maps each label back to a document ID. The ranking request omits the structured internal UUID fields and the final delivered-evidence map; its excerpts are untrusted candidate text that can contain any string, and the model sees these bounded candidate excerpts (not the final evidence). Each document's excerpt is its candidate chunk texts joined and cut at a code-point boundary to a per-document byte budget (default 500 bytes, at most 1000) inside a total content bound of 12,000 UTF-8 bytes; below a 64-byte minimum the stage is skipped with no call. That bound is a conservative engineering limit, not a tokenizer proof: the provider count admission decides. The answer must be `{"ranking": [label, ...]}` with an enum of the window's labels, unique, at least one; an invalid ranking is discarded whole, with no partial salvage (this is separate from the shape of a grounded answer and from quote validation). The final order is the listed labels in model order, then the unlisted window documents in baseline order, then the documents beyond the window. Excerpts affect ranking only: admitted evidence still uses the full chunk texts under the unchanged evidence-budget rules, although a different order can change which chunks the greedy admission selects.

**Budget, count admission and the work a call reports.** The request goes through the provider call path on the run's shared budget scope (`RunBinding`) with the configured reranker actor (normally Luna): mandatory count admission, at most one count unit and one inference (one run call slot), a local sub-deadline of its own (default 10 s, at most 30 s), no retry, no repair and no model fallback. The embedding query is a separate one-input run-bound job (see **Embedding foundation**). Three things stay apart:
- `provider_requests` on a **result** is this invocation's embedding request count, preserved through trace conflicts;
- an optional per-invocation record `invocation` (on results of rerank-configured steps, and on rerank-enabled refusals that know of work already done; legacy and no-rerank refusals gained no new reporting) with the embedding requests, the rerank grants this call obtained (`rerank_counts_claimed`, `rerank_inferences_dispatched`) and whether cleanup was unconfirmed. These come from two trailing default-false flags on the provider attempt record, set immediately after the ledger's count and dispatch grants: a grant means the ledger authorized the step, not that bytes left the process;
- the stored trace's historical rerank summary, identical for every replay of the step.
The ledger remains the billing authority and the actual transport counts are separate evidence. A pure audit replay of a step reports zero new work; `replayed` identifies the stored trace and is never proof that this invocation did nothing. When concurrent callers write the same step the first trace wins and a losing paid ranking is disclosed as unused. Baseline fallback (flagged) covers only the documented availability and local sub-deadline cases while the global deadline is alive; cancellation, global expiry and integrity failures never become success. Per-query feature and bound checks run after a legitimate existing trace can replay but before the intent, any embedding or any provider work, so an unconfigured or over-cap request refuses without spend.

**Grounding validator.** Input: a model's `GroundedAnswer` (cited assertions or an abstention; a structured answer is only a proposal) and caller-supplied context: the run, corpus and the steps whose delivered evidence the answer may cite. The validator rechecks the workspace, run, steps, corpus and every stored identity (the trace ID derived from workspace, run and step; the immutable intent, request and payload digests; the delivered `E`-to-chunk mapping; document, version, stored version digest and span) with the same trace checks as replay, without the original query. What cannot be reconstructed without the query is not claimed: that the query text hashes to `query_sha256`, that the allowlist matches `scope_sha256` and that the configuration fields match `config_sha256`. Quotes match exactly in code points with no whitespace, case or Unicode normalization. Without offsets a quote must occur exactly once, so a repeated or overlapping occurrence is ambiguous; explicit offsets may select one exact occurrence. Evidence from mixed generations invalidates all otherwise matching citations, while other failed checks stay visible. Three claims stay apart: historical identity (`verified`: the run's own digest-verified trace delivered this chunk, the version body digest holds and the quote is exactly those code points); current-ready (`generation_current`, one pointer observation at validation time, never a promise that it stays true; replay does not refresh evidence); and claim support, which is constant false. A model's `policy_dependent` label is not verifiable, so a mislabelled policy claim can escape abstention. None of this is user authorization, consent or approval: the caller authorizes.

**Citation recorder and reconciliation (`persistence/citations.py`).** `record` takes a bundle that carries no status and treats it as an assertion: the caller's context must equal the bundle's or it refuses before any SQL. It runs one short `READ COMMITTED` read-write transaction on its own connection (owned from acquisition, static SQL, no provider, human or model work inside):
1. lock the corpus row `FOR SHARE` (publication takes it `FOR UPDATE`, so an activation is ordered entirely before or after the transaction) and observe the equal rows already present;
2. require every claim's generation to be the active one (`stale_evidence` otherwise);
3. recheck every claim field by field on this connection (the first failure refuses the whole batch), including that a ready chunk which was not delivered in that step fails;
4. checkpoint the deadline, insert every new stable ID (`INSERT ... ON CONFLICT DO NOTHING`; the existing ready-generation guard runs on each new row), then read every distinct ID back and compare it field by field and against the body slice (an absent or unequal row is `citation_id_conflict`);
5. COMMIT. An exception from COMMIT has an unknown outcome and is reported as ambiguous (`record_ambiguous`), never as success; a COMMIT acknowledged after the deadline returns `deadline_passed` with the rows kept and the commit marked observed.
New writes are all or none; equal rows that already existed are a normal state (an earlier subset, or another bundle citing the same span) and are reported, not rewritten; duplicate claims in a bundle map deterministically. `recorded` describes the rows this recorder wrote or found equal: at commit they were ready-generation evidence delivered to this run's authorized step and quoting the exact body slice, not that they stay current. It says nothing about other rows in `app.citations`: the existing insert guard alone does not check the run, the delivered `E` map or the quote relationships that this recorder rechecks. `reconcile` is read-only and historical (it reads citations, step records and version bodies, never the chunk table), so it works after an activation; `not_observed_yet` and missing IDs never prove absence (an ambiguous commit may still be completing), there is no definitive "not recorded", and an observation never authorizes a write. Fault injection exists only as an explicit test-only plan, refused outside tests. The cleanup paths protect the primary unexpected error (rollback and close failures are attached as notes); an operational failure of rollback or close can still propagate and stays visible.

**Limits.**
- Synthetic fixtures, synthetic vectors and scripted provider transports only; no real-provider call, no retrieval-quality, rerank-benefit, cost, saving or latency result, and no model comparison. A passing fixture shows mechanics.
- Grounding establishes the historical identity of a quote in delivered evidence. It does not establish entailment, correctness, current policy or authorization, which the calling service must supply; the configured investigation supplies the caller-side scope and integration.
- SQL transactions, including the wait on a concurrent insert of the same citation ID, are not interrupted by deadlines. Finite deadlines and phase checkpoints decide what is returned once control comes back; no hard wall-clock bound is claimed.
- Grants are ledger grants, not physical transmission; non-observation of rows is not absence; a retired snapshot is never current evidence.

<a id="retrieval-evaluation-machinery-t15a"></a>

## Retrieval evaluation machinery

Internal, offline machinery for a later retrieval evaluation (`policyops_contracts/e01.py`, `policyops.studies.e01_plan`, `policyops.retrieval.records` and `diagnostics`, and the evaluator's `e01_metrics`). No study has been run, and there is no controller, migration, HTTP route, worker or agent caller. It has been exercised only on synthetic fixtures and local PostgreSQL; no quality, coverage, cost or performance result exists.

**Contracts and planning.** A manifest (status `proposed`) enumerates every scheduled slot (phase, arm, task, trial) with a derived UUID identity, whether it has a provider path, its common budget envelope and a closed cohort of tasks and trials per arm. Arm selection is a separate, immutable decision record, so the manifest digest does not change after selection. Planning is pure: envelopes derive from the actual actor reservations (a chat attempt and an embedding batch), each cap is checked against the budget ledger's own cap type, and the declared ceilings keep chat calls, embedding batches, token maxima and USD apart. A manifest is admitted only if every (phase, arm) cohort is permitted for its phase and domain, covers every task and trial, and follows that phase's plan, provider path and common envelope, so the comparable arms of a phase always share one envelope (the replay screen's lexical arm has no provider path and no envelope). The declared ceilings are sums over the manifest's own declared slots, and the optional confirmation phase counts the most expensive legal selection, which is the costliest single simpler arm plus the reranked arm. Ceilings are reservation maxima, not expected spend, and corpus ingestion is excluded. All of this is a proposed design only: no controller exists and no study has been run or has spent anything. The selection rule is a replay screen that only proposes confirmations, then an in-situ decision table (reranking only on an in-situ lower bound above zero, a simpler arm only when its in-situ result clears a proposed 0.05 margin, otherwise the hybrid arm). The margin is a descriptive proposal, not a measured result. Records hold identities, stems and digests, not query text or labels; costs are unknown unless a slot's own ledger scope supplies them.

**Three object kinds.** Metrics keep these apart:
- **D**, the delivered set: the deduplicated union of document stems of the evidence a trajectory's retrieval steps actually delivered. It is the basis of every headline coverage.
- **C**, the candidate set: the documents in the bounded fused pool of those steps. It is reported separately as candidate coverage and is never a headline. D is a subset of C for ranked modes; for the full-policy control C equals D.
- **The full ranking** of each step, a permutation of its candidates, used only for ranked-list query proxies.

**Metrics (evaluator side, exact fractions).** Required-document labels are task-level labels for a whole trajectory, not per-turn relevance. Trial coverage is the share of a task's labelled documents in D. Outcomes must match the manifest's scheduled slots exactly (no missing, duplicate, unscheduled or wrong-arm record), and each record's steps are bound to the arm's configuration. Each metric has three variants over the same slot set:
- **strict** (headline): a slot that did not complete contributes an empty D, so zero coverage;
- **observed progress** (diagnostic): the partial sets of every slot, completed or not;
- **complete-case** (diagnostic): completed slots only, and undefined (not zero) when none completed.

Task-macro coverage averages trials within a task and then tasks; document-macro weights each labelled document equally; the all-required rate asks whether every label was delivered. Query proxies (Recall@k with its ceiling, MRR, R-precision) are diagnostic and are never turn-relevance judgments or gates. Paired comparisons pair arms on the same task and trial, then take a task-cluster bootstrap with the type-7 percentile (h = (B-1)p, exact interpolation). A separate sensitivity resamples heuristic scenario groups while keeping the task-weighted estimand. Task weighting does not treat trials or grouped tasks as independent, and the intervals are descriptive selection aids on the 39 development tasks with several arms, not confirmatory significance.

**Labels.** The evaluator reads banking labels only for development tasks: the dev IDs come from the reviewed split manifest, then exactly those pinned task files are opened and only the ID and required documents are kept. Labels never enter the application runtime, prompts, records or logs.

**Authoritative read-only export (`retrieval/records.py`).** It turns stored retrieval steps into records. It rechecks each trace against its immutable intent and version spans without a query (`check_step`, evidence verification), maps every delivered and candidate document UUID through the workspace's `app.documents` rows to a source stem that must be in the digest-verified ingest manifest and match the span's source URI, and checks the trace's generation membership. A missing, foreign or unlisted mapping, or a trace that contradicts itself, is an export error and is never dropped. This proves the consistency of stored records, not the query, the ranking, semantic support or authorization. Queries are not stored in the records, so full offline replay needs the visible-query sidecar planned for banking retrieval study.

**Local diagnostics (`retrieval/diagnostics.py`).** Two named operations run `EXPLAIN (ANALYZE, BUFFERS)` over the fixed lexical and dense branch statements as the application runtime in a read-only, workspace-scoped transaction. A query has character-count and character bounds and a vector has dimension and validity checks; the branch size and repeat count have small fixed limits. These are input bounds, not retrieval-step token admission, and they do not establish a hard wall-clock interruption of a running statement. The output is a local plan and timing sample on one machine and database, not a production latency or quality claim. There is no diagnostics command-line tool.

**Limits.**
- Offline typed planning and metrics, the authoritative read-only export and the named local diagnostics are implemented. Banking development trajectories, the study controller, selection, query sidecar and quality gates remain outside this release.
- Synthetic fixtures only: a passing test shows mechanics, not retrieval quality, coverage gain, cost or latency.
- Query-less verification, strict-versus-observed reporting and paired intervals do not prove entailment, current policy or authorization.

<a id="minimal-agent-baseline-t20"></a>

## Minimal agent baseline

The minimal agent (`policyops.orchestration.minimal` and `ports`, and the conversation
contracts) owns a bounded half-duplex loop. It is used by the benchmark harness and remains
distinct from the checkpointed workbench graph. [E03](evaluation.md#e03-model-comparison)
reports its live retail results. Synthetic and local PostgreSQL tests separately cover
multi-turn history, cancellation with held billing, unknown tool outcomes, shared budget
admission and rejection of late replies.

**Ownership and construction.** One `MinimalAgent` owns one conversation: the transcript, counters, the last accepted retail step, the turn index, the terminal state and any pending tool are private. The caller supplies only `turn(UserMessage, deadline=...)` with an absolute monotonic deadline; `snapshot()` returns a bounded immutable copy and does not resume anything. A closed, busy or invalidly-deadlined call is refused before any state change or port call. After a terminal outcome, cancellation and unexpected errors included, every further turn is refused, so a possibly executed action or an in-flight model call is never continued under a fresh key. Construction runs pure checks only and builds nothing by default: the policy, prompt, tool-catalog and agent-actor digests must match the configuration, retail mode must use exactly the typed retail tools with a retail policy, the knowledge flag must go with a knowledge port (and the knowledge step limit is positive exactly then), the output cap must fit the agent actor, and a test-only port or the fictional fixture policy is refused outside the test environment. A template request goes through the provider `prepare` step, which makes no count, network or reservation. No default provider, client or count exists at construction; the first one that can exist is on the first turn's model call.

**Injected ports.** The model, tool and knowledge ports are explicit arguments. The one production model adapter, `agent_model_port(ledger, binding, providers)`, is the existing provider `call` for the fixed `agent` actor with zero retries and zero repairs, on the caller's ledger, binding and providers factory. It records the agent actor's configuration digest when built and rechecks it before every call: a changed configuration returns a contract-gap report without calling the factory, reserving or sending. A ledger conflict or an inactive scope becomes a failed report and never a new key. Tool-call validation is not authorization: retail writes stay behind the deterministic gateway and approval path, the baseline executes nothing itself, and the fake tools are test fixtures. The knowledge port is a read-only interface that returns content only; the runtime binds its result to the pending call. Its banking Retriever-backed adapter remains outside this release.

**Domains and the knowledge tool.** The retail mode puts the visible retail policy in the prompt (the full-policy control) and offers the typed retail tools; a protocol violation or an invalid argument is an invalid reply, and the exact handoff message after a transfer ends the conversation. An optional read-only `search_policy` knowledge tool has a reserved name, counts toward every catalog limit and has its own step limit. The retail policy used in the unit and integration tests is a fictional fixture, and the pinned public retail policy text is not in the repository. A separate control loaded that pinned policy from the acquired upstream data tree, outside the repository and with no task payload, and its digest matched the contract. It showed that the full text and all 16 typed retail tools are preserved in the built request and that the real serializer's pure preparation accepts it, with a scripted model reply and no provider or count request. That checks input and serialization mechanics only: it is not token-count admission, policy-following quality or a provider conversation.

**Invalid replies and history.** The benchmark protocol accepts a single valid tool call
with accompanying text by dropping the text before delivery and recording `tool_text_dropped`.
The gateway and investigation graph keep strict parsing.
An invalid reply (several calls, no action, an unknown tool, invalid arguments, a retail protocol violation, invalid structured output or an oversized message) appends only a fixed runtime notice from a closed code set. No model text, call or ID is kept, and too many in a row is a terminal outcome. The provider history is built purely from the transcript: each accepted action is one assistant message, each run of user-side entries is one user message in append order, and a tool result must be the very next entry after its call. Otherwise the agent raises an invariant error and never re-sorts. Conversation IDs and keys never reach prompt content.

**Unknown outcomes, cancellation and billing.** From the moment a tool call is dispatched until a validated result carrying exactly that call ID is accepted, its outcome is recorded as unknown. A port error, an invalid, foreign or oversized result, or a cancellation leaves it unknown and ends the conversation; absence of a result is never read as non-execution, and nothing is retried. Model-call keys are deterministic from the conversation and a call index counted before each await, and a terminal outcome is never followed by a re-key. A model reply that returns after the deadline is terminal and is never accepted as a timely message, while the ledger keeps whatever the call really billed. A cancellation sets the terminal state and re-raises the original exception. The ledger is the billing authority: outcomes carry grant counts, never costs, and grant counts are not proof of transmission.

**Limits and an ordinary choice.** Defaults are 16 model calls per conversation, 8 tool steps per turn, 2 consecutive invalid replies, 128 transcript entries and 48,000 content bytes, 1,024 output tokens, and no knowledge steps unless the knowledge tool is on; these bound the loop and are not token proofs, since provider count admission decides. The agent does not bind itself to one event loop: it owns no loop-bound resource, a turn that starts while another runs (on any loop or thread) is refused, and ordinary sequential turns from different loops are accepted. That does not mean injected ports are portable across loops; each port keeps its own resource requirements.

**Limits.**
- Scripted component tests establish mechanics; the separate E03 studies provide live retail outcomes
  under their specified limits. They do not establish workbench graph quality.
- Nothing is authorized or executed by this component, and no real write is claimed.
- A port or synchronous wait that ignores cancellation is not interrupted; late replies are rejected only after they return. Turns are serialized at entry only, with no port-level thread-safety guarantee, and prompt quality is evaluated only within the separately specified benchmark studies.
- There is no command-line tool for it. The graph, checkpoints, HTTP, worker and UI are implemented separately. The banking
  Retriever-backed knowledge adapter and trajectory study remain outside this release.

## Dev calibration allowlist and demo seeds

`evals/manifests/tau2-19f13ea3/retail-calibration.json` is rebuilt from the committed data-audit manifests by
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


## Retail simulator

`evals/src/policyops_evals/retail_sim` is the evals-owned `retail-simulator` service (retail simulator). The application never
imports it; `policyops.adapters.retail_client` talks to it over HTTP, and the shared RPC models live in
`policyops_contracts.retail_service` (exported with the other schemas).

**Fixture and upstream.** A fixture root holds exactly the reviewed `data/tau2/domains/retail/db.json` and `LICENSE`,
copied from a verified checkout and checked against `evals/manifests/tau2-19f13ea3/source.json`. `TAU2_DATA_DIR`
points there, so no task, split or held-out file is present. The service uses `RetailDB` and `RetailTools`
directly. Importing the `tau2` package also loads its runner, registry, agent and voice modules (import time only),
and the one import-time `audioop` deprecation warning is ignored by message; nothing else is constructed or run.

**State.** Each case has one isolated copy of the full upstream database (`retail-state/v1`: canonical JSON of the
upstream model; float repr round-trips exactly; capped at 8 MiB), bound once to a fixture identity and the case's
customer. The case `version` is a serial; the customer's user and orders have their own positive integer versions;
the catalog is immutable within the fixture and has version 1.

**Scope.** Writes and reads must stay within the bound customer: another customer's order, user or payment method is
answered as not found whether it exists or not, and user lookups return only the bound customer. The catalog is
shared. The service checks service identity, scope, versions and the exact effect; it does not decide approval or
consent, which stay with the application's services.

**One write.** Under the case row lock (`FOR UPDATE`), and in this order:
1. look up the operation ID (a stored outcome with the same fingerprint replays; another fingerprint conflicts);
2. scope, then the order and user versions (stale is a terminal `version_conflict`), then exact coverage of every
   resource the tool reads, catalog included;
3. run the upstream tool on a freshly decoded candidate;
4. project the *actual* effect from the before and after states, tool by tool (below), converting every changed
   amount with exact money (no epsilon or rounding);
5. compare it with the approved expected effect, and commit the new state, versions, a terminal row and an immutable
   receipt in one transaction, or record one terminal negative row and change nothing else.
The signed context's expiry is checked again at the write, so a request that expired while waiting applies nothing.
No network or model call happens inside the transaction. CPU is bounded structurally (the fixed fixture, 64 KiB
bodies, at most 50 items, the bounded calculator grammar), not preempted: database timeouts do not interrupt Python.

**Effect projection.** The whole state is diffed and every changed path must belong to the tool:
- `modify_pending_order_items`: each target position must carry *its own* variant's item ID, price and options (the
  pinned upstream reuses the last variant for every position; such a candidate is refused even when the aggregate
  payment matches); one payment or refund line of the exact difference; the gift-card balance delta.
- `exchange_delivered_order_items`: only the request metadata changes (sorted old and new items, the method, the exact
  difference); items, payments and balances must not. Pairing comes from the approved call.
- `return_delivered_order_items`: sorted items and the refund method; upstream records no refund amount.
- cancel, address and payment changes: the status, refund or payment lines and balance deltas, exactly.

**Identity.** The operation fingerprint (`policyops.retail-operation/v1`) covers tenant, case, customer, fixture,
operation ID, call, expected effect, the expected versions (order-independent) and the caller's `intent_sha256`. The
signed transport context (`policyops.retail-auth/v1`, HMAC-SHA256) covers method, path, the complete body digest,
scope, tenant, case, customer, fixture, a lifetime of at most 60 s and a single-use nonce; these are not part of the
fingerprint, so a retry with a fresh context is the same operation. A fence names the *original* fingerprint.

**Outcomes.** `committed` (with a receipt); `upstream_rejected`, `effect_mismatch`, `money_unrepresentable`,
`version_conflict` and `fenced` change nothing else and are terminal. A lookup returns a stored outcome or `unknown`;
only `POST .../fence` makes absence definitive. A malformed, unauthenticated or uncovered request mints no row. A lost
response, a timeout or a 5xx is `unknown` to the client, which never retries a write itself.

**Reads.** Read results carry bounded, typed details rather than raw upstream objects: each variant's sorted
options with its product name, ordered items with names and options, fulfillments, the cancel reason, a recorded
exchange or return *request* (an exchange request records the quoted difference as exact money; neither moves money
or items), and for the case's own customer their name, email, payment methods and only the order IDs that are
really theirs. Each detail has an explicit `to_snapshot()` projection into the minimal domain snapshots
(`UserSnapshot`, `OrderSnapshot`, `VariantSnapshot`), which are unchanged and remain the deterministic rule inputs.

**Faults.** Test and demo only (`serve --faults`; the endpoint does not exist otherwise): one-shot 429 or 503 before
the work, a bounded delay, or commit-then-503. Each adds an `X-PolicyOps-Fault` header.

## Policy and tool gateway

`policyops.gateway` is the only path from a run's typed agent step to the retail service. It composes the
deterministic domain rules; it does not reimplement them, and it dispatches no write.

### Scope

**How the scope is built.** `GatewayScope` (run, case-customer binding, fixture digest) is built by the server.
`load_scope` reads the persisted run and case under the workspace scope, and refuses a binding for another case or
customer.

**Binding before contact.** The gateway checks that the retail client is bound to exactly that tenant, case,
customer and fixture, and refuses before any request if it is not.

**Model identifiers are compared, never adopted.** A `user_id` or `order_id` in a step is only compared with the
scope; it never becomes one.

### Steps

**Parsing.** The provider result becomes one typed step through the closed parser (`parse_result`, built on the provider
bridge):
- an unknown tool is out of scope (`scope.supported_requests`);
- an extra field on an order modification is an unsupported change (`modify.allowed_fields`);
- any other invalid or extra argument is fixed invalid input.

Dispatch is a closed match on the validated call. A step object that skipped validation is re-validated and refused.

**Lookups.**
- A lookup authenticates only if the service answers the case's bound customer.
- The authentication is recorded in `app.customer_authentications`, first write wins. A different identity is a
  `customer_mismatch` and is never adopted.
- An unknown, refused or not-found lookup records nothing. The service hides other customers, so a lookup for one
  reads as not found.

**Reads.** A read result must be the requested resource, listing exactly its own resource version. Anything else is
`facts_invalid`. The typed detail goes back to the model as untrusted data, and its strings never steer anything.

**Writes.**
1. The gateway collects the facts for the decision in a fixed order: the customer, the order, then each distinct
   replacement item through `get_item_details`. The replacement's product comes from the service, never from the
   call.
2. Every read in one collection must report the same `case_version`. Otherwise the whole collection is repeated, at
   most three collections in total, and then refused as retryable `facts_inconsistent`. A mixed-version fact set is
   never evaluated.
3. `evaluate_write` decides. An allowed write becomes a `ProposalPreview`: the server-rendered text, computed, not
   persisted and `actionable: false`. It carries no proposal ID, digest, consent or approval authority. The durable,
   actionable pending proposal is created by the proposal service.

**Order targets in investigations.** Each order-targeted write checks the proposed order against exact `#W` or `W`
tokens followed by seven digits in persisted case messages. The sources are the seeded scenario opener, simulated
customer turns and operator-entered customer turns. Agent messages, staff notes, help-desk ticket text and tool results
convey no target authority. A stated ID proves the customer mentioned an order. Consent and separate reviewer approval
still establish authority for the specific effect. Help-desk provenance could be evaluated separately in the future.

If the customer stated any IDs, the proposed order must be one of them. If they stated none, the proposed order
must be the sole order in the tool's actionable status on the bound customer's profile. The gateway reads the complete
profile closure at one coherent retail case version, with at most 16 sibling reads across recollections. Missing or
inconsistent facts fail closed. Sibling reads establish eligibility and contribute no expected mutation versions.
Description-only requests with several actionable orders require clarification even when a description distinguishes one.
The shared rule refuses with `policy_denied` and detail `target_clarification_required`. Proposal creation checks the
customer statements again under the case lock and refuses agent order facts without target selection data.

**Once-per-order tools.** The default operation history (`IncompleteHistory`) is incomplete, so every once-per-order
tool escalates (`orders.modify_exchange_once`). The execution executor passes `LedgerHistory` (below).

**Transfer.** A transfer returns the handoff observation; the next step must be the exact handoff message.

### Execution precheck

`precheck(scope, refs, ...)` is the gate the executor (execution) calls immediately before a dispatch. It takes
references only, the proposal ID and version and the consent and approval IDs, and loads each record from a
`DecisionStore`. It re-validates each record from its serialized form, so a constructed or untyped object is no
authority.

**Before any read**, it requires:
- a decision store. `PgDecisionStore` loads persisted authority; omitting it refuses with `no_decision_store`;
- a proposal for this run, customer and pinned policy;
- a consent and an approval bound to it, with the chronology checked;
- the run's durable lookup authentication.

**Then it reads the current facts** and re-evaluates them:
- for an investigation order write, customer statements are bounded to sequences earlier than that proposal's
  persisted presentation. The executor repeats the target check against fresh retail facts at reservation, first
  dispatch and any resend. A refusal requires a fresh proposal, consent and approval;
- a denial or escalation is returned as itself, so approval never overrides an invalid policy;
- a different effect, resource-version set or rule set is `stale_version`.

**After those reads**, it checks:
- that the approver still holds the reviewer role;
- that the proposal's evidence is still current;
- the time, once more.

**What it returns.** It returns the exact `MutationRequest` and `authorization_not_after`, the earliest of the
approval, consent and proposal expiries. It assigns no operation ID and dispatches nothing.

The service checks the expected resource versions under its case lock and the client caps expiry at commit. A sibling
can become eligible between precheck and send without changing an expected resource version. This residual race is the
trade-off for keeping the existing mutation contract and fingerprints, which support reconciliation by operation ID.

### Rule coverage

[`docs/policy-coverage.json`](policy-coverage.json) maps every source-traced rule to the gateway cases that exercise
it. It is generated from the executable case table in `tests/support/policyops_testing/gateway_cases.py`, and a test
requires byte equality.

**Per case it records:**
- the asserted outcome, error code and rule ID;
- for a case whose asserted rule differs from the covered rule, the reason;
- whether it ran with the labelled test-only complete history.

**Requirements by rule kind:**

| Rule kind | Requirement |
|---|---|
| Deterministic | Executed allow and deny cases. A rule the typed contract enforces is denied by the closed parser, before any read |
| Escalation | Escalation cases |
| Presentation and protocol | Gateway cases plus the named existing tests |
| Not codified (`grounding.no_fabrication`, `time.est_database`) | Listed with their reason; counted as uncovered |

**What the map does and does not prove.** It records a mapping. The evidence is the parametrized test that
executes every case.

<a id="approved-execution-and-reconciliation-t19"></a>

## Approved execution and reconciliation

Implemented in `services/execution.py` (`Executor`, `LedgerHistory`), `runtime/executions.py`
(`ExecutionDispatcher`), `persistence/executions.py` and revision `0012`; verified by
`tests/integration/test_execution_retail.py` against the real `RetailClient`, the owned retail simulator simulator process and
PostgreSQL as the runtime and discovery roles.

- **Identity.** One execution per approval. The operation ID is a `uuid4` chosen once at reservation and stored with
  the immutable `MutationRequest` and its operation fingerprint; every retry, lookup and fence reuses them. A second
  approval for the same order (or user) cannot be reserved while an execution on that target is unresolved. A
  repeated reservation returns the stored operation only when it names the same run, proposal, consent and approval
  (otherwise `IdempotencyConflict`); it is not re-prechecked, so it neither renews an expired approval nor mints an ID.
  Every transition re-reads the locked row and refuses a caller snapshot whose binding differs; a stored outcome (and
  its receipt) must be of that row's operation and fingerprint.
- **Authority.** Only persisted proposal review records (read by `PgDecisionStore`, `PgMembership`, `PgSessionStore`,
  `PgEvidencePort`) authorize. The dispatch checkpoint locks evidence corpora, run, proposal, the approver's
  memberships and the execution, then rechecks the claim, the run, the proposal status, the reviewer role, the
  evidence and `now < authorization_not_after - margin` before `dispatched` commits; only then is the request sent.
  The HMAC token is transport identity, not approval. Checks are immediately before the hand-off; revocation after
  the request begins is not atomic with it.
- **Recording.** Any validated stored outcome (`mutate`, `lookup`, `fence`, or a late original) is routed alike:
  committed -> `succeeded` with the receipt, fenced -> `reconciled`, other stored outcomes -> `failed`; an equal
  terminal observation is a no-op, a contradiction is an audited alert and never overwrites. `Unknown` and refusals
  leave `unknown`, written only by the current claim. Local settling (`precheck_refused`,
  `cancelled_before_dispatch`) is possible only before any checkpoint. Each transition commits its
  `execution.changed` run event, outbox intent and audit row together; events stay durable after a cancelled run
  (the run is not reopened; a live SSE stream that has already closed does not see them).
- **Reconciliation.** Lookup absence is never proof. While authority is current and the dispatch cap allows, a fresh
  precheck may resend the same operation; otherwise the operation is fenced (allowed after expiry or cancellation:
  no business effect, the original fingerprint). A fence is sent only under a live claim re-read after any lookup,
  with its service token capped at that claim's lease end; a worker whose claim lapsed sends nothing and the next
  claimant fences. Once-per-order tools with their own
  unresolved execution are fenced rather than resent. Past the reconciliation cap a row stays `unknown`,
  unscheduled and holding its target: explicitly unresolved, never guessed.
- **Limits.** PostgreSQL uses configured per-statement, lock and idle timeout profiles, but SQL and COMMIT are synchronous and can delay cancellation; an in-flight request cannot be
  cancelled; the token's lease cap narrows a stale worker's window but is no COMMIT deadline. The component assumes
  one coherent retail database and ledger lifetime with no independent ledger deletion and no retail reset while
  operations are unresolved: such a reset is not detected (local Compose). `LedgerHistory` is complete only for a simulator
  case written exclusively through this ledger. The review continuation composes the persisted scope resolver and retail client.
- **E04 development harness.** `tests/support/policyops_testing/execution_faults.py` (seeded fault plan, crash hooks,
  raw trial records, derived summary) drives the real dispatcher in a small seeded test; the completed comparative study is described in [evaluation](evaluation.md#e04-operation-ledger-versus-naive-retry).

## Investigation graph and checkpoints

`runtime.investigation.build_investigation_spec` composes an injected model/provider factory, run-bound retail
gateway, policy retriever and citation recorder into a `RuntimeSpec`. Install it in the same `RuntimeCatalog`
passed to the API runtime and worker. The default API/Compose demo leaves model-driven investigation unconfigured.

The graph investigates one action at a time through `investigate`, `retrieve`, `read`, `propose` and `finalize`.
Writes prepare an immutable proposal and presentation, then leave the run in `waiting_approval`; they do not
execute commerce changes. Answers require every assertion cited and every quote verified and recorded, or return
a fixed abstention. Citation checks establish retrieved identity and exact quotes; `claim_support_validated`
stays `False`. Approval/consent decisions and new-input resume belong to the subsequent workflow.

An async, tenant-bound saver stores versioned JSON-only checkpoints in three migration-owned FORCE-RLS tables.
Every mutation checks the worker generation in the same transaction. Checkpoints use a server-derived thread ID
and synchronous durability. A reclaimed invocation resumes with `ainvoke(None, ...)`, preserving scheduler state,
input snapshot, counters and pending actions. Proposal preparation reconciles the same run/step before collecting
facts again; final messages, message events and run status commit atomically in worker finish. Terminal checkpoints
short-circuit model/tool work. A lost billed model response becomes `provider_result_unavailable` under the original
invocation key, without paying for a replacement response.

Investigation state v2 fits context at intake, before checkpointing node results and before each model request.
It evicts the oldest unpinned completed call/result pairs first, then old notices and agent history. Input messages,
pending actions, validated evidence-bearing search pairs and typed proposal/presentation/consent/decision facts
remain pinned. Arguments, quotes and presented terms are never shortened. If the required material cannot fit,
the run stops with `context_limit`. Version 1 investigation snapshots fail closed; there is no implicit upgrade.
Provider preparation also enforces server-owned aggregate bounds before decoding schemas/arguments or building
provider histories: 256 messages, 2,048 parts, 32,768 structural nodes and 256 KiB of UTF-8 content/schema text.
Escaped canonical inference and count bodies are measured with early exit before full encoding, each at 512 KiB.
These bounds are digest-bound and do not replace token admission or token headroom checks.

Resource exhaustion produces a typed `run.stopped` event and a fixed message saying what stopped and that no
further actions will run. Message, event, terminal run state and job completion commit together. Resource stops
use `budget_exceeded`; context/contract failures use `failed`. Unconfirmed usage is reported explicitly and its
reserved cost remains held. In-process billing evidence can still be lost on a crash; there is no accounting outbox.
The final permitted model answer may finalize deterministically, but another model/tool step cannot start after
an exhausted cap. Embedding/reranking budget exhaustion stops investigations even when standalone retrieval is
configured to fall back. A stopped run never automatically resumes or resets its caps. Graph loop/integrity
failures keep separate failure codes.

The custom saver trades stock `PostgresSaver` features for explicit tenant RLS, restricted runtime grants and a
closed serializer that cannot reconstruct arbitrary Python objects. Runtime DDL, forks, subgraphs, arbitrary object
payloads and checkpoint pruning are unsupported. Framework checkpoint v4, codec v1 and application state v2 are
checked separately; incompatible state fails closed. Persisted step counts and an independent graph recursion
limit bound loops. Unit tests exercise the graph with fake ports and the closed codec; PostgreSQL integration
cases cover worker completion, restart/reclaim, fences, tenant denial and cancellation.
Graph identity uses an explicit semantic version plus topology, state schema and checkpoint versions, preserving
in-flight runs through unrelated source edits while requiring a deliberate version bump for behavioral changes.

SQL and gateway calls are synchronous and can block the event loop, heartbeat and cancellation: there is no hard
deadline guarantee. The run-bound ledger checks the investigation claim at reservation, count and dispatch admission, including
a post-lock-wait recheck. A previously admitted in-flight provider call cannot be unsent by a later fence. Checkpoints do not supply provider-result
replay, remote exactly-once execution, customer consent or staff approval.


## Approval continuation and outcomes

An investigation presents one durable proposal and waits for approval. An operator-entered customer reply is
classified for consent in the message transaction; a staff note never gives consent. A separate staff decision
enqueues a durable review job. Approval revalidates authority and reserves through execution; the dispatcher alone sends
the mutation using its stable operation ID. Rejection, expiry or staleness ends with a typed refusal. Rejection
does not automatically replan: it provides no new authorized intent, and replanning could re-propose the declined
action or spend more model calls. A new investigation is a new run.

Terminal ledger changes and capped unknowns enqueue outcome jobs. These only project durable truth into a bounded,
deterministic summary and `review.outcome` event, atomically with the final run state. Committed success requires
the actual bound receipt. A fenced operation resolves the workflow with no business effect. An unknown outcome
stays unconfirmed and reconciling; it never means success. A late receipt produces a correction at its new ledger
version. A cancelled run stays cancelled and still receives later execution truth; cancellation cannot undo a
remote commit. Outcome delivery has a separate 24-hour deadline, ten attempts and 30-second leases.

The run's active allowance counts queued, running and reconciling time, including backoff and downtime.
Only `waiting_input` and `waiting_approval` pause it; duplicate transitions and reclaim do not replenish it.
`deadline_at` is the current active segment's projection and is null while waiting or terminal. Proposal,
consent, approval, execution authorization and job delivery deadlines remain absolute UTC. New execute jobs
have a separate 24-hour delivery deadline. Migration `0015` cannot refund historical wait; upgrade with workers quiescent.

Runtime transactions configure statement / lock / idle-in-transaction timeouts in milliseconds: DEFAULT
5000 / 1000 / 5000, LEASE 1000 / 250 / 2000, and RETRIEVAL snapshot 15000 / 1000 / 5000. Pool checkout is
configured for two seconds, and the served API retains its finite connection timeout. These are per-operation
settings; synchronous SQL can delay cancellation, and network or COMMIT acknowledgement loss prevents a universal
wall-clock guarantee. A failed COMMIT is an unknown outcome, reconciled by the original IDs before more work.
Run-bound agent, query-embedding and reranker spending also requires the current investigation claim, rechecked
inside admission after lock waits. Accounting can finish after fencing.

If accounting fails after dispatch, further dispatch stops. Available normalized usage remains in the process's
report, and unsettled reservations stay conservatively held; a typed failure summary states the uncertainty.
There is no billing-evidence outbox: a process crash can lose that available evidence. A lost settlement COMMIT
acknowledgement may already have settled the attempt; durable state must be checked using the same attempt ID.
Legacy pending proposals predating review continuation are not migrated, and dead-lettered summaries have no operational repair tooling. See `tests/integration/test_review_outcomes.py` for the approval-to-summary and recovery cases.

[docs/policy-coverage.json](policy-coverage.json) maps every policy rule to its executed cases. See
[docs/architecture.md](architecture.md#policy-and-tool-gateway).


## Observability

Core telemetry is off by default. For the served API, set `POLICYOPS_TELEMETRY_ENABLED=true` and
`POLICYOPS_TELEMETRY_EXPORTER=console` (JSON to stdout) or `memory` (bounded, process-local inspection).
Library/worker hosts explicitly call `policyops.telemetry.configure(TelemetrySettings())` once before composing
the worker and own the returned backend's `close()` at shutdown. The Compose worker supports console and
memory telemetry. The API and Compose worker install the served JSON log configuration. The fixed resource uses
the service name `policyops-api`, `policyops-worker` or
`policyops-demo`, with no resource detectors. Default instrumentation skips SDK provider and exporter construction.

Manual spans cover route templates, job claim/execute/finish, graph nodes, provider attempts, retrieval, tool
steps, review, execution reservation/dispatch/reconciliation and SQL failure phases. Only allowlisted enums,
UUID correlation IDs, bounded counts, SQLSTATE classes and exception type names are recorded. Structured logs
discard free-form messages, arguments and tracebacks. Customer text, prompts, responses, tool arguments,
evidence, names, email addresses, credentials, cookies, DSNs and raw request paths are never recorded.
Incoming trace headers and baggage are ignored. Instrumentation uses the versioned `policyops.telemetry/v1`
schema rather than adopting changing GenAI semantic fields; provider mappings remain local to the adapters.

The direct `opentelemetry-sdk` 1.45.1 dependency provides standard context, batching, metrics and test exporters
instead of a custom tracing runtime. It pins API 1.45.1 and semantic-conventions 0.66b1; all three distributions
declare Apache-2.0 and ship their license files. See [third-party notices](../THIRD_PARTY_NOTICES.md#opentelemetry).
HTTP templates come from FastAPI's resolved OpenAPI paths and selected inclusion context, preserving router
prefixes and parameter placeholders; unmatched paths have no route attribute.

Counters record provider dispatch attempts, known input/output usage and priced USD, fixed error codes and observed
job/review/execution outcomes. Unknown bills remain unconfirmed. These lossy counters are diagnostic observations;
the durable usage/execution ledgers remain authoritative. Due queue depth and oldest due age (including expired
leases) use a separate best-effort read with the discovery role's existing scheduling grants. Metric labels are
closed provider/model/outcome/kind/code sets, with no UUIDs. A bounded 256-job cache links previous attempts within
one worker process; after restart/eviction, use run and operation UUIDs to correlate separate traces.

`policyops.provider.dispatch_duration` is an additive histogram in `policyops.telemetry/v1`. It records adapter
send/response/cleanup elapsed seconds with provider and model labels for chat and embedding requests. Its fixed
bucket boundaries are 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30 and 60 seconds. Token
counting, ledger accounting and retry backoff sit outside the timed boundary.

The SDK batches at most 256 queued spans, 32 per batch, and reads metrics periodically. Exporters run on one
daemon lane with 32 pending batches; overflow is dropped. A blocked exporter may retain one active batch until it
returns or the process exits. Shutdown detaches immediately, drains in the background and never waits on exporter
code. Memory mode retains the last 256 spans and 16 metric batches (`backend.spans.get_finished_spans()` and
`backend.metrics.items`) for local inspection and tests. A short-lived driver can call `backend.flush(seconds)`
before shutdown. A successful flush confirms the SDK handed data through the lane without observed lane losses.
The demo also queries Grafana to confirm ingestion.

The optional `policyops[otlp]` extra uses the pinned OpenTelemetry HTTP/protobuf exporter. OTLP requires explicit
numeric loopback HTTP traces and metrics URLs and refuses deployment. Startup refuses every `OTEL_*` variable.
The session ignores ambient proxy and credential settings, rejects redirects, and discards collector response
bodies. The host-side demo driver sends the existing manual signals to the local Grafana stack.
[Local profile operations](operations.md#local-observability-profile).


## Operator workbench

The case workspace discovers and starts investigations, streams bounded ordered activity, inspects exact
proposal versions and opens historical evidence with verified quote highlighting. Reviewers use `/approvals`
for a paged inbox and an exact-version review with action arguments, recorded effects, verbatim terms,
customer consent, policy/resource bindings and server-clock expiry. Analysts can inspect; only reviewers decide.
Staff approval and customer consent remain separate. A confirmation binds the displayed version, digest and
reason; uncertain decisions offer only an explicit identical-payload replay. Canonical reloads expose stale
reviews and decisions recorded by another reviewer.

Both workspaces separate investigation lifecycle from factual action outcomes: pending, refused, fenced
noncommit, unconfirmed or committed with a receipt reference. A late receipt after cancellation is shown as a
correction. These screens have jsdom coverage and the local Compose browser flows described in
[evaluation](evaluation.md#recovery-and-e07-correctness). Broader screen-reader and responsive-layout
review remain open. Receipt downloads, raw fact inspection
and model-generated customer replies remain outside this slice. A configured runtime is required for execution.


## Ingestion operator commands

Operator commands. The default is a **read-only plan**: it verifies, parses, compares with the active generation and
reports cache misses and a worst-case estimate, with no write, reservation, credential read or request. `--execute`
allows writes. Any embedding request additionally needs `--paid` with **every** cap given explicitly (there are no
defaults): `--model`, `--dimensions`, `--max-usd`, `--max-calls`, `--max-input-tokens` and `--max-seconds`, within
fixed ceilings (USD 1.00, 1,000 calls, 5,120,000 local tokens, 3,600 seconds) and equal to the configured
`text-embedding-3-small`/1536 actor. An import whose inputs are all cached publishes locally without `--paid`.

```powershell
# Offline: confirm the ingestion manifest matches the committed data-audit manifests.
python -B scripts/devenv.py uv --project evals run --frozen python -B -m policyops_evals.ingest_manifest --check

# Acquire the pinned data first (see Data and licensing); the acquisition root is the `tree` directory inside --dest.
$tree = 'D:\path\outside\tau2-fetch\tree'
$manifest = 'evals\manifests\tau2-19f13ea3\ingest-corpora.json'
$digest = (Get-FileHash -Algorithm SHA256 $manifest).Hash.ToLower()

# Read-only plan (default). Connects with the libpq environment (PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSFILE) as
# policyops_app_runtime; prints one JSON object (counts, digests, estimate), never document text or secrets.
python -B scripts/devenv.py uv run --frozen python -B -m policyops.retrieval.cli ingest --workspace <workspace-uuid> `
  --corpus-key tau2-banking-knowledge --manifest $manifest --manifest-sha256 $digest --acquisition-root $tree

# Local writes only (all inputs already cached, or a completed job): add --execute.
# Paid embedding (separate, explicitly authorized operation): add --execute --paid --model text-embedding-3-small
#   --dimensions 1536 --max-usd <usd> --max-calls <n> --max-input-tokens <n> --max-seconds <n>
# OPENAI_API_KEY is read only after the paid preflight passed.
```

Exit codes: 0 planned, unchanged or activated; 1 verification failure or unexpected error; 2 refused; 3 embedding
incomplete (the previous generation stays active); 4 stale activation (another import changed the corpus). When
provider work remains, a resume with different caps, a smaller token ceiling than the job's frozen total, or an
expired incomplete job is refused, never silently widened, reissued or retried. Publishing an already settled job
from the cache is local: it needs no `--paid` caps and does not validate a paid budget it does not use. No
full-corpus paid run has been performed, and the earlier one-request embedding smoke above is the only live embedding evidence; no retrieval quality, cache savings
or performance is claimed.

## Read-only MCP over stdio

`python -m policyops.mcp` serves the pinned MCP 2.3.0 protocol over the client's subprocess pipes. It opens no
listening socket and offers no HTTP/SSE transport. Its startup-fixed tools are `find_user_id_by_email`,
`find_user_id_by_name_zip`, `get_user_details`, `get_order_details`, `get_product_details`, `get_item_details`,
`list_all_product_types` and `search_policy`. Input schemas reuse the strict retail DTOs, with their server-owned
`tool` discriminator removed. Policy search takes only `query`. Extra fields, including identity selectors, fail
validation. The output schema is an object containing a discriminated `result`: read, lookup, cited policy data,
or the existing normalized `ToolError`. Unknown tools, including writes, return `policy_unsupported`.

The trusted launcher supplies `POLICYOPS_MCP_CONFIG` as serialized `policyops.mcp.config.Configuration`, and the
opaque existing session cookie separately as `POLICYOPS_MCP_SESSION`. Configuration fixes principal, workspace,
role, persisted run, server-side customer binding, corpus, fixture digest and a credential window of at most one
hour. It cannot create a membership or replace the case's persisted customer. Every valid call uses the existing
`AuthService.resolve/authorize(VIEW_CASE)` and checks that the fixed role remains current, reloads the persisted
gateway scope, then rechecks identity before delivery. Session expiry, session revocation and membership removal
deny subsequent calls. The session/principal foreign key and existing session lifecycle establish the current
staff identity; this schema has no separate user-disable flag. No identity comes from tool arguments.

Retail reads go through `Gateway.step` and `PgSessionStore`, preserving lookup-before-read and single-customer
authorization. Lookup may record its existing durable customer authentication; no business mutation, proposal,
consent or approval endpoint is exposed. Policy search uses the existing T13 read-only retrieval snapshot, lexical
fusion and bounded token delivery through `gateway.policy_search`; it makes no embedding/model calls and writes
no retrieval intents, traces or jobs. Citations contain immutable document-version/chunk IDs, source URI, exact
character span, text and digest. Citation provenance does not establish semantic support or current policy truth.

`POLICYOPS_DB_*` and the existing authentication settings configure the two verified runtime database roles.
`POLICYOPS_MCP_RETAIL_ORIGIN` and `POLICYOPS_MCP_RETAIL_KEY_HEX` configure the existing signed retail adapter.
These are trusted process settings; they are never tools or model-visible configuration. No `.env` is read.
Database transactions close before adapter calls. A lazy pool owns up to `concurrency` child processes (default 1,
maximum 4), each serially handling length-prefixed bounded request/result frames. Workers reuse their engines,
OIDC and retail clients; both database runtime roles are verified on every call, HTTP connections are checked
when used, and session/scope/role authorization is never cached. Call timeout defaults to 10 seconds (maximum 30),
including cold worker startup, with an 8 KiB argument bound and a 64 KiB result bound. Input MCP frames are limited
to 16,384 characters before JSON parsing. Cancellation, timeout, malformed/oversized output, health-check failure
or an unavailable result kills and reaps the worker within a separate two-second cleanup bound; the next call
spawns a replacement. Expected identity/policy refusals are clean results and may reuse the worker. A sole stdin
reader also watches pipe EOF and stops the worker if the server dies, even during a blocked call. Workers recycle
after 100 calls or on next use after five minutes by default (`worker_max_calls`, ceiling 1,000;
`worker_max_age_seconds`, ceiling 3,600). `worker_mode=cold` retains per-call spawning for comparison.
PostgreSQL's statement/lock/idle limits remain in force.
Read work already received by the remote retail service can finish after local cancellation; no mutation is sent.

The PostgreSQL tests in `tests/integration/test_mcp_parity.py` and `scripts/mcp_parity_report.py` replay applicable
T30 read cells and E05 text through a real SDK `ClientSession` over stdio. Reports compare decisions, error codes
and complete typed payloads and include per-call direct/MCP timings and paired overhead p50/p95/max. The report
separates cold calls (including worker spawn/resource setup), warm calls, and facade-only refusals, using request-local
MCP metadata; each group includes counts, failures, direct/MCP times and paired overhead. Both paths reuse clients.
`--worker-mode warm|cold` selects the comparison (default warm); the mixed overall overhead is not the warm protocol
cost. All original
E05 candidate actions are writes: they are refused here; their exact customer/tool text is separately replayed as
cited policy data. This is a read projection, not another execution of E05's approval/write races. Reports expose
that scope and enforce the expected case IDs. Synchronous synthetic corpus publication finishes before the replay
event loop starts. Latency excludes the session handshake; cold and warm groups remain fixture-dependent samples.
`scripts/mcp_luna_smoke.py` provides two scripted demo read tasks using the existing OpenAI adapter and persistent
budget ledger. It records preflight without paid opt-in; execution requires `--execute-paid` and explicit cost,
inference/count-call and time caps, with a hard ceiling of $0.05 and no retries, repair or model fallback.
The smoke checks the unchanged MCP input schemas against the adapter's supported domain subset before provider
count/dispatch and records their exact JSON, wire projections and projection metadata. The wire projection omits value
patterns; local validation still enforces them. Its prompt explicitly requires the complete `#W` plus seven-digit
order ID, and its manifest records the prompt hash. A smoke-only response tee retains up to four tool names (64
characters each), argument prefixes (512 characters each), and up to five validation keyword/path pairs (160
characters each) per call, including calls the adapter rejects. It buffers at most 64 KiB of an inference response;
oversized or malformed diagnostic input is marked explicitly. Only fictional fixture data belongs in this smoke.
It records exception-group leaf types without messages. Diagnostics observe delivery and preserve the adapter's
validation, billing and cleanup behavior; they never authorize execution or retain headers/full response bodies.

### Bedrock InvokeModel contract (G7)

`BEDROCK_REGISTRY` opts into `bedrock:us.anthropic.claude-haiku-5-5`, revision `pricing.2026-11-15.v1`. Existing registries,
actor defaults and `SNAPSHOT_2026_11_05` retain their values. The fixed request is
`POST https://bedrock-runtime.us-west-2.amazonaws.com/model/us.anthropic.claude-haiku-5-5/invoke`, with
`anthropic_version: "bedrock-2023-05-31"`, thinking disabled and low effort. There is no Anthropic service-tier
field. Non-streaming text histories and text/structured responses are implemented. Tool-use/result content,
positive cache modes, other models and long context are refused. Schemas may be declared,
but continuation with non-text blocks is unsupported. The US geographic inference profile may serve requests
in **us-east-1, us-east-2 or us-west-2**. Data stays in the US, with no single-region guarantee.
The bare `anthropic.claude-haiku-5-5` ID is a rejected alternative: this model supports inference profiles only,
so on-demand invocation by that ID is not offered (`bedrock.on_demand_unsupported`). The `global.` profile has
no US geographic bound and is refused separately (`bedrock.global_profile_unsupported`). Other Bedrock IDs
yield `bedrock.model_unsupported`; all three codes omit supplied values.

The profile ID is a single URI segment. Its dots and hyphens are unreserved and stay literal; it has no colon.
A colon in a model ID would be `%3A` on the wire and `%253A` in the SigV4 canonical URI (the percent is encoded
again). Version-suffixed IDs, ARNs and pre-encoded variants are refused; the fixed literal path needs no escaping.

Construct `BedrockAccess.from_settings(BedrockSettings(...))` before computing the call deadline, then pass it as
`Providers.bedrock`. Explicit settings are `POLICYOPS_BEDROCK_PROFILE`, `POLICYOPS_BEDROCK_REGION` (only
`us-west-2`), and optional `POLICYOPS_BEDROCK_CREDENTIALS_FILE` / `POLICYOPS_BEDROCK_CONFIG_FILE`. Otherwise use
the platform user's `~/.aws/credentials` and `~/.aws/config`. Settings never carry access keys.

Only botocore's `SharedCredentialProvider` and `ConfigProvider` run, in that order, over capped local snapshots
(1 MiB each). Both named-profile sections are checked before either provider is constructed. Any `sso_*`,
`role_arn`, `source_profile`, `credential_process`, `web_identity_token_file`, `credential_source`, `login_session`
or legacy `aws_security_token` key yields `bedrock.credentials_unsupported_provider`, without values. Use
`aws_session_token`. Missing/partial profiles fail closed. Providers receive checked dictionaries, eliminating
a check/load race. No environment, SSO, assume-role, process, web-identity, container or metadata provider exists.
Static keys have no expiry. A session token is used as given, never refreshed. Each access object freezes keys
until reconstructed; expired tokens get a final credential/access error. Local reads precede the inference
deadline; filesystem latency is not claimed to be bounded by the HTTP timeout.

Every `AWS_*` and `ANTHROPIC_*` environment name is refused, including empty values and matching regions. This
stronger names-only rule avoids reading secret values and fails closed on future settings:

| Refused names | Reason |
|---|---|
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_SECURITY_TOKEN` | Ambient credentials bypass the static profile. |
| `AWS_PROFILE`, `AWS_DEFAULT_PROFILE` | Profile selection belongs to explicit settings. |
| `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE` | File selection belongs to explicit settings/platform defaults. |
| `AWS_REGION`, `AWS_DEFAULT_REGION`, `AWS_STS_REGIONAL_ENDPOINTS` | Region/STS routing cannot change the fixed endpoint and signing region; matching values are also refused. |
| `AWS_ENDPOINT_URL*`, `AWS_USE_FIPS_ENDPOINT`, `AWS_USE_DUALSTACK_ENDPOINT` | Endpoint overrides conflict with fixed host/residency. |
| `AWS_CA_BUNDLE` | Trust overrides cannot change inference TLS trust. |
| `AWS_ROLE_ARN`, `AWS_ROLE_SESSION_NAME`, `AWS_WEB_IDENTITY_TOKEN_FILE` | Role/web-identity acquisition is outside the static contract. |
| `AWS_CONTAINER_CREDENTIALS_*`, `AWS_EC2_METADATA_*`, `AWS_METADATA_SERVICE_*` | Container/metadata acquisition may perform unbounded network I/O. |
| `AWS_BEARER_TOKEN_BEDROCK` | Bearer auth cannot replace SigV4/static-profile auth. |
| Other `AWS_*` | Fail closed on further credential, endpoint, trust, retry, logging or discovery settings. |
| All `ANTHROPIC_*`, including API keys, base URLs, profile, custom headers and logging | Prevent redirection, alternate authentication and SDK logging configuration. |

HTTP proxy variables are ignored by `trust_env=False`; redirects and transport retries are disabled. Per attempt,
an `AWSRequest` is synchronously signed with botocore 1.43.120's SigV4 primitives for service `bedrock`.
`_QuietSigV4Auth.add_auth` omits upstream DEBUG calls that expose canonical token/date headers and signatures;
golden and upstream-equivalence tests check unchanged canonicalization, HMAC and injection. No global logger is
modified. Authorization, token and date headers exist only in memory/on the wire, with transport comparisons
held in `SecretStr`; none enter identities, traces, ledger records or errors. The existing `BoundedTransport`
checks exact signed values, host/path/body and framing, caps responses, permits one request per attempt and closes
on cancellation. Signing has no thread or background task.

Rejected alternatives: `AnthropicBedrock` / `anthropic[bedrock]` (auth runs in a worker before the supplied transport;
the probe demonstrated post-cancellation work), boto3/direct SDK HTTP (bypasses the bounded boundary), and full
botocore chains (network/process/refresh side effects). Only botocore is added; its wheel still includes service
data, although only auth/request/static-provider functionality is used. No count API is used, including Mantle.

Admission is `UTF8(system + all message text) + bytes(canonical tools and output_config) + 1024 + 64 × messages`.
One text block per message prevents DTO part counts multiplying framing. Byte-level BPE tokens each consume at
least one source byte, bounding text even for multibyte Unicode. Canonical schema bytes count names, descriptions,
keys, enums and punctuation. The 1024 fixed allowance conservatively covers system/assistant framing, tool
declaration/choice and output-schema instructions; 64 per message covers roles, separators and turn framing
(four times the illustrative 16-token allowance). This is specific to the pinned text-only template.
The ledger reserves the actor maximum; the byte bound plus configured admission headroom must fit that ceiling
before dispatch. Actual input above the byte bound blocks, even if within admission headroom. Typical five-passage
requests are about 26k bytes / 6.5k tokens: approximately 4× reservation overestimate. Enlarge actor/caps explicitly
when needed; default actors remain unchanged. Actual usage settles the bill.

Strict Messages responses require `id`, `type`, `role`, text content, stop reason and input/output usage. The AWS
request ID comes only from `x-amzn-RequestId`, not Messages `id`. Optional cache fields default to zero only when
absent; all reported counts, TTL splits and reasoning must agree. Unknown/contradictory evidence retains liability;
known usage settles even for invalid payloads or contract overruns. Unexpected cache writes are priced then blocked.
A response model ID is optional because the fixed InvokeModel path binds identity. Profile-routed bodies may
return `claude-haiku-5-5`, `anthropic.claude-haiku-5-5` or `us.anthropic.claude-haiku-5-5`; these are accepted and
retained as returned-model evidence. Other supplied model IDs block settlement with `model_unconfirmed`.
No Anthropic service-tier pin is applied. HTTP 400/403/404 are final, including access/credential/agreement errors;
408/424/429/500/503 are retryable within the existing limits. ModelNotReady is 429. Error bodies and header values
are discarded in favor of fixed `http_NNN` classes.

Primary references: [InvokeModel contract/errors](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InvokeModel.html),
[signer](https://github.com/boto/botocore/blob/1.43.120/botocore/auth.py),
[static providers and full-chain alternatives](https://github.com/boto/botocore/blob/1.43.120/botocore/credentials.py).
The profile uses the coordinator's us-west-2 Price List in-region **Standard** rows, effective 2026-10-01:
input $0.11, output $0.55, cache write 5m $0.1375, cache write 1h $0.22 and cache read $0.011 per million tokens.
These are the higher published tier. Reservation and settlement conservatively use them even if AWS bills
geographic profiles at the source-region rate; this is an accounting assumption, not verified account billing.
The live smoke returned HTTP 403. Live access was declined for this new AWS account
for now. Offline tests establish the adapter contract.

## Local help desk

| Flow | Durable boundary |
|---|---|
| Zammad trigger to case | An optional local webhook commits a signed wake-up to a workspace inbox. The worker fetches a bounded ticket snapshot and writes its fictional requester binding, link and messages in one transaction. |
| Case to internal note | A receipt-backed outcome commits its note intent alongside the outcome message. A separate leased worker pass checks for an existing article and writes a pre-send checkpoint. Ambiguous sends use lookup only. |

The [integration guide](integration.md) describes the wire fields, local overlay, fault cases and verification.
