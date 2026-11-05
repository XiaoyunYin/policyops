# Architecture: retail contracts and domain rules

This page describes what is implemented so far. The application database (schema, roles, migrations) is described
in [database.md](database.md), and OIDC/session authentication handlers and role dependencies in
[authentication.md](authentication.md). Business case/message handlers, the agent runtime, the retail simulator
and the web UI remain later work. The contracts and rules below are pure, typed and tested, but they do not by
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
dependencies enforce (session cookie, CSRF token and Origin, `Idempotency-Key`, `If-Match`, cookie-setting
responses) and every error status are documented explicitly with the error envelope. FastAPI's default
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

- **Start.** It takes the T08 idempotent write path (replay of the original 202, 409 for a changed intent). Then,
  under the case lock, it rechecks the current role and the case version, and allows at most one active workbench
  run per case (`409 api.run_active`, also enforced by a partial unique index). It creates, in one transaction:
  - the run, bound to the case version, the initiating principal and the frozen server runtime spec (its real
    graph, prompt and config digests);
  - its first event and outbox intent;
  - its execute job;
  - an audit row.

  Mode, digests, times and fences are all server-owned.
- **No runtime is installed yet.** The production runtime catalog is empty until T21 installs an investigation
  runtime. Starting a run therefore answers `503 runtime.unconfigured` before anything is written, and a job that
  is already queued with an unknown spec fails visibly (see dead letters below). Deterministic scripted
  executors exist only in the test support package; they and the fixed test clock are refused outside the test
  environment (`build_runs_runtime`, `build_worker`, `build_dispatcher`). No model or provider is ever called.
- **Time authority.** Leases, deadlines and run/job/event times come from PostgreSQL `clock_timestamp()`. It is read
  after the locks a decision depends on: `now()` is the transaction start, and would still accept a lease that
  expired while the transaction waited for a lock. A test proves this boundary.
- **Lock order.** Everywhere: idempotency key → case → run → job → outbox rows. A heartbeat takes only the job lock.
  No transaction spans an executor call, a sleep, an SSE yield or a human wait.
- **Discovery and claims.** The worker discovers candidate jobs (due queued jobs and expired leases) as the narrow
  `policyops_worker_discovery` role, which reads only scheduling metadata. It then claims as the app runtime in the
  job's workspace, with `SKIP LOCKED` on the run and then the job. Before any work it rechecks, in that order:
  - the job kind (only `run.execute`) and that the run is in an executable state (`queued` or `running`; paused
    states need a later, authorized resume path);
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
  terminal run is returned unchanged with no event. Nothing remote exists to undo here (T19 adds reconciliation).
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
- The executor is a deterministic test executor; there is no investigation runtime.
- Workers are in-process objects. One real-process test kills an OS worker and reclaims its lease, but there is no
  packaged worker entrypoint or deployment (T38).
- Cross-database clock skew does not apply, because the database clock is the only authority.
- A job kind that some worker does not support is dead-lettered by that worker, so new kinds must ship only after
  every worker supports them.
- **Stream cancellation and in-flight polls.** When the stream is cancelled (the delivery deadline, a disconnect),
  a session check or database poll that is already running (including the initial authorization and preflight
  snapshot before any headers are sent) is abandoned, not interrupted. Its worker thread
  finishes the query, ends its short transaction and returns the connection to the pool. Until then it holds that
  connection and a thread. The application sets no statement timeout of its own, so how long that takes depends on
  the database. The HTTP response itself still ends at the deadline.
- **What the deadline covers.** The delivery deadline and the stalled-send behaviour were tested at the ASGI level
  (including the composed app over real PostgreSQL), not with a stalled physical socket or behind a reverse proxy.

## Model configuration and usage budgets

`policyops.budget` (T10) holds the allowed models, their dated prices, the cost calculator, the actor configuration,
the usage ledger rules and the offline evaluation preflight. It imports no provider SDK or HTTP framework and makes
no provider call itself. The offline provider adapters (see "Provider adapters" below) account for every physical
request they make through this ledger. The investigation runtime does not call them yet, and no live call has been
made through them.

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
  Anthropic text still says "unverified", meaning no live verification). It is part of every actor configuration
  digest, so it is not rewritten.
- **Actors and caps.**
  - Defaults: agent, simulator and reranker use Luna with low effort; the judge uses Haiku with low effort; the
    embedding model is called at 1536 dimensions.
  - Chat requests are capped at 16000 input and 2048 output tokens. The embedding actor reserves at most 8192 tokens
    and 64 inputs per request.
  - A workbench run gets 12 calls and $0.05, counting every request of every actor. An evaluation scenario gets
    $0.20, an invocation $5, and a study $5 unless its manifest declares another finite ceiling.
  - A non-run operation (future ingestion) gets its own finite budget: 64 calls and $0.05.
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
    that disables implicit SDK retries, is T11's.
  - The ledger checks the run's state but not a worker's claim; the fence check before dispatch belongs to the T21
    runtime.
  - The 180 active seconds per run are configured but not enforced here.
  - The overrun block has no operator reset.
- **Provider extensions (revision 0007):** every new attempt is intent version 2 and binds the request fingerprint. It
  needs exactly one admitted count before `begin_dispatch`, and a contract block (separate from the monetary overrun)
  stops new holds, counts and dispatches in every charged scope. Version 1 attempts from 0006 can still settle or be
  released, but never dispatch.

## Provider adapters

`policyops.providers` turns a provider-neutral `ModelRequest` (`policyops_contracts.model`, pydantic only) into one
exact OpenAI Responses or Anthropic Messages request. It sends that request through the official SDKs, pinned
exactly (`openai` 3.40.0, `anthropic` 2.3.0, the newest version before the lock's supply-chain cutoff), and accounts
for every physical request in the usage ledger. **No live call has been made through these adapters.** (Earlier,
separately documented project work did make count-only provider requests; they did not use these adapters.) The
offline tests exercise the request boundary, the response mapping and the accounting over a scripted mock transport.
They are not evidence of provider behaviour, any account's access, model quality, counting accuracy or price.

- **Preparation** (`serialize.prepare`): every local check runs before anything is reserved: the registry, the
  implemented provider contract (`contract.py`), schema registration, history consistency and the output limit.
  - The result keeps the request as canonical body **bytes**, integer-only and strict.
  - `request_sha256` hashes the contract version, method, host, path, version headers and body. Keys and auth
    headers are never part of it, or of anything stored or logged.
- **Wire contract:**
  - **Luna:** effort `low`, `service_tier="default"`, `store=false`, no parallel tool calls, `truncation="disabled"`.
    Cache `none` is sent as `prompt_cache_options.mode=explicit` with no breakpoints; cache `30m` is implicit at 30m;
    `12h` is refused (the SDK documents 30m as the only supported TTL).
  - **Haiku:** `thinking={"type": "disabled"}` with `output_config.effort="low"`, `standard_only` tier,
    `speed="standard"`, no sampling parameters, no `inference_geo`. Only cache `none` is implemented: no cache
    markers, no replayed thinking and no per-message effort change.
- **Identity on the wire** (`transport.BoundedTransport`): each count and each request gets a fresh SDK client
  (`max_retries=0`, explicit timeout) over a fresh `httpx2.AsyncClient` (`trust_env=False`, no redirects). Its
  transport lets exactly one request through, and only if all of these hold:
  - the method, fixed host and path, and the fixed `Host`;
  - JSON content type, a `Content-Length` matching the body, no duplicated header and only allowlisted header
    names;
  - the pinned version headers and exactly the expected bearer credential (compared in constant time);
  - a body that re-encodes canonically to the bound bytes.

  Responses must be uncompressed and stay within 1 MiB and 64 KiB per line. A client is refused while any
  `OPENAI_*` / `ANTHROPIC_*` environment variable other than the API key's is set; only the names are checked.
- **Counting** is required: one supported count per attempt, over the full projection of the same prepared request
  (instructions/system, messages, tools, output format, effort/thinking). The count is claimed in the ledger before
  the call and never retried.
  - It admits the request only if `tokens + max(10%, 256)` fits the actor's maximum prompt, and `begin_dispatch`
    re-checks that itself.
  - A known prompt larger than the count plus that headroom settles and blocks (`count_underestimate`).
  - Count units are finite per scope and never returned.
- **Usage evidence** (`results.py`):
  - **OpenAI** `input_tokens` includes cached tokens. **Anthropic** `input_tokens` excludes the cache reads and the
    cache creation, so the whole prompt is their sum, and the 5m/1h split must account for the creation total.
  - **Known, fully priced usage settles exactly**, whatever the answer's outcome.
  - **A known contract mismatch** settles the exact bill and contract-blocks every charged scope; the result becomes
    a `contract_gap` with no payload. Examples: cache writes under cache `none`, a prompt above the admitted maximum,
    output above `max_output_tokens`, a thinking block.
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
- **Capability record** (`capability.py`): the live cells are all `not_run`. Its smoke manifest is **preliminary
  data only** (`preliminary_not_enforceable`): it is not an executable or approved plan, and no live run happens
  without a separately reviewed driver and explicit approval.
- **Limits:**
  - **No live evidence:** there is no live capability, counting or estimate-versus-usage evidence, so the live
    acceptance stays open.
  - **Deferred to the worker runtime:** recovering a stale count or dispatch claim needs the worker fence, as do
    the 180 active seconds.
  - **Cancellation:** a provider may keep generating after a local cancel; the hold stays.
  - **Unimplemented modes:** the Anthropic positive cache modes and OpenAI 12h are refused, not implemented.

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


## Retail simulator

`evals/src/policyops_evals/retail_sim` is the evals-owned `retail-simulator` service (T16). The application never
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
