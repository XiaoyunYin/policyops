# Application database: schema, roles, migrations and restore

This page describes the PostgreSQL schema and roles in `packages/policyops/src/policyops/persistence/`. Everything here is tested against the pinned PostgreSQL 17.11 + pgvector 0.8.7 image (`pytest -m postgres`; Windows Docker Desktop is the only platform where that has actually run so far).

The database stores records and enforces relational invariants. The [authentication service](authentication.md) validates identity, sessions and current workspace membership using these records. Business workflow authorization and execution are implemented in the gateway and services;
see [architecture](architecture.md#approval-continuation-and-outcomes). Row-level security and constraints support those services.

## Transport and explicit trust

The API's `DatabaseSettings` reads `POLICYOPS_DB_SSLMODE` (default `verify-full`) and
`POLICYOPS_DB_SSLROOTCERT` (optional absolute POSIX or Windows path, with no control
characters). Path checks are lexical and never open the file or report its contents or
configured value. `verify-ca` and `verify-full` require that path in every environment;
deployment requires `verify-full` plus the explicit root. There is no fallback to libpq's
home-directory root or `sslrootcert=system`. Missing/unreadable/invalid roots fail on
connection. Local `require` remains available to standalone configurations; `disable`
requires a loopback IP. Compose always requires explicit `verify-full` plus a root.

All Compose clients use `postgres` and `/run/secrets/postgres_tls_cert`, mounted by the
base file. This self-signed server leaf is itself the pinned trust anchor, with SAN
`DNS:postgres`; it is not a general certificate authority. See the
[deployment TLS and renewal model](deployment.md#database-tls). SCRAM-SHA-256 remains
required independently of TLS. The PostgreSQL integration harness's disposable loopback
connections may use `disable`; those tests do not prove deployed TLS verification.

API and Compose helpers share `REFUSED_LIBPQ_ENV`. Refusal diagnostics name variables
and fixed reasons only. The [libpq environment reference](https://www.postgresql.org/docs/17/libpq-envars.html)
documents the following inputs; they are refused even if an explicit argument would win:

| Refused variables | Reason |
|---|---|
| `PGSERVICE`, `PGHOSTADDR` | Service entries or an independent address can redirect the endpoint or supply trust settings |
| `PGSSLROOTCERT` | Trust must come from the explicit application path |
| `PGSSLMODE`, `PGREQUIRESSL` | TLS verification policy, including the deprecated encryption switch, has one source |
| `PGSSLCRL`, `PGSSLCRLDIR` | Ambient revocation files/directories change which peer certificates are accepted |
| `PGSSLCERT`, `PGSSLKEY`, `PGSSLCERTMODE` | Ambient client certificates/keys or certificate mode change TLS identity/authentication |
| `PGSSLNEGOTIATION`, `PGSSLCOMPRESSION`, `PGSSLSNI` | Prevent ambient changes to negotiation, compression or the presented server name |
| `PGSSLMINPROTOCOLVERSION`, `PGSSLMAXPROTOCOLVERSION` | Prevent ambient protocol bounds changing the TLS policy |

No documented libpq TLS environment option is intentionally skipped. `PGGSSENCMODE`
is not refused because `gssencmode=disable` is explicit, preventing GSS from superseding
TLS; `PGCHANNELBINDING` controls SCRAM channel binding, not trust-root selection, and
retains libpq's policy. Ordinary `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`,
`PGOPTIONS` and timeouts cannot replace arguments passed explicitly. `PGSERVICEFILE`
and `PGSYSCONFDIR` do not select a service when `PGSERVICE` is refused. This is an
operator configuration boundary; it does not isolate libpq from a compromised host or
OpenSSL installation, nor forbid libpq's default client-certificate/CRL file discovery.

## Roles

Bootstrap creates five cluster roles. All of them are `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, the runtime roles are also `NOINHERIT`, and none may be a member of another role.

| Role | Purpose | Access |
|---|---|---|
| `policyops_app_migrator` | Owns the schemas and runs Alembic | DDL in its database. It has no data policy under forced RLS, so it reads no tenant rows |
| `policyops_app_runtime` | API and worker | Tenant tables in `app`, plus its current workspace and memberships in `identity`; `USAGE` on `checkpoints` |
| `policyops_auth_runtime` | Trusted authentication service | `identity` only: workspaces, principals, memberships, sessions, login requests |
| `policyops_eval_runtime` | Evaluation recording | `evaluation` only |
| `policyops_worker_discovery` | Finds work for the worker and outbox dispatcher (runtime) | Column `SELECT` on job (`id, workspace_id, state, available_at, lease_expires_at, deadline_at`) and outbox (`id, workspace_id, topic, created_at, delivered_at`) scheduling metadata through read-only policies; no payloads, identity or session data, and no writes. Claims and work then run as the app runtime |

- **Auth role.** Pre-workspace identity lookups (principal by issuer and subject, a principal's memberships across workspaces) need rows that no workspace scope can select. A separate, narrowly granted auth role does this, rather than a `SECURITY DEFINER` function. It sees all identity rows by design: that service is the trusted boundary, and it has no business, evaluation or retail access.
- **Passwords.** These are sent to the server as SCRAM-SHA-256 verifiers computed on the client. The plaintext never reaches the server, its logs or `pg_stat_activity`. A test checks that the verifier is byte-identical to one PostgreSQL computes itself.
- **Schema privileges.** No runtime role may create objects in any schema. On application-owned objects (the `identity`, `app`, `evaluation` and `checkpoints` schemas, their tables and functions, and the version table), `PUBLIC` has no privileges, and there are no default privileges. This does not cover PostgreSQL's own defaults outside those objects: `PUBLIC` keeps `USAGE` on schema `public` (`CREATE` is revoked), and built-in and pgvector functions remain executable by `PUBLIC`.

## Bootstrap (superuser, idempotent)

`policyops.persistence.bootstrap` has three steps:

1. `provision_roles` creates the five roles, or re-asserts their attributes and passwords if they exist.
2. `provision_database` creates the database owned by the migrator from `template0`, revokes `PUBLIC` access, and grants `CONNECT` to the runtime roles. It refuses a database owned by another role.
3. `provision_extensions` runs inside that database. It installs `vector`, revokes `CREATE` on `public`, and reports the installed version and its actual `trusted` metadata.

Bootstrap also refuses:
- a connection that is not a superuser or not autocommit;
- invalid database names;
- a missing password.

It never creates or grants anything in a `retail` schema. Retail roles and DDL belong to retail simulator.

## Schemas and tenancy

| Schema | Contents |
|---|---|
| `identity` | workspaces, principals (global), memberships, sessions, browser-bound login requests |
| `app` | cases and messages, documents and versions, runs and events, action proposals, presentations, consents, decisions, tool executions, jobs, outbox, audit, index generations, corpora and generation membership (`0010`), chunks, retrieval traces, retrieval step intents (`0011`), citations, usage reservations and events, budget scopes and usage attempts (`0006`) |
| `evaluation` | evaluation runs and trials, study/invocation/scenario budget scopes and usage attempts (`0006`), durable trial claims and study bindings (`0016`) (not tenant data; isolated by schema and role) |
| `checkpoints` | tenant-bound threads, checkpoints and writes (`0013`); the runtime never runs setup or migrations |

**Tenant relationships.**
- Every tenant table has `workspace_id NOT NULL`, and every one with its own `id` also has `UNIQUE (workspace_id, id)`. The exception is `proposal_presentations`, whose natural composite primary key is workspace, proposal and version, with no `id`. Every tenant relationship is a composite foreign key, so a reference to another workspace's row fails in the database even with a valid UUID, and even for a superuser.
- Optional links use the default `MATCH SIMPLE`: a NULL link is no link, and because `workspace_id` is never NULL, a non-NULL link is always checked.
- There are no cascades and no `SET NULL`.
- Principals use global issuer/subject identity and single-column references. Login requests are pre-workspace auth-service records; tenant permissions still come from current memberships.

**Row-level security.**
- RLS is enabled and forced on every `identity` and `app` table, with policies for named roles only.
- The app runtime's policies compare `workspace_id` with `app.current_workspace()`. That value is `policyops.workspace_id`, set by `database.workspace_transaction` with `set_config(..., true)`.
- The setting is transaction-local, so PostgreSQL discards it at commit or rollback. A pooled connection therefore never carries a scope into its next use; tests check this after commit, after rollback and after a database error.
- Unset or empty means no rows and no writes.
- Chunks are visible to the app runtime only when their index generation is `ready`.

## Invariants enforced by the database

Revision `0017` raises generation document counts to 0..5000 and membership ordinals to 0..4999 for the 4,110-passage structural corpus; chunks stay capped at 10,000, Markdown v1 stays capped at 2,000 documents, and downgrade atomically refuses rows outside the old bounds without altering data.

- **Append-only records.** Messages, run events, consents, decisions, presentations, audit events, usage events, citations, traces and the request-idempotency ledger get `INSERT`/`SELECT` only. Other tables get column-level `UPDATE` grants, and nothing gets `DELETE`.
- **Proposals.** A proposal's bound content cannot change. A trigger, which fires even for the owner and superusers, allows only setting the presentation time once and forward status moves.
- **The binding chain.** Proposal, presentation, consent and decision records store every contract field and reconstruct to the exact contracts. Composite keys tie each record to the previous one: the same case, run, proposal version, action digest and presentation digest. They also tie each record to the referenced message's stored case, sequence, text digest, source and author. A record whose recorded evidence disagrees with the referenced row is rejected.
  - The database compares stored digest and sequence fields between rows. It does not recompute a hash from a message body: the typed repository computes `text_sha256` when it appends a message, and the SQL check on that column validates only its format.
- **One per proposal version.** Each proposal version has at most one presentation, one consent and one terminal decision.
- **Optimistic versions.** Versions are integers ≥ 1, and updates check the expected version (`StaleVersion`).
- **Runs and jobs (`0005`).**
  - One active workbench run per case, by a partial unique index.
  - `0 ≤ event_retention_floor ≤ event_highwater`; sequences are allocated from the high-water mark.
  - A job is leased exactly when it has a claim ID (and an owner and expiry).
  - The runtime can update the run generation and high-water mark, but not the floor.
  - Run-operation ledger rows link to their run through `(workspace_id, case_id, run_id)`.
- **Request identity and counts (`0007`).**
  - A version 2 attempt requires its `request_sha256`; only version 2 attempts have counts.
  - A dispatched version 2 attempt must have an admitted count.
  - `counts_used ≤ cap_counts` per scope. `diagnostic` is bounded to 2 KiB of text.
  - The runtimes can update the count state and tokens, the contract block and the diagnostic, and the scopes'
    `counts_used` and `contract_block`. They can never update `intent_version`, `request_sha256` or `cap_counts`.
- **Customer authentication (`0008`).**
  - `app.customer_authentications` holds at most one row per run (`PRIMARY KEY (workspace_id, run_id)`). The row is
    the identity lookup that authenticated the case's bound customer in that run.
  - The composite foreign key `(workspace_id, case_id, run_id)` to `app.runs` refuses a row that names another
    case's run.
  - The composite foreign key `(workspace_id, case_id, user_id)` to `app.cases (workspace_id, id,
    customer_user_id)` refuses a row for any customer except the one the case is bound to. A case without a bound
    customer can have none. The referenced key is `cases_customer_binding_unique`, which the revision adds. While a
    run is authenticated, its case's customer cannot be changed.
  - Only the gateway writes a row, from a lookup it performed. There is no API that accepts one.
  - The application runtime has `SELECT` and `INSERT` only, so a recorded authentication is never rewritten or
    removed at runtime. RLS is forced.
  - The repository's `record` is first write wins: the identical authentication again is a no-op; a different
    customer, or a foreign-key refusal, raises `AuthenticationConflict` and never authenticates.
- **Embedding foundation (`0009`).** Five tables, each with composite workspace keys and forced workspace RLS for
  the app runtime:
  - `app.embedding_jobs`: one job per `(workspace_id, purpose, subject_key)`. It records the digest of the full
    intended ordered input set, the request configuration and tokenizer digests, and an immutable `deadline_at`
    (`CHECK (deadline_at > created_at)`). The runtime can update only `state`, `version` and `updated_at`.
  - `app.embedding_job_inputs`: every intended input by position, with its exact text and local token count. A
    CHECK ties `input_sha256` to the text's UTF-8 SHA-256. Select and insert only.
  - `app.embedding_batches`: the frozen dispatch plan (ordered positions, request fingerprint, local tokens,
    operation ID, ledger attempt ID). The runtime can update only `state`, `lease_owner`, `lease_until`, `fence` and
    `updated_at`, so the plan itself never changes. A batch's attempt is unique per workspace.
  - `app.embedding_attempt_evidence`: one row per accounted physical request with parseable billing. Its composite
    foreign keys reference the batch `(workspace_id, job_id, ordinal, attempt_id)` and the ledger attempt
    `(workspace_id, id)`. `prompt_tokens` and `total_tokens` must be equal unless the outcome is
    `usage_contradiction`. Vector norms are an exact `numeric[]` diagnostic, never a floating-point column. Select
    and insert only.
  - `app.embedding_cache`: the first validated `vector(1536)` per `(workspace_id, input_sha256,
    request_config_sha256)`, referencing the evidence row that published it. Select and insert only, so a cached
    vector is never replaced, deleted or visible to another workspace.
- **Corpus ingestion (`0010`).** Written only by the ingestion component (`persistence/corpora.py`); there is no
  HTTP or worker writer.
  - `app.corpora`: one stable slot per `(workspace_id, corpus_key)` with the active generation pointer and an
    optimistic `version`. The pointer is a composite foreign key `(workspace_id, corpus_key, active_generation_id)`,
    so it can only name a generation of the same corpus; at most one `ready` generation exists per corpus (partial
    unique index). The runtime can `SELECT`, `INSERT` and update only the pointer, version and `updated_at`.
    Activation is a compare-and-swap on this row.
  - `app.index_generations` gains corpus provenance (source repository, commit and tree, source and corpus manifest
    digests, license scope, render, chunk configuration, tokenizer and request-configuration digests, expected-set
    and generation-key digests, document and chunk counts). A row has all of it or none (legacy rows).
  - `app.generation_documents`: the exact membership of a generation, including documents with no chunk, with the
    version, `source_uri`, path, Git blob and raw file digest and size of that revision. Select and insert only.
  - `app.documents` gains the owning `corpus_key` and a unique `source_uri` per workspace, so a stable source
    identity cannot belong to two corpora. `app.chunks` gains section offsets, the plain `text_sha256` (a CHECK ties
    it to the text), the embedding input digest and request configuration (a foreign key to the immutable
    embedding-cache entry), and a unique position per generation; the existing ready-only chunk policy is unchanged.
    `app.citations` gains a composite foreign key `(workspace_id, chunk_id, document_version_id)` referencing
    `app.chunks (workspace_id, id, document_version_id)`, which binds each citation's document version to its
    cited chunk.
  - Guards (PL/pgSQL, `SECURITY INVOKER`, no `EXECUTE` for `PUBLIC`; they run with the caller's own privileges and
    RLS, and no new role or `SECURITY DEFINER` exists):
    - Inserting a chunk or membership row locks its generation `FOR SHARE` and requires it to be visible and
      `building`. That lock conflicts with the status change of a concurrent activation, so no row can be added to
      a generation after another transaction verified and activated it.
    - A corpus generation starts `building`; only `building` to `ready`/`failed` and `ready` to `retired` are
      allowed, and `ready_at` changes only with the first.
    - A deferred constraint at commit requires that no corpus generation is left `building` and that a generation is
      `ready` exactly when its corpus points at it. This is structural only: it does not inspect chunk contents.
    - A citation insert requires a chunk visible to the inserting role (for the app runtime: in a `ready`
      generation), the trace's generation and the chunk's document version, and a span inside the chunk. This checks
      structure; it does not authorize the citing run or show that the span supports a claim.
  - The repository's publish transaction, historical citation read and their exact checks are described in
    [architecture.md](architecture.md#corpus-ingestion). Retired and `building` chunks stay hidden from the runtime.
- **Execution ledger (`0012`).** `app.tool_executions` gains the immutable binding (case, run, consent, tool, target,
  stored request jsonb, operation fingerprint, authorization `not_after`) with a composite foreign key to the exact
  approval, `UNIQUE (workspace_id, approval_id)`, a partial unique index allowing one unresolved execution per case
  target, claim/lease, counters, backoff and typed outcome columns with one NULL-safe CHECK of the allowed
  state/outcome/resolver/receipt/dispatch combinations (a NULL terminal outcome never passes), and triggers that keep the
  binding immutable, terminal rows final, counters monotonic, transitions to the execution state machine and refuse every
  DELETE. The runtime may update only the mutable columns; `policyops_worker_discovery` reads only scheduling
  columns. The upgrade refuses a populated legacy table (nothing is backfilled by guessing); the downgrade refuses
  any row even with `allow_data_loss`.
- **Retrieval step intents (`0011`).** One table, `app.retrieval_steps`, written only by the retrieval component:
  - primary key `(workspace_id, run_id, step)` with `step` between 0 and 9999 (flat CHECKs); the composite foreign key `(workspace_id, run_id)` references `app.runs`; the deterministic `trace_id` is unique per workspace;
  - `request_sha256` and its three components `query_sha256`, `scope_sha256` and `config_sha256` are SHA-256 text with format CHECKs; this table stores no query text, scope or configuration plaintext (the query embedding job's input text is stored separately, in `app.embedding_job_inputs`, under the embedding foundation's safeguards);
  - forced workspace RLS; the app runtime has `SELECT` and `INSERT` only, so an intent is never changed or removed; no function and no trigger;
  - there is no foreign key from `app.retrieval_traces`: traces written before this revision remain valid historical records, and a trace without an intent is reported as unsupported for replay;
  - it exists so that a retry after a failed trace write cannot change the query, scope or configuration under an already-paid embedding job: the same step with a different fingerprint conflicts before any provider work.
- **Evaluation export reads (offline retrieval metrics, no new revision).** The retrieval evaluation export adds only read-only queries over existing tables: workspace-scoped `app.documents` (to map a document ID to its corpus key and source URI) and `app.generation_documents` (to check a trace generation's membership). It adds no table, grant, trigger or role and writes nothing, and that component introduces no additional revision. The local plan diagnostics run `EXPLAIN (ANALYZE, BUFFERS)` of the fixed retrieval branch statements as the application runtime inside a read-only transaction.
- **Citation recording (grounding, no new revision).** The retrieval component records citations in the existing `app.citations` table under its existing grants (the runtime has `SELECT` and `INSERT` only), forced workspace row-level security and the `0010` insert guard, which checks that a cited chunk is visible (a ready generation), in the trace's generation and document version, and contains the span. The guard alone does not check the run, the delivered evidence mapping or the quote; the recorder rechecks those before writing. Row IDs are stable UUIDs derived from the claim, so a retry never creates a second row; equal rows that already exist are accepted and conflicting ones refused. All new rows of a batch are written in one short transaction that locks the corpus row against a concurrent activation. No migration, trigger or role is added. A row written by the recorder asserts historical, ready-generation evidence at its commit only; other rows in the table carry no such assertion.
- **Usage budget ledger (`0006`).**
  - A budget scope holds server-set caps and exact counters (`spent_usd`, `held_usd`, `calls_consumed`,
    `calls_held`, and a sticky `overrun`), with `calls_consumed + calls_held <= cap_calls` checked in the database.
  - App scopes (forced RLS) are one per workbench run (`UNIQUE (workspace_id, run_id)`, composite foreign key to the
    run) or one per non-run operation (`UNIQUE (workspace_id, operation_kind, operation_key)`).
  - Evaluation scopes are a study (`UNIQUE (study_key)`) with invocations and scenarios
    (`UNIQUE (parent_id, task_id, trial_index, config_sha256)`). Composite keys make a scenario and an invocation
    belong to a study, and make an attempt's invocation and scenario belong to the attempt's study.
  - A usage attempt is one accounted provider request (a retry is a new attempt). It holds the internal attempt ID,
    the immutable intent (actor, provider, model, price revision, the digest of the full actor configuration, cache
    mode, request bounds, operation ID, the reservation and the intent digest) and its state:
    `reserved | dispatching | released | settled | unresolved`. A settled attempt carries its usage (at most 4 KiB),
    usage digest, actual tier and cost; only a settled attempt can be `overrun`.
  - A provider request ID belongs to at most one attempt (unique per workspace and provider; per provider in the
    evaluation schema).
  - The runtimes can update only the counters and the settlement fields. Caps, bindings and intent are not
    updatable, and nothing can be deleted.
- **Idempotency keys.** The database makes these keys unique: tool executions (`operation_id`), jobs and outbox entries (dedupe keys), and usage events (provider request IDs). The repositories add payload comparison where they exist; reusing a key with a different payload raises `IdempotencyConflict` and keeps the original, never last-writer-wins.
  - Tool executions compare the approval and the argument digest.
  - Jobs compare an immutable request fingerprint: the SHA-256 of every requested field except the row ID and creation time. It is stored in `request_sha256`, which the runtime cannot update. The same request therefore still replays after a worker has changed the job's state, attempts or `available_at`.
  - Usage events compare every recorded field. Since `0006` an event may instead name its usage attempt
    (`UNIQUE (workspace_id, attempt_id)`); a CHECK requires an attempt or a provider request ID, so legacy events keep
    their exact provider replay key. One provider request ID cannot be recorded for two attempts, nor by both an
    attempt and the legacy path.
  - Outbox entries have SQL key uniqueness only; no repository implements payload comparison for them yet.
  - HTTP case writes (`app.request_idempotency`, revision `0004`) are keyed by workspace, principal, operation and the client's `Idempotency-Key`. Each row stores the SHA-256 of the typed request intent and the original successful response (status 2xx, JSON body of at most 64 KiB, ETag). It links to its case by `(workspace_id, case_id)`, and a message write also to that case's message by `(workspace_id, case_id, message_id)`, so a ledger row cannot name a message of another case; only message writes name a message. The runtime can insert and read rows, never change or delete them, and RLS is forced on the workspace scope.
- **Money.**
  - Commerce money stays integer minor units in the contracts.
  - USD amounts use unconstrained `NUMERIC` with checks: finite, between 0 (inclusive) and 10^6 (exclusive), at most 18 fractional digits.
  - A fixed `NUMERIC(p, s)` is not used anywhere, because PostgreSQL would round to the scale before any check runs.
  - Unknown cost is NULL with an explicit status, never zero.
  - There are no floating-point columns.
- **Other checks.** TTLs mirror the contracts (at most 15 minutes for proposals, consents and approvals). JSON and text sizes are bounded, and every status, role and source value has a named `CHECK` (no PostgreSQL enum types).

## Migrations

The chain lives in `persistence/migrations/` and has sixteen revisions. The early revisions are `0001` (identity, cases, actions, jobs, audit), `0002` (retrieval, usage, evaluation, checkpoints), `0003` (single-use login requests and session idle/CSRF state), `0004` (the request-idempotency ledger and the `(workspace_id, created_at DESC, id DESC)` case-queue index), and `0005` (run initiator, fencing generation, event high-water mark and retention floor, job claim IDs and error codes, run ledger operations, the discovery role's grants), and `0006` (the usage budget ledger: app and evaluation budget scopes and usage attempts, attempt-linked usage events), `0007` (request-bound v2 intents, per-attempt counts, count resources and
contract blocks), `0008` (durable customer lookup authentication per run), `0009` (the embedding foundation: jobs, inputs, frozen batches, attempt evidence and the vector cache), `0010` (corpus ingestion: corpora, generation membership and provenance, publication and citation guards) and `0011` (retrieval steps: the append-only per-step request intent). Revisions `0012`–`0016` add execution, checkpoints, review continuation, active-time accounting
and durable evaluation claims. The version table is `public.policyops_app_alembic_version`. `policyops.persistence.migrate` runs it on a SQLAlchemy connection the caller opened as the migrator; there is no URL or ini file with credentials.

- **Precondition.** `upgrade` and `downgrade` need a connection with no open transaction. Otherwise Alembic would run all revisions inside the caller's transaction, so they raise `MigrationPreconditionError` before doing anything, and never commit or roll back the caller's work. `current` leaves no transaction behind.
- **Upgrade.** Each revision runs in its own transaction. A failing revision rolls back completely and the version stays at the previous revision. A test makes revision `0002` fail midway and checks that.
- **Previous-revision upgrade.** A database at `0001` with imported synthetic data upgrades to head with every existing row unchanged.
- **Authentication upgrade.** Revision `0003` also upgrades a populated `0002` database. Existing sessions receive NULL idle/CSRF fields and require a new login; the auth service rejects them. New login requests have a bounded expiry and single-use consumption state, with access restricted to the auth role.
- **Run upgrade.** Revision `0005` upgrades a populated `0004` database in place. It backfills each run's event high-water mark from its stored events and leaves legacy runs without an initiator, and the worker refuses to run those. The backfill lifts FORCE RLS inside the revision's transaction and restores it. Data that violates the new rules (two active workbench runs on one case, or a leased job, which predates claim IDs) refuses the upgrade without being rewritten. The revision needs the discovery role, so run bootstrap first.
- **Ingestion upgrade.** Revision `0010` upgrades a populated `0009` database in place. Before changing anything it
  counts rows that would violate the constraints it adds: duplicate document source identities, duplicate chunk
  positions, and citations whose document version, trace generation or span disagree with their chunk. Any such row
  refuses the whole upgrade (`LegacyIncompatible`, with counts only, no IDs or text) in the revision's transaction:
  nothing is repaired, dropped or rewritten, and the version stays at `0009`. The check lifts and restores each
  table's exact FORCE state. A passing upgrade validates structural agreement only, and it cannot add the
  historical fact that a legacy citation's chunk was ready when it was cited. Existing rows and grants are otherwise
  unchanged. Verification: a copy of a genuine populated `0008` dump (34 tables, 15 of them non-empty) was restored
  and upgraded through `0009` to `0010`. All 34 row counts stayed the same; the row-level inventories of the 33
  pre-existing data tables stayed identical, and the 34th table, the Alembic version table, advances by design. After
  an empty-data downgrade to `0008` the full 34-table inventory was restored, and a re-upgrade reproduced it. The
  three widened retrieval tables (documents, generations and chunks) were empty in that historical dump, so
  populated legacy retrieval data is covered by separate migration fixtures, not by the dump.
- **Retrieval step upgrade.** Revision `0011` upgrades a populated `0010` database in place by adding one empty table with its policy and grants; no existing table changes. The migration test compares both the row counts and a full-row content inventory (SHA-256 of each table's canonical row text, in a stable order) of every table in the four application schemas `identity`, `app`, `evaluation` and `checkpoints` before and after the upgrade; the advancing `public.policyops_app_alembic_version` table is excluded from that comparison.
- **Embedding foundation upgrade.** Revision `0009` upgrades a populated `0008` database in place. It only adds
  the five empty tables, their policies and grants; existing rows and grants are unchanged. A test restores a
  `pg_dump` of a populated `0008` database into a separate database, upgrades it, compares every pre-existing
  table's row count and runs an embedding job on the result.
- **Customer authentication upgrade.** Revision `0008` upgrades a populated `0007` database in place:
  - it adds the empty `app.customer_authentications` and the `(workspace_id, id, customer_user_id)` unique key on
    `app.cases`. Cases were already unique by `(workspace_id, id)`, so the key restricts no existing row;
  - existing rows and grants are unchanged, which a test checks with per-table row digests and a grant comparison;
  - the application runtime gains exactly `SELECT` and `INSERT` on the new table.
- **Request identity upgrade.** Revision `0007` upgrades a populated `0006` database in place.
  - Existing attempts become intent version 1, keeping their digest, with no request fingerprint. They can still be
    settled, marked unresolved or released, but never dispatched.
  - Each scope's `cap_counts` is backfilled to its `cap_calls`. The backfill lifts and restores each table's exact
    FORCE state.
  - A `BEFORE INSERT` trigger then refuses any new version 1 attempt, on every role path.
- **Budget ledger upgrade.** Revision `0006` upgrades a populated `0005` database in place. It only adds tables and
  makes `usage_events.provider_request_id` optional; existing events and their replay keys are unchanged. The legacy
  `usage_reservations` table is left as it is, and nothing writes it.
- **Case API upgrade.** Revision `0004` upgrades a populated `0003` database in place. It adds a `(workspace_id, case_id, id)` unique key on messages for the ledger's message link, the ledger table and the queue index; it changes no existing row.
- **Downgrade.**
  - Dropping a revision's tables or columns loses their data, so a downgrade can be lossy.
  - Each revision step runs and commits in its own transaction, so a multi-revision downgrade is not atomic as a whole. If an earlier revision refuses, the later revisions it passed through stay downgraded (for example, `0006` → `0004` with empty `0006` ledger tables but populated runs leaves the database at `0005`; with ledger rows, `0006` itself refuses and the database stays at `0006`).
  - It is refused (`DataLossRefused`) while the affected tables hold rows, unless `allow_data_loss=True` is passed explicitly. For `0003`, either login-request or session rows trigger refusal; an explicitly allowed downgrade drops the added session fields while retaining session rows. For `0004`, ledger rows trigger refusal (dropping them would break replay of committed writes); without them the downgrade removes exactly the ledger, the index and the message key. For `0005`, runs or jobs trigger refusal (their fencing, initiator and high-water fields would be lost). With `allow_data_loss=True`, the downgrade also deletes exactly the `run.start` / `run.cancel` ledger rows, because the restored `0004` operation CHECK cannot hold them; case-ledger rows are kept. Their replays are lost: a later retry with such a key is treated as a new request. Re-upgrading to `0005` afterwards backfills each run's high-water mark from its remaining events, but cannot restore the generation (0 again), the initiator (NULL, so the worker will not execute those runs) or the deleted ledger rows. For `0007`, the downgrade is refused whenever version 2, count or contract-block data exists, **even with
`allow_data_loss=True`**: dropping it would leave scope totals that no longer match their attempts, so that recovery
is a restore from a consistent backup. Without such data it removes the columns and triggers, keeps version 1 rows
and restores the exact FORCE flags. For `0009`, rows in any of its five tables trigger refusal (job identities, evidence of billed requests and cached vectors would be lost); `allow_data_loss=True` drops exactly those tables, and the vectors must then be paid for again. Without rows the downgrade drops the tables and re-upgrading restores them. For `0010`, the downgrade is refused while `app.corpora` or `app.generation_documents` has rows, or while any generation, document or chunk carries the new provenance columns. With `allow_data_loss=True` it drops the guards, constraints, new columns and the two tables; the ingested documents, versions, chunks and generations remain as ordinary legacy rows without their provenance, section, corpus and membership information, and the cached vectors of `0009` are untouched. That override is destructive and does not restore anything; recovery of the provenance is a restore from a consistent backup, and re-upgrading afterwards does not recreate it. For `0011`, the downgrade is refused while `app.retrieval_steps` has rows, because dropping intents would let a retried step change its request; `allow_data_loss=True` drops exactly that table, existing traces are retained, and the dropped intents are not recovered by a re-upgrade. An empty downgrade followed by a re-upgrade restores the empty table, and the remaining tables' full-row inventories (same four schemas, version table excluded) are compared after the destructive path as well. For `0008`, rows in `app.customer_authentications` trigger refusal (dropping them would silently de-authenticate runs). Without them the downgrade drops exactly the table and the case key, and re-upgrading restores both. For `0006`, rows in any budget scope or usage attempt table trigger refusal (holds, consumed calls and settled costs would be lost). With `allow_data_loss=True`, the downgrade also deletes exactly the usage events that name only an attempt, because the restored NOT NULL provider request ID cannot hold them; attempt events that have a provider request ID are kept as legacy rows. It lifts FORCE on `app.usage_events` for that delete only if the table was forced, and restores exactly the previous state.
  - The check lifts `FORCE ROW LEVEL SECURITY` temporarily, because the migrator sees no tenant rows otherwise. It then restores each table's previous state, both when it refuses (the rollback) and when it passes. Before runtime a passing check left the table unforced, which in practice meant `identity.sessions` after an empty `0003` downgrade. A regression test covers forced and unforced tables.
- **Restore.** A restore is a separate operation, not a downgrade. A tested path dumps with `pg_dump -Fc` and restores with `pg_restore --single-transaction` into a separate, freshly provisioned database, as the superuser. It preserves:
  - row counts;
  - constraints, policies and forced RLS;
  - table and column grants, triggers and schema ACLs;
  - the migration version.

  The app runtime's tenant scope works on the restored copy. Database-level `CONNECT` grants are not part of a dump; bootstrap's database step re-creates them.

## Synthetic importer

`policyops.persistence.importer.import_synthetic_world` loads the fictional example world and the committed contract examples (proposal, presentation, consent, approval). It goes through the same repositories and roles as the application: identity rows via the auth role, everything else via the app role in the example workspace's scope. A repeated import is refused (`AlreadyImported`).

## Runtime clocks and SQL bounds

Revision `0015` adds `runs.active_remaining_us` and `active_started_at`, and makes `deadline_at` nullable.
Queued/running/reconciling segments consume allowance; human wait and terminal states clear the active segment.
The transition guard prevents replenishment and segment restarts. The conservative backfill preserves active
projections, freezes the unexpired remainder of historical waits, and assigns terminal rows zero allowance.
It cannot refund past waiting time. Nonempty downgrade requires the explicit lossy override. FORCE RLS and
existing composite keys remain; only the app runtime receives the three clock-column UPDATE grants.

Runtime transactions apply transaction-local `set_config` profiles after BEGIN: statement / lock / idle limits
are DEFAULT 5000/1000/5000 ms, LEASE 1000/250/2000 ms, and RETRIEVAL snapshot 15000/1000/5000 ms.
Pool checkout is two seconds. Migration/bootstrap/dump/restore are separate from these runtime profiles.
55P03 and 57014 are local retryable failures; idle termination/disconnect requires durable-state checks.
Permission, authentication and schema errors retain their original permanent/configuration meaning.
`TransactionOutcomeUnknown` means COMMIT was attempted without acknowledgement; rollback/close cannot prove
non-commit. Reservation/dispatch grant uncertainty permits no provider send. Reconcile using the same attempt,
message, proposal or operation ID; citation recording retains its existing `record_ambiguous` result.
These settings do not establish a total DNS/network/workflow wall-clock guarantee.

## Limits

- **Administrators.** The owner, migrator or a superuser can still alter or drop data, policies or triggers. Append-only and audit guarantees hold against the runtime roles, not against database administrators.
- **Data migrations.** Future data migrations must set a workspace scope or add an explicit, reviewed policy, because the migrator sees no tenant rows.
- **Component boundaries.** Operator-run ingestion writes corpus generations; configured investigation
  composes retrieval and citation recording with caller-side scope and claim checks. The default Compose
  demo leaves investigation unconfigured. Historical quote verification is implemented; entailment and
  measured banking retrieval quality are not. See [retrieval](architecture.md#retrieval-steps),
  [grounding](architecture.md#reranking-and-citation-grounding) and [evaluation](evaluation.md).

- **Linux.** The POSIX/Linux run of the PostgreSQL tests (the CI `postgres` job) has not been executed.


## Retail schema

The `retail` schema belongs to retail simulator and has its own Alembic chain (`evals/migrations/retail`, version table
`retail.alembic_version`) and roles, provisioned by `policyops-retail-simulator bootstrap` on a superuser
connection: `retail_migrator` owns the schema, `retail_runtime` has only the grants below. Both are NOSUPERUSER,
NOBYPASSRLS and members of nothing; PUBLIC has no access to `retail`, the application roles have none, and the
retail roles have none outside it (`bootstrap.check_isolation` checks both directions).

| Revision | Table | Runtime grants | Notes |
|---|---|---|---|
| `r0001` | `case_states` | SELECT, INSERT, UPDATE (version, state, state_sha256, updated_at) | tenant, case, customer and fixture identity are immutable |
| `r0001` | `case_resources` | SELECT, INSERT, UPDATE (version) | the customer's user and orders |
| `r0002` | `operations` | SELECT, INSERT | one immutable terminal row per accepted operation; a receipt iff committed |
| `r0002` | `token_uses` | SELECT, INSERT, DELETE (expired rows only, by policy) | single-use service nonces |
| `r0002` | `fault_plans` | SELECT, INSERT, UPDATE (remaining), DELETE | test faults |

Every table forces row-level security on `retail.tenant_id`/`retail.case_id` (transaction-local settings); with
neither set nothing is visible. The two revisions are dependency-separated initial revisions, not a record of
production releases. A downgrade is refused while a revision's tables hold rows (the guard lifts FORCE for its own
count); recovery uses a consistent backup of state, resources and operations together. The service refuses to run
on a schema that is not at the head revision.
