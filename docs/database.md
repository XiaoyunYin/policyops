# Application database: schema, roles, migrations and restore

This page describes the PostgreSQL schema and roles in `packages/policyops/src/policyops/persistence/`. Everything here is tested against the pinned PostgreSQL 17.11 + pgvector 0.8.7 image (`pytest -m postgres`; Windows Docker Desktop is the only platform where that has actually run so far).

The database stores records and enforces relational invariants. The [authentication service](authentication.md) validates identity, sessions and current workspace membership using these records. Business workflow authorization and execution remain later work. Row-level security and constraints support those services.

## Roles

Bootstrap creates four cluster roles. All of them are `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, the runtime roles are also `NOINHERIT`, and none may be a member of another role.

| Role | Purpose | Access |
|---|---|---|
| `policyops_app_migrator` | Owns the schemas and runs Alembic | DDL in its database. It has no data policy under forced RLS, so it reads no tenant rows |
| `policyops_app_runtime` | API and worker | Tenant tables in `app`, plus its current workspace and memberships in `identity`; `USAGE` on `checkpoints` |
| `policyops_auth_runtime` | Trusted authentication service | `identity` only: workspaces, principals, memberships, sessions, login requests |
| `policyops_eval_runtime` | Evaluation recording | `evaluation` only |

- **Auth role.** Pre-workspace identity lookups (principal by issuer and subject, a principal's memberships across workspaces) need rows that no workspace scope can select. A separate, narrowly granted auth role does this, rather than a `SECURITY DEFINER` function. It sees all identity rows by design: that service is the trusted boundary, and it has no business, evaluation or retail access.
- **Passwords.** These are sent to the server as SCRAM-SHA-256 verifiers computed on the client. The plaintext never reaches the server, its logs or `pg_stat_activity`. A test checks that the verifier is byte-identical to one PostgreSQL computes itself.
- **Schema privileges.** No runtime role may create objects in any schema. On application-owned objects (the `identity`, `app`, `evaluation` and `checkpoints` schemas, their tables and functions, and the version table), `PUBLIC` has no privileges, and there are no default privileges. This does not cover PostgreSQL's own defaults outside those objects: `PUBLIC` keeps `USAGE` on schema `public` (`CREATE` is revoked), and built-in and pgvector functions remain executable by `PUBLIC`.

## Bootstrap (superuser, idempotent)

`policyops.persistence.bootstrap` has three steps:

1. `provision_roles` creates the four roles, or re-asserts their attributes and passwords if they exist.
2. `provision_database` creates the database owned by the migrator from `template0`, revokes `PUBLIC` access, and grants `CONNECT` to the runtime roles. It refuses a database owned by another role.
3. `provision_extensions` runs inside that database. It installs `vector`, revokes `CREATE` on `public`, and reports the installed version and its actual `trusted` metadata.

Bootstrap also refuses:
- a connection that is not a superuser or not autocommit;
- invalid database names;
- a missing password.

It never creates or grants anything in a `retail` schema. Retail roles and DDL belong to T16.

## Schemas and tenancy

| Schema | Contents |
|---|---|
| `identity` | workspaces, principals (global), memberships, sessions, browser-bound login requests |
| `app` | cases and messages, documents and versions, runs and events, action proposals, presentations, consents, decisions, tool executions, jobs, outbox, audit, index generations, chunks, retrieval traces, citations, usage reservations and events |
| `evaluation` | evaluation runs and trials (not tenant data; isolated by schema and role) |
| `checkpoints` | empty: ownership and `USAGE` only. T21 owns the checkpoint DDL; the runtime never runs setup or migrations |

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

- **Append-only records.** Messages, run events, consents, decisions, presentations, audit events, usage events, citations, traces and the request-idempotency ledger get `INSERT`/`SELECT` only. Other tables get column-level `UPDATE` grants, and nothing gets `DELETE`.
- **Proposals.** A proposal's bound content cannot change. A trigger, which fires even for the owner and superusers, allows only setting the presentation time once and forward status moves.
- **The binding chain.** Proposal, presentation, consent and decision records store every contract field and reconstruct to the exact contracts. Composite keys tie each record to the previous one: the same case, run, proposal version, action digest and presentation digest. They also tie each record to the referenced message's stored case, sequence, text digest, source and author. A record whose recorded evidence disagrees with the referenced row is rejected.
  - The database compares stored digest and sequence fields between rows. It does not recompute a hash from a message body: the typed repository computes `text_sha256` when it appends a message, and the SQL check on that column validates only its format.
- **One per proposal version.** Each proposal version has at most one presentation, one consent and one terminal decision.
- **Optimistic versions.** Versions are integers ≥ 1, and updates check the expected version (`StaleVersion`).
- **Idempotency keys.** The database makes these keys unique: tool executions (`operation_id`), jobs and outbox entries (dedupe keys), and usage events (provider request IDs). The repositories add payload comparison where they exist; reusing a key with a different payload raises `IdempotencyConflict` and keeps the original, never last-writer-wins.
  - Tool executions compare the approval and the argument digest.
  - Jobs compare an immutable request fingerprint: the SHA-256 of every requested field except the row ID and creation time. It is stored in `request_sha256`, which the runtime cannot update. The same request therefore still replays after a worker has changed the job's state, attempts or `available_at`.
  - Usage events compare every recorded field.
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

The chain lives in `persistence/migrations/` and has four revisions: `0001` (identity, cases, actions, jobs, audit), `0002` (retrieval, usage, evaluation, checkpoints), `0003` (single-use login requests and session idle/CSRF state), and `0004` (the request-idempotency ledger and the `(workspace_id, created_at DESC, id DESC)` case-queue index). The version table is `public.policyops_app_alembic_version`. `policyops.persistence.migrate` runs it on a SQLAlchemy connection the caller opened as the migrator; there is no URL or ini file with credentials.

- **Precondition.** `upgrade` and `downgrade` need a connection with no open transaction. Otherwise Alembic would run all revisions inside the caller's transaction, so they raise `MigrationPreconditionError` before doing anything, and never commit or roll back the caller's work. `current` leaves no transaction behind.
- **Upgrade.** Each revision runs in its own transaction. A failing revision rolls back completely and the version stays at the previous revision. A test makes revision `0002` fail midway and checks that.
- **Previous-revision upgrade.** A database at `0001` with imported synthetic data upgrades to head with every existing row unchanged.
- **Authentication upgrade.** Revision `0003` also upgrades a populated `0002` database. Existing sessions receive NULL idle/CSRF fields and require a new login; the auth service rejects them. New login requests have a bounded expiry and single-use consumption state, with access restricted to the auth role.
- **Case API upgrade.** Revision `0004` upgrades a populated `0003` database in place. It adds a `(workspace_id, case_id, id)` unique key on messages for the ledger's message link, the ledger table and the queue index; it changes no existing row.
- **Downgrade.**
  - Dropping a revision's tables or columns loses their data, so a downgrade can be lossy.
  - It is refused (`DataLossRefused`) while the affected tables hold rows, unless `allow_data_loss=True` is passed explicitly. For `0003`, either login-request or session rows trigger refusal; an explicitly allowed downgrade drops the added session fields while retaining session rows. For `0004`, ledger rows trigger refusal (dropping them would break replay of committed writes); without them the downgrade removes exactly the ledger, the index and the message key.
  - The refusal rolls back the check's temporary `NO FORCE ROW LEVEL SECURITY`.
- **Restore.** A restore is a separate operation, not a downgrade. A tested path dumps with `pg_dump -Fc` and restores with `pg_restore --single-transaction` into a separate, freshly provisioned database, as the superuser. It preserves:
  - row counts;
  - constraints, policies and forced RLS;
  - table and column grants, triggers and schema ACLs;
  - the migration version.

  The app runtime's tenant scope works on the restored copy. Database-level `CONNECT` grants are not part of a dump; bootstrap's database step re-creates them.

## Synthetic importer

`policyops.persistence.importer.import_synthetic_world` loads the fictional example world and the committed contract examples (proposal, presentation, consent, approval). It goes through the same repositories and roles as the application: identity rows via the auth role, everything else via the app role in the example workspace's scope. A repeated import is refused (`AlreadyImported`).

## Limits

- **Administrators.** The owner, migrator or a superuser can still alter or drop data, policies or triggers. Append-only and audit guarantees hold against the runtime roles, not against database administrators.
- **Data migrations.** Future data migrations must set a workspace scope or add an explicit, reviewed policy, because the migrator sees no tenant rows.
- **Not yet built.** Authorization decisions, membership checks on use, job leasing, budget logic, ingestion and retrieval queries are later tasks. The schema supports them but does not perform them.
- **Linux.** The POSIX/Linux run of the PostgreSQL tests (the CI `postgres` job) has not been executed.
