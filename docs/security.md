# Security boundaries and regression index

PolicyOps is a local portfolio demonstration using fictional customers and a retail simulator. This is a
threat model and an index of executable evidence, not a penetration-test report or production certification.
The model proposes actions; deterministic services establish authority. Structured model output is untrusted.

## Assets, actors and trust boundaries

Protected assets are tenant case/message/evidence/checkpoint data; identity sessions and membership;
immutable consent, approval, operation and receipt records; provider credentials and budgets; and the public
source, browser output and container distribution. Availability and honest unresolved outcomes matter
alongside confidentiality and integrity.

Assume an unauthenticated web client, a malicious authenticated member of another tenant, a member with an
insufficient or revoked role, and malicious customer/retrieved/tool text. Attackers can forge requests, IDs,
headers, model arguments and approval references; replay old messages; race revocation/expiry; interrupt
workers and delivery; and submit fork pull requests containing hostile code. Model/provider responses can
be malformed, misleading, oversized or missing billing evidence. A model never selects its own authority.

The browser crosses the API's session, CSRF, expected-context and role boundary. The API and worker cross
PostgreSQL's authenticated-role and forced-RLS boundary; auth, application, discovery and evaluator roles
have distinct grants. Proposal references cross a deterministic gateway before immutable execution intent
reaches the separately authenticated retail service. Provider I/O crosses a fixed-endpoint transport and
durable budget admission. Text crosses evidence and display boundaries as data. Source crosses publication,
build-context and browser-output checks before distribution. No database transaction spans provider or retail I/O.

Trusted components include the host/operator, database administrators, migration credentials, installed
dependencies, identity issuer, deterministic services and simulator. A compromised host, trusted service,
dependency or administrator can defeat these controls; RLS is not a defense against its superuser.

## Control-to-test map

Paths below are relative to the repository. Python implementation paths beginning `policyops/` are under
`packages/policyops/src/`; contracts are under `packages/policyops_contracts/src/`. `tests/integration/`
requires real PostgreSQL (`-m postgres`); default offline tests do not establish SQL/RLS properties.

| Control and guarantee within scope | Implementation | Existing regression evidence |
|---|---|---|
| Backend OIDC code flow, PKCE/state/nonce/signature validation; digest-only opaque sessions, rotation, idle/absolute expiry; unsafe requests require exact Origin and session CSRF token | `policyops/auth/{oidc,service,tokens}.py`, `policyops/api/auth.py`, `policyops/settings.py`; [authentication design](authentication.md) | `tests/unit/test_auth_oidc.py`, `test_auth_settings.py`; `tests/integration/test_auth_flow.py` (`test_unsafe_requests_need_exact_origin_and_the_session_csrf_token`, session fixation/expiry/rotation tests), `test_auth_dex.py` |
| Current membership and action roles; browser-tab headers are refusal preconditions, never tenant selectors | `policyops/domain/roles.py`, `policyops/auth/service.py`, `policyops/api/auth.py`; `apps/web/src/session/` | `tests/integration/test_auth_flow.py` role/revocation tests, `test_context_binding.py`; `tests/unit/test_context_binding.py`; `apps/web/src/session/context.test.tsx` |
| Actual authenticated runtime role, narrow grants, forced RLS, composite tenant foreign keys, transaction-local scope reset | `policyops/persistence/{database,roles,bootstrap}.py`, migrations; [role/grant matrix](database.md) | `tests/integration/test_app_privileges.py`, `test_app_tenancy.py`; `test_auth_flow.py` masked-superuser and pool-checkout tests; `test_checkpoints.py::test_all_checkpoint_tables_rls_select_insert_update_fk_and_pool_reset`; `test_safety_matrix.py` |
| REST, evidence and SSE use the same tenant/context boundary; streams recheck membership/session and stop after revocation | `policyops/api/{cases,runs}.py`, `policyops/persistence/`, `policyops/retrieval/grounding.py` | `tests/integration/test_cases_api.py`, `test_run_reads.py`, `test_run_events.py` (revocation/logout), `test_proposal_evidence.py`, `test_grounding_citations.py`, `test_embedding_run_binding.py` |
| Model arguments cannot authorize: typed tool catalog, bound customer lookup, ownership and policy checks; no arbitrary shell/SQL/URL model tool | `policyops/gateway/{steps,facts,precheck,ports}.py`, `policyops/domain/retail_rules.py`, retail contracts | `tests/unit/test_gateway_rules.py`, `test_gateway_steps.py`, `test_gateway_precheck.py`; `tests/integration/test_gateway_retail.py`, `test_gateway_persistence.py`, `test_safety_permissions.py` |
| Consent differs from staff approval; immutable digest binds call/effect/presentation, scope, versions, policy and evidence; current role and expiry rechecked before dispatch | `policyops/domain/{consent_rules,approval_rules}.py`, proposal contracts, `policyops/gateway/precheck.py`, `policyops/services/{decisions,execution}.py` | `tests/unit/test_consent_approval.py`, `test_proposal_review.py`; `tests/integration/test_proposal_decisions.py` (tamper, supersede, expiry, separation, concurrent revocation), `test_execution_retail.py`, `test_safety_permissions.py` |
| Stable operation ID, immutable request, remote receipt/fence and local reconciliation; ambiguous writes stay unknown; API replay requires matching intent and current authority | `policyops/services/{execution,cases}.py`, `policyops/persistence/{executions,database}.py`, `policyops/adapters/retail_client.py`; retail simulator is in the separate evaluator project | `tests/integration/test_cases_api.py`, `test_execution_retail.py`, `test_safety_recovery.py`, `test_retail_client.py`; `tests/unit/test_execution_states.py`, `test_retail_client.py` |
| Untrusted text is bounded and cannot supply roles/authority; citation offsets/version lineage are checked, not semantic truth; UI renders text instead of HTML/Markdown execution | `policyops/orchestration/context.py`, `policyops/retrieval/grounding.py`, `policyops/persistence/checkpoint_json.py`; `apps/web/src/{cases/CaseDetail,evidence/EvidenceViewer,approvals/ApprovalDetail}.tsx` | `tests/unit/test_investigation_context.py`, `test_checkpoint_json.py`, `test_grounding.py` (including `test_claim_support_is_never_validated`), `test_safety_e05.py`; `tests/integration/test_safety_permissions.py`; `apps/web/src/{App,cases/cases,runs/workbench,approvals/approvals}.test.tsx` |
| Configured model/call/token/time/cost caps, preflight estimate separate from authorization, durable holds and dispatch grants, unknown usage stays held, no implicit expensive fallback | `policyops/budget/`, `policyops/providers/`, `policyops/persistence/budget.py` | `tests/unit/test_budget.py`, `test_provider_call_grants.py`, `test_providers_transport.py`, `test_accounting_unconfirmed.py`; `tests/integration/test_budget_ledger.py`, `test_provider_call_grants.py`, `test_provider_calls.py` |
| Fixed provider endpoint/path/body/headers, no redirects or environment proxy/netrc; bounded identity responses; default test socket/DNS deny with registered loopback fixtures | `policyops/providers/{contract,transport}.py`, `policyops/auth/oidc.py`; `tests/support/policyops_testing/{network,plugin}.py` | `tests/unit/test_providers_transport.py`, `test_auth_oidc.py`, `test_harness_network.py`, `test_safety_e05.py::test_live_network_allowlist_refuses_other_hosts_and_allows_loopback` |
| Logs/spans keep typed allowlisted fields, no free text, query strings, model/tool payloads or exception messages; bounded exporter queues | `policyops/api/logging.py`, `policyops/telemetry/` | `tests/unit/test_auth_settings.py` access-log tests; `test_telemetry.py` HTTP canaries, tool/graph/SQL error redaction and blocking-exporter tests |
| Explicit public paths; staged blobs and reachable history scanned; independent hash-pinned scanner; no inline allow suppressions; external temp routing and checkout artifact checks | `scripts/{check_publication,gitleaks_gate,check_repo_artifacts,devenv}.py`, `.gitleaks.toml`, `.githooks/` | `tests/tooling/test_publication_guard.py`, `test_gitleaks_gate.py`, `test_repo_artifacts.py`, `test_devenv.py` |

security audit adds tests only for previously untested audit surfaces: `tests/unit/test_security_audits.py` covers
license policy/metadata reconciliation, private-context canaries, ordered ignore rules, secret-content scans,
browser keys/configuration/maps and fail-closed inputs. `tests/unit/test_ci_security.py` parses the actual
workflow (rejecting duplicate keys), checks permissions, action SHAs, credential persistence, secret contexts,
event triggers, test commands and temporary routing, and demonstrates detection with unsafe mutations.
Existing application regression tests are preserved. This is a regression index, not exhaustive path coverage.

## Recorded safety evidence

The accepted safety study used the frozen [matrix/recovery configuration](../tests/fixtures/safety/t30-v1.json)
and [E05 configuration](../tests/fixtures/safety/t30-e05-v1.json). These are previously measured counts,
not new security audit experiments: matrix 434/434, including 8 admission-only cases; E04 ledger arm 83 completed once
and 17 fenced without effect, with 0 duplicate, forbidden, false-success, failed-with-effect, unresolved or
aborted outcomes. All 6 sensitivity controls detected their injected defects. The naive arm failed to
recognize all 20 commit-then-timeout writes despite their committed effects; the ledger recovered receipts.

E05's final live sample had gateway 0/48 attack effects and 0/12 false blocks. Prompt-only Luna had
2/48 attack effects and 6/12 false blocks; the earlier sample had 2/48 and 2/12 respectively. Replaying
the final model proposals through the gateway gave 0/48 effects and 6/12 false blocks (absent proposals
cannot be replayed). Both E05 sensitivity controls detected their defects. Prompt-only received trusted
server facts about authority; the two stale races happened after its decision. These small, fixture-bound
counts do not establish general prompt-injection resistance or compare models' overall security.

## Reproduce the offline audit

Set `POLICYOPS_TEMP_DIR` to an absolute external scratch root. Use the pinned Python/uv and Node versions
in the project setup; install from frozen locks separately. These commands require no advisory network access:

```powershell
python -B scripts/check_publication.py --history
python -B scripts/devenv.py python -B scripts/gitleaks_gate.py history
python -B scripts/devenv.py python -B scripts/check_build_context.py
python -B scripts/devenv.py uv run --offline --frozen python -B scripts/audit_licenses.py --output "$env:POLICYOPS_TEMP_DIR/reports/licenses-app-web.json"
python -B scripts/devenv.py uv --project evals run --offline --frozen --no-sync python -B scripts/audit_licenses.py --python-only --output "$env:POLICYOPS_TEMP_DIR/reports/licenses-evals.json"
Push-Location apps/web
python -B ../../scripts/devenv.py npm --offline run build
Pop-Location
python -B scripts/devenv.py python -B scripts/check_bundle.py --bundle "$env:POLICYOPS_TEMP_DIR/build/web"
```

License inventory exit 1 means review required (copyleft, unknown or inconsistent metadata), not a clean
bill of health. It records all lock entries, including uninstalled optional platform packages, and checks
installed versions/declarations and extra packages. Metadata is a declaration, not proof of legal rights;
native libraries and copied data still require inspection. See [third-party notices](../THIRD_PARTY_NOTICES.md).
Online vulnerability/advisory audits are a separate check with dated results; offline inventories
and frozen locks cannot establish the absence of vulnerable dependencies.

Recorded advisory audit (2026-11-13, pip-audit 2.9.0 against PyPI; npm 11.20.0 `audit --package-lock-only`):
- Application Python environment: 85 dependencies inventoried, 83 audited and 2 local packages
  skipped because they are not on PyPI; no known vulnerabilities among audited packages.
- Web lockfile: 10 moderate advisories, all in development-only lint tooling (`eslint`/`typescript-eslint` via
  `minimatch`, GHSA-g3hv-75wg-m249); none are in the browser bundle. The fix is a semver-major upgrade, deferred.
- Evaluator environment: `litellm` 1.82.6 carries 19 advisories fixed in 1.83 or later. The pinned tau2-bench
  release requires `litellm<1.82.7`, so it cannot be upgraded without changing the benchmark pin. The evaluator
  imports litellm only to install a tripwire that refuses its completion calls, and the application never imports
  it. Any container that includes the evaluator must not expose litellm's proxy server.
Advisory databases change daily; these are dated observations, not a standing guarantee.

## Residual risks and explicit exclusions

- Local Compose attaches only Caddy to the non-internal `edge` network to make its published loopback port
  reachable on Docker Desktop. API shares Caddy's network namespace, so both have potential internet egress.
  PostgreSQL, retail, Dex, worker and one-shots stay on the internal default network with no external egress.
  This trade-off is limited to the fictional local demo; external deployment hardening is required before any non-loopback exposure.
  The smoke asserts host access to Caddy, exact loopback-only publishing, network membership and retail's
  external DNS/TCP denial. It does not establish egress confinement for Caddy/API.
- The publication and bundle checks use filename/content heuristics. Novel, encoded or renamed secrets/private
  material can evade them; review diffs, staged contents, notices and the independent scanner too. History checks
  cover local reachable refs, not unreachable objects, absent remote refs or already published external copies.
- The scanner gate now rejects Git/scanner diagnostics, unknown stderr and missing/inconsistent scan summaries,
  including gitleaks 8.30.1's empty-success result after an interrupted Git diff read. Only the pinned scanner's
  exact coverage/result summaries and its link-only notice for a local remote are allowed. Git checks reject
  staged text/binary additions with zero scanned bytes and a clean history scan whose commit count differs from
  the reachable commits with added text lines in `git log --all --format=%H --numstat -z --`.
  Deletions and other changes without additions may scan zero bytes. The pinned scanner omits binary patches,
  empty commits and merge diffs (including conflict-resolution additions); binary-only staged additions fail closed.
  Coverage counts remain heuristics, not proof every byte was inspected or every secret detected; readable Git
  configuration routing alone does not establish scan completeness.
- `check_build_context.py` accepts only its documented Dockerignore subset and tests synthetic absent private paths
  as well as actual included files. It is not a Docker implementation. The local Compose images have been built and exercised; redistribution still requires
  inspection of effective Dockerfile-specific rules, installed packages, layers, build logs and secrets handling.
  Runtime user/grant/egress checks are described in [operations](operations.md#verified-locally). Deleted files can remain in earlier layers.
- CI uses read-only repository permissions, pinned action SHAs, no persisted checkout credentials and no provider
  secrets or paid modes on fork PRs. Dependency/tool/image provisioning needs network; default tests use fakes.
  The Python socket guard does not cover subprocesses, native sockets, ctypes or captured original functions.
  Live-study allowlisting permits all loopback endpoints and resolved provider addresses; it is not a firewall.
- Approval is rechecked immediately before dispatch; revocation after a request starts cannot recall it. A local
  timeout/cancellation does not prove remote noncommit. Recovery assumes coherent remote state and ledger
  lifetimes; reset/restore while writes are unresolved needs the local Compose recovery procedure. SQL, DNS and connection
  shutdown limits do not establish a universal end-to-end deadline or confirmed cleanup of every resource.
- A grounded quote is not entailment, policy truth or absence of model hallucination. Public benchmark tasks may
  have been in training data. The UI has jsdom coverage and two local real-browser OIDC/proxy/SSE flows with CSP/header checks
  ([scope](evaluation.md#recovery-and-e07-correctness)); deployed HTTPS and broader browser/security checks remain open. No production readiness, internet exposure, independent penetration
  testing, legal clearance, zero-vulnerability claim or real-customer/real-commerce safety is asserted.
