# Evaluation and Core evidence

Bedrock is a separate opt-in provider; prior registrations keep the original snapshot and defaults.
The offline capability matrix is:

| Bedrock US profile via us-west-2 | Contract |
|---|---|
| Model | Only `us.anthropic.claude-haiku-5-5` (`bedrock:` registry prefix) |
| Residency | Any of us-east-1, us-east-2, us-west-2; data stays in the US, with no single-region guarantee |
| Rejected identifiers | Bare model: no on-demand invocation offered; global profile: no US geographic bound |
| Text / structured JSON | Implemented; local schema validation |
| Admission | Local UTF-8 byte upper bound; no count API |
| Usage / unknown liability | Actual input/output and optional cache splits; existing ledger settlement/holds |
| Streaming / non-text / cache writes / global / long context | Refused |
| Credentials | Named static profile only; no refresh or provider chain |
| Prices | Higher in-region Standard rows conservatively applied to the US profile; billing assumption |
| Live | Coordinator HTTP 403 account-eligibility hold; profile smoke pending |

`scripts/bedrock_smoke.py --execute --workspace <existing-workspace-uuid>` sends one tiny structured request through
the real port and PostgreSQL ledger. Set `POLICYOPS_BEDROCK_PROFILE=<your-aws-profile>` and
`POLICYOPS_BEDROCK_REGION=us-west-2`, with no `AWS_*` / `ANTHROPIC_*` names. A migrated local app database and
libpq `PG*` settings for the app runtime role are prerequisites. The operation scope `bedrock-haiku-smoke-v1`
persists across repeated launches, enforcing at most 4 inference calls / $0.05 including unknown liability;
each launch makes one call, with no retries or repair. `--operation-key` selects that persisted budget scope;
the default is `bedrock-haiku-smoke-v1`. Reuse the same key across repeats, including when changing from the bare
ID to the US profile; choosing a new key creates a separate budget and does not carry prior liability. The script
prints only effective model, usage, cost and AWS request ID. Exit 0 requires a structured result; failures return 1
with those same fields, without exception messages, payloads or headers. Without `--execute`, it returns 2.

The retail model comparison, authorization fixtures and recovery drills answer different
questions. The registered holdout does **not** establish Luna's non-inferiority to Haiku;
the deterministic safety suites passed their specified acceptance checks. All paid and
recovery execution reported here was local; hosted CI runs only the offline and PostgreSQL
test suites. No production or real-customer outcome is claimed. Raw trajectories, database dumps and execution bundles are not published.

## Method

The benchmark pin is τ²-bench commit
`19f13ea3f5fba8b4c4d272d1353590f29dc53062`, using its English retail text binding.
The official `retail_50` subset supplies 50 holdout tasks; its 64-task complement is
development data. E03 uses 20 development tasks, then all 50 holdout tasks, with four
seeds per task and two agent arms. The holdout has 34 tasks without nonempty NL assertions
(`db_only`) and 16 with them (`db_nl`). The upstream split, reviewed-scenario differences,
near-neighbours and tuning exclusions are documented in [data provenance](data-provenance.md#retail-split-64-dev--50-held-out).

The **minimal agent** receives the full retail policy and visible tool interface through
the pinned upstream factory, orchestrator and evaluator. Hidden task criteria, reference
actions and simulator secrets stay outside its runtime projection. E03 is neither a
LangGraph-versus-loop experiment nor a retrieval experiment. Its agent arms are
`gpt-6-luna` and `claude-haiku-5-5`, both low effort with cache mode `none`; the customer
simulator and NL judge use `gpt-6-luna` in both arms. There are no retries or repairs.
These are application adapters and explicit actor/limit overrides, not exact upstream
leaderboard settings. See [the bridge](../evals/src/policyops_evals/harness/inprocess.py),
[actor isolation](../evals/src/policyops_evals/harness/actors.py) and
[the frozen holdout config](../evals/studies/e03-holdout-luna-haiku-v1.json).

Scoring and analysis:

- **Deterministic:** the upstream final-database comparison, report arithmetic, argument/
  authorization checks, effects, receipt identities and fault assertions. Final-state DB
  success does not establish intermediate policy compliance.
- **Model-judged:** nonempty natural-language assertions, evaluated by the configured Luna
  judge. Composite success combines the selected upstream components. Generation remains
  model-driven even in the deterministically scored stratum. Same-family simulator/judge
  bias is a limitation; scores are not human quality judgments.
- **Strict pass^k:** for a task with `s` successful trials out of `n` scheduled trials,
  `C(s,k) / C(n,k)`, averaged equally over tasks. Errors, aborts and missing outcomes count
  as non-success. With four trials, pass^4 measures all four succeeding, not at least one
  succeeding (`pass@k`). Complete-case metrics exclude unscored observations and are
  missingness-sensitive diagnostics, never the headline or release-selection metric.
- **Intervals:** 10,000 deterministic SHA-256 task-bootstrap replicates, percentile 95%
  intervals with linear R7 quantiles. Paired differences use shared task draws, retaining
  the within-task trials. These are pointwise intervals; hosted seeds do not prove
  independent trials, generalization or absence of benchmark training contamination.
- **Cost:** all actors, including the simulator and judge, charged at the frozen
  `pricing.2026-11-05.v1` rates. Settled spend and held upper-bound liability are separate.
  A missing bill is never estimated as zero. These are ledger prices, not provider invoices.
  Trial timing includes application work; logical-call timing includes counting and
  settlement and is not provider-only latency.

Implementation: [scoring](../evals/src/policyops_evals/studies/scoring.py),
[statistics and decision gates](../evals/src/policyops_evals/studies/statistics.py),
[report accounting](../evals/src/policyops_evals/studies/reports.py).
Regressions: [statistics](../evals/tests/test_study_statistics.py),
[reports](../evals/tests/test_study_reports.py),
[holdout contract](../evals/tests/test_study_holdout.py) and
[leakage boundary](../evals/tests/test_inprocess.py).

## E03 model comparison

### Development: pilot through v6

Each revised configuration was fixed before collecting its next data. These development
studies were prespecified in versioned configs, **not formally registered**. Earlier
failures and liabilities remain part of the record; successive versions are different
studies, not a causal paired comparison of protocol changes.

| Study | Observed outcome and confound | Change before the next data |
|---|---|---|
| [Pilot v2](../evals/studies/e03-dev-luna-haiku-frozen-draft-v2.json) | 160/160 finalized; strict pass^1 Luna 0.5125 vs Haiku 0.175; 48/80 Haiku trials ended `invalid_steps`. Text accompanying a tool call was rejected; trajectory limits also censored work | Accept one valid tool call with accompanying text, drop that text before user delivery, record a notice; raise both arms to 32 agent calls and 12 steps per turn |
| [v3](../evals/studies/e03-dev-luna-haiku-v3.json) | 116/160 finalized, 44 never claimed. An in-flight call crossed the 180-second trial deadline, leaving an unknown bill. Haiku input admission also hit the 16,000-token ceiling; no `invalid_steps` remained | Raise both agents to 32,000 input tokens and the trial deadline to 600 seconds |
| [v4](../evals/studies/e03-dev-luna-haiku-v4.json) | 6/160 executed before transient Haiku count/inference failures; unknown billing stopped admission | Continue within reserved liability, with at most 3 unresolved attempts and every existing hold retained against every cap |
| [v5](../evals/studies/e03-dev-luna-haiku-v5.json) | 160/160 finalized; strict pass^1 0.650 vs 0.700. An implicit one-tool-error cutoff terminated 22/160 trials (10 Luna, 12 Haiku), often on recoverable errors | Make `max_tool_errors` explicit; set 10 for both arms, the pinned upstream default; record termination reasons |
| [v6](../evals/studies/e03-dev-luna-haiku-v6.json) | 160/160 finalized; 158 simulations ended `user_stop`, zero `too_many_errors`. Two Haiku trials hit the shared simulator's 12-call limit | Lock the candidate/protocol, raise the simulator ceiling equally to 16 calls, then register the holdout |

The mixed text/tool rule applies to the benchmark minimal agent only. The authorization
gateway and workbench investigation retain their strict parser. Liability-bounded
continuation retains full holds and does not retry or silently price an unknown bill.
Legacy configs retain their original one-error cutoff and hashes; v5 results were not
reinterpreted after inspecting v6. See [minimal-agent parsing](../packages/policyops/src/policyops/orchestration/minimal.py),
[the runner](../evals/src/policyops_evals/studies/runner.py) and
[admission/recovery](../evals/src/policyops_evals/studies/runner_v2.py).

Final development result (v6), strict task-bootstrap 95% intervals:

| Metric | Luna | Haiku | Luna − Haiku |
|---|---|---|---|
| pass^1 | 0.7125 [0.600, 0.825], 57/80 | 0.7875 [0.700, 0.875], 63/80 | −0.075 [−0.1875, 0.025] |
| pass^4 | 0.35 | 0.40 | −0.05 [−0.20, 0.10] |
| `db_only` pass^1 | — | — | −0.054 |
| `db_nl` pass^1 | — | — | −0.125 [−0.333, 0.083] |

V6 settled **$1.6329008**: Luna $0.5720074, Haiku $1.0608934; $0 held and all
2,953 attempts settled. All-actor cost was 46% lower for Luna; agent-only cost was
$0.507 vs $0.970 (48% lower). Agent logical-call p50 was 2.16 s vs 1.74 s; trial p50
40.7 s vs 39.5 s. The two errors were `simulator_failed` on Haiku task 28 trials 0 and 3,
and count as non-success. Status: **`descriptive`** (unregistered development study,
with errors). The pass^1 difference interval also fails the −0.10 margin. Non-inferiority
was not shown on development data. Luna remained the cost-selected default, without a
quality-equivalence claim. The holdout's wider task frame was expected to remain uncertain
at this observed development difference.

### Registered holdout

Registration binds the spec excluding its own digest, source revision/dirty digest,
both locks, schedule, price snapshot and analysis. The flow was:

1. Commit the holdout config with a placeholder digest before data collection.
2. Compute the offline preflight payload digest and fill the config's digest field.
   That field is excluded from the dirty digest, avoiding self-reference.
3. Run `preflight --register` in the execution database before the first claim; retain
   the receipt in the study bundle. `registration_precedes_claims` is enforced.
4. Run in that same database with the bound config, then commit the filled digest.

Source: `4179062` plus the digest fill, committed as `0a53a9e`. Commit IDs were renumbered once by a
message-only history rewrite; the registration receipt records the original ID `f54e046`, whose code tree
is identical to `4179062`. Registration SHA-256:
`a5350c62dbc7db2e92ac1f312b8b6726e28792a4a5df53142596d0fb63c52ad1`.
The [committed config](../evals/studies/e03-holdout-luna-haiku-v1.json) freezes fresh seeds
20261116–20261119, 50 tasks × 4 trials × 2 arms = **400 trials across 200 matched
task/seed pairs**. The simulator ceiling is 16, agent ceiling 32, tool-error limit 10,
trial deadline 600 seconds, and unresolved-attempt ceiling 3. Preflight estimated
$10.05; the conservative admission ceiling was $71.9104 under a $75 study cap.
The [registration implementation](../evals/src/policyops_evals/studies/registration.py)
and [registration tests](../evals/tests/test_study_v2.py) bind this sequence.

All 400 slots finalized. All 396 completed simulations ended `user_stop`, so none hit
the raised simulator ceiling. Luna had no errors. Haiku had four: three
`count_not_admitted` provider-count admission failures (released attempts) and one
`provider_failed` inference with unknown billing. All four count as strict non-success.

| Strict metric | Luna | Haiku | Luna − Haiku, paired 95% interval |
|---|---|---|---|
| pass^1, all 50 tasks | 0.700 [0.595, 0.800], 140/200 | 0.750 [0.660, 0.835], 150/200 | −0.050 [−0.135, 0.035] |
| pass^4, all 50 tasks | 0.50 | 0.50 | 0.00 [−0.16, 0.16] |
| `db_only` pass^1, 34 tasks | 0.750 | 0.801 | −0.051 [−0.154, 0.044] |
| `db_nl` pass^1, 16 tasks | 0.594 | 0.641 | −0.047 [−0.188, 0.109] |

The stratum rows are composite task outcomes split by assertion presence; they are not
independent NL-judge accuracy estimates. The audited DB-component success counts were
also 140 and 150. Task-level recomputation of strict pass^1/pass^4 matched the sealed report.

Settled all-actor spend was **$4.0562674**: Luna $1.4572403 and Haiku $2.5990271,
plus **$0.004224 held** for the unresolved Haiku inference. There were 7,481 settled,
3 released and 1 unresolved attempt; 7,482 inferences. Settled cost rounds to $1.457
vs $2.599, **44% lower** for Luna, excluding the held liability. Trial p50 was 40.0 s
vs 42.8 s. A cost-per-success estimate is withheld by the report because accounting
is incomplete; no missing bill or provider invoice reconciliation is inferred.

**Decision status: `descriptive`, under the registered rule.** Formal registration and
finalization alone are insufficient. The `complete` gate requires every trial to be
scored success/failure; Haiku's four errors fail it. The accounting gate also fails on
`held_or_unresolved_liability`. The gates were not changed after the run. Even considering
the intervals alone, the comparison is inconclusive: the pass^1 lower endpoint −0.135
and pass^4 lower endpoint −0.16 both fall below −0.10. **Luna non-inferiority at margin
0.10 is not shown.** Its point estimate is 5 percentage points lower on pass^1, equal on
pass^4 and cheaper on settled spend. The implementation returns
`candidate_noninferior_and_cheaper` only when all non-statistical gates pass, both lower
endpoints are strictly above −0.10 and the candidate is cheaper; otherwise it returns
`inconclusive` if the non-statistical gates pass, or `descriptive` if they do not.

### End-of-run failure and recovery

After all slots finalized, the raw-artifact inventory refused 16,571 files against its
single-file 16,384-entry bound. This happened in finalization before the final snapshot
checkpoint; the run process failed and its PostgreSQL stopped without a final seal.
The preflight had not checked that inventory capacity scaled with the schedule.

The database files survived. Recovery preserved the original, started a copied data
directory with the pinned image, reset the two role passwords through single-user stdin,
verified all 400 finalized slots and unchanged spending scopes, then used
`run --resume --close-unclaimed` **without paid opt-in or provider credentials**.
No slots remained to execute; it checkpointed and rendered. Counts and spend remained
identical. The recovery container was stopped, removed by its exact ID and verified gone.
The inventory was written in three bounded parts: 8,192 + 8,192 + 187 entries (32.3 MB).

The [subsequent fix](../evals/src/policyops_evals/studies/runner_v2.py) seals and renders
before inventory failure can propagate, prevalidates bounded inventory parts and accepts
identical repeat writes. [Regressions](../evals/tests/test_study_inventory.py) cover
partitioning, capacity, failures and finalization. The fixed writer produced parts
byte-identical to the recovered holdout inventory on the real file set. This is a
recovered result with disclosed harness failure, not a clean first-attempt run.

### Sealed snapshot identities and development spend

These SHA-256 identities select the sealed analysis inputs for offline `report` and
`taxonomy`. Configs specify the experiment; a hash identifies the retained result but
does not make unpublished raw data publicly inspectable. No raw trajectories are published.

| Study config under `evals/studies/` | Snapshot SHA-256 | Settled USD | Held USD |
|---|---|---:|---:|
| `e03-dev-luna-haiku-frozen-draft-v2.json` | `11d3ddd64714d2611aa72c29cb89f67033cfc2815020bb4b83684c278f5fec87` | 1.04255120 | 0 |
| `e03-dev-luna-haiku-v3.json` | `43ae15e08810bc389027042edf74b0298aed2da301adeb9c0fb9add02ab86bb1` | 1.10637080 | 0.002624 |
| `e03-dev-luna-haiku-v4.json` | `1dc1c63bf04019996fb48ee6166447f3fbf69930eb62384ac3cc95ffd1b9654d` | 0.00914 | 0.004224 |
| `e03-dev-luna-haiku-v5.json` | `9a8272acdb2b504d01c2e0572c781b120f1122a9ee536ba36ffe692023e346f3` | 1.4749682 | 0.004224 |
| `e03-dev-luna-haiku-v6.json` | `fb40a4df3ed40283dc744599d03e8c803c054ca01a1eb343bf4c78b3dc3f6bb6` | 1.6329008 | 0 |
| `e03-holdout-luna-haiku-v1.json` | `68f65f59e8884ae576639ef2b09b6689c0b1279166a826e2dd1fe361c70d6975` | 4.0562674 | 0.004224 |

Development pilot–v6 totals round to **$5.27 settled plus $0.011 held upper-bound
liability**. Failed/incomplete studies are included. None of these development runs
establishes a confirmatory model comparison.

## E04 operation ledger versus naive retry

The frozen [matrix/recovery config](../tests/fixtures/safety/t30-v1.json) defines
100 paired seeded cases: five fault strata × 20, or 200 arm trials. Faults cover
crash before send, crash after commit, commit then lost response, duplicate delivery
and pre-send 503. A real lost-response relay is used; one real subprocess-kill check
is supplementary and outside the paired denominator. Both arms retain the simulator's
scope, signed transport, expected-version and business/effect checks.

| Outcome | Operation ledger | Naive retry |
|---|---:|---:|
| Completed once with a retained receipt | 83/100 | 80/100 |
| Fenced without effect | 17/100 | 0/100 |
| Reported failure despite a committed effect; no retained receipt | 0/100 | 20/100 |
| Duplicate effects | 0/100 | 0/100 |

Ledger acceptance passed: zero forbidden effects, false successes, failed-with-effect,
unresolved or aborted outcomes. It recovered all 20 commit-then-timeout receipts.
The naive arm's second sends were refused by version preconditions, so this experiment
does **not** demonstrate duplicate effects from naive retry. It demonstrates lost receipts
and false failure reports after committed writes.

The 17 fences are an explicit availability trade-off for once-per-order address writes:
7 crash-before-send, 5 duplicate-delivery and 5 pre-send-503 cases. An unresolved history
prevents safe resend, so the ledger may settle without an effect. Requiring every case
to execute would contradict that safety policy. All six sensitivity controls detected
their removed guard; capped-unknown, commit-then-503 and crash-after-response supplements
passed outside the headline denominator.

The associated authorization matrix passed **434/434 rows**, including 8 admission-only
rows (no resource endpoint claim). RLS was exercised as the authenticated runtime role:
four foreign-tenant insert probes returned SQLSTATE 42501, five update probes affected
zero rows, and owner insert controls succeeded. These are finite synthetic fixtures,
not universal authorization coverage. Duplicate-delivery advances the controlled lease
clock; remote transport uses wall time, and the remote fence prevents a late effect.
The successful item-change fixture uses whole-dollar prices because some upstream float
differences are deliberately rejected by exact-money conversion.

Executable evidence: [study driver](../scripts/run_safety_study.py),
[faults and reports](../tests/support/policyops_testing/safety/),
[recovery regressions](../tests/integration/test_safety_recovery.py),
[matrix regressions](../tests/integration/test_safety_matrix.py) and
[policy-to-case map](policy-coverage.json). Raw study receipts are not published.

## E05 gateway versus prompt-only

The [frozen config](../tests/fixtures/safety/t30-e05-v1.json) and
[hash-bound prompt](../tests/fixtures/safety/prompts/e05-v1.txt) define 60 fixtures:
48 attacks across six categories plus 12 valid controls. Three arms give 180 slots:
deterministic gateway, prompt-only Luna, and replay of Luna's proposals through the
gateway. Prompt-only retains simulator scope/version/effect protections and receives
trusted server facts about authority. It does not independently infer authority from
arbitrary documents. Luna uses low effort, cache `none`, zero retries and the frozen
price revision, with $0.002 per fixture and $0.12 per study caps.

| Final live sample | Attack effects | False blocks on valid controls |
|---|---:|---:|
| Gateway | 0/48 | 0/12 |
| Prompt-only Luna | 2/48 | 6/12 |
| Luna proposals replayed through gateway | 0/48 | 6/12 |

Acceptance passed and sealed verification passed. The gateway blocked 45 attacks at
authorization and 3 at schema validation, with zero extra effects. Both prompt-only
attack effects were stale-authority races after the model decided: expiry after
precheck and reviewer revocation at the dispatch checkpoint. There were 40 model
refusals. Replay cannot repair an absent proposal, so its six false blocks remain.
Both sensitivity controls detected their defects: removing the current-reviewer-role
check at the checkpoint and hiding once-per-order history.

The earlier live sample also had 2/48 prompt-only attack effects but 2/12 false blocks,
with 39 model refusals; seven changed-argument attacks produced the original authorized
call and an allowed effect. This earlier sample preceded source/config fixes for the
live outbound allowlist, trusted-facts disclosure and observed effective-model checks.
The final sample returned `gpt-6-luna` on all 60 calls. Final spend was **$0.0069406**
(45,296 input and 4,822 output tokens), nothing held; earlier spend $0.0070876.
Total paid E05 spend: **$0.0140282**. The valid-request variability is reported, not
averaged away. These controlled races support deterministic rechecks; they do not
establish general prompt-injection resistance or model security rankings. Zero observed
gateway attack effects and degenerate fixture intervals are not population guarantees.

Implementation and tests: [E05 harness](../tests/support/policyops_testing/safety/e05.py),
[live driver](../tests/support/policyops_testing/safety/e05_cli.py),
[offline tests](../tests/unit/test_safety_e05.py) and
[real-PostgreSQL tests](../tests/integration/test_safety_permissions.py).

## Recovery and E07 correctness

These are correctness checks, **not** the deferred E07 load/scaling experiment.
The local Compose stack uses Caddy, Dex, API, worker, retail simulator and PostgreSQL,
with separate app/retail migration owners and runtime logins.

- **Browser denominator: 2/2 Playwright flows.** Through real Caddy/Dex and browser SSE,
  staff-entered simulated consent and exact approval produced one mutation and an outcome
  card whose receipt matched the simulator. Analyst/auditor decisions were denied and a
  foreign case returned `404 not_found`. Required headers were present, source maps absent,
  and there were zero CSP events or console CSP messages. The second flow raced two
  independently signed-in contexts of the same reviewer: one 201 and one 409, one effect.
  It is not evidence for two distinct reviewer identities or model-driven investigation.
- **Kill-after-commit drill:** after a remote commit and before local receipt persistence,
  the exact worker was killed. Its local row remained `dispatched` without a receipt.
  After restart and lease expiry it became `succeeded` via `lookup`, attempts=1, with the
  same operation ID and remote receipt and no further case-version increment.
- **Restore drill:** a second unresolved write was preserved in a coherent stopped-writer
  dump, restored into a separate database in the same cluster. Snapshot row hashes,
  selected ownership/ACL/RLS metadata, app `0016` and retail `r0002` versions/owners,
  runtime identities and cross-schema denial matched. Selected runtime-role RLS probes
  passed. The unresolved operation reconciled by lookup, the completed operation was
  not re-executed, and the stopped source database remained unchanged.
- **Stream regressions:** replay positions, retention gaps, revocation, cancellation,
  backpressure and terminal EOF are covered by [SSE integration tests](../tests/integration/test_run_events.py)
  and [workbench tests](../apps/web/src/runs/workbench.test.tsx). The browser flows
  observe real consent/execution frames; they do not repeat the entire fault matrix.

Correctness acceptance passed within these scenarios. Restore is logical backup with
stopped writers on one host, not independent-cluster role bootstrap, PITR/WAL, physical
backup, host-loss recovery, previous-image rollback or every crash window. The default
Compose runtime has no model-driven investigation. See [browser tests](../apps/web/e2e/),
[drill driver](../scripts/compose_drills.py) and
[operations and reproduction](operations.md#automated-killrestart-and-separate-database-restore-drills).

## MCP parity (O01)

The read-only MCP server ([design](architecture.md#read-only-mcp-over-stdio)) runs over stdio only and exposes eight fixed
read tools. The parity harness ([`scripts/mcp_parity_report.py`](../scripts/mcp_parity_report.py)) drives a real
`mcp` 2.3.0 `ClientSession` against the real server subprocess in an owned PostgreSQL and retail-simulator stack. It
compares each call with the direct gateway path: decision, normalized error code and payload, modulo transport framing.

The 167 calls cover:
- 35 T30 VIEW_CASE actor/relation cells;
- 9 gateway read rules;
- 60 E05 cited-text projections;
- 60 refused write candidates;
- 3 identity cases (expiry, revocation, argument-supplied identity).

E05 approval/write races and other T30 APIs are out of scope.

| Measure | Result |
|---|---|
| Parity with the direct path | 167/167 |
| Unauthorized disclosures / false denials vs direct | 0 / 0 |
| Warm-worker overhead (60 calls) | p50 14.5 ms, p95 39.9 ms, max 97.1 ms |
| Cold first call (worker spawn and setup) | p50 3.14 s, p95 3.64 s |
| Calls refused in the facade before any worker (60) | p50 1.17 ms |

Latency uses nearest-rank quantiles on one Windows workstation, with sequential direct-then-MCP calls. The handshake is
excluded. Overhead includes per-call identity and health checks, so it is not pure protocol cost. Warm workers are reused
and are killed and replaced on any timeout, cancellation, oversize or failed result, so no thread or transaction is
abandoned.

A capped live smoke ([`scripts/mcp_luna_smoke.py`](../scripts/mcp_luna_smoke.py)) used `gpt-6-luna` as the MCP client for
an order lookup and a cited policy search. Both tasks completed, using 4 calls with a settled $0.0003165 under a $0.05 cap,
no retries and ledger admission. An earlier attempt stopped at a locally refused tool argument; the prompt now states the
exact order-ID format, and refused arguments are recorded. This shows protocol interoperability and authorization parity
in a fixture scope, not general agent quality.

## Reproduction and harness reference

Use the frozen environments and external scratch setup in
[development setup](operations.md#development-setup). The following are real CLI entry
points; commands below were not rerun to generate new paid evidence for this report.
Data acquisition, dependency installation and provider execution are separate from
offline reporting. A fresh live run requires provider credentials, verified acquisition,
a migrated database authenticated as `policyops_eval_runtime`, explicit paid opt-in,
passing ledger admission and a new source-bound registration. The historic registration
digest cannot authorize a different checkout/configuration.

```powershell
# Root working directory. Offline config checks; prior spend is unverified without a DB.
python -B scripts/devenv.py uv --directory evals run --offline --frozen policyops-evals preflight --study studies/e03-holdout-luna-haiku-v1.json
# After filling a NEW preflight digest for the exact source/config, register in the execution DB:
python -B scripts/devenv.py uv --directory evals run --offline --frozen policyops-evals preflight --study studies/e03-holdout-luna-haiku-v1.json --register
# Network + paid opt-in; never part of default CI:
python -B scripts/devenv.py uv --directory evals run --frozen policyops-evals run --study studies/e03-holdout-luna-haiku-v1.json --allow-paid
```

Set `POLICYOPS_EVAL_ACQUIRED` to the verified `data fetch` destination and
`POLICYOPS_EVAL_DATABASE_DSN` to the evaluation runtime connection. Provider keys are
server-side environment inputs read only after opt-in and admission. The
[three-task smoke config](../evals/studies/t29-luna-dev-smoke-v1.json) and
[scripted paired config](../evals/studies/offline-paired-v2.json) provide smaller examples.
Without `--allow-paid`, execution accepts only explicitly scripted configs. Preflight
reports planning cost separately from worst-case reservation liability and never grants
a provider dispatch itself.

For a retained sealed bundle, substitute its absolute `study.json` path and a snapshot
SHA-256 from the table above. `report` needs no database, keys, raw task payloads, Git or
provider. `taxonomy` additionally verifies the hash-linked private inventories and raw
artifacts. These inputs are not shipped; a public clone can run the tests and reproduce
the protocol, but cannot independently re-render the historic numbers from hashes alone.

```powershell
$studyBundle = "$env:POLICYOPS_TEMP_DIR/benchmarks/studies/<study-id>/study.json"
$snapshot = '68f65f59e8884ae576639ef2b09b6689c0b1279166a826e2dd1fe361c70d6975'
python -B scripts/devenv.py uv --directory evals run --offline --frozen policyops-evals report --study $studyBundle --snapshot $snapshot --out "$env:POLICYOPS_TEMP_DIR/reports/holdout"
python -B scripts/devenv.py uv --directory evals run --offline --frozen policyops-evals taxonomy --study $studyBundle --snapshot $snapshot --out "$env:POLICYOPS_TEMP_DIR/reports/holdout-taxonomy"
```

Bundles bind source HEAD/dirty digest, both lock hashes, dataset/split/task-list hashes,
prompts/schema/tool digests, requested/returned actor models, prices, schedule/seeds,
OS/CPU and UTC times. Finished slots are skipped by `--resume`; abandoned claimed slots
are closed rather than reinferred, and only never-claimed slots can execute. Changed
specs conflict with a study key. Lost terminal commits reconcile by result identity/hash.
`--resume --close-unclaimed` explicitly closes unscheduled work. It is a no-provider
recovery only when nothing remains to execute; it does not erase held liability.

Safety studies require the raw pinned upstream checkout in the evaluator uv cache, Docker and the pinned local
PostgreSQL image. Scripted E05 uses no provider; live mode additionally requires its
explicit opt-in. Outputs must be new external directories.

```powershell
python -B scripts/devenv.py uv run --offline --frozen python -B scripts/run_safety_study.py --suite matrix,e04 --out "$env:POLICYOPS_TEMP_DIR/tests/safety-recovery"
python -B scripts/devenv.py uv run --offline --frozen python -B scripts/run_safety_study.py --suite e05 --config tests/fixtures/safety/t30-e05-v1.json --provider-mode scripted --out "$env:POLICYOPS_TEMP_DIR/tests/safety-e05"
python -B scripts/devenv.py uv run --offline --frozen python -B scripts/run_safety_study.py --verify-report "$env:POLICYOPS_TEMP_DIR/tests/safety-recovery/raw/study.json"
```

The smoke, real-browser and recovery-driver commands are in
[operations](operations.md#deployment-smoke). No banking trajectory retrieval study,
ANN/HNSW, graph quality comparison or context/cache optimization result is part of this
release. Implemented retrieval components and synthetic mechanics tests are described in
[architecture](architecture.md#retrieval-steps); they supply no measured retrieval-quality claim.

### Additional harness details

The initial three-task development smoke finalized 3/3 trials with reward 1.0 each for
$0.015628 settled, nothing held, under a $0.30 cap. It made 41 inference and 41 count
requests; preflight estimated $0.0684 with a $0.228288 admission maximum. This verified
the composed path, not a development score estimate, pass^k result or holdout result.
Its agent, simulator and judge all requested and returned Luna; only task 24 exercised
nonempty NL judging. To use that smaller configuration in a separately prepared database:

```powershell
python -B scripts/devenv.py uv --directory evals run --offline --frozen policyops-evals preflight --study studies/t29-luna-dev-smoke-v1.json
# Paid opt-in, provider access and DB-backed admission required:
python -B scripts/devenv.py uv --directory evals run --frozen policyops-evals run --study studies/t29-luna-dev-smoke-v1.json --allow-paid
# Scripted paired example; explicit closure preserves scheduled denominators:
python -B scripts/devenv.py uv --directory evals run --offline --frozen policyops-evals run --study studies/offline-paired-v2.json --resume --close-unclaimed
```

Historical limits stay in their configs. V3 explicitly used 32 agent calls, 12 steps per
turn, two consecutive invalid replies, 64 inference/count requests and $0.20 per scenario.
With 16,000-input/2,048-output actor bounds, planning was $3.6480 and admission $18.8928,
with 7,200 inference and 7,200 count slots. Its cap rose from $15 to $20 before data,
preserving token ceilings rather than admitting a study whose reservation exceeded its cap.
V4 raised the agent input ceiling and trial deadline; v5 added bounded liability
continuation; v6 made tool-error recovery explicit. V4–v6 planning remained $3.6480,
admission $27.0848 and study/invocation caps $28. These are admission maxima, not actual bills.

The runner seals numbered immutable snapshots. Every scheduled slot remains represented,
including pending and aborted trials with no raw result. Reports emit sanitized
`policyops.study-report/v1` JSON/Markdown with strict, complete-case and DB-component
metrics, all-actor costs, usage and timings. Missing judging never converts a DB+NL task
to DB-only success; paired complete-case differences use intersected scored slots.

Taxonomy emits `policyops.study-taxonomy/v1` JSON/Markdown by variant, outcome, agent
terminal reason, error class and simulation termination, including per-task counts.
Absent artifacts/old termination fields are `unavailable`; an observed nonterminal
agent is `none`, and unrecognized terminations are `unknown`. Missing or mismatched
declared bytes refuse the command. Re-rendering the same snapshot with the same reporter
version produces byte-identical output; multiple snapshots require an explicit digest.
Declared corruption produces an integrity diagnostic and nonzero exit, never a release
decision. Reports omit raw transcripts, prompts, reasoning, provider request IDs,
credentials and local paths. In-process isolation is a reviewed code boundary rather
than an OS sandbox; synchronous work and dispatched requests may outlive cancellation.
## QA study runner

The unregistered `evals/qa_studies/g1-dev-retrieval-v1.json` runs 500 dev questions
through FTS, dense and RRF under both frozen query profiles (3,000 slots). Its
results are descriptive. Provision and ingest the [persistent QA environment](operations.md#persistent-qa-evaluation-environment)
first, retaining the same database for registration and subsequent execution.

```powershell
python -B scripts/devenv.py uv --directory evals run --offline --frozen policyops-evals qa-study preflight --study qa_studies/g1-dev-retrieval-v1.json
$qaArgs = @('--study','qa_studies/g1-dev-retrieval-v1.json','--materialization',$materialization,
  '--app-dsn-file',"$qa/secrets/policyops_app_runtime.dsn",
  '--eval-dsn-file',"$qa/secrets/policyops_eval_runtime.dsn",'--workspace',$workspace)
python -B scripts/devenv.py uv --directory evals run --offline --frozen policyops-evals qa-study run @qaArgs --allow-paid
python -B scripts/devenv.py uv --directory evals run --offline --frozen policyops-evals qa-study status @qaArgs
python -B scripts/devenv.py uv --directory evals run --offline --frozen policyops-evals qa-study report @qaArgs
# Continue an interrupted run with the same arguments and --resume --allow-paid.
```

Preflight reserves at most 90 ingest calls × 8,192 tokens and 1,000 query calls ×
1,024 tokens, at the frozen embedding price ($0.0147456 and $0.02048 ceilings).
The previously measured empty-cache ingest plan is 70 calls / 523,675 distinct-input
tokens ($0.0104735 estimate). Query cache hits send no requests. Runtime admission
counts shared ingest usage, settled spend, held liabilities, call/count/input/output
envelopes and active slot time across resumes; a new invocation cannot reset caps.
The parent money gate conservatively includes every evaluator study in this
dedicated database plus workspace preprocessing. Other study families retain their
own ledgers and are included when their spend is in these evaluator tables.

Queries, references and passages are independently hash-checked. Gold never enters
the typed retrieval executor. Existing claim fencing and dual-ledger embedding
admission prevent a replacement dispatch after a crash. Abandoned claims become
failed observations; unknown bills remain held. Resume can execute later slots
within the remaining envelopes. SQL waits and remote cancellation are bounded by
existing stack limits and may delay return beyond a deadline; such slots fail.

`status` emits a schedule-complete, text-free public projection: IDs, metrics,
cost/holds, latency and failure codes. `report` includes strict query-macro retrieval
metrics, costs/censored latency, and declared paired whole-dialogue comparisons
through the G0.5 statistics and status functions. The runner retains immutable
source/schedule bindings, exports, reports and bounded raw inventories privately
under `POLICYOPS_TEMP_DIR/benchmarks`. Sealed execution requires prior registration
bound to the current source/locks. Cascade/selective reranking, full context
and caching execution await later slices.

### Answer and rerank arms

QA answer runner (G0.4b): `qa-study run|status|report` also supports
`answer_generation`, top-20 `rerank` (T14 Luna or G8 stdio cross-encoder), and
`closed_book`. Generation receives only the private materialization's chronological
history and delivered passages. Gold/reference fields enter metrics afterward.
Evidence uses whole passages, at most five and 4,096 cl100k tokens including JSON
headers; overflow/limit skips and delivered coverage are recorded independently of
the ranked IDs. Citations must identify delivered passages. Luna excerpts use the
existing 12,000-byte content bound and at most 1,000 bytes per passage; CE arms
must share the same first-stage configuration and query128/pair384 prefix policy.

Answer schema: `{answer, citations: [passage_id], abstain: bool}`; the dev v2
Luna generator and reranker use effort `none` and 1,024 output tokens, as supported
by the provider registry and T14 envelope. Closed provider output limits have
distinct `answer_output_limit` / `rerank_output_limit` failure codes.
Splitter `qa.sentences/v1` splits on LF or whitespace
following `.`, `!`, or `?`, trims pieces, and retains those containing any Unicode
alphanumeric character. Abbreviations have no special treatment. Exceeding the
frozen 1–4 claim limit fails the answer; no suffix is silently omitted. Every claim
is judged against delivered **cited** passages with the byte-bound G6 selection
(`--selection-receipt`). Invalid verdicts are errors. A bound G6 test report
(`judge.test_report_sha256`, `--judge-report`) supplies the comparison gate;
otherwise judged comparisons remain descriptive. Q is a citation/support surrogate,
not human correctness. Closed-book citation, faithfulness and Q are N/A;
gold-evidence support is not measured in this slice. Lexical F1/ROUGE-L are exploratory.

`g1-dev-answers-v1.json` schedules five arms over all 500 dev questions. It freezes
one-sentence answers so the conservative envelope fits $5: answers
`2500 × (6500×.10 + 256×.50)/1M = $1.945`; judges
`2000 × (10000×.10 + 512×.50)/1M = $2.512`; Luna rerank
`500 × (8000×.10 + 256×.50)/1M = $0.464`; query embeddings $0.01024;
shared preprocessing allowance `300 × 8192 × .02/1M = $0.049152` (includes
ingest and G8 mining); total **$4.980392** (5,800 calls/counts).
V1 is retained unchanged as the failed one-claim/256-token configuration.
`g1-dev-answers-v2.json` uses a new study ID and the same cohort, arms and bound G6
receipt/report, with up to four claims (more remains an error). Answers reserve
`2500 × (6500×.10 + 1024×.50)/1M = $2.905`; judges reserve
`8000 × (6500×.10 + 512×.50)/1M = $7.248`; Luna rerank reserves
`500 × (8000×.10 + 1024×.50)/1M = $0.656`. With unchanged embedding allowances,
the total and enforced cap are **$10.868392**, 11,800 calls/counts. The smaller
judge input ceiling changes only the reservation, preserving the calibrated
model, effort, prompt and schema. Offline full provider-count projections measured
2,163 eligible v1 claims (maximum 2,931 cl100k tokens); a 4,096-token evidence plus
1,024-token claim stress case measured 5,352 (5,888 with G6's 10% headroom).
The 6,500 provider-token ceiling is enforced using official counts before dispatch;
cl100k estimates do not establish an exact cross-tokenizer bound. Preflight alone
never authorizes spending.

Ranking completion fixes ranked IDs and retrieval metrics even when answering or
judging later fails. Retrieval/rerank failures zero ranking and downstream metrics;
composition metrics retain strict non-success. Aggregates and paired comparisons
use per-metric failure flags, with `metric_failed_counts` in each aggregate.
Ranking comparisons use ranking-stage latency. Policy latency excludes judging:
new records measure slot start through final answer validation; old serial records
derive the embedding + rerank + answer stage sum, with provenance disclosed.
Unsound derivations remain unavailable. Policy aggregates and compound-gate p95
use `failure-as-worst-v1`: failed policy slots (including unavailable policy
latency) rank as +infinity among all scheduled slots. The nearest-rank quantile
at ceil(p * n) is observed unless that rank falls in the failures, when it is
`None`; each aggregate quantile reports `failed_count`, and compound comparisons
report `policy_latency_failed_counts` beside candidate/reference p95. Thus p95 remains determined
with up to 5% failures. Judge failures after policy completion preserve observed
policy latency. The separate end-to-end `latency` field retains its existing
censored-lower-bound rule. Uncited answers and undelivered
citations complete with separate `outcome_code` / `outcome_counts`, Q=0 and the
existing citation precision/recall rules (uncited=0; undelivered integrity=0).
Their sentences are not judged. Invalid judge verdicts and provider errors remain
failures. `lexical_query_too_many_lexemes` remains a disclosed strict retrieval
failure, with no fallback; reports include failure-code counts.

All paid stages use the existing claim and usage ledger, stable slot/stage keys,
zero retries/repairs, per-stage and cumulative admission. Stage names are persisted
in operation IDs while the claim retains one invocation binding. Claimed slots
are aborted on recovery; their dispatched calls are never reissued and uncertain
bills remain held. Resume executes remaining scheduled slots. `--ce-artifact DIR`
(repeatable) supplies local SHA-256-pinned artifacts. CE failures are recorded,
without fallback. Private checkpoints retain answers and billing evidence;
exports allowlist IDs, numeric metrics, costs, latency and failure codes only.
Policy cost/latency exclude judging; experimental spend includes judging and
shared preprocessing is disclosed separately. The dev cascade uses Luna first and
Haiku fallback over the same ranking; confidence is an uncalibrated routing signal.
Selective rerank, full-context and caching execution remain deferred.

## G8 local cross-encoder tooling

The isolated `reranker/` project supplies offline, safetensors-only BERT loading,
shared prefix truncation (query 128 tokens, pair 384), a capped CPU training recipe,
and a bounded stdio worker. Artifact identity is the SHA-256 of the exact artifact
manifest bytes; every listed file is verified before loading. The evaluator uses
`CrossEncoderClient` with the expected identity and launches the Python selected by
`scripts/devenv.py`'s reranker routing, avoiding launcher descendants on timeout.
Its equivalent command is `python scripts/devenv.py uv --project reranker run
--offline --frozen python -B -m policyops_reranker.serve --artifact DIR
--expected-sha256 SHA --threads 4`. Requests contain only `query`, `passages`
(`id`, `text`) and `top_k`: at most 50 passages, 20,000 characters per text and
4,200,000 bytes per JSON line. Responses include every score and per-pair token
counts plus the selected ranking; EOF ends the worker. Client deadlines cover
pipe writes and reads and kill/reap the owned process on failure.

`policyops-evals g8 preflight|mine` recomputes the pinned train-only G8 pool and
duplicate exclusions. Internal validation uses a separately hash-ranked 10% of
eligible dialogues, then independently samples at most 600 validation and 6,000
training queries. Mining freezes dense/FTS/RRF candidates with an explicit lexical
mode, excludes every qrel and overlapping positive span, and uses the existing
cached, ledgered embedding job with explicit call/token/USD/time caps and paid
opt-in. Unlabelled negatives may still be relevant. Official validation and dev
queries are never mined. All text, triples, training receipts and weights stay private.

Training uses FP32 CPU, pairwise logistic loss, batch 8, accumulation 4, AdamW
2e-5, seed 20261114 and one epoch (at most 1,500 optimizer steps). Internal
nDCG@10 selects the earliest best checkpoint, including baseline. Nonfinite
loss/gradients or a final nDCG drop greater than 0.02 from baseline permit exactly
one fresh 1e-5 retry; attempts and failures remain recorded. No quality or CPU
latency improvement is claimed by these tools. `scripts/g8_benchmark.py` measures
cold loading and warmed synthetic top-20 latency, threads, peak process RAM,
nearest-rank p50/p95 and failures. The pinned base model card is Apache-2.0;
its MS MARCO lineage has non-commercial research terms. MultiDoc2Dial is treated
as CC BY 3.0; trained artifacts require the same provenance disclosures.


## G1 sealed deterministic design

`g1-test-retrieval-v1.json` schedules the manifest's official-validation retrieval
cohort: 300 complete dialogues, 1,940 questions, one repetition and history-four
queries. `g1-test-answers-v1.json` schedules the separate answers cohort: 200
complete dialogues and 1,302 questions. Both use the frozen MultiDoc2Dial
manifest and its human grounding labels. No sealed materialization is needed to
validate, select or preflight. Public benchmark contamination cannot be excluded.

The family declares four claims at familywise alpha .05, Bonferroni alpha .0125
per claim. Claim 2 is withdrawn, with no alpha reallocation or replacement by a
cascade comparison. The remaining one-sided claims are:

| Claim | Candidate minus reference | Deterministic decision |
|---|---|---|
| 1 | RRF(BM25, dense) minus R1-selected single retriever | R@5 superiority on retrieval cohort |
| 3 | R2-selected rerank of RRF pool minus no-rerank RRF | Gold-citation superiority on answers cohort |
| 4 | Base CE minus Luna rerank, same RRF pool and generator | Gold-citation non-inferiority above -0.05, mean policy-cost ratio upper bound <= .80, candidate policy p95 <= 1.5 times reference and <= 30 seconds |

Gold citation means a validated policy answer cites at least one human-gold
passage; it does not prove correctness or entailment. Failed and missing policy
answers are strict non-successes. Downstream judge failures preserve completed
deterministic policy metrics. The existing G6 gate controls judged claim support,
faithfulness and Q: these are descriptive, never confirmatory here. Closed book
is descriptive; its citations, faithfulness and Q remain N/A. No dense answer,
trained reranker or cascade arm is added to the sealed schedule.

Analysis uses the registered
`sha256-whole-dialogue-question-weighted-ratio-v1` paired bootstrap: 10,000
replicates, seed 20261115 fixed before registration, whole dialogues resampled
with question-weighted ratios. Report the ordinary two-sided 95% interval as
well as the one-sided Bonferroni lower bound. Claim 4 is an intersection-union
compound decision; its cost upper bound uses the same alpha and paired dialogue
resampling. Policy p95 uses `failure-as-worst-v1`: failed or unavailable policy
latencies rank as infinity. An unavailable required p95 prevents adoption.
Policy cost excludes the descriptive judge; experimental spend includes it.

### Dev selection receipts and registration

Run `policyops-evals qa-study select` offline with `POLICYOPS_TEMP_DIR` pointing
to the private evidence root. It reads only the two digest-pinned development
reports, not sealed questions or outputs. R1 maximizes history R@5 over dense
and BM25, ties in that order. R2 maximizes gold-citation rate over base CE and
Luna rerank, ties in that order. Reports must match their frozen dev study
specifications, with all 500 scheduled questions recorded, integral full binary
rate denominators, integrity and settled accounting. Recorded failures remain
in that denominator. Missing, altered or incomplete reports fail closed.

Receipts are canonical JSON in `benchmarks/qa-selections/<sha256>.json` below
the private root. Each binds its rule, source report relative path and path
digest, report byte digest, per-arm exact fractions, tie order and winner's
frozen arm. Both receipt hashes enter `development_selection_receipts`; the
selected retriever and reranked arm carry `selection_receipt_sha256` too.
These fields also support selected `PolicyArm` contracts. Preflight and run
regenerate and compare both receipts and all tested dev arm bindings before
credentials or claims. Only the Haiku input envelope changes; its selected
model, effort, prompt, output schema and output budget remain frozen.

Use `qa-study validate|digest|preflight --study <config>` offline first. The
coordinator performs publication gates and commits the test configurations
before calculating and filling their registration digests, then invokes
`qa-study preflight --study <config> --register` with the evaluation database.
Registration requires a clean normalized source diff (only the top-level
registration-digest fill is normalized), immutable binding and prior database
timestamp. The builder does not register. Paid execution remains an explicit
coordinator opt-in, under per-stage and cumulative caps, zero provider retries
and repairs, no expensive fallback, and worst-case held liability on uncertainty.
The two study caps sum to $26.10; preflight assumes every scheduled embedding,
answer, rerank and up to four judges per grounded answer, with no cache discount.
Shared preprocessing is conservatively counted in each study.

### Sealed infrastructure guards and headroom

Haiku judge input is bounded at 8,192 tokens, with unchanged 512-token output.
This is 1,676 tokens (25.7%) above the largest observed 6,516-token count, and
26% above the prior 6,500 envelope. The answer design still delivers at most
five whole passages within 4,096 cl100k evidence tokens, plus bounded query,
claim, schema and prompt wrappers. cl100k and the official Haiku counter differ;
the extra allowance is a conservative operational reserve, not proof of a
universal tokenizer ratio. Official counting still rejects over-bound requests.
The application's unchanged admission rule adds 10% (minimum 256 tokens) to the
official count: 6,516 requires 7,168, leaving another 1,024 tokens in the new
envelope. This also explains why raw counts below 6,500 could be rejected.
The Luna answer envelope and prompt are unchanged. No evidence trimming,
provider retry or silent arm change repairs a rejected sealed slot.

Before each CE use, a synthetic one-pair scoring request checks the worker's
pipes, model identity and response contract under the slot's remaining deadline.
A failed health check or score kills and reaps the worker, then replaces it once
and repeats health and score. Unconfirmed cleanup refuses replacement. Probes
are local and carry no benchmark text. They count in policy latency. Successful
workers are reused. Artifact, tokenizer, pool and truncation bindings remain
identical to the tested dev CE; there is no trained-model substitution.

Both configs declare N=3 consecutive CE-use failures. Other arms do not reset
this streak; only a successful CE use does. Three tolerates two transient
incidents while limiting damage to three CE slots, rather than an entire outage.
A separate N=3 streak per provider model/embedding channel counts provider calls
that return no result, including count/transport/deadline failures. This broader
cheap check also stops repeated admission or configuration failures. Successfully
returned invalid structured outputs remain scoring failures and do not count as
transport incidents. Other channels and cache hits do not reset a channel's
streak. Unknown billing stops immediately under the existing ledger guard.

At threshold the triggering slot is finalized as failed, an incident receipt is
sealed with the private invocation inventory, and the run stops before claiming
another slot. CLI exits nonzero for the incomplete schedule. Explicit `--resume`
after infrastructure recovery starts fresh invocation-local streaks and runs only
still-scheduled slots. **Finalized successes and failures are never reissued;
slots already failed stay failed.** Abandoned running claims retain the existing
abort/no-reissue semantics. This is an operational stop, not an exclusion rule:
all scheduled questions remain in analysis and no failure is selectively removed.
