# Evaluation and Core evidence

The retail model comparison, authorization fixtures and recovery drills answer different
questions. The registered holdout does **not** establish Luna's non-inferiority to Haiku;
the deterministic safety suites passed their specified acceptance checks. All execution
reported here was local. Hosted CI has not run, and no production or real-customer outcome
is claimed. Raw trajectories, database dumps and execution bundles are not published.

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

Source: `f54e046` plus the digest fill, committed as `01a2196`. Registration SHA-256:
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
