This proposed pilot is for a fictional online retailer in the τ²-bench retail simulator.

# Supervised retail support pilot

## Context

PolicyOps lets a support operator investigate a case and review a proposed action
alongside its policy citations and the relevant order evidence. The customer gives
simulated consent to the exact terms. A separate staff reviewer approves the sealed
proposal, and the execution service rechecks authority before dispatching to the
retail simulator. The seeded demo exercises this review and execution path from an
existing proposal, using simulated consent entered by staff.
[Workflow](../README.md#workflow) · [Review contracts](architecture.md#proposal-review)

### Pilot decision

Can staff use cited proposals in a supervised simulator without losing control of
which order changes?

A correct proposal identifies the action and its target, uses supported arguments,
and gives the reviewer evidence to check the decision. A successful simulator write
also requires consent, approval, a dispatch-time authority check, and an outcome
the team can reconcile against simulator state.

## Scope

- Cancellation, return, and default-address changes on fictional retail fixtures,
  plus handoff to a staffed queue when policy requires it.
- Ambiguous multi-order requests are abstain-only. Record that the target is
  ambiguous and leave it with staff for follow-up. The agent may propose a write
  in a subsequent investigation once the customer identifies a unique target.
- Refunds, payments, model-written customer replies, real customer data, and live
  commerce are out of scope. So are high availability, point-in-time recovery,
  and a service-level agreement.
- Use one model for model-driven simulator runs. The scenario evidence covers
  `gpt-6-luna` at low effort. The Bedrock adapter is offline-verified only.
  [Scenario conditions](evaluation.md#design-and-gates) · [Bedrock adapter](evaluation.md#bedrock-adapter)

## Scorecard

The scenario rows use the paired held-out comparison of the revised tool-contract
profile with the baseline, using `gpt-6-luna` at low effort in both arms. The grader
uses recorded responses before gateway validation. The authorization, recovery,
and operations rows use separate checks at the stages named in the table.

| Measure | Verified here (with conditions) | Proposed pilot measurement | Decision if the check fails |
|---|---|---|---|
| Proposal quality | Exact first proposals on held-out write-positive cases were **171/192 vs 3/192** before the gateway. Exactness requires the right tool, target, and arguments after the required reads. [Held-out result](evaluation.md#held-out-result) | **Proposed.** Score the first attempt against the fixture label, retaining every scheduled case. Review errors by workflow. | Keep the affected workflow proposal-only and replay it after correction. |
| Ambiguity and abstention | The revised profile attempted unsafe writes in **2/16** held-out ambiguous cases. Across all held-out negatives, unsafe attempts were **2/48 vs 0/48**. The upper bound of the paired confidence interval was **+0.104**. The revised profile stopped at the invalid-reply cap on **21/48** negatives. [Held-out safety](evaluation.md#held-out-result) | **Proposed.** Track attempts, clean abstentions, and stops before decision separately. Expand the labelled ambiguous stratum. | Pause expansion on any ambiguous write proposal. Keep ambiguous requests abstain-only. |
| Handoff | Correct held-out handoffs were **7/16 vs 9/16** before the gateway. The grade requires a valid transfer and the required follow-up message. [Held-out handoff](evaluation.md#held-out-result) | **Proposed.** Replay handoff cases with their existing labels and check that staff receive the cases with enough context to continue. | Route handoffs directly to staff until the workflow passes. |
| Authorization | In the final dispatch study, the deterministic gateway produced effects on **0/48** attack fixtures and falsely blocked **0/12** valid controls. Prompt-only `gpt-6-luna` at low effort produced **2/48** and **6/12**, respectively. The separate deterministic authorization matrix passed **434/434** synthetic rows, including admission-only checks. [Dispatch study](evaluation.md#e05-gateway-versus-prompt-only) · [Matrix](evaluation.md#e04-operation-ledger-versus-naive-retry) | **Proposed.** Replay prohibited requests and valid controls. Compare dispatch decisions with simulator effects and count false blocks separately. | Stop dispatch on a prohibited effect. Investigate false blocks before advancing the affected workflow. |
| Recovery | In **100** paired fault cases with no model in the recovery loop, the ledger completed **83/100** once with a receipt and fenced **17/100** without effect. Both arms had **0/100** duplicates. Naive retry reported failure for **20/20** writes that committed and lost their response in that fault stratum. [Recovery study](evaluation.md#e04-operation-ledger-versus-naive-retry) | **Proposed.** Reconcile each operation ID across ledger, receipt, and simulator state. Record completed, fenced, unresolved, and duplicate outcomes. | Stop dispatch for a duplicate effect or unexplained receipt mismatch. Hold expansion while any outcome is unresolved. |
| Operations | The seeded single-host deployment passed **28/28** live verifier checks, including HTTPS and Dex login. It has no SLA and runs without model provider keys. [Deployment evidence](../README.md#live-demo--deploy) | **Proposed.** Verify sign-in, service health, audit visibility, and simulated write reconciliation in the pilot environment. | Hold at the current phase until the failed check passes. |
| Latency and cost | The local observability profile uses scripted provider replies and fixture token counts. Configured prices show how the accounting behaves on that fixture. [Local observability](../README.md#local-observability-profile) | **Proposed.** Establish a phase-0 baseline. Time proposal generation and dispatch separately from staff review. Record settled cost and held liability for any approved model run. | Investigate unexpected latency or spend and keep limits in force. The pilot commits to no SLO. |
| Reviewer rejection rate on ambiguous proposals | The scenario evaluation measured attempts before the gateway. Reviewer rejection of ambiguous proposals has never been measured. [Evaluation boundary](evaluation.md#held-out-result) | **Proposed.** In shadow review, present fixture proposals with ambiguous targets. Report how many reviewers reject for ambiguity out of all labelled ambiguous proposals shown. Record missed or undecided reviews. | Hold simulator dispatch for the affected workflow if reviewers miss an ambiguous target. |

Set acceptance criteria for proposal quality, handoff, and reviewer catch rate
before replay. Keep the labelled denominators and report missing outcomes. Treat
the deployment verifier as evidence for the exercised single-host profile and
local telemetry as evidence for the scripted workflow.

## Integration points

| Integration | Pilot requirement |
|---|---|
| OIDC identity provider | Map operators and reviewers to the tenant and their staff roles. The integration has been verified with Dex only. Verify sign-in and role mapping in the pilot environment. [Authentication](authentication.md) |
| Order API adapter | Put order reads and simulated writes behind the retail port. The adapter must accept a stable idempotency key and support receipt lookup by operation ID. Without the key, the ledger cannot rely on the remote service to deduplicate retries. Without lookup, it may be unable to reconcile a lost response. Fence unresolved writes and hold write rollout if either capability is missing. [Execution and reconciliation](architecture.md#approved-execution-and-reconciliation) |
| Policy corpus ingestion | Load versioned policy into the pilot workspace. Preserve source identity and the cited policy text so reviewers can inspect the rule that supports a proposed action. [Architecture](architecture.md) |
| Model provider | Keep provider keys server-side. Apply the configured call, token, time, and cost caps, including reservations for unsettled usage. The public seeded demo has no provider keys. [Budget controls](architecture.md#model-configuration-and-usage-budgets) |
| OTLP | Use the local profile to inspect traces and metrics for investigation, review, and simulated dispatch. Only the local observability profile has been exercised here. [Local setup](operations.md#local-observability-profile) |

## Data and security requirements

- Use fictional retail fixtures derived from public data with labels known by
  construction. Keep case records, evidence, event streams, and operation
  receipts within their workspace. Retain enough evidence for review and
  reconciliation through the agreed pilot retention window.
- Use tenant row-level security under the actual runtime role. Keep migration
  and runtime roles separate and verify foreign-tenant denial as the runtime
  role. Include an authorized control so a broken integration cannot pass by
  denying every request. [Database roles](database.md#roles)
- Bind customer consent and staff approval separately to the exact sealed
  proposal. Show staff the target, arguments, citations, and consent state.
  Any change to the sealed terms requires a new decision. Recheck authority
  at dispatch and keep evidence of the outcome. [Review and dispatch](architecture.md#proposal-review)
- Keep provider credentials and sensitive payloads out of case evidence and
  telemetry. Review the security boundary and its documented exclusions before
  advancing to simulator dispatch. [Residual risks](security.md#residual-risks-and-explicit-exclusions)

## Proposed rollout

The support team reviews the target, arguments, and citations and records reasons
for rejection. The integration team checks identity, policy ingestion, and the
retail adapter before enabling dispatch. The pilot lead uses the scorecard to
decide whether each workflow can advance.

### Phase 0 — Offline replay

Replay labelled fixtures for exact proposals, abstention, handoff, authorization,
and recovery. Include ambiguous orders, unique orders with similar selectors, and
requests missing required facts. Establish the baseline for measurement, confirm
staff can inspect citations and receipts, and agree on the criteria for shadow
review before looking at results. Use fresh development fixtures for new trials.

### Phase 1 — Shadow review

Have staff review cited proposals with simulator dispatch disabled. Record target
corrections, rejection reasons, undecided cases, and review time. Use labelled
ambiguous proposals in shadow exercises to measure reviewer catch rate while
keeping those cases ineligible for any write. Investigate disagreement against
the order facts and policy before advancing.

Include shadow cases where the proposed action is allowed by policy but the
customer's description fits multiple orders. Check that reviewers treat target
ambiguity as its own rejection reason. Check routing separately on labelled
handoff cases so a missed transfer has a visible outcome.

### Phase 2 — Human-approved simulator writes

Start with default-address changes. Add cancellation and then return when each
workflow meets the agreed criteria in shadow review and passes the dispatch and
recovery checks. Require simulated consent and separate staff approval for each
write. Keep ambiguous requests abstain-only throughout this phase.

## Risks and exit decision

- The observed first-match behavior persists in the held-out evidence. The RCA
  proposes a deterministic order-selection check and review context for other
  matches. Until there is evidence for those controls, keep the ambiguity
  boundary explicit in fixture labels and staff review. [Ambiguous order selection RCA](rca-ambiguous-order-selection.md)
- A stop before decision lowers the observed attempt count without showing that
  the model recognized ambiguity. Review cap stops separately from deliberate
  abstentions and keep staff handoff available when the model cannot proceed.
- The measurements cover one model alias and finite fixture sets. Single-host
  deployment and fixture-based telemetry limit what the pilot can establish
  about availability, throughput, and spend.

### Go or hold

Advance only when the agreed scorecard checks pass, the prohibited and valid
controls behave as expected, and each simulated write has an explained outcome
in simulator state and the ledger. Verify that staff can explain a rejected
proposal, a fence without effect, and how an unresolved receipt is handled.
Keep the affected workflow in shadow review if those checks fail.

### Stop and recover

On an unauthorized effect, duplicate effect, or unexplained receipt mismatch,
stop dispatch, retain the case and operation evidence, and return to proposal-only
review. Reconcile in-flight operations by stable operation ID. Resume simulator
dispatch only after the failure is explained and the affected checks pass again.
