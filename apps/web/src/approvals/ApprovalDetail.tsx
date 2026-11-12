import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "react-aria-components/Button";
import { Link } from "react-router";
import type { ApiError, MeOut } from "../api/client";
import { useScopedLoader } from "../cases/common";
import { RunOutcomeCard } from "../runs/RunOutcomeCard";
import { useRunObservation } from "../runs/useRunObservation";
import { useWriteLedger } from "../session/SessionProvider";
import { ErrorPanel, Status } from "../ui/feedback";
import { getDetail, type Detail } from "./api";
import { DecisionForm } from "./DecisionForm";
import { ExpiryCountdown, useExpiry } from "./ExpiryCountdown";
import { ActionArguments, ConsentPanel, EffectDiff, PolicyBinding, PresentationText } from "./Inspection";
import { useVisibleRefresh } from "./refresh";

const fingerprint = (d: Detail): string => JSON.stringify({ ...d, server_time: null });
export function ApprovalDetail({ id, version, me }: { id: string; version: number; me: MeOut }) {
  const load = useScopedLoader(); const ledger = useWriteLedger();
  const [detail, setDetail] = useState<{ value: Detail; sampledAt: number } | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [changed, setChanged] = useState(false);
  const previous = useRef<string | null>(null);
  const restoreFocus = useRef(false);
  const refreshButton = useRef<HTMLButtonElement>(null);
  const reload = useCallback(() => {
    load(`proposal:${id}:${String(version)}`, (options) => getDetail(id, version, options), (next) => {
      const revision = fingerprint(next);
      if (previous.current !== null && previous.current !== revision) {
        setChanged(true);
        restoreFocus.current = document.activeElement?.closest(".decision-panel, .decision-confirmation") != null;
      }
      previous.current = revision;
      if (next.decision !== null) ledger.confirmDecision(next.decision);
      setDetail({ value: next, sampledAt: performance.now() }); setError(null);
    }, (failure) => { setDetail(null); setError(failure); });
  }, [load, ledger, id, version]);
  useEffect(reload, [reload]);
  useEffect(() => {
    if (restoreFocus.current) { refreshButton.current?.focus(); restoreFocus.current = false; }
  }, [detail]);
  useVisibleRefresh(reload);
  useEffect(() => ledger.onSettled((entry) => {
    if (entry.kind === "decision" && entry.proposalId === id && entry.proposalVersion === version) reload();
  }), [ledger, id, version, reload]);
  return <><div className="section-bar"><Link to="/approvals">← Approval inbox</Link><Button ref={refreshButton} className="button" onPress={reload}>Refresh exact proposal</Button></div>
    {changed ? <p className="notice" role="alert">Canonical proposal details changed. Review the current version and decision state below.</p> : null}
    {error !== null ? <ErrorPanel error={error} onRetry={reload} /> : detail === null ? <Status label="Loading exact proposal…" />
      : <Review detail={detail.value} sampledAt={detail.sampledAt} me={me} reload={reload} />}</>;
}
function Review({ detail: d, sampledAt, me, reload }: { detail: Detail; sampledAt: number; me: MeOut; reload: () => void }) {
  const p = d.proposal;
  const [observationRevision, setObservationRevision] = useState(0);
  const observation = useRunObservation(p.scope.case_id, p.scope.run_id, observationRevision);
  const reloadOutcome = useCallback(() => { setObservationRevision((v) => v + 1); reload(); }, [reload]);
  const expiry = useExpiry(d, sampledAt, reload);
  const marker = observation.activity?.events.filter((e) => "payload" in e && ["approval.decided", "consent.recorded", "consent.clarification_requested", "proposal.presented"].includes(e.payload.type)).at(-1)?.sequence;
  useEffect(() => { if (marker !== undefined) reload(); }, [marker, reload]);
  // Server time refreshes do not invalidate a review; any canonical content change destroys its draft/confirmation.
  const revision = fingerprint(d);
  return <div className="approval-detail"><section className="approval-identity"><p className="eyebrow">Exact sealed proposal</p><h2>{p.action.tool.replaceAll("_", " ")}</h2>
    <p>Version <strong>{String(p.proposal_version)}</strong> · {d.state.replaceAll("_", " ")}</p><p className="wrap-anywhere">Action digest <code>{p.action_digest}</code></p>
    <p className="wrap-anywhere muted">Proposal {p.proposal_id} · customer {p.customer_user_id}</p><p className="message-text">{p.rationale}</p>
    <Link to={`/cases/${p.scope.case_id}/runs/${p.scope.run_id}`}>Open case investigation</Link></section>
    <ExpiryCountdown detail={d} {...expiry} />
    {observation.error !== null ? <ErrorPanel error={observation.error} onRetry={reloadOutcome} /> : observation.activity !== null
      ? <RunOutcomeCard activity={observation.activity} proposalId={p.proposal_id} version={p.proposal_version} /> : <Status label="Loading factual run outcome…" />}
    <p className="muted">Reads refresh every 15 seconds while visible · outcome observation {observation.phase}.</p>
    <div className="approval-grid"><div className="approval-column"><ActionArguments detail={d} /><EffectDiff detail={d} /><PresentationText detail={d} /></div>
      <div className="approval-column"><ConsentPanel detail={d} /><PolicyBinding detail={d} />
        <DecisionForm key={revision} detail={d} me={me} remaining={expiry.remaining} reload={reload} /></div></div>
  </div>;
}
