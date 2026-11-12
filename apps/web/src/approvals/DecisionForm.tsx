import { useRef, useState } from "react";
import { Button } from "react-aria-components/Button";
import { Dialog, Heading } from "react-aria-components/Dialog";
import { Modal, ModalOverlay } from "react-aria-components/Modal";
import { TextField } from "react-aria-components/TextField";
import { TextArea } from "react-aria-components/TextArea";
import { Label } from "react-aria-components/Label";
import { expectedContextOf, sameContext, type MeOut } from "../api/client";
import { isUnresolved } from "../api/writes";
import { CAPACITY_NOTICE } from "../cases/common";
import { capabilities } from "../session/permissions";
import { useWriteEntries, useWriteLedger } from "../session/SessionProvider";
import { Reference } from "../ui/feedback";
import { validReason, type DecisionPayload, type Detail } from "./api";

export function DecisionForm({ detail: d, me, remaining, reload }: { detail: Detail; me: MeOut; remaining: () => number; reload: () => void }) {
  const ledger = useWriteLedger(); const entries = useWriteEntries();
  const [reason, setReason] = useState("");
  const [frozen, setFrozen] = useState<Readonly<DecisionPayload> | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const frozenRef = useRef<Readonly<DecisionPayload> | null>(null);
  const p = d.proposal;
  const entry = entries.find((e) => e.kind === "decision" && e.proposalId === p.proposal_id
    && e.proposalVersion === p.proposal_version && sameContext(e.context, expectedContextOf(me)));
  const locked = entry !== undefined && (isUnresolved(entry) || entry.phase === "applied");
  const eligible = capabilities(me.roles).has("decideProposals") && d.state === "awaiting_decision" && d.decision === null
    && d.presentation !== null && d.consent !== null && Date.parse(d.consent.confirmed_at) <= Date.parse(d.server_time) && remaining() > 0;
  const close = (): void => { frozenRef.current = null; setFrozen(null); };
  const prepare = (decision: DecisionPayload["decision"]): void => {
    if (!eligible || locked || !validReason(reason)) { setNotice("Enter a reason of 1–500 characters, without control or incomplete characters."); return; }
    const payload = Object.freeze({ proposal_version: p.proposal_version, action_digest: p.action_digest, decision, reason });
    frozenRef.current = payload; setFrozen(payload); setNotice(null);
  };
  const confirm = (): void => {
    const payload = frozenRef.current;
    // Consume synchronously, before React commits and before any await. The shared ledger is the second guard.
    if (payload === null || d.consent === null || !eligible || remaining() === 0 || locked) { close(); return; }
    frozenRef.current = null; setFrozen(null);
    const result = ledger.begin({ kind: "decision", caseId: p.scope.case_id, runId: p.scope.run_id, ifMatch: null, payload: null,
      decision: { proposalId: p.proposal_id, payload, consentId: d.consent.consent_id } });
    if ("refused" in result) setNotice(result.refused === "capacity" ? CAPACITY_NOTICE : "This proposal already has a pending decision in this tab.");
  };
  const failure = entry?.failure;
  const recorded = d.decision ?? (entry?.result?.kind === "decision" ? entry.result.value : null);
  return <section className="inspection-panel decision-panel" aria-label="Staff approval"><p className="eyebrow">Staff review</p><h2>Staff approval decision</h2>
    <p>Record a decision on this exact version. Approval is followed by execution checks; it does not establish a business effect.</p>
    {recorded !== null ? <div role="status"><h3>{recorded.principal_id !== me.principal_id ? "Already decided by another reviewer"
      : recorded.decision === "approve" ? "Approval recorded — execution pending" : "Rejection recorded"}</h3>
      <p>{recorded.decision === "approve" ? "Approval" : "Rejection"} · reviewer {recorded.principal_id}</p><p className="message-text">{recorded.reason}</p></div> : null}
    {entry?.phase === "inFlight" ? <p role="status">Recording decision…</p> : null}
    {entry?.phase === "unknown" ? <div className="notice" role="alert"><h3>Decision unconfirmed</h3>
      <p>{entry.attempts > 1 && failure?.kind === "http" ? "This retry was refused. The earlier decision is still unconfirmed." : "No reliable answer arrived. The decision may have been recorded. It has not been sent again."}</p>
      {entry.decision != null ? <div><p>Frozen {entry.decision.payload.decision} · version {String(entry.decision.payload.proposal_version)}</p>
        <p className="wrap-anywhere"><code>{entry.decision.payload.action_digest}</code></p><p className="message-text">{entry.decision.payload.reason}</p></div> : null}
      {ledger.canRetry(entry) && recorded === null && capabilities(me.roles).has("decideProposals")
        ? <Button className="button" onPress={() => { ledger.retry(entry.id); }}>Retry the same decision</Button>
        : <p>{entry.decision == null ? "The frozen payload was discarded on a session change."
          : recorded !== null ? "The canonical decision prevents further submission." : "The reviewer role is required to retry."} Reload canonical detail to check the outcome.</p>}</div> : null}
    {failure !== null && failure !== undefined ? <div className="panel panel-error" role="alert"><h3>{entry?.phase === "unknown" ? "This attempt was refused or unconfirmed" : "Decision refused"}</h3>
      <p>{failure.status === 410 || failure.code === "expired" ? "The review expired. " : ""}{failure.detail ?? "No reliable response was available."}</p>
      {failure.ruleId !== null ? <p>Rule: <code>{failure.ruleId}</code></p> : null}<Reference id={failure.correlationId} />
      <Button className="button" onPress={reload}>Reload canonical detail</Button></div> : null}
    {!capabilities(me.roles).has("decideProposals") ? <p className="notice">Inspection only. The reviewer role is required to decide.</p> : recorded === null ? <>
      {!eligible ? <p className="notice">New decisions unavailable: {remaining() === 0 ? "review expired" : d.state.replaceAll("_", " ")}. Current customer consent is required for approve and reject.</p> : null}
      <TextField className="text-field" value={reason} onChange={setReason} isDisabled={locked || !eligible || frozen !== null}>
        <Label>Decision reason</Label><TextArea className="textarea" maxLength={1000} /></TextField>
      <p className="muted">Required · 1–500 Unicode characters. The same reason is retained for an explicit retry.</p>
      <div className="actions"><Button className="button button-primary" onPress={() => { prepare("approve"); }} isDisabled={locked || !eligible}>Approve…</Button>
        <Button className="button" onPress={() => { prepare("reject"); }} isDisabled={locked || !eligible}>Reject…</Button></div></> : null}
    {notice !== null ? <p role="alert">{notice}</p> : null}
    <ModalOverlay className="modal-overlay" isOpen={frozen !== null && eligible} onOpenChange={(open) => { if (!open) close(); }} isDismissable>
      <Modal className="modal"><Dialog className="dialog decision-confirmation" role="alertdialog"><Heading slot="title">Confirm exact staff decision</Heading>
        <p>{frozen?.decision === "approve" ? "Approve" : "Reject"} proposal {p.proposal_id}</p><p>Version {String(frozen?.proposal_version)}</p>
        <p className="wrap-anywhere">Action digest <code>{frozen?.action_digest}</code></p><p className="message-text">{frozen?.reason}</p>
        <p>Customer consent remains a separate server-checked requirement.</p><div className="actions"><Button className="button" autoFocus onPress={close}>Back to review</Button>
          <Button className="button button-primary" onPress={confirm}>Confirm {frozen?.decision === "approve" ? "approval" : "rejection"}</Button></div>
      </Dialog></Modal>
    </ModalOverlay>
  </section>;
}
