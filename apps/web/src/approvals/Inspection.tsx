import { Link } from "react-router";
import type { ReactNode } from "react";
import type { Detail } from "./api";

// Only the closed, bounded decoded action/effect DTOs enter this renderer. Money is never divided or rounded.
function Value({ value }: { value: unknown }): ReactNode {
  if (value === null) return <span>Not recorded</span>;
  if (Array.isArray(value)) return <ol className="exact-values">{value.map((v: unknown, i) => <li key={i}><Value value={v} /></li>)}</ol>;
  if (typeof value === "object") {
    const r = value as Record<string, unknown>;
    if ("amount_minor" in r && "currency" in r) return <span>{String(r["amount_minor"])} minor units · {String(r["currency"])}</span>;
    return <dl className="exact-fields">{Object.entries(r).map(([k, v]) => <div key={k}><dt>{k}</dt><dd><Value value={v} /></dd></div>)}</dl>;
  }
  return <span className="message-text">{typeof value === "string" || typeof value === "number" || typeof value === "boolean" ? String(value) : "Unavailable"}</span>;
}
export function ActionArguments({ detail }: { detail: Detail }) {
  return <section className="inspection-panel" aria-label="Action arguments"><h2>Action arguments</h2><Value value={detail.proposal.action} /></section>;
}
export function EffectDiff({ detail }: { detail: Detail }) {
  const effect = detail.proposal.effect;
  const pairs: [string, unknown, unknown][] = "address_before" in effect ? [["Address", effect.address_before, effect.address_after]]
    : "status_before" in effect ? [["Status", effect.status_before, effect.status_after]] : [];
  if (effect.kind === "modify_pending_order_payment") pairs.push(["Payment method", effect.from_payment_method_id, effect.to_payment_method_id]);
  if (effect.kind === "modify_pending_order_items" || effect.kind === "exchange_delivered_order_items") {
    effect.changes.forEach((change, i) => {
      pairs.push([`Item ${String(i + 1)}`, change.item_id, change.new_item_id], [`Item ${String(i + 1)} price`, change.price_before, change.price_after]);
    });
  }
  return <section className="inspection-panel" aria-label="Effect diff"><h2>Expected effect</h2>
    {pairs.length > 0 ? <div className="table-wrap"><table className="table effect-table"><caption>Recorded before and after values</caption><thead><tr><th>Field</th><th>Before</th><th>After</th></tr></thead>
      <tbody>{pairs.map(([label, before, after], i) => <tr key={i}><th scope="row">{label}</th><td><Value value={before} /></td><td><Value value={after} /></td></tr>)}</tbody></table></div> : null}
    <p className="muted">Exact sealed effect follows. Only explicitly recorded before values are shown.</p><Value value={effect} />
  </section>;
}
export function PresentationText({ detail: d }: { detail: Detail }) {
  return <section className="inspection-panel" aria-label="Presentation text"><p className="eyebrow">Verbatim server presentation</p><h2>Terms presented to the customer</h2>
    <p className="message-text">{d.proposal.presentation.text}</p><p className="wrap-anywhere muted">Text SHA-256 <code>{d.proposal.presentation.text_sha256}</code></p>
    <p className="muted">Presentation message: {d.presentation?.message_id ?? "Not recorded"}</p></section>;
}
export function ConsentPanel({ detail: d }: { detail: Detail }) {
  const c = d.consent;
  return <section className="inspection-panel consent-panel" aria-label="Customer consent"><p className="eyebrow">Customer authorization</p><h2>Customer consent</h2>
    <p>Customer consent is separate from staff approval. Staff approval does not supply customer consent.</p>
    {c === null ? <p className="notice">No current customer confirmation recorded. Approve and reject are unavailable.</p> : <>
      <p className="message-text">{c.customer_message_text}</p><dl className="evidence-metadata">
        <div><dt>Consent ID</dt><dd>{c.consent_id}</dd></div><div><dt>Source</dt><dd>{c.message_source === "operator_entered_customer" ? "Entered by staff (simulation)" : "Simulated customer"}</dd></div>
        <div><dt>Entered by</dt><dd>{c.entered_by ?? "No staff actor"}</dd></div><div><dt>Customer message reference</dt><dd>{c.customer_message_id} · sequence {String(c.customer_message_sequence)}</dd></div>
        <div><dt>Basis</dt><dd>{c.basis}</dd></div><div><dt>Confirmed (UTC)</dt><dd>{c.confirmed_at}</dd></div><div><dt>Consent expires (UTC)</dt><dd>{c.expires_at}</dd></div>
      </dl></>}
  </section>;
}
export function PolicyBinding({ detail: { proposal: p } }: { detail: Detail }) {
  return <section className="inspection-panel" aria-label="Policy binding"><h2>Policy & resource binding</h2><dl className="evidence-metadata">
    <div><dt>Policy</dt><dd>{p.policy.path}</dd></div><div><dt>Source commit</dt><dd><code>{p.policy.source_commit}</code></dd></div>
    <div><dt>Policy SHA-256</dt><dd><code>{p.policy.sha256}</code></dd></div><div><dt>Rules</dt><dd>{p.rule_ids.join(", ")}</dd></div></dl>
    <h3>Sealed resource versions</h3><ul>{p.resource_versions.map((r) => <li key={`${r.kind}:${r.resource_id}`}>{r.kind} {r.resource_id} · version {String(r.version)}</li>)}</ul>
    <h3>Proposal evidence</h3>{p.evidence.length === 0 ? <p>No cited evidence recorded.</p> : <ul>{p.evidence.map((e) => <li key={e.evidence_id}>
      <Link to={`/cases/${p.scope.case_id}/runs/${p.scope.run_id}/evidence/${e.evidence_id}`} state={{ versionId: e.document_version_id, versionDigest: e.content_sha256 }}>
        Inspect source {e.evidence_id.slice(0, 8)}</Link><p className="wrap-anywhere muted">Version {e.document_version_id} · SHA-256 {e.content_sha256}</p></li>)}</ul>}
  </section>;
}
