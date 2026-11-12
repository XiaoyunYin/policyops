import { getBoundJson, runView, type BoundRequestOptions } from "../api/client";
import { bad, digest, integer, parseCitation, parseEvidence, parseSnapshot, record, scope, scopeOf, uuid,
  type CitationPage, type EvidenceView, type RunPage, type RunSnapshot } from "./contracts";

export function cursorOf(value: unknown): string | null {
  if (value !== null && (typeof value !== "string" || value.length === 0 || value.length > 400)) bad();
  return value;
}
export async function listRuns(caseId: string, cursor: string | null, options: BoundRequestOptions): Promise<RunPage> {
  if (!uuid(caseId)) bad();
  const query = new URLSearchParams({ limit: "25" });
  if (cursor !== null) query.set("cursor", cursor);
  const p = record(await getBoundJson(`/api/v1/cases/${caseId}/runs?${query.toString()}`, options));
  if (!Array.isArray(p["items"]) || p["items"].length > 25) bad();
  const items = p["items"].map((v) => runView(v, caseId));
  if (new Set(items.map((v) => v.run_id)).size !== items.length) bad();
  return { items, next_cursor: cursorOf(p["next_cursor"]) };
}
export async function getSnapshot(caseId: string, runId: string, options: BoundRequestOptions): Promise<RunSnapshot> {
  const s = scope(options.context, caseId, runId);
  return parseSnapshot(await getBoundJson(`/api/v1/runs/${runId}/snapshot?tail=100`, options), s);
}
export async function listCitations(caseId: string, runId: string, cursor: string | null,
                                    options: BoundRequestOptions): Promise<CitationPage> {
  const s = scope(options.context, caseId, runId);
  const query = new URLSearchParams({ limit: "25" });
  if (cursor !== null) query.set("cursor", cursor);
  const p = record(await getBoundJson(`/api/v1/runs/${runId}/citations?${query.toString()}`, options));
  if (!Array.isArray(p["items"]) || p["items"].length > 25) bad();
  const items = p["items"].map((v) => parseCitation(v, s));
  if (new Set(items.map((v) => v.citation_id)).size !== items.length) bad();
  return { items, next_cursor: cursorOf(p["next_cursor"]) };
}
export async function getEvidence(caseId: string, runId: string, citationId: string,
                                   options: BoundRequestOptions): Promise<EvidenceView> {
  const s = scope(options.context, caseId, runId);
  if (!uuid(citationId)) bad();
  return parseEvidence(await getBoundJson(`/api/v1/evidence/${citationId}?run_id=${runId}`, options), s, citationId);
}

// Slice A reads an exact proposal for inspection only. Slice B owns the full decision/detail decoder.
export interface InspectedProposal {
  id: string; version: number; digest: string; text: string; state: string;
  resources: { kind: string; resourceId: string; version: number }[];
  evidence: { id: string; versionId: string; digest: string }[];
  consent: { id: string; text: string; source: string; enteredBy: string | null; expires: string } | null;
}
export async function getProposal(caseId: string, runId: string, id: string, version: number,
                                   options: BoundRequestOptions): Promise<InspectedProposal> {
  if (!uuid(id) || !integer(version, 1)) bad();
  const v = record(await getBoundJson(`/api/v1/proposals/${id}?version=${String(version)}`, options));
  const p = record(v["proposal"]);
  scopeOf(p["scope"], scope(options.context, caseId, runId));
  const presentation = record(p["presentation"]);
  if (p["proposal_id"] !== id || p["proposal_version"] !== version || !digest(p["action_digest"])
      || typeof presentation["text"] !== "string" || Array.from(presentation["text"]).length > 8000
      || !["awaiting_presentation", "awaiting_consent", "awaiting_decision", "approved", "approval_expired",
        "rejected", "superseded", "expired"].includes(String(v["state"]))
      || !Array.isArray(p["resource_versions"]) || p["resource_versions"].length > 64
      || !Array.isArray(p["evidence"]) || p["evidence"].length > 32) bad();
  const resources = p["resource_versions"].map((v) => {
    const r = record(v);
    if (!["order", "user", "product"].includes(String(r["kind"])) || typeof r["resource_id"] !== "string"
        || r["resource_id"].length > 200 || !integer(r["version"], 1)) bad();
    return { kind: String(r["kind"]), resourceId: r["resource_id"], version: r["version"] };
  });
  const evidence = p["evidence"].map((v) => {
    const r = record(v);
    if (!uuid(r["evidence_id"]) || !uuid(r["document_version_id"]) || !digest(r["content_sha256"])) bad();
    return { id: r["evidence_id"], versionId: r["document_version_id"], digest: r["content_sha256"] };
  });
  let consent: InspectedProposal["consent"] = null;
  if (v["consent"] !== null) {
    const c = record(v["consent"]);
    if (!uuid(c["consent_id"]) || typeof c["customer_message_text"] !== "string"
        || Array.from(c["customer_message_text"]).length > 4000
        || !["simulated_customer", "operator_entered_customer"].includes(String(c["message_source"]))
        || (c["entered_by"] !== null && !uuid(c["entered_by"])) || typeof c["expires_at"] !== "string") bad();
    consent = { id: c["consent_id"], text: c["customer_message_text"], source: String(c["message_source"]),
      enteredBy: c["entered_by"], expires: c["expires_at"] };
  }
  return { id, version, digest: p["action_digest"], text: presentation["text"], state: String(v["state"]),
    resources, evidence, consent };
}
