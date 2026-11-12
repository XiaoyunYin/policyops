import { useCallback } from "react";
import { Link, useLocation } from "react-router";
import { useSessionResource } from "../session/SessionProvider";
import type { BoundRequestOptions } from "../api/client";
import { ErrorPanel, Status } from "../ui/feedback";
import { getEvidence } from "../runs/api";
import type { EvidenceView } from "../runs/contracts";
import { bad, digest, record, uuid } from "../runs/contracts";

export function EvidenceText({ evidence }: { evidence: EvidenceView }) {
  const points = Array.from(evidence.text); // Stored offsets count code points; preserve combining marks verbatim.
  const start = evidence.span_start - evidence.excerpt_start;
  const end = evidence.span_end - evidence.excerpt_start;
  return <p className="evidence-excerpt">{points.slice(0, start).join("")}
    <mark>{points.slice(start, end).join("")}</mark>{points.slice(end).join("")}</p>;
}
export function EvidenceViewer({ caseId, runId, citationId }: { caseId: string; runId: string; citationId: string }) {
  const location = useLocation();
  const expected = location.state as unknown;
  const load = useCallback(async (options: BoundRequestOptions) => {
    const evidence = await getEvidence(caseId, runId, citationId, options);
    if (expected !== null) {
      const binding = record(expected);
      if ("versionId" in binding || "versionDigest" in binding) {
        if (!uuid(binding["versionId"]) || !digest(binding["versionDigest"])
            || evidence.document_version_id !== binding["versionId"] || evidence.version_sha256 !== binding["versionDigest"]) bad();
      }
    }
    return evidence;
  }, [caseId, runId, citationId, expected]);
  const { resource, reload } = useSessionResource(load, `evidence:${runId}:${citationId}`);
  return <section className="evidence-viewer" aria-labelledby="evidence-heading">
    <div className="section-bar"><div><p className="eyebrow">Source inspection</p><h3 id="evidence-heading">Historical evidence</h3></div>
      <Link className="button" to={`/cases/${caseId}/runs/${runId}`} state={{ focusCitation: citationId }}>Close evidence</Link></div>
    <p className="muted">This is the recorded historical version, not current policy or proof that a claim is supported.</p>
    {resource.status === "loading" ? <Status label="Loading historical evidence…" /> : resource.status === "failed"
      ? <><p className="notice">{resource.error.status === 409 || resource.error.kind === "malformed" ? "Evidence integrity could not be verified."
        : resource.error.status === 403 ? "Evidence access is unavailable." : resource.error.status === 404 ? "This evidence is hidden or missing." : "Evidence is unavailable."}</p>
        <ErrorPanel error={resource.error} onRetry={reload} /></> : <>
        <EvidenceText evidence={resource.data} />
        <dl className="evidence-metadata">
          <div><dt>Source URI</dt><dd>{resource.data.source_uri}</dd></div>
          <div><dt>Document</dt><dd>{resource.data.document_id}</dd></div>
          <div><dt>Version</dt><dd>{resource.data.version} · {resource.data.document_version_id}</dd></div>
          <div><dt>Version SHA-256</dt><dd><code>{resource.data.version_sha256}</code></dd></div>
          <div><dt>Quote offsets</dt><dd>{String(resource.data.span_start)}–{String(resource.data.span_end)} (Unicode code points; end excluded)</dd></div>
          <div><dt>Quote SHA-256</dt><dd><code>{resource.data.quote_sha256}</code></dd></div>
        </dl>
      </>}
  </section>;
}
