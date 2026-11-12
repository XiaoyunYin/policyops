import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "react-aria-components/Button";
import { Link } from "react-router";
import type { ApiError } from "../api/client";
import { Timestamp, useScopedLoader } from "../cases/common";
import { EmptyState, ErrorPanel, Status } from "../ui/feedback";
import { listApprovals, type Page } from "./api";
import { useVisibleRefresh } from "./refresh";

export function ApprovalInbox() {
  const load = useScopedLoader();
  const [page, setPage] = useState<Page | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const refreshButton = useRef<HTMLButtonElement>(null);
  const focusedRow = useRef<Element | null>(null);
  const read = useCallback((cursor: string | null) => {
    load("approvals", (options) => listApprovals(cursor, options), (next) => {
      focusedRow.current = document.activeElement?.closest(".approval-list a") ?? null;
      setPage((old) => {
        const unique = new Map((cursor === null ? [] : old?.items ?? []).map((p) => [`${p.proposal_id}:${String(p.proposal_version)}`, p]));
        for (const p of next.items) unique.set(`${p.proposal_id}:${String(p.proposal_version)}`, p);
        return { items: [...unique.values()].slice(0, 200), next_cursor: next.next_cursor };
      }); setError(null); setBusy(false);
    }, (failure) => {
      focusedRow.current = document.activeElement?.closest(".approval-list a") ?? null;
      setPage(null); setError(failure); setBusy(false);
    });
  }, [load]);
  const refresh = useCallback(() => { read(null); }, [read]);
  useEffect(refresh, [refresh]);
  useEffect(() => {
    if (focusedRow.current !== null && !focusedRow.current.isConnected) refreshButton.current?.focus();
    focusedRow.current = null;
  }, [page]);
  useVisibleRefresh(refresh);
  return <section className="approval-inbox" aria-label="Approval inbox">
    <div className="section-bar"><div><p className="eyebrow">Reviewer queue</p><h2>Awaiting a staff decision</h2>
      <p className="muted">Oldest first · refreshes every 15 seconds while visible. Customer consent is checked separately.</p></div>
      <Button ref={refreshButton} className="button" onPress={() => { setBusy(true); refresh(); }} isDisabled={busy}>Refresh inbox</Button></div>
    {error !== null ? <ErrorPanel error={error} onRetry={refresh} /> : page === null ? <Status label="Loading approvals…" />
      : page.items.length === 0 ? <EmptyState title="No approvals waiting"><p>Current eligible proposals will appear here.</p></EmptyState>
        : <><ol className="approval-list">{page.items.map((p) => <li key={`${p.proposal_id}:${String(p.proposal_version)}`}>
          <div><p className="eyebrow">Version {String(p.proposal_version)} · {p.state.replaceAll("_", " ")}</p>
            <h3><Link to={`/approvals/${p.proposal_id}/versions/${String(p.proposal_version)}`}>{p.tool.replaceAll("_", " ")}</Link></h3>
            <p className="muted">Created <Timestamp value={p.created_at} /> · expires <Timestamp value={p.expires_at} /></p>
            <p className="wrap-anywhere"><span className="muted">Action digest </span><code>{p.action_digest}</code></p></div>
          <Link className="button" to={`/approvals/${p.proposal_id}/versions/${String(p.proposal_version)}`}>Review version {String(p.proposal_version)}</Link>
        </li>)}</ol><div className="actions"><Button className="button" isDisabled={busy || page.next_cursor === null || page.items.length >= 200}
          onPress={() => { setBusy(true); read(page.next_cursor); }}>Load more approvals</Button><span className="muted">{String(page.items.length)} shown · maximum 200</span></div></>}
    <p role="status" aria-live="polite" className="visually-hidden">{busy ? "Refreshing inbox" : page === null ? "" : `${String(page.items.length)} approvals shown`}</p>
  </section>;
}
