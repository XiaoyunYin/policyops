// The case queue: status filter, cursor pagination with a fixed row cap, and New case for operating roles.

import { useEffect, useState } from "react";
import { Button } from "react-aria-components/Button";
import { Label, RadioButton, RadioField, RadioGroup } from "react-aria-components/RadioGroup";
import { Link, useNavigate } from "react-router";

import {
  CASE_PAGE_LIMIT,
  expectedContextOf,
  listCases,
  sameContext,
  type ApiError,
  type CasePage,
  type CaseStatus,
  type CaseView,
  type MeOut,
} from "../api/client";
import { capabilities } from "../session/permissions";
import { useWriteEntries, useWriteLedger } from "../session/SessionProvider";
import { EmptyState, ErrorPanel, Status } from "../ui/feedback";
import { CAPACITY_NOTICE, STATUS_LABELS, Timestamp, WriteStatus, shortId, useScopedLoader } from "./common";

/** At most this many pages (and so CASE_PAGE_LIMIT times as many rows) are held. */
export const MAX_QUEUE_PAGES = 8;
export const MAX_QUEUE_ROWS = MAX_QUEUE_PAGES * CASE_PAGE_LIMIT;

type Filter = CaseStatus | "all";
const FILTERS: readonly Filter[] = ["all", "open", "in_progress", "resolved", "closed"];

interface QueueState {
  readonly phase: "loading" | "ready" | "failed" | "loadingMore";
  readonly rows: readonly CaseView[];
  readonly cursor: string | null;
  readonly pages: number;
  readonly error: ApiError | null;
  readonly moreError: ApiError | null;
}

const INITIAL: QueueState = { phase: "loading", rows: [], cursor: null, pages: 0, error: null, moreError: null };

function appendPage(state: QueueState, page: CasePage): QueueState {
  const seen = new Set(state.rows.map((row) => row.case_id));
  const fresh = page.items.filter((row) => !seen.has(row.case_id));
  const rows = [...state.rows, ...fresh].slice(0, MAX_QUEUE_ROWS);
  const pages = state.pages + 1;
  // A page that adds nothing new would only repeat itself: stop rather than fetch endlessly.
  const cursor = pages >= MAX_QUEUE_PAGES || rows.length >= MAX_QUEUE_ROWS || (state.pages > 0 && fresh.length === 0)
    ? null : page.next_cursor;
  return { phase: "ready", rows, cursor, pages, error: null, moreError: null };
}

export function CaseQueue({ me }: { me: MeOut }) {
  const load = useScopedLoader();
  const navigate = useNavigate();
  const ledger = useWriteLedger();
  const entries = useWriteEntries();
  const context = expectedContextOf(me);
  const canOperate = capabilities(me.roles).has("operateCases");
  const [filter, setFilter] = useState<Filter>("all");
  const [epoch, setEpoch] = useState(0);
  const [state, setState] = useState<QueueState>(INITIAL);
  const [notice, setNotice] = useState<string | null>(null);
  const status = filter === "all" ? null : filter;

  useEffect(() => {
    load("cases", (options) => listCases(options, { status }), (page) => {
      setState(appendPage(INITIAL, page));
    }, (error) => {
      setState({ ...INITIAL, phase: "failed", error });
    });
  }, [load, status, epoch]);

  useEffect(() => ledger.onSettled((entry) => {
    if (entry.kind === "createCase" && entry.phase === "applied" && entry.result?.kind === "createCase") {
      ledger.consume(entry.id);
      void navigate(`/cases/${entry.result.value.case_id}`);
    }
  }), [ledger, navigate]);

  const restart = (): void => {
    setState(INITIAL);
    setEpoch((value) => value + 1);
  };

  const loadMore = (): void => {
    const cursor = state.cursor;
    if (cursor === null || state.phase !== "ready") {
      return;
    }
    setState({ ...state, phase: "loadingMore", moreError: null });
    load("cases", (options) => listCases(options, { status, cursor }), (page) => {
      setState((previous) => appendPage(previous, page));
    }, (error) => {
      setState((previous) => ({ ...previous, phase: "ready", moreError: error }));
    });
  };

  const create = (): void => {
    setNotice(null);
    const begun = ledger.begin({ kind: "createCase", caseId: null, ifMatch: null, payload: null });
    if ("refused" in begun && begun.refused === "capacity") {
      setNotice(CAPACITY_NOTICE);
    }
  };

  const creation = entries.filter((entry) => entry.kind === "createCase" && sameContext(entry.context, context));
  const creating = creation.some((entry) => entry.phase === "inFlight" || entry.phase === "unknown");

  return (
    <>
      <div className="toolbar">
        <RadioGroup className="filter-group" orientation="horizontal" value={filter} onChange={(value) => {
          setFilter(value as Filter);
          setState(INITIAL);
        }}>
          <Label className="filter-label">Status</Label>
          {FILTERS.map((choice) => (
            <RadioField key={choice} value={choice}>
              <RadioButton className="filter-choice">{choice === "all" ? "All" : STATUS_LABELS[choice]}</RadioButton>
            </RadioField>
          ))}
        </RadioGroup>
        <div className="actions">
          <Button className="button" onPress={restart}>Refresh</Button>
          {canOperate ? (
            <Button className="button button-primary" isDisabled={creating} onPress={create}>New case</Button>
          ) : null}
        </div>
      </div>
      {!canOperate ? <p className="muted">Your role can read cases but not open or change them.</p> : null}
      {notice !== null ? <p className="panel panel-error" role="alert">{notice}</p> : null}
      {creation.map((entry) => (
        <WriteStatus key={entry.id} entry={entry} onRefresh={restart} refreshLabel="Refresh the list" />
      ))}
      <QueueBody state={state} filtered={status !== null} onRetry={restart} onMore={loadMore} />
    </>
  );
}

function QueueBody({ state, filtered, onRetry, onMore }: {
  state: QueueState;
  filtered: boolean;
  onRetry: () => void;
  onMore: () => void;
}) {
  if (state.phase === "loading") {
    return <Status label="Loading cases…" />;
  }
  if (state.phase === "failed" && state.error !== null) {
    return <ErrorPanel error={state.error} onRetry={onRetry} />;
  }
  if (state.rows.length === 0) {
    return (
      <EmptyState title={filtered ? "No cases with this status" : "No cases in this workspace"}>
        <p className="muted">{filtered ? "Choose another status to see more cases."
          : "Cases opened in this workspace will be listed here."}</p>
      </EmptyState>
    );
  }
  const capped = state.rows.length >= MAX_QUEUE_ROWS || state.pages >= MAX_QUEUE_PAGES;
  return (
    <>
      <div className="table-wrap">
        <table className="table">
          <caption className="visually-hidden">Cases</caption>
          <thead>
            <tr>
              <th scope="col">Case</th>
              <th scope="col">Status</th>
              <th scope="col">Customer</th>
              <th scope="col">Updated</th>
            </tr>
          </thead>
          <tbody>
            {state.rows.map((item) => (
              <tr key={item.case_id}>
                <td>
                  <Link to={`/cases/${item.case_id}`}
                        aria-label={`${item.scenario}, ${STATUS_LABELS[item.status]}, case ${shortId(item.case_id)}`}>
                    {item.scenario}
                  </Link>
                  <span className="muted case-ref"> {shortId(item.case_id)}</span>
                </td>
                <td><span className={`status-pill status-${item.status}`}>{STATUS_LABELS[item.status]}</span></td>
                <td>{item.customer_bound ? "Linked" : "Not linked"}</td>
                <td><Timestamp value={item.updated_at} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {state.pages > 1 ? (
        <p className="muted table-note">Cases can change while you browse, so the list may not be a single
          snapshot. Refresh to start again.</p>
      ) : null}
      {state.moreError !== null ? <ErrorPanel error={state.moreError} onRetry={onMore}
                                              retryLabel="Try loading more again" /> : null}
      {state.cursor !== null ? (
        <Button className="button" isDisabled={state.phase === "loadingMore"} onPress={onMore}>
          {state.phase === "loadingMore" ? "Loading…" : "Load more"}
        </Button>
      ) : capped ? (
        <p className="muted table-note">Showing the first {String(state.rows.length)} cases. Filter by status to
          narrow the list.</p>
      ) : null}
    </>
  );
}
