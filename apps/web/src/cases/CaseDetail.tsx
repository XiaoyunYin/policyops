// One case: its header, the conversation with an explicit source label on every message, the composer and the
// investigation control.
//
// The message history is the contiguous prefix fetched page by page from sequence 0 (`cursor` is the last sequence of
// that prefix). A message this tab posts lands at the case's newest sequence, which can be far beyond the loaded
// prefix; it is kept as a separate known suffix, so posting never moves the history cursor past messages that were
// never fetched. At most MAX_MESSAGES are held in total, from two fixed budgets: MAX_PREFIX for the fetched prefix
// and MAX_SUFFIX for the newest posts beyond it (older posts drop out of the suffix first). Once the prefix budget is
// full it stays capped, and later posts, including ones contiguous with it, go to the suffix. Case snapshots are applied only when their version is not older than the one shown: an idempotent
// replay returns the original (older) snapshot and a slow read may arrive after a newer one.

import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "react-aria-components/Button";
import { Link, useNavigate } from "react-router";

import {
  expectedContextOf,
  ApiError,
  getCase,
  listMessages,
  sameContext,
  type CaseView,
  type MeOut,
  type MessagePage,
  type MessagePosted,
  type MessageSource,
  type MessageView,
} from "../api/client";
import type { WriteEntry } from "../api/writes";
import { capabilities } from "../session/permissions";
import { useWriteEntries, useWriteLedger } from "../session/SessionProvider";
import { EmptyState, ErrorPanel, Status } from "../ui/feedback";
import { CAPACITY_NOTICE, STATUS_LABELS, Timestamp, WriteStatus, useScopedLoader } from "./common";
import { Composer } from "./Composer";
import { RunWorkspace } from "../runs/RunWorkspace";
import type { Payload } from "../runs/contracts";

/** Messages held for one case in total: the fetched prefix plus this tab's newest posts beyond it. */
export const MAX_MESSAGES = 1000;
export const MAX_SUFFIX = 50;
export const MAX_PREFIX = MAX_MESSAGES - MAX_SUFFIX;

export const SOURCE_LABELS: Readonly<Record<MessageSource, string>> = {
  staff_note: "Staff note · internal, not sent to the customer",
  operator_entered_customer: "Customer message · entered by staff (simulation)",
  simulated_customer: "Simulated customer",
  seeded: "Demo conversation",
  agent: "Agent",
  helpdesk_ticket: "Help desk ticket",
};

interface History {
  readonly prefix: readonly MessageView[];
  readonly cursor: number;
  /** The server has messages after the prefix that have not been fetched (or the cap was reached). */
  readonly more: boolean;
  readonly capped: boolean;
  /** Messages this tab posted beyond the prefix, by sequence. */
  readonly suffix: readonly MessageView[];
}

const EMPTY_HISTORY: History = { prefix: [], cursor: 0, more: false, capped: false, suffix: [] };

export function newerCase(current: CaseView | null, next: CaseView): CaseView {
  return current === null || next.version >= current.version ? next : current;
}

export function extendHistory(history: History, page: MessagePage): History {
  const known = new Set(history.prefix.map((message) => message.message_id));
  const room = MAX_PREFIX - history.prefix.length;
  const fresh = page.items.filter((message) => message.sequence > history.cursor && !known.has(message.message_id))
    .slice(0, Math.max(0, room));
  const prefix = [...history.prefix, ...fresh];
  const cursor = prefix.length === 0 ? history.cursor : prefix[prefix.length - 1]?.sequence ?? history.cursor;
  // An empty page after the cap means nothing newer yet, not room: the prefix budget stays used up.
  const capped = prefix.length >= MAX_PREFIX
    && (history.capped || page.next_after_sequence !== null || fresh.length < page.items.length);
  const ids = new Set(prefix.map((message) => message.message_id));
  return {
    prefix, cursor, capped, more: !capped && page.next_after_sequence !== null,
    suffix: history.suffix.filter((message) => message.sequence > cursor && !ids.has(message.message_id)),
  };
}

export function addPosted(history: History, message: MessageView): History {
  if (history.prefix.some((known) => known.message_id === message.message_id)
      || history.suffix.some((known) => known.message_id === message.message_id)) {
    return history;
  }
  if (!history.more && !history.capped && history.prefix.length < MAX_PREFIX
      && message.sequence === history.cursor + 1) {
    return { ...history, prefix: [...history.prefix, message], cursor: message.sequence };
  }
  const suffix = [...history.suffix, message].sort((a, b) => a.sequence - b.sequence).slice(-MAX_SUFFIX);
  return { ...history, suffix };
}

interface Detail {
  readonly phase: "loading" | "ready" | "failed" | "busy";
  readonly caseView: CaseView | null;
  readonly history: History;
  readonly error: ApiError | null;
  readonly readError: ApiError | null;
}

export interface Draft {
  readonly source: "staff_note" | "operator_entered_customer" | null;
  readonly text: string;
  readonly confirming: boolean;
}

const EMPTY_DRAFT: Draft = { source: null, text: "", confirming: false };

type PostedEvent = Extract<Payload, { type: "case.message_posted" }>;

export function CaseDetail({ caseId, runId, citationId, me }: { caseId: string; runId?: string | undefined; citationId?: string | undefined; me: MeOut }) {
  const load = useScopedLoader();
  const messageLoad = useScopedLoader();
  const navigate = useNavigate();
  const ledger = useWriteLedger();
  const entries = useWriteEntries();
  const context = expectedContextOf(me);
  const canOperate = capabilities(me.roles).has("operateCases");
  const [detail, setDetail] = useState<Detail>({ phase: "loading", caseView: null, history: EMPTY_HISTORY,
                                                 error: null, readError: null });
  const [draft, setDraft] = useState<Draft>(EMPTY_DRAFT);
  const [announcement, setAnnouncement] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [focusComposer, setFocusComposer] = useState(0);
  const [syncingCase, setSyncingCase] = useState(false);
  const pendingMessages = useRef<PostedEvent[]>([]);
  const onMessages = useCallback((events: PostedEvent[]): void => {
    // A later event can supersede a slow read. Include the messages that read has yet to apply.
    const bySequence = new Map([...pendingMessages.current, ...events].map((event) => [event.message_sequence, event]));
    const wanted = [...bySequence.values()].sort((a, b) => a.message_sequence - b.message_sequence).slice(-50);
    const first = wanted[0];
    if (first === undefined) return;
    pendingMessages.current = wanted;
    setSyncingCase(true);
    messageLoad(`case-live-messages:${caseId}`, async (options) => {
      const page = await listMessages(caseId, first.message_sequence - 1, options);
      const found: MessageView[] = [];
      for (const event of wanted) {
        let message = page.items.find((m) => m.sequence === event.message_sequence);
        if (message === undefined) message = (await listMessages(caseId, event.message_sequence - 1, options)).items[0];
        if (message === undefined || message.sequence !== event.message_sequence || message.message_id !== event.message_id
            || message.source !== event.source) throw new ApiError("malformed");
        found.push(message);
      }
      // The message commit also advances the case version used by the next write.
      return { messages: found, view: await getCase(caseId, options) };
    }, ({ messages, view }) => {
      pendingMessages.current = [];
      setDetail((previous) => previous.caseView === null ? previous : {
        ...previous, caseView: newerCase(previous.caseView, view), history: messages.reduce(addPosted, previous.history),
      });
      setSyncingCase(false);
    }, (error) => {
      pendingMessages.current = [];
      setSyncingCase(false);
      setDetail((previous) => error.status === 403 || error.status === 404
        ? { ...previous, phase: "failed", caseView: null, history: EMPTY_HISTORY, error }
        : { ...previous, readError: error });
    });
  }, [messageLoad, caseId]);

  useEffect(() => {
    load(`case:${caseId}`, async (options) => {
      const view = await getCase(caseId, options);
      return { view, page: await listMessages(caseId, 0, options) };
    }, ({ view, page }) => {
      setDetail({ phase: "ready", caseView: view, history: extendHistory(EMPTY_HISTORY, page), error: null,
                  readError: null });
    }, (error) => {
      setDetail((previous) => ({ ...previous, phase: "failed", error }));
    });
  }, [load, caseId]);

  useEffect(() => ledger.onSettled((entry) => {
    if (entry.caseId !== caseId) {
      return;
    }
    if (entry.kind === "postMessage" && entry.result?.kind === "postMessage") {
      const posted: MessagePosted = entry.result.value;
      setDetail((previous) => ({ ...previous, caseView: newerCase(previous.caseView, posted.case),
                                 history: addPosted(previous.history, posted.message) }));
      setDraft(EMPTY_DRAFT);
      setFocusComposer((value) => value + 1);
      setAnnouncement(entry.replayed ? "Your message is recorded. The server had already received this request."
        : `Posted as ${posted.message.source === "staff_note" ? "a staff note" : "a customer message entered by staff"}.`);
      ledger.consume(entry.id);
    }
    if (entry.kind === "startRun" && entry.result?.kind === "startRun") {
      const run = entry.result.value;
      setAnnouncement(entry.replayed ? "The investigation had already been requested. Attached to its recorded run."
        : "Investigation requested. Attached to its recorded run.");
      void navigate(`/cases/${caseId}/runs/${run.run_id}`);
      load(`case:${caseId}`, (options) => getCase(caseId, options), (view) => {
        setDetail((previous) => ({ ...previous, caseView: newerCase(previous.caseView, view) }));
      }, (error) => { setDetail((previous) => ({ ...previous, readError: error })); });
      ledger.consume(entry.id);
    }
  }), [ledger, caseId, navigate, load]);

  const refresh = (): void => {
    if (detail.phase !== "ready") {
      return;
    }
    const after = detail.history.cursor;
    setDetail({ ...detail, phase: "busy", readError: null });
    load(`case:${caseId}`, async (options) => {
      const view = await getCase(caseId, options);
      return { view, page: await listMessages(caseId, after, options) };
    }, ({ view, page }) => {
      setDetail((previous) => ({ ...previous, phase: "ready", caseView: newerCase(previous.caseView, view),
                                 history: previous.history.cursor === after ? extendHistory(previous.history, page)
                                   : previous.history }));
    }, (error) => {
      setDetail((previous) => ({ ...previous, phase: "ready", readError: error }));
    });
  };

  const loadMore = (): void => {
    if (detail.phase !== "ready" || !detail.history.more) {
      return;
    }
    const after = detail.history.cursor;
    setDetail({ ...detail, phase: "busy", readError: null });
    load(`case:${caseId}`, (options) => listMessages(caseId, after, options), (page) => {
      setDetail((previous) => ({ ...previous, phase: "ready",
                                 history: previous.history.cursor === after ? extendHistory(previous.history, page)
                                   : previous.history }));
    }, (error) => {
      setDetail((previous) => ({ ...previous, phase: "ready", readError: error }));
    });
  };

  if (detail.phase === "loading") {
    return <Status label="Loading the case…" />;
  }
  if (detail.caseView === null) {
    return detail.error !== null ? (
      <>
        <ErrorPanel error={detail.error} />
        <Link className="button" to="/cases">Back to cases</Link>
      </>
    ) : <Status label="Loading the case…" />;
  }
  const view = detail.caseView;
  const mine = (kind: WriteEntry["kind"]): WriteEntry[] => entries.filter((entry) => entry.kind === kind
    && entry.caseId === caseId && sameContext(entry.context, context));
  const posts = mine("postMessage");
  const runs = mine("startRun");
  const posting = posts.find((entry) => entry.phase === "inFlight" || entry.phase === "unknown") ?? null;
  const busy = detail.phase === "busy";

  const send = (): void => {
    setNotice(null);
    if (syncingCase || draft.source === null) {
      return;
    }
    const begun = ledger.begin({ kind: "postMessage", caseId, ifMatch: view.version,
                                 payload: { source: draft.source, text: draft.text } });
    if ("refused" in begun && begun.refused === "capacity") {
      setNotice(CAPACITY_NOTICE);
    } else if ("entry" in begun) {
      setDraft({ ...draft, confirming: false });
    }
  };

  const startInvestigation = (): void => {
    if (syncingCase) return;
    setNotice(null);
    const begun = ledger.begin({ kind: "startRun", caseId, ifMatch: view.version, payload: null });
    if ("refused" in begun && begun.refused === "capacity") {
      setNotice(CAPACITY_NOTICE);
    }
  };

  return (
    <>
      <section className="case-summary" aria-label="Case summary">
        <dl className="facts">
          <div><dt>Status</dt><dd><span className={`status-pill status-${view.status}`}>
            {STATUS_LABELS[view.status]}</span></dd></div>
          <div><dt>Customer</dt><dd>{view.customer_bound ? "Customer linked" : "No customer linked"}</dd></div>
          <div><dt>Case</dt><dd><code className="wrap-anywhere">{view.case_id}</code></dd></div>
          <div><dt>Version</dt><dd>{String(view.version)}</dd></div>
          <div><dt>Opened</dt><dd><Timestamp value={view.created_at} /></dd></div>
          <div><dt>Updated</dt><dd><Timestamp value={view.updated_at} /></dd></div>
        </dl>
        <div className="actions">
          <Button className="button" isDisabled={busy} onPress={refresh}>Refresh</Button>
          <Link className="button" to="/cases">Back to cases</Link>
        </div>
      </section>
      <div className="visually-hidden" role="status">{announcement}</div>
      {notice !== null ? <p className="panel panel-error" role="alert">{notice}</p> : null}

      <section aria-labelledby="conversation-heading">
        <h2 id="conversation-heading">Conversation</h2>
        {syncingCase && canOperate ? <Status label="Updating case version…" /> : null}
        {detail.readError !== null ? <ErrorPanel error={detail.readError} /> : null}
        <MessageList history={detail.history} me={me} busy={busy} onMore={loadMore} />
      </section>

      {canOperate ? (
        <>
          <section aria-labelledby="composer-heading">
            <h2 id="composer-heading">Add to the conversation</h2>
            {posts.map((entry) => <WriteStatus key={entry.id} entry={entry} onRefresh={refresh}
                                               refreshLabel="Refresh the conversation" />)}
            <Composer draft={posting?.payload != null ? { source: posting.payload.source, text: posting.payload.text,
                                                           confirming: false } : draft}
                      locked={posting !== null} submitDisabled={syncingCase}
                      focusSignal={focusComposer} onChange={setDraft} onSend={send} />
          </section>
          <section aria-labelledby="run-heading">
            <h2 id="run-heading">Investigation</h2>
            <p className="muted">An investigation lets the agent gather facts and propose actions for review.</p>
            {runs.map((entry) => <RunStatus key={entry.id} entry={entry} onRefresh={refresh} />)}
            <Button className="button" onPress={startInvestigation}
                    isDisabled={syncingCase || runs.some((entry) => entry.phase === "inFlight" || entry.phase === "unknown")}>
              Start investigation
            </Button>
          </section>
        </>
      ) : (
        <p className="muted">Your role can read this case but not add to it or start an investigation.</p>
      )}
      <RunWorkspace caseId={caseId} runId={runId} citationId={citationId} me={me} onMessages={onMessages} />
    </>
  );
}

function RunStatus({ entry, onRefresh }: { entry: WriteEntry; onRefresh: () => void }) {
  if (entry.phase === "applied") {
    return (
      <p className="panel" role="status">
        {entry.replayed ? "The investigation had already been requested." : "Investigation requested."} Its
        activity is shown in the workbench below.
      </p>
    );
  }
  if (entry.phase === "notApplied" && entry.failure?.runtimeUnconfigured === true) {
    return (
      <section className="panel" role="status">
        <h3>Investigations aren't available on this server</h3>
        <p>This request didn't start an investigation. You can still read the case and add notes or customer
          messages.</p>
      </section>
    );
  }
  return <WriteStatus entry={entry} onRefresh={onRefresh} />;
}

function author(message: MessageView, me: MeOut): string {
  if (message.entered_by === null) {
    return message.source === "agent" ? "Agent" : "System";
  }
  return message.entered_by === me.principal_id ? "You" : "Another staff member";
}

function MessageItem({ message, me }: { message: MessageView; me: MeOut }) {
  return (
    <li className={`message message-${message.source}`}>
      <p className="message-meta">
        <span className="source-badge">{SOURCE_LABELS[message.source]}</span>
        <span>{author(message, me)}</span>
        <Timestamp value={message.created_at} />
      </p>
      <p className="message-text">{message.text}</p>
    </li>
  );
}

function MessageList({ history, me, busy, onMore }: {
  history: History;
  me: MeOut;
  busy: boolean;
  onMore: () => void;
}) {
  if (history.prefix.length === 0 && history.suffix.length === 0) {
    return <EmptyState title="No messages yet" />;
  }
  // A gap is any missing sequence between the end of the prefix and the posts kept after it.
  const gap = history.suffix.some((message, index) =>
    message.sequence !== (index === 0 ? history.cursor : (history.suffix[index - 1]?.sequence ?? 0)) + 1);
  return (
    <>
      <ol className="messages" aria-label="Messages">
        {history.prefix.map((message) => <MessageItem key={message.message_id} message={message} me={me} />)}
      </ol>
      {history.more ? (
        <Button className="button" isDisabled={busy} onPress={onMore}>
          {busy ? "Loading…" : "Load more messages"}
        </Button>
      ) : null}
      {history.capped ? (
        <p className="muted table-note">Showing the first {MAX_PREFIX.toLocaleString("en-US")} messages.</p>
      ) : null}
      {history.suffix.length > 0 ? (
        <>
          {gap ? <p className="muted table-note">Some earlier messages aren't loaded yet; the latest recorded messages are shown
            below them.</p> : null}
          {history.suffix.length >= MAX_SUFFIX ? <p className="muted table-note">Only the latest
            {" "}{String(MAX_SUFFIX)} messages are kept here.</p> : null}
          <ol className="messages" aria-label="Latest messages">
            {history.suffix.map((message) => <MessageItem key={message.message_id} message={message} me={me} />)}
          </ol>
        </>
      ) : null}
    </>
  );
}
