// Shared pieces of the case screens: labels, timestamps, a scoped loader for paged reads and the status of a write.

import { useCallback, useEffect, useRef } from "react";
import { Button } from "react-aria-components/Button";

import { ApiError, toApiError, type BoundRequestOptions, type CaseStatus } from "../api/client";
import type { WriteEntry, WriteKind } from "../api/writes";
import { useSessionController, useWriteLedger } from "../session/SessionProvider";
import { describeError, Reference } from "../ui/feedback";

export const STATUS_LABELS: Readonly<Record<CaseStatus, string>> = {
  open: "Open",
  in_progress: "In progress",
  resolved: "Resolved",
  closed: "Closed",
};

const DATE_TIME = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

export function Timestamp({ value }: { value: string }) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? <span>—</span> : <time dateTime={value}>{DATE_TIME.format(date)}</time>;
}

export function shortId(id: string): string {
  return id.slice(0, 8);
}

/**
 * One channel of reads under the current session generation. Starting a load supersedes the previous one (its
 * result is dropped even if it arrives), and unmounting or a session change drops all of them. 401 and
 * context_changed go to the session as for useSessionResource; other failures go to `onError`.
 */
export function useScopedLoader(): <T>(resource: string, load: (options: BoundRequestOptions) => Promise<T>,
                                       onData: (data: T) => void, onError: (error: ApiError) => void) => void {
  const controller = useSessionController();
  const current = useRef<AbortController | null>(null);
  useEffect(() => () => {
    current.current?.abort();
    current.current = null;
  }, []);
  return useCallback(<T,>(resource: string, load: (options: BoundRequestOptions) => Promise<T>,
                          onData: (data: T) => void, onError: (error: ApiError) => void): void => {
    current.current?.abort();
    const local = new AbortController();
    current.current = local;
    const scope = controller.scope();
    const abort = (): void => {
      local.abort();
    };
    scope.signal.addEventListener("abort", abort, { once: true });
    if (scope.signal.aborted) {
      local.abort();
    }
    const live = (): boolean => current.current === local && !local.signal.aborted && controller.isCurrent(scope);
    const context = scope.context;
    const pending = context === null ? Promise.reject(new ApiError("malformed"))
      : load({ signal: local.signal, context });
    pending.then(
      (data) => {
        scope.signal.removeEventListener("abort", abort);
        if (live()) {
          controller.reportSuccess(scope, resource);
          onData(data);
        }
      },
      (error: unknown) => {
        scope.signal.removeEventListener("abort", abort);
        if (!live()) {
          return;
        }
        const failure = toApiError(error);
        if (failure.unauthenticated) {
          controller.reportUnauthenticated(scope, resource);
        } else if (failure.contextChanged) {
          controller.reportContextChanged(scope, failure, resource);
        } else {
          onError(failure);
        }
      },
    );
  }, [controller]);
}

const PENDING_LABEL: Readonly<Record<WriteKind, string>> = {
  createCase: "Creating a case…",
  postMessage: "Posting…",
  startRun: "Starting an investigation…",
  cancelRun: "Requesting cancellation…",
  decision: "Recording decision…",
};

const UNCONFIRMED: Readonly<Record<WriteKind, string>> = {
  createCase: "We couldn't confirm whether the case was created",
  postMessage: "We couldn't confirm whether your message was posted",
  startRun: "We couldn't confirm whether the investigation was started",
  cancelRun: "Cancellation request unconfirmed",
  decision: "Decision unconfirmed",
};

const NOT_APPLIED: Readonly<Record<WriteKind, string>> = {
  createCase: "The case wasn't created",
  postMessage: "Your message wasn't posted",
  startRun: "No investigation was started",
  cancelRun: "Cancellation was refused",
  decision: "Decision refused",
};

function refusalBody(entry: WriteEntry, failure: ApiError): string {
  if (failure.staleVersion) {
    return entry.kind === "postMessage"
      ? "The case changed after you opened it. Refresh to see the latest, then send again. Your text is kept."
      : "The case changed after you opened it. Refresh to see the latest, then try again.";
  }
  if (failure.runtimeUnconfigured) {
    return "Investigations aren't available on this server, so nothing was started.";
  }
  if (failure.runActive) {
    return "This case already has an investigation in progress. This request didn't start another one.";
  }
  return describeError(failure).body;
}

/**
 * The state of one write for its own view. An unknown outcome offers an explicit retry of the identical request
 * (which may complete the original now) when the request is still intact here, and never a way to drop it.
 */
export function WriteStatus({ entry, onRefresh, refreshLabel }: {
  entry: WriteEntry;
  onRefresh?: () => void;
  refreshLabel?: string;
}) {
  const ledger = useWriteLedger();
  const failure = entry.failure;
  if (entry.phase === "inFlight") {
    return (
      <div className="status" role="status">
        <span className="spinner" aria-hidden="true" />
        <span>{entry.attempts > 1 ? "Retrying the same request…" : PENDING_LABEL[entry.kind]}</span>
      </div>
    );
  }
  if (entry.phase === "applied") {
    return null; // the view shows the result itself
  }
  if (entry.phase === "notApplied") {
    return (
      <section className="panel panel-error write-status" role="alert">
        <h2>{NOT_APPLIED[entry.kind]}</h2>
        <p>{failure !== null ? refusalBody(entry, failure) : "The server refused the request."}</p>
        {failure !== null ? <Reference id={failure.correlationId} /> : null}
      </section>
    );
  }
  const retryable = ledger.canRetry(entry);
  return (
    <section className="panel panel-error write-status" role="alert">
      <h2>{UNCONFIRMED[entry.kind]}</h2>
      {failure !== null && failure.kind === "http" && entry.attempts > 1 ? (
        <p>The retry was refused ({describeError(failure).title.toLowerCase()}), so it did nothing. Whether the
          earlier request was applied is still unconfirmed.</p>
      ) : (
        <p>No reliable answer arrived{failure !== null ? ` (${describeError(failure).title.toLowerCase()})` : ""}.
          It may have been applied. It hasn't been sent again.</p>
      )}
      {retryable ? (
        <p className="muted">Retrying sends the identical request with the same identity. If the first one wasn't
          recorded, this completes it now; it can't be applied twice.</p>
      ) : entry.kind === "postMessage" && entry.payload === null ? (
        <p className="muted">This tab no longer holds its text, so it can't be retried here. Refresh to check
          whether it arrived. Reloading the page discards this tab's record of it.</p>
      ) : null}
      {failure !== null ? <Reference id={failure.correlationId} /> : null}
      <div className="actions">
        {retryable ? (
          <Button className="button button-primary" onPress={() => { ledger.retry(entry.id); }}>
            Retry the same request
          </Button>
        ) : null}
        {onRefresh !== undefined ? (
          <Button className="button" onPress={onRefresh}>{refreshLabel ?? "Refresh"}</Button>
        ) : null}
      </div>
    </section>
  );
}

export const CAPACITY_NOTICE = "Several requests in this tab haven't been confirmed yet. Resolve them before sending "
  + "another.";
