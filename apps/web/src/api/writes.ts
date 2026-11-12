// In-memory ledger of this tab's case/run writes and staff decisions, independent of React.
// Decisions freeze their proposal/version/digest/decision/reason and consent binding together. Their replay identity
// is the exact payload under (context, proposal ID, version), shared by approve and reject; the internal `key` is
// not sent. They reuse capacity, uncertainty, context stripping and unload protection, without case ETag semantics.
//
// Each entry is one operation: its Idempotency-Key, the principal and workspace it was composed for, the case
// version it is based on and, for a message, the text. They are fixed synchronously when the user sends, before the
// first await, and every attempt of the operation repeats them unchanged. There is no automatic retry and no new key
// for an unresolved operation: the user may explicitly retry the same request, in the same visible context only.
//
// Outcomes are decided per operation, not per response. The server rechecks the caller's role and the case's
// visibility before it looks up a stored result for the key, so a refusal of a later attempt (401, 403, 404,
// context_changed, CSRF) proves only that this attempt did nothing; after an earlier attempt whose outcome is
// unknown the operation stays unknown. So do the temporary refusals of a start (runtime.unconfigured, run_active),
// even though the server makes them after its replay lookup: a failed attempt stores no record for the key, so that
// lookup proves only that nothing was recorded yet, not that an earlier attempt still queued or in transit cannot
// apply later (another run can finish, another worker can have a runtime). Once uncertain, an operation settles only
// on a validated success, fresh or replayed (it applied), or on stale_version for a message or a start: the same
// immutable If-Match stays stale under the monotonic case version, so the identical request can never apply. A
// recognized refusal of the first attempt, temporary or not, settles that this attempt was not applied.
//
// Bounds and isolation. At most MAX_WRITES entries exist in total; an unresolved entry is never evicted, and a new
// write is refused before any network use when only unresolved entries remain. On every session transition that
// leaves the ready view an entry was created in (another generation, principal or workspace, or no ready view at
// all) the entry's text, result and failure are dropped synchronously; only content-free metadata keyed to its
// original context remains. A late response is still validated, but then records only its phase. Views read
// entries for their own context only. Dropping references does not erase bytes already handed to the browser's
// network stack, and an unload discards the ledger (the provider asks before unloading while an entry is unresolved).

import {
  ApiError,
  REQUEST_TIMEOUT_MS,
  createCase,
  cancelRun,
  expectedContextOf,
  postMessage,
  sameContext,
  startRun,
  toApiError,
  type CaseView,
  type ExpectedContext,
  type MessagePosted,
  type RunView,
  type StaffMessageSource,
} from "./client";
import { decide, sameDecision, type Decision, type DecisionPayload } from "../approvals/api";
import type { Scope, SessionState } from "../session/controller";

export const MAX_WRITES = 8;

export type WriteKind = "createCase" | "postMessage" | "startRun" | "cancelRun" | "decision";
export type WritePhase = "inFlight" | "unknown" | "applied" | "notApplied";

export interface MessageDraft {
  readonly source: StaffMessageSource;
  readonly text: string;
}

export type WriteResult =
  | { readonly kind: "decision"; readonly value: Decision }
  | { readonly kind: "createCase"; readonly value: CaseView }
  | { readonly kind: "postMessage"; readonly value: MessagePosted }
  | { readonly kind: "startRun" | "cancelRun"; readonly value: RunView };

export interface WriteEntry {
  readonly id: number;
  readonly key: string;
  readonly kind: WriteKind;
  readonly context: ExpectedContext;
  /** The session generation the entry's text and results belong to. */
  readonly generation: number;
  readonly caseId: string | null;
  readonly runId?: string | null;
  readonly decision?: { readonly proposalId: string; readonly payload: DecisionPayload; readonly consentId: string } | null;
  readonly proposalId?: string | null;
  readonly proposalVersion?: number | null;
  readonly ifMatch: number | null;
  /** The message text, only while the original ready view is still shown. */
  readonly payload: MessageDraft | null;
  readonly phase: WritePhase;
  /** Some attempt of this operation got no definitive answer, so it may have applied. */
  readonly uncertain: boolean;
  readonly attempts: number;
  /** The last attempt's validated result or failure, only while its view is still current. */
  readonly result: WriteResult | null;
  readonly failure: ApiError | null;
  readonly replayed: boolean;
}

interface Sent {
  readonly result: WriteResult;
  readonly replayed: boolean;
}

export type BeginRefusal = "duplicate" | "capacity" | "noContext";

interface WriteBase {
  readonly caseId: string | null;
  readonly runId?: string | null;
  readonly ifMatch: number | null;
  readonly payload: MessageDraft | null;
}
export type WriteSpec = WriteBase & (
  | { readonly kind: "decision"; readonly decision: { readonly proposalId: string; readonly payload: DecisionPayload; readonly consentId: string } }
  | { readonly kind: Exclude<WriteKind, "decision">; readonly decision?: never }
);

/** What the ledger needs from the session: its scope and state, and where to report refusals. */
export interface LedgerSession {
  scope(): Scope;
  isCurrent(scope: Scope): boolean;
  getState(): SessionState;
  subscribe(listener: () => void): () => void;
  reportUnauthenticated(scope: Scope, resource: string): void;
  reportContextChanged(scope: Scope, error: ApiError, resource: string): void;
  reportSuccess(scope: Scope, resource: string): void;
}

const UNRESOLVED: ReadonlySet<WritePhase> = new Set(["inFlight", "unknown"]);

export function isUnresolved(entry: WriteEntry): boolean {
  return UNRESOLVED.has(entry.phase);
}

/**
 * How one failed attempt bears on the whole operation. Only a permanent stale_version settles an operation that an
 * earlier attempt left uncertain; a first attempt is also settled by a recognized refusal envelope.
 */
export function failedAttemptOutcome(kind: WriteKind, uncertain: boolean, error: ApiError,
): "notApplied" | "unknown" {
  if (error.kind !== "http" || error.status === null) {
    return "unknown"; // no answer, or an answer that could not be read: it may have applied
  }
  if ((kind === "postMessage" || kind === "startRun") && error.staleVersion) {
    return "notApplied";
  }
  if (uncertain) {
    return "unknown"; // a temporary refusal now does not fence an earlier attempt that may still apply
  }
  if (kind === "startRun" && (error.runtimeUnconfigured || error.runActive)) {
    return "notApplied";
  }
  if (error.code === null || error.ruleId === "api.idempotency_mismatch") {
    return "unknown";
  }
  return error.status >= 400 && error.status < 500 ? "notApplied" : "unknown";
}

function newKey(): string {
  return crypto.randomUUID();
}

export class WriteLedger {
  private entries: readonly WriteEntry[] = [];
  private nextId = 1;
  private readonly listeners = new Set<() => void>();
  private readonly settledListeners = new Set<(entry: WriteEntry) => void>();
  private readonly timeoutMs: number;
  private readonly unsubscribe: () => void;

  constructor(private readonly session: LedgerSession, options: { timeoutMs?: number } = {}) {
    this.timeoutMs = options.timeoutMs ?? REQUEST_TIMEOUT_MS;
    this.unsubscribe = session.subscribe(() => {
      this.dropStale();
    });
  }

  readonly getSnapshot = (): readonly WriteEntry[] => this.entries;

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  /** Called when an entry settles while the view that sent it is still current (never for a late result). */
  onSettled(listener: (entry: WriteEntry) => void): () => void {
    this.settledListeners.add(listener);
    return () => {
      this.settledListeners.delete(listener);
    };
  }

  hasUnresolved(): boolean {
    return this.entries.some(isUnresolved);
  }

  /** Entries of `context` only (optionally one kind on one case); never another principal's or workspace's. */
  entriesFor(context: ExpectedContext | null, kind?: WriteKind, caseId?: string | null): WriteEntry[] {
    return this.entries.filter((entry) => sameContext(entry.context, context)
      && (kind === undefined || entry.kind === kind) && (caseId === undefined || entry.caseId === caseId));
  }

  /**
   * Record and send a new operation under the current ready view. Synchronous until the request is handed to fetch,
   * so a second activation finds the first entry. A settled entry of the same kind on the same case is replaced.
   */
  begin(spec: WriteSpec): { entry: WriteEntry } | { refused: BeginRefusal } {
    const scope = this.session.scope();
    const context = scope.context;
    const state = this.session.getState();
    if (context === null || state.status !== "ready" || !this.session.isCurrent(scope)) {
      return { refused: "noContext" };
    }
    const same = this.entries.filter((entry) => sameContext(entry.context, context) && entry.kind === spec.kind
      && (spec.kind === "decision" ? entry.proposalId === spec.decision.proposalId
        && entry.proposalVersion === spec.decision.payload.proposal_version
        : entry.caseId === spec.caseId && (entry.runId ?? null) === (spec.runId ?? null)));
    if (same.some(isUnresolved)) {
      return { refused: "duplicate" };
    }
    let kept = this.entries.filter((entry) => !same.includes(entry));
    while (kept.length >= MAX_WRITES) {
      const oldestSettled = kept.find((entry) => !isUnresolved(entry));
      if (oldestSettled === undefined) {
        return { refused: "capacity" };
      }
      kept = kept.filter((entry) => entry !== oldestSettled);
    }
    const decision = spec.decision == null ? null : Object.freeze({ proposalId: spec.decision.proposalId,
      consentId: spec.decision.consentId, payload: Object.freeze({ ...spec.decision.payload }) });
    const entry: WriteEntry = {
      id: this.nextId, key: newKey(), kind: spec.kind, context, generation: state.generation, caseId: spec.caseId,
      runId: spec.runId ?? null, decision, proposalId: decision?.proposalId ?? null,
      proposalVersion: decision?.payload.proposal_version ?? null,
      ifMatch: spec.ifMatch, payload: spec.kind === "postMessage" ? spec.payload : null, phase: "inFlight",
      uncertain: false, attempts: 1, result: null, failure: null, replayed: false,
    };
    this.nextId += 1;
    this.entries = [...kept, entry];
    this.emit();
    this.dispatch(entry, scope);
    return { entry };
  }

  /** Whether `retry` would send: the entry is unknown, its context is the visible one, and its request is intact. */
  canRetry(entry: WriteEntry): boolean {
    const scope = this.session.scope();
    return entry.phase === "unknown" && sameContext(entry.context, scope.context)
      && (entry.kind !== "postMessage" || entry.payload !== null)
      && (entry.kind !== "decision" || entry.decision != null);
  }

  /** Explicitly send the identical request again (same key, body and If-Match). It may apply the operation now. */
  retry(id: number): boolean {
    const entry = this.entries.find((candidate) => candidate.id === id);
    if (entry === undefined || !this.canRetry(entry)) {
      return false;
    }
    const scope = this.session.scope();
    const state = this.session.getState();
    if (state.status !== "ready" || !this.session.isCurrent(scope)) {
      return false;
    }
    // A start or a new case may be retried in a later view of the same context; its results belong to that view.
    const next: WriteEntry = { ...entry, phase: "inFlight", attempts: entry.attempts + 1, result: null,
                               failure: null, generation: state.generation };
    this.replace(next);
    this.dispatch(next, scope);
    return true;
  }

  /** Remove a settled entry once its view has shown it. Unresolved entries cannot be removed. */
  consume(id: number): void {
    const entry = this.entries.find((candidate) => candidate.id === id);
    if (entry !== undefined && !isUnresolved(entry)) {
      this.entries = this.entries.filter((candidate) => candidate !== entry);
      this.emit();
    }
  }

  /** A canonical read can confirm the identical natural-key decision after a lost response. */
  confirmDecision(value: Decision): void {
    const scope = this.session.scope();
    for (const entry of this.entries) {
      if (entry.phase !== "unknown" || entry.decision == null || !this.session.isCurrent(scope)
          || entry.generation !== scope.generation || !sameContext(entry.context, scope.context)) continue;
      if (sameDecision(value, entry.decision.proposalId, entry.decision.payload, entry.context)
          && value.scope.case_id === entry.caseId && value.scope.run_id === entry.runId && value.consent_id === entry.decision.consentId) {
        this.replace({ ...entry, phase: "applied", result: { kind: "decision", value }, decision: null, failure: null });
      }
    }
  }

  dispose(): void {
    this.unsubscribe();
  }

  private dispatch(entry: WriteEntry, scope: Scope): void {
    // Writes have their own signal: a session change does not abort them, so their late answer is still recorded.
    const options = { signal: new AbortController().signal, timeoutMs: this.timeoutMs, context: entry.context };
    const id = entry.id;
    let pending: Promise<Sent>;
    try {
      pending = this.send(entry, options);
    } catch (error) {
      pending = Promise.reject(error instanceof Error ? error : new ApiError("malformed"));
    }
    pending.then(
      (sent) => {
        this.settle(id, scope, sent);
      },
      (error: unknown) => {
        this.settle(id, scope, { error: toApiError(error) });
      },
    );
  }

  private send(entry: WriteEntry, options: { signal: AbortSignal; timeoutMs: number; context: ExpectedContext },
  ): Promise<Sent> {
    const { key, caseId, ifMatch } = entry;
    if (entry.kind === "decision" && entry.decision != null) {
      const binding = entry.decision;
      return decide(binding.proposalId, binding.payload, options).then((written) => {
        if (written.value.scope.case_id !== entry.caseId || written.value.scope.run_id !== entry.runId
            || written.value.consent_id !== binding.consentId) throw new ApiError("malformed");
        return { result: { kind: "decision", value: written.value }, replayed: written.replayed };
      });
    }
    if (entry.kind === "createCase") {
      return createCase(key, options).then((written) => ({
        result: { kind: "createCase", value: written.value }, replayed: written.replayed }));
    }
    if (entry.kind === "cancelRun" && caseId !== null && entry.runId != null) {
      return cancelRun(entry.runId, caseId, key, options).then((written) => ({
        result: { kind: "cancelRun", value: written.value }, replayed: written.replayed }));
    }
    if (caseId === null || ifMatch === null) {
      return Promise.reject(new ApiError("malformed"));
    }
    if (entry.kind === "startRun") {
      return startRun(caseId, key, ifMatch, options).then((written) => ({
        result: { kind: "startRun", value: written.value }, replayed: written.replayed }));
    }
    const payload = entry.payload;
    if (payload === null) {
      return Promise.reject(new ApiError("malformed"));
    }
    return postMessage(caseId, payload, key, ifMatch, options).then((written) => ({
      result: { kind: "postMessage", value: written.value }, replayed: written.replayed }));
  }

  private settle(id: number, scope: Scope, outcome: Sent | { error: ApiError }): void {
    const entry = this.entries.find((candidate) => candidate.id === id);
    if (entry === undefined || entry.phase !== "inFlight") {
      return;
    }
    // Results and failures are kept only for the view that sent the request; a late answer records its phase.
    const current = this.session.isCurrent(scope) && entry.generation === scope.generation
      && sameContext(entry.context, scope.context);
    const resource = `write:${entry.kind}`;
    let next: WriteEntry;
    if ("result" in outcome) {
      next = { ...entry, phase: "applied", replayed: outcome.replayed, result: current ? outcome.result : null, failure: null,
               payload: null, decision: null };
    } else {
      const phase = failedAttemptOutcome(entry.kind, entry.uncertain, outcome.error);
      next = { ...entry, phase, uncertain: entry.uncertain || phase === "unknown", result: null,
               failure: current ? outcome.error : null,
               payload: current && phase === "unknown" ? entry.payload : null,
               decision: current && phase === "unknown" ? entry.decision ?? null : null };
    }
    this.replace(next);
    if (!current) {
      return;
    }
    for (const listener of [...this.settledListeners]) {
      listener(next);
    }
    if ("result" in outcome) {
      this.session.reportSuccess(scope, resource);
    } else if (outcome.error.unauthenticated) {
      this.session.reportUnauthenticated(scope, resource);
    } else if (outcome.error.contextChanged) {
      this.session.reportContextChanged(scope, outcome.error, resource);
    }
  }

  private dropStale(): void {
    const state = this.session.getState();
    const visible = state.status === "ready" ? expectedContextOf(state.me) : null;
    const entries = this.entries.map((entry) => {
      const keep = state.status === "ready" && state.generation === entry.generation
        && sameContext(entry.context, visible);
      if (keep || (entry.payload === null && entry.decision == null && entry.result === null && entry.failure === null)) {
        return entry;
      }
      return { ...entry, payload: null, decision: null, result: null, failure: null };
    });
    if (entries.some((entry, index) => entry !== this.entries[index])) {
      this.entries = entries;
      this.emit();
    }
  }

  private replace(next: WriteEntry): void {
    this.entries = this.entries.map((entry) => (entry.id === next.id ? next : entry));
    this.emit();
  }

  private emit(): void {
    for (const listener of [...this.listeners]) {
      listener();
    }
  }
}
