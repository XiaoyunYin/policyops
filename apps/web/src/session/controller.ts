// Session and workspace state machine, independent of React.
//
// Every context change (bootstrap, workspace switch, sign-out, expiry, a changed identity) starts a new generation:
// the previous generation's AbortController is aborted and a fresh one created. Work records the generation it
// started under and is applied only while that generation is current and unaborted, so a late success or a late 401
// from an earlier context is discarded even when the request ignored its abort signal.
//
// The switch and sign-out POSTs run under the new generation's live signal. Their outcome can be uncertain (no
// response, timeout): the server may have rotated or revoked the session anyway. An uncertain switch therefore reloads
// /me before any workspace is shown again, and an uncertain sign-out is reported as unconfirmed, never as "still
// signed in" or "signed out".
//
// A scope also carries the expected context (principal and workspace) of the view it was created for; workspace-bound
// requests send it, and the server refuses them with 409 context_changed when the shared session has moved on. Only
// that explicit refusal, or a 401 (an in-flight cookie another tab revoked), reconciles: the view is cleared at once,
// /me is reloaded once for the incident and the route returns to /cases.
//
// Automatic recovery is bounded per incident. A reconciliation records the generation it produced and the resource
// whose refusal started it. While that generation is current, only a success of that same resource closes the
// incident; a sibling resource succeeding does not, because the refused resource has not recovered. Any further 401
// or context_changed in that generation stops instead of reloading again: a 401 ends the session (expiry), a
// context_changed shows the refusal with an explicit "Reload session" action. Every other transition (boot or that
// explicit reload, a workspace switch, sign-out, a changed context found by refresh) starts a new generation, so the
// next refusal is a new incident. With an endpoint that keeps refusing, a view therefore costs at most one automatic
// /me reload. No earlier write is replayed automatically, least of all in a new context; resource reads are simply
// loaded again for the regenerated view.

import {
  ApiError,
  REQUEST_TIMEOUT_MS,
  expectedContextOf,
  getMe,
  logout,
  sameContext,
  selectWorkspace,
  toApiError,
  type ExpectedContext,
  type MeOut,
} from "../api/client";
import { safeReturnTo } from "./returnTo";

/** A failed workspace switch, shown once the server's current session has been reloaded. */
export interface SwitchNotice {
  kind: "switchFailed";
  workspaceName: string;
  error: ApiError;
}

/** The session changed in another window; the view was reloaded for the current one. Carries no earlier content. */
export interface ContextNotice {
  kind: "contextChanged";
}

export type SessionNotice = SwitchNotice | ContextNotice;

/** Where a reconciliation sends the router: an ID-bearing path belongs to the earlier context. */
export const LANDING_PATH = "/cases";

export type SessionState =
  | { status: "booting" }
  | { status: "bootFailed"; error: ApiError }
  | { status: "signedOut"; byUser: boolean }
  | { status: "noWorkspace"; me: MeOut; notice: SessionNotice | null }
  | { status: "chooseWorkspace"; me: MeOut; notice: SessionNotice | null }
  | { status: "ready"; me: MeOut; generation: number; notice: SessionNotice | null }
  | { status: "reconciling" }
  | { status: "switching"; workspaceName: string }
  | { status: "expired"; returnTo: string }
  | { status: "signingOut" }
  | { status: "signOutUnconfirmed" };

export interface Scope {
  readonly generation: number;
  readonly signal: AbortSignal;
  /** The ready view's principal and workspace when the scope was created; null outside a ready view. */
  readonly context: ExpectedContext | null;
}

type Reconciliation = { previous: ExpectedContext | null; changed: boolean };

/** An open automatic recovery: the generation the reconciliation produced and the resource that was refused. */
interface Recovery {
  readonly generation: number;
  readonly resource: string;
}

export interface SessionOptions {
  timeoutMs?: number;
}

export class SessionController {
  private state: SessionState = { status: "booting" };
  private generation = 0;
  private controller = new AbortController();
  private readonly listeners = new Set<() => void>();
  private readonly timeoutMs: number;
  /** Current local path, used as the sign-in return path when the session expires. */
  private path = "/";
  /** The open automatic recovery, until its refused resource succeeds in the generation it produced. */
  private recovery: Recovery | null = null;
  private routeReset: ((path: string) => void) | null = null;

  constructor(options: SessionOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? REQUEST_TIMEOUT_MS;
  }

  trackPath(path: string): void {
    this.path = path;
  }

  readonly getState = (): SessionState => this.state;

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  /** Navigation used to leave an earlier context's route (registered by the provider). */
  onRouteReset(navigate: (path: string) => void): () => void {
    this.routeReset = navigate;
    return () => {
      if (this.routeReset === navigate) {
        this.routeReset = null;
      }
    };
  }

  /** The current generation, its signal and the ready view's expected context, captured together. */
  scope(): Scope {
    const state = this.state;
    return { generation: this.generation, signal: this.controller.signal,
             context: state.status === "ready" ? expectedContextOf(state.me) : null };
  }

  isCurrent(scope: Scope): boolean {
    return scope.generation === this.generation && !scope.signal.aborted;
  }

  boot(): void {
    const scope = this.advance({ status: "booting" });
    void this.loadMe(scope, "signedOut", null);
  }

  /**
   * A data request under `scope` was refused with 401 (ignored if `scope` is stale). The request may have carried a
   * cookie that another tab has since replaced, so /me is reloaded once before the session is declared ended.
   * `resource` identifies the refused request (the resource key), for the recovery bound described above.
   */
  reportUnauthenticated(scope: Scope, resource: string): void {
    if (this.isCurrent(scope) && this.state.status === "ready") {
      this.reconcile(scope, new ApiError("http", 401, "unauthenticated"), resource);
    }
  }

  /** A bound request under `scope` was refused with 409 context_changed (ignored if `scope` is stale). */
  reportContextChanged(scope: Scope, error: ApiError, resource: string): void {
    if (this.isCurrent(scope) && this.state.status === "ready" && error.contextChanged) {
      this.reconcile(scope, error, resource);
    }
  }

  /**
   * A bound request for `resource` under `scope` succeeded. If it is the resource whose refusal opened the current
   * recovery, the reconciliation is confirmed and the incident closed; a sibling's success leaves it open.
   */
  reportSuccess(scope: Scope, resource: string): void {
    const recovery = this.recovery;
    if (this.isCurrent(scope) && recovery !== null && recovery.generation === scope.generation
        && recovery.resource === resource) {
      this.recovery = null;
    }
  }

  switchWorkspace(workspaceId: string): void {
    const state = this.state;
    if (state.status !== "ready" && state.status !== "chooseWorkspace") {
      return;
    }
    const target = state.me.workspaces.find((choice) => choice.workspace_id === workspaceId);
    if (target === undefined || (state.status === "ready" && state.me.workspace_id === workspaceId)) {
      return;
    }
    // Old workspace content is removed before the request is sent; the POST gets the new generation's live signal.
    const scope = this.advance({ status: "switching", workspaceName: target.name });
    void this.runSwitch(scope, workspaceId, target.name);
  }

  signOut(): void {
    const status = this.state.status;
    if (status === "booting" || status === "signingOut" || status === "signedOut" || status === "switching") {
      return;
    }
    const scope = this.advance({ status: "signingOut" });
    void this.runSignOut(scope);
  }

  /**
   * Re-check the session (e.g. when the tab becomes visible): another tab may have switched workspace, signed out or
   * signed in again. A changed identity or workspace starts a new generation; otherwise only roles are refreshed.
   */
  refresh(): void {
    const state = this.state;
    if (state.status !== "ready" && state.status !== "expired") {
      return;
    }
    const scope = this.scope();
    getMe(this.options(scope)).then(
      (me) => {
        if (!this.isCurrent(scope)) {
          return;
        }
        const current = this.state;
        if (current.status === "ready" && me.principal_id === current.me.principal_id
            && me.workspace_id === current.me.workspace_id
            && me.workspaces.some((choice) => choice.workspace_id === me.workspace_id)) {
          this.set({ ...current, me });
        } else if (current.status === "ready") {
          this.leaveRoute();
          this.advanceTo(me, { kind: "contextChanged" });
        } else if (current.status === "expired") {
          this.advanceTo(me, null);
        }
      },
      (error: unknown) => {
        // /me itself answered 401: there is nothing further to reconcile against.
        if (toApiError(error).unauthenticated && this.isCurrent(scope) && this.state.status === "ready") {
          this.expire();
        }
        // Other failures of a background check change nothing; the next request reports them.
      },
    );
  }

  /** Abort outstanding work (unmount). A later boot() starts again. */
  dispose(): void {
    this.generation += 1;
    this.controller.abort();
    this.controller = new AbortController();
  }

  private options(scope: Scope): { signal: AbortSignal; timeoutMs: number } {
    return { signal: scope.signal, timeoutMs: this.timeoutMs };
  }

  private set(next: SessionState): void {
    this.state = next;
    for (const listener of [...this.listeners]) {
      listener();
    }
  }

  private advance(next: SessionState): Scope {
    this.controller.abort();
    this.generation += 1;
    this.controller = new AbortController();
    this.set(next);
    return this.scope();
  }

  private advanceTo(me: MeOut, notice: SessionNotice | null): void {
    this.controller.abort();
    this.generation += 1;
    this.controller = new AbortController();
    this.set(this.fromMe(me, notice));
  }

  private expire(): void {
    this.advance({ status: "expired", returnTo: safeReturnTo(this.path) });
  }

  private leaveRoute(): void {
    this.path = LANDING_PATH;
    this.routeReset?.(LANDING_PATH);
  }

  private reconcile(scope: Scope, error: ApiError, resource: string): void {
    if (this.recovery?.generation === scope.generation) {
      // This view came from a reconciliation whose refused resource has not succeeded since: stop here.
      this.recovery = null;
      if (error.unauthenticated) {
        this.expire();
      } else {
        this.advance({ status: "bootFailed", error });
      }
      return;
    }
    const previous = scope.context;
    const next = this.advance({ status: "reconciling" }); // clears the earlier view at once
    this.recovery = { generation: next.generation, resource };
    if (error.contextChanged) {
      this.leaveRoute();
    }
    void this.loadMe(next, "expired", null, { previous, changed: error.contextChanged });
  }

  private fromMe(me: MeOut, notice: SessionNotice | null): SessionState {
    if (me.workspaces.length === 0) {
      return { status: "noWorkspace", me, notice };
    }
    const selected = me.workspaces.some((choice) => choice.workspace_id === me.workspace_id);
    return selected
      ? { status: "ready", me, generation: this.generation, notice }
      : { status: "chooseWorkspace", me, notice };
  }

  private async loadMe(scope: Scope, onUnauthenticated: "signedOut" | "expired",
                       failedSwitch: { workspaceId: string; workspaceName: string; error: ApiError } | null,
                       reconciliation: Reconciliation | null = null,
  ): Promise<void> {
    let me: MeOut;
    try {
      me = await getMe(this.options(scope));
    } catch (error) {
      if (!this.isCurrent(scope)) {
        return;
      }
      const failure = toApiError(error);
      if (failure.unauthenticated) {
        if (onUnauthenticated === "expired") {
          this.expire();
        } else {
          this.set({ status: "signedOut", byUser: false });
        }
      } else {
        this.set({ status: "bootFailed", error: failure });
      }
      return;
    }
    if (!this.isCurrent(scope)) {
      return;
    }
    // After an uncertain switch, the reloaded session decides: if the target is now selected, the switch applied.
    let notice: SessionNotice | null = failedSwitch !== null && me.workspace_id !== failedSwitch.workspaceId
      ? { kind: "switchFailed", workspaceName: failedSwitch.workspaceName, error: failedSwitch.error }
      : null;
    if (reconciliation !== null
        && (reconciliation.changed || !sameContext(reconciliation.previous, expectedContextOf(me)))) {
      if (!reconciliation.changed) {
        this.leaveRoute();
      }
      notice = { kind: "contextChanged" };
    }
    this.set(this.fromMe(me, notice));
  }

  private async runSwitch(scope: Scope, workspaceId: string, workspaceName: string): Promise<void> {
    try {
      await selectWorkspace(workspaceId, this.options(scope));
    } catch (error) {
      if (!this.isCurrent(scope)) {
        return;
      }
      const failure = toApiError(error);
      if (failure.unauthenticated) {
        this.expire();
        return;
      }
      // Refused, lost or timed out: reload the authoritative session before showing any workspace again.
      await this.loadMe(scope, "expired", { workspaceId, workspaceName, error: failure });
      return;
    }
    if (this.isCurrent(scope)) {
      await this.loadMe(scope, "expired", null);
    }
  }

  private async runSignOut(scope: Scope): Promise<void> {
    try {
      await logout(this.options(scope));
    } catch (error) {
      if (!this.isCurrent(scope)) {
        return;
      }
      // 401: there is no valid session, so the user is signed out. Anything else may or may not have applied.
      this.set(toApiError(error).unauthenticated ? { status: "signedOut", byUser: true }
        : { status: "signOutUnconfirmed" });
      return;
    }
    if (this.isCurrent(scope)) {
      this.set({ status: "signedOut", byUser: true });
    }
  }
}
