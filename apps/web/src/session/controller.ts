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

import {
  ApiError,
  REQUEST_TIMEOUT_MS,
  getMe,
  logout,
  selectWorkspace,
  toApiError,
  type MeOut,
} from "../api/client";
import { safeReturnTo } from "./returnTo";

/** A failed workspace switch, shown once the server's current session has been reloaded. */
export interface SwitchNotice {
  workspaceName: string;
  error: ApiError;
}

export type SessionState =
  | { status: "booting" }
  | { status: "bootFailed"; error: ApiError }
  | { status: "signedOut"; byUser: boolean }
  | { status: "noWorkspace"; me: MeOut }
  | { status: "chooseWorkspace"; me: MeOut; notice: SwitchNotice | null }
  | { status: "ready"; me: MeOut; generation: number; notice: SwitchNotice | null }
  | { status: "switching"; workspaceName: string }
  | { status: "expired"; returnTo: string }
  | { status: "signingOut" }
  | { status: "signOutUnconfirmed" };

export interface Scope {
  readonly generation: number;
  readonly signal: AbortSignal;
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

  /** The current generation and its signal. */
  scope(): Scope {
    return { generation: this.generation, signal: this.controller.signal };
  }

  isCurrent(scope: Scope): boolean {
    return scope.generation === this.generation && !scope.signal.aborted;
  }

  boot(): void {
    const scope = this.advance({ status: "booting" });
    void this.loadMe(scope, "signedOut", null);
  }

  /** A data request under `scope` was refused with 401: the session ended (ignored if `scope` is stale). */
  reportUnauthenticated(scope: Scope): void {
    if (this.isCurrent(scope) && this.state.status === "ready") {
      this.expire();
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
        } else if (current.status === "ready" || current.status === "expired") {
          this.advanceTo(me, null);
        }
      },
      (error: unknown) => {
        if (toApiError(error).unauthenticated) {
          this.reportUnauthenticated(scope);
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

  private advanceTo(me: MeOut, notice: SwitchNotice | null): void {
    this.controller.abort();
    this.generation += 1;
    this.controller = new AbortController();
    this.set(this.fromMe(me, notice));
  }

  private expire(): void {
    this.advance({ status: "expired", returnTo: safeReturnTo(this.path) });
  }

  private fromMe(me: MeOut, notice: SwitchNotice | null): SessionState {
    if (me.workspaces.length === 0) {
      return { status: "noWorkspace", me };
    }
    const selected = me.workspaces.some((choice) => choice.workspace_id === me.workspace_id);
    return selected
      ? { status: "ready", me, generation: this.generation, notice }
      : { status: "chooseWorkspace", me, notice };
  }

  private async loadMe(scope: Scope, onUnauthenticated: "signedOut" | "expired",
                       failedSwitch: { workspaceId: string; workspaceName: string; error: ApiError } | null,
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
    const notice = failedSwitch !== null && me.workspace_id !== failedSwitch.workspaceId
      ? { workspaceName: failedSwitch.workspaceName, error: failedSwitch.error }
      : null;
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
