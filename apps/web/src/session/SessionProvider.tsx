import { createContext, use, useEffect, useState, useSyncExternalStore, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router";

import { ApiError, toApiError, type BoundRequestOptions } from "../api/client";
import { SessionController, type SessionState } from "./controller";

const SessionContext = createContext<SessionController | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [controller] = useState(() => new SessionController());

  useEffect(() => controller.onRouteReset((path) => {
    void navigate(path, { replace: true });
  }), [controller, navigate]);

  useEffect(() => {
    controller.trackPath(location.pathname);
  }, [controller, location.pathname]);

  useEffect(() => {
    controller.boot();
    return () => {
      controller.dispose();
    };
  }, [controller]);

  useEffect(() => {
    const onVisibility = (): void => {
      if (document.visibilityState === "visible") {
        controller.refresh();
      }
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [controller]);

  return <SessionContext value={controller}>{children}</SessionContext>;
}

export function useSessionController(): SessionController {
  const controller = use(SessionContext);
  if (controller === null) {
    throw new Error("useSessionController must be used inside SessionProvider");
  }
  return controller;
}

export function useSessionState(): SessionState {
  const controller = useSessionController();
  return useSyncExternalStore(controller.subscribe, controller.getState);
}

export type Resource<T> =
  | { status: "loading" }
  | { status: "ready"; data: T }
  | { status: "failed"; error: ApiError };

const LOADING = { status: "loading" } as const;

/**
 * Load workspace-bound data under the current session generation, with the expected context captured in the same
 * scope (never read again at dispatch). A result is applied only if the component is still mounted for the same
 * request and the generation is still current; a 401 or a 409 context_changed is reported to the session (which
 * ignores stale ones and reconciles at most once per incident); other failures, ordinary conflicts included, stay
 * with the resource. `key` names the resource to the session: only its own success closes a recovery its refusal
 * opened. `load` must be stable (defined at module level or memoized).
 */
export function useSessionResource<T>(load: (options: BoundRequestOptions) => Promise<T>, key: string,
): { resource: Resource<T>; reload: () => void } {
  const controller = useSessionController();
  const [attempt, setAttempt] = useState(0);
  const [settled, setSettled] = useState<{ token: string; result: Resource<T> } | null>(null);
  const token = `${key}\n${String(attempt)}`;

  useEffect(() => {
    const scope = controller.scope();
    const local = new AbortController();
    const abort = (): void => {
      local.abort();
    };
    scope.signal.addEventListener("abort", abort, { once: true });
    if (scope.signal.aborted) {
      local.abort();
    }
    const live = (): boolean => !local.signal.aborted && controller.isCurrent(scope);
    const context = scope.context;
    const pending = context === null
      ? Promise.reject(new ApiError("malformed")) // no valid context to bind: nothing is sent
      : load({ signal: local.signal, context });
    pending.then(
      (data) => {
        if (live()) {
          controller.reportSuccess(scope, key);
          setSettled({ token, result: { status: "ready", data } });
        }
      },
      (error: unknown) => {
        if (!live()) {
          return;
        }
        const failure = toApiError(error);
        if (failure.unauthenticated) {
          controller.reportUnauthenticated(scope, key);
        } else if (failure.contextChanged) {
          controller.reportContextChanged(scope, failure, key);
        } else {
          setSettled({ token, result: { status: "failed", error: failure } });
        }
      },
    );
    return () => {
      scope.signal.removeEventListener("abort", abort);
      local.abort();
    };
  }, [controller, key, load, token]);

  const resource: Resource<T> = settled !== null && settled.token === token ? settled.result : LOADING;
  return {
    resource,
    reload: () => {
      setAttempt((value) => value + 1);
    },
  };
}
