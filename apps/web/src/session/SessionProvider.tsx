import { createContext, use, useEffect, useState, useSyncExternalStore, type ReactNode } from "react";
import { useLocation } from "react-router";

import { ApiError, toApiError, type RequestOptions } from "../api/client";
import { SessionController, type SessionState } from "./controller";

const SessionContext = createContext<SessionController | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const location = useLocation();
  const [controller] = useState(() => new SessionController());

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
 * Load data under the current session generation. A result is applied only if the component is still mounted for
 * the same request and the generation is still current; a 401 is reported to the session (which ignores stale ones).
 * `load` must be stable (defined at module level or memoized).
 */
export function useSessionResource<T>(load: (options: RequestOptions) => Promise<T>, key: string,
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
    load({ signal: local.signal }).then(
      (data) => {
        if (live()) {
          setSettled({ token, result: { status: "ready", data } });
        }
      },
      (error: unknown) => {
        if (!live()) {
          return;
        }
        const failure = toApiError(error);
        if (failure.unauthenticated) {
          controller.reportUnauthenticated(scope);
        } else {
          setSettled({ token, result: { status: "failed", error: failure } });
        }
      },
    );
    return () => {
      scope.signal.removeEventListener("abort", abort);
      local.abort();
    };
  }, [controller, load, token]);

  const resource: Resource<T> = settled !== null && settled.token === token ? settled.result : LOADING;
  return {
    resource,
    reload: () => {
      setAttempt((value) => value + 1);
    },
  };
}
