import { useEffect, useState } from "react";
import { useSessionController } from "../session/SessionProvider";
import { observeRun, type Observation } from "./observer";

export function useRunObservation(caseId: string, runId: string, revision = 0): Observation {
  const controller = useSessionController();
  const [observation, setObservation] = useState<Observation>({ activity: null, phase: "hydrating", error: null });
  useEffect(() => {
    const captured = controller.scope();
    let local = new AbortController();
    const resource = `activity:${runId}`;
    const start = (): void => {
      if (captured.context === null || !controller.isCurrent(captured)) return;
      void observeRun(caseId, runId, { context: captured.context, signal: local.signal }, (next) => {
        if (local.signal.aborted || !controller.isCurrent(captured)) return;
        if (next.error?.unauthenticated === true) controller.reportUnauthenticated(captured, resource);
        else if (next.error?.contextChanged === true) controller.reportContextChanged(captured, next.error, resource);
        else {
          if (next.error === null && next.activity !== null) controller.reportSuccess(captured, resource);
          setObservation(next);
        }
      });
    };
    const abort = (): void => { local.abort(); };
    const visibility = (): void => {
      local.abort();
      if (document.visibilityState === "visible") { local = new AbortController(); start(); }
      else setObservation((v) => ({ ...v, phase: "paused" }));
    };
    captured.signal.addEventListener("abort", abort, { once: true });
    document.addEventListener("visibilitychange", visibility);
    if (!captured.signal.aborted && document.visibilityState !== "hidden") start();
    return () => {
      local.abort(); captured.signal.removeEventListener("abort", abort);
      document.removeEventListener("visibilitychange", visibility);
    };
  }, [controller, caseId, runId, revision]);
  return observation;
}
