import { ApiError, toApiError, type BoundRequestOptions } from "../api/client";
import { getSnapshot } from "./api";
import { scope, type RunSnapshot } from "./contracts";
import { ActivityGap, append, hydrate, isTerminal, needsObservation, type Activity } from "./reducer";
import { delay, streamEvents } from "./stream";

export type Phase = "hydrating" | "connecting" | "live" | "resyncing" | "backoff" | "settled" | "paused" | "blocked";
export interface Observation { activity: Activity | null; phase: Phase; error: ApiError | null }
export interface ObservationIO {
  snapshot: typeof getSnapshot;
  stream: typeof streamEvents;
  wait: typeof delay;
  random: () => number;
}
const DEFAULT_IO: ObservationIO = { snapshot: getSnapshot, stream: streamEvents, wait: delay, random: Math.random };

/** One owned observation, disposed by abort. Reads never retry a write. Injected IO makes recovery deterministic. */
export async function observeRun(caseId: string, runId: string, options: BoundRequestOptions,
  publish: (state: Observation) => void, io: ObservationIO = DEFAULT_IO): Promise<void> {
  const s = scope(options.context, caseId, runId);
  let activity: Activity | null = null;
  let failures = 0;
  let recoveries = 0;
  let lastRecovery = -1;
  let phase: Phase = "hydrating";
  const emit = (error: ApiError | null = null): void => {
    if (!options.signal.aborted) publish({ activity, phase, error });
  };
  const recover = (): void => {
    if (lastRecovery === activity?.cursor) recoveries += 1;
    else { recoveries = 1; lastRecovery = activity?.cursor ?? -1; }
    if (recoveries >= 3) throw new ApiError("malformed");
  };
  const install = (snapshot: RunSnapshot, gap: boolean): void => {
    if (activity !== null && snapshot.highwater < activity.cursor) throw new ApiError("malformed");
    activity = hydrate(snapshot, gap, activity ?? undefined); emit();
  };
  let mustHydrate = true;
  let gap = false;
  let polling = false;
  try {
    while (!options.signal.aborted) {
      try {
        if (mustHydrate) {
          phase = "hydrating"; emit();
          install(await io.snapshot(caseId, runId, options), gap);
          mustHydrate = false;
        }
        if (activity === null) throw new Error("Missing activity snapshot");
        if (polling) {
          phase = "settled"; emit();
          await io.wait(5000, options.signal);
          const fresh = await io.snapshot(caseId, runId, options);
          if (fresh.highwater > activity.cursor) { polling = false; continue; }
          install(fresh, activity.historyGap);
          continue;
        }
        phase = "connecting"; emit();
        let control: "resync" | "reconnect" | null = null;
        // Flush on a short timer too: a quiet stream must display a single event immediately.
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          for await (const item of io.stream(s, activity.cursor, options)) {
            phase = "live";
            if (item.kind === "event") {
              // Commit contiguous positions individually; publication is batched, never buffering gaps.
              const before: number = activity.cursor;
              activity = append(activity, [item.value]);
              if (activity.cursor > before) { failures = 0; recoveries = 0; }
              if (timer === undefined) timer = setTimeout(() => {
                timer = undefined;
                emit();
              }, 0);
            } else if (item.kind === "heartbeat") { failures = 0; emit(); }
            else { control = item.kind; break; }
          }
          emit();
        } finally { clearTimeout(timer); }
        if (control === "resync") {
          recover(); mustHydrate = true; gap = true; phase = "resyncing"; emit(); continue;
        }
        if (control === "reconnect") {
          phase = "backoff"; emit();
          await io.wait(Math.min(30000, 1000 * 2 ** Math.min(failures++, 5)) + io.random() * 250, options.signal);
          continue;
        }
        // Every EOF revalidates authorization and canonical state. EOF alone never means success.
        const fresh = await io.snapshot(caseId, runId, options);
        if (fresh.retention_floor > activity.cursor) { recover(); mustHydrate = true; gap = true; continue; }
        if (fresh.highwater > activity.cursor) { recover(); continue; }
        install(fresh, activity.historyGap);
        if (isTerminal(fresh.run)) {
          if (needsObservation(activity)) { polling = true; continue; }
          phase = "settled"; emit(); return;
        }
        phase = "backoff"; emit();
        await io.wait(Math.min(30000, 1000 * 2 ** Math.min(failures++, 5)) + io.random() * 250, options.signal);
      } catch (e) {
        if (options.signal.aborted as boolean) return;
        const error = toApiError(e);
        if (error.unauthenticated || error.contextChanged || error.status === 403 || error.status === 404) {
          activity = null; phase = "blocked"; emit(error); return;
        }
        if (e instanceof ActivityGap) { recover(); phase = "resyncing"; emit(); continue; }
        if (error.status === 409 && error.ruleId === "api.event_gap_resync_required") {
          recover(); mustHydrate = true; gap = true; phase = "resyncing"; emit(); continue;
        }
        if (error.kind === "malformed") {
          phase = "blocked"; emit(error);
          return;
        }
        // Initial hydration errors require an explicit retry; reconnect/poll failures back off.
        if (mustHydrate && activity === null) { phase = "blocked"; emit(error); return; }
        phase = "backoff"; emit(error);
        await io.wait(Math.min(30000, 1000 * 2 ** Math.min(failures++, 5)) + io.random() * 250, options.signal);
      }
    }
  } catch (e) {
    if (!options.signal.aborted) { phase = "blocked"; emit(toApiError(e)); }
  }
}
