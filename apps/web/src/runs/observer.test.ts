/* eslint-disable @typescript-eslint/require-await -- Scripted asynchronous ports intentionally settle immediately. */
import { expect, test } from "vitest";
import { ApiError } from "../api/client";
import { CASE, CONTEXT, RUN_ID, committed, event, run, snapshot } from "../test/runFixtures";
import type { RunSnapshot } from "./contracts";
import { observeRun, type Observation, type ObservationIO } from "./observer";
import type { StreamItem } from "./stream";

function harness() {
  const abort = new AbortController();
  if (CONTEXT === null) throw new Error("fixture");
  const context = CONTEXT;
  const states: Observation[] = [];
  const cursors: number[] = [];
  const waits: number[] = [];
  const io: ObservationIO = {
    snapshot: async () => snapshot(),
    stream: async function* (_scope, after) { cursors.push(after); yield* [] as StreamItem[]; },
    wait: async (ms) => { waits.push(ms); if (waits.length > 10) abort.abort(); }, random: () => 0,
  };
  const execute = () => observeRun(CASE.case_id, RUN_ID, { context, signal: abort.signal }, (s) => { states.push(s); }, io);
  return { abort, states, cursors, waits, io, execute };
}
test("a 1/3 arrival gap replays after 1, discards 3, and fills 2 before displaying 3", async () => {
  const h = harness();
  let reads = 0, connects = 0;
  h.io.snapshot = async () => reads++ === 0 ? snapshot() : snapshot({ highwater: 3,
    run: run({ state: "succeeded", event_highwater: 3 }), events: [event(1), event(2), event(3)] });
  h.io.stream = async function* (_scope, after) {
    h.cursors.push(after);
    const items = connects++ === 0 ? [event(1), event(3)] : [event(1), event(2), event(3)];
    for (const value of items) yield { kind: "event", value };
  };
  await h.execute();
  expect(h.cursors).toEqual([0, 1]);
  const final = h.states.at(-1);
  expect(final?.phase).toBe("settled");
  expect(final?.activity?.events.map((e) => e.sequence)).toEqual([1, 2, 3]);
});
test("EOF refreshes authorization and drops protected activity on 403", async () => {
  const h = harness();
  let reads = 0;
  h.io.snapshot = async () => { if (reads++ > 0) throw new ApiError("http", 403); return snapshot(); };
  await h.execute();
  expect(reads).toBe(2);
  expect(h.states.at(-1)).toMatchObject({ phase: "blocked", activity: null, error: { status: 403 } });
});
test.each([new ApiError("http", 401), new ApiError("http", 409, "context_changed"), new ApiError("http", 404)])(
  "auth/context/resource refusals stop automatic recovery", async (error) => {
    const h = harness();
    h.io.stream = async function* () { yield* [] as StreamItem[]; throw error; };
    await h.execute();
    expect(h.waits).toEqual([]); expect(h.states.at(-1)?.activity).toBeNull();
  });
test("retention 409 rehydrates with a gap marker then resumes after the new highwater", async () => {
  const h = harness();
  let reads = 0, connects = 0;
  const fresh: RunSnapshot = snapshot({ highwater: 10, retention_floor: 8, projections_complete: false,
    run: run({ event_highwater: 10, state: "succeeded" }), events: [event(9), event(10)] });
  h.io.snapshot = async () => reads++ === 0 ? snapshot() : fresh;
  h.io.stream = async function* (_scope, after) {
    h.cursors.push(after);
    yield* [] as StreamItem[];
    if (connects++ === 0) throw new ApiError("http", 409, "conflict", null, null, false, "api.event_gap_resync_required");
  };
  h.io.wait = async () => { h.abort.abort(); };
  await h.execute();
  expect(h.cursors).toEqual([0, 10]);
  expect(h.states.some((s) => s.activity?.historyGap === true)).toBe(true);
});
test("three no-progress resyncs block and reconnect controls back off exponentially", async () => {
  const h = harness();
  h.io.stream = async function* () { yield { kind: "resync" }; };
  await h.execute();
  expect(h.states.at(-1)?.phase).toBe("blocked");
  const b = harness();
  b.io.stream = async function* () { yield { kind: "reconnect" }; };
  b.io.wait = async (ms) => { b.waits.push(ms); if (b.waits.length === 7) b.abort.abort(); };
  await b.execute();
  expect(b.waits).toEqual([1000, 2000, 4000, 8000, 16000, 30000, 30000]);
});
test("cancelled EOF continues read observation and replays a late receipt", async () => {
  const h = harness();
  let reads = 0, connects = 0, waits = 0;
  const initial = snapshot({ run: run({ state: "cancelled" }) });
  const late = snapshot({ highwater: 1, run: run({ state: "cancelled", event_highwater: 1 }),
    events: [committed(1)], latest_execution: committed(1) });
  h.io.snapshot = async () => reads++ < 2 ? initial : late;
  h.io.stream = async function* () { if (connects++ > 0) yield { kind: "event", value: committed(1) }; };
  h.io.wait = async (ms) => { h.waits.push(ms); if (++waits >= 2) h.abort.abort(); };
  await h.execute();
  const a = h.states.at(-1)?.activity;
  expect(a?.run.state).toBe("cancelled"); expect(a?.latestExecution).toEqual(committed(1));
  expect(h.waits).toEqual([5000, 5000]);
});
