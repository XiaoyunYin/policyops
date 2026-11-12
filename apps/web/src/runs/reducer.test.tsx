import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test } from "vitest";
import { ApiError } from "../api/client";
import { committed, event, review, run, snapshot } from "../test/runFixtures";
import { ActivityTimeline } from "./ActivityTimeline";
import { parseEvent } from "./contracts";
import { ActivityGap, append, hydrate, needsObservation } from "./reducer";

test("ordered replay ignores duplicates and rejects a gap without displaying the early event", () => {
  const a = append(hydrate(snapshot()), [event(1)]);
  expect(() => append(a, [event(3)])).toThrow(ActivityGap);
  expect(a.cursor).toBe(1);
  const b = append(a, [event(1), event(2), event(3)]);
  expect(b.events.map((e) => e.sequence)).toEqual([1, 2, 3]);
  expect(() => append(b, [event(2, { type: "run.state_changed", previous: "running", current: "failed" })])).toThrow(ApiError);
  expect(() => append(b, [{ ...event(4), event_id: event(2).event_id }])).toThrow(ApiError);
});
test("10,000 activities retain 500/render 100, preserve pinned truth, and allow history keyboard navigation", async () => {
  const user = userEvent.setup();
  let a = append(hydrate(snapshot()), [committed(1)]);
  for (let i = 2; i <= 10000; i++) a = append(a, [event(i)]);
  expect(a.events).toHaveLength(500);
  expect(a.latestExecution).toEqual(committed(1));
  const view = render(<ActivityTimeline activity={a} />);
  const list = screen.getByRole("list", { name: "Investigation activity" });
  expect(within(list).getAllByRole("listitem")).toHaveLength(100);
  const earlier = screen.getByRole("button", { name: "Earlier" });
  earlier.focus(); await user.keyboard("{Enter}");
  const before = within(list).getAllByRole("listitem")[0]?.textContent;
  a = append(a, [event(10001)]);
  view.rerender(<ActivityTimeline activity={a} />);
  expect(within(list).getAllByRole("listitem")[0]?.textContent).toBe(before);
  expect(document.activeElement).toBe(earlier);
  expect(screen.getByRole("status").textContent).toContain("new activities");
  await user.click(screen.getByRole("button", { name: "Jump to latest" }));
  expect(list.textContent).toContain("10001");
});
test("snapshot projection merge is sequence ordered and does not replay projections as timeline entries", () => {
  const s = snapshot({ run: run({ event_highwater: 50 }), highwater: 50, events: [event(50)],
    latest_review: review(10, "unknown", 2), latest_execution: committed(40) });
  const a = hydrate(s);
  expect(a.latestExecution).toEqual(committed(40));
  expect(a.events).toEqual([event(50)]);
  const b = append(a, [review(51, "unknown", 1)]);
  expect(b.latestExecution).toEqual(committed(40));
  expect(b.latestReview).toEqual(review(10, "unknown", 2));
  const afterPurge = hydrate({ ...s, latest_execution: null, latest_review: null, projections_complete: false }, true, b);
  expect(afterPurge.latestExecution).toEqual(committed(40));
});
test("contradictory same-ledger revision and terminal facts become integrity failures", () => {
  const a = append(hydrate(snapshot()), [review(1, "unknown", 2)]);
  expect(() => append(a, [review(2, "succeeded", 2)])).toThrow(ApiError);
  const b = append(a, [committed(2)]);
  expect(() => append(b, [review(3, "reconciled", 3)])).toThrow(ApiError);
  const conflict = committed(3);
  if (conflict.payload.type !== "execution.changed") throw new Error("fixture");
  const payload = { ...conflict.payload, receipt_sha256: "e".repeat(64) };
  expect(() => append(b, [{ ...conflict, payload }])).toThrow(ApiError);
});
test("cancelled lifecycle stays cancelled through unknown and a late receipt", () => {
  let a = append(hydrate(snapshot()), [event(1, { type: "run.state_changed", previous: "running", current: "cancelled" })]);
  a = append(a, [review(2, "unknown", 1), committed(3)]);
  expect(a.run.state).toBe("cancelled");
  expect(a.latestExecution?.payload.type).toBe("execution.changed");
  expect(needsObservation(a)).toBe(true);
});
test("run success alone never installs an action result; unsupported positions advance without raw data", () => {
  let a = append(hydrate(snapshot()), [{ event_id: event(1).event_id, sequence: 1, event_type: "future", schema_version: "v2" }]);
  a = append(a, [event(2, { type: "run.state_changed", previous: "running", current: "succeeded" })]);
  expect(a.cursor).toBe(2); expect(a.latestExecution).toBeNull(); expect(a.latestReview).toBeNull();
  render(<ActivityTimeline activity={a} />);
  expect(screen.getByText("Unsupported activity event")).toBeTruthy();
  expect(screen.queryByText(/Action committed/)).toBeNull();
});
test("critical cross-field outcome validation rejects incomplete success", () => {
  const e = committed(1);
  if (e.payload.type !== "execution.changed") throw new Error("fixture");
  expect(() => parseEvent({ ...e, payload: { ...e.payload, receipt_sha256: null } }, e.scope)).toThrow(ApiError);
  const r = review(1, "succeeded", 1);
  if (r.payload.type !== "review.outcome") throw new Error("fixture");
  expect(() => parseEvent({ ...r, payload: { ...r.payload, decision_id: null } }, r.scope)).toThrow(ApiError);
});
