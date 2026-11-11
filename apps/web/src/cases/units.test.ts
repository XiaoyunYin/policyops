// Unit checks of the message text rules and the write ledger's bounds, with a minimal fake session.

import { describe, expect, test } from "vitest";

import { ApiError, expectedContextOf, type MeOut, type MessagePage, type MessageView } from "../api/client";
import { MAX_WRITES, WriteLedger, failedAttemptOutcome, type LedgerSession } from "../api/writes";
import type { Scope, SessionState } from "../session/controller";
import { FakeApi, me } from "../test/fakeApi";
import { MAX_MESSAGES, MAX_PREFIX, MAX_SUFFIX, addPosted, extendHistory } from "./CaseDetail";
import { checkMessageText } from "./text";

describe("message text mirrors the server's code-point and control rules", () => {
  test.each([
    ["a", 1, null],
    ["\t tab and\nnewline", 17, null],
    ["\u{1F600}".repeat(4000), 4000, null], // astral: 8000 UTF-16 units, 4000 code points
    ["\u{1F600}".repeat(4000) + "a", null, "tooLong"],
    ["x".repeat(4001), 4001, "tooLong"],
    ["", 0, "empty"],
    ["line\r\nbreak", 11, "control"],
    ["next\u0085line", 9, "control"],
    ["del\u007f", 4, "control"],
    ["c1 end\u009f", 7, "control"],
    ["nbsp ok", 7, null],
    ["lone \ud83d high", 11, "surrogate"],
    ["lone \ude00 low", 10, "surrogate"],
    ["swapped \ude00\ud83d", 10, "surrogate"],
  ])("%j", (text, codePoints, problem) => {
    expect(checkMessageText(text)).toEqual({ codePoints, problem });
  });
});

describe("one failed attempt and the whole operation", () => {
  const http = (status: number, code: ApiError["code"], ruleId: string | null): ApiError =>
    new ApiError("http", status, code, "detail", null, false, ruleId);

  test("refusals settle only a first attempt, except the permanent stale version", () => {
    const forbidden = http(403, "forbidden", "auth.role");
    expect(failedAttemptOutcome("postMessage", false, forbidden)).toBe("notApplied");
    expect(failedAttemptOutcome("postMessage", true, forbidden)).toBe("unknown");
    expect(failedAttemptOutcome("postMessage", true, http(409, "context_changed", null))).toBe("unknown");
    expect(failedAttemptOutcome("postMessage", true, http(409, "stale_version", "api.stale_version")))
      .toBe("notApplied");
    expect(failedAttemptOutcome("startRun", true, http(409, "stale_version", "api.stale_version")))
      .toBe("notApplied");
    // Temporary refusals after the replay lookup: a failed attempt stores no record, so they fence nothing earlier.
    for (const refusal of [http(503, "unavailable", "runtime.unconfigured"), http(409, "conflict", "api.run_active")]) {
      expect(failedAttemptOutcome("startRun", false, refusal)).toBe("notApplied");
      expect(failedAttemptOutcome("startRun", true, refusal)).toBe("unknown");
    }
    expect(failedAttemptOutcome("createCase", true, http(409, "stale_version", "api.stale_version")))
      .toBe("unknown");
    expect(failedAttemptOutcome("postMessage", false, http(409, "conflict", "api.idempotency_mismatch")))
      .toBe("unknown");
    expect(failedAttemptOutcome("startRun", false, new ApiError("http", 503))).toBe("unknown");
    expect(failedAttemptOutcome("postMessage", false, new ApiError("malformed", 201))).toBe("unknown");
  });
});

function readySession(profile: MeOut): LedgerSession {
  const signal = new AbortController().signal;
  const state: SessionState = { status: "ready", me: profile, generation: 1, notice: null };
  const scope: Scope = { generation: 1, signal, context: expectedContextOf(profile) };
  return {
    scope: () => scope, isCurrent: () => true, getState: () => state, subscribe: () => () => undefined,
    reportUnauthenticated: () => undefined, reportContextChanged: () => undefined, reportSuccess: () => undefined,
  };
}

describe("ledger duplicate activation", () => {
  test("a second activation in the same tick finds the first entry and sends nothing", () => {
    const api = new FakeApi();
    api.defer("POST", "/api/v1/cases");
    const ledger = new WriteLedger(readySession(me()));
    const spec = { kind: "createCase", caseId: null, ifMatch: null, payload: null } as const;
    expect("entry" in ledger.begin(spec)).toBe(true);
    expect(ledger.begin(spec)).toEqual({ refused: "duplicate" });
    expect(api.calls).toHaveLength(1);
    ledger.dispose();
  });
});

describe("ledger capacity", () => {
  test("never evicts unresolved writes and refuses the next one before any request", () => {
    const api = new FakeApi();
    const pending = Array.from({ length: MAX_WRITES }, () => api.defer("POST", "/api/v1/cases"));
    const ledger = new WriteLedger(readySession(me()));
    for (let index = 0; index < MAX_WRITES; index += 1) {
      const caseId = `c0000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`;
      expect("entry" in ledger.begin({ kind: "startRun", caseId, ifMatch: 1, payload: null })).toBe(true);
    }
    const calls = api.calls.length;
    expect(ledger.begin({ kind: "createCase", caseId: null, ifMatch: null, payload: null }))
      .toEqual({ refused: "capacity" });
    expect(api.calls.length).toBe(calls);
    expect(ledger.getSnapshot()).toHaveLength(MAX_WRITES);
    expect(pending).toHaveLength(MAX_WRITES);
    ledger.dispose();
  });
});

describe("bounded message history", () => {
  const caseId = "c0000000-0000-4000-8000-000000000091";
  const message = (sequence: number): MessageView => ({
    message_id: `f0000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`, case_id: caseId, sequence,
    source: "staff_note", entered_by: "11111111-1111-4111-8111-111111111111", text: `Message ${String(sequence)}`,
    text_sha256: "a".repeat(64), created_at: "2026-11-11T12:00:00Z",
  });
  const server = (total: number) => (after: number): MessagePage => {
    const items = Array.from({ length: Math.max(0, Math.min(200, total - after)) }, (_, index) =>
      message(after + index + 1));
    return { items, next_after_sequence: items.length === 200 ? (items.at(-1)?.sequence ?? null) : null };
  };
  const stored = (history: ReturnType<typeof extendHistory>): MessageView[] => [...history.prefix, ...history.suffix];
  const empty = extendHistory({ prefix: [], cursor: 0, more: false, capped: false, suffix: [] },
                              { items: [], next_after_sequence: null });

  test("the budgets add up to the overall cap", () => {
    expect(MAX_PREFIX + MAX_SUFFIX).toBe(MAX_MESSAGES);
  });

  test("refresh at the cap and 60 later posts never exceed the overall cap and keep the latest post", () => {
    let total = MAX_MESSAGES;
    let history = empty;
    for (let step = 0; step < 10 && !history.capped; step += 1) {
      history = extendHistory(history, server(total)(history.cursor));
    }
    expect(history.capped).toBe(true);
    expect(history.prefix).toHaveLength(MAX_PREFIX);
    history = extendHistory(history, server(total)(history.cursor)); // Refresh from the actual cursor
    expect(history.capped).toBe(true);
    expect(history.cursor).toBe(MAX_PREFIX);
    for (let index = 0; index < 60; index += 1) {
      total += 1;
      history = addPosted(history, message(total));
      if (index % 7 === 0) {
        history = extendHistory(history, server(total)(history.cursor));
      }
      expect(stored(history).length).toBeLessThanOrEqual(MAX_MESSAGES);
      expect(stored(history).some((known) => known.sequence === total)).toBe(true);
      expect(history.cursor).toBe(MAX_PREFIX); // never moved past messages that were not fetched
    }
    expect(history.suffix).toHaveLength(MAX_SUFFIX);
    expect(history.suffix.at(-1)?.sequence).toBe(total);
  });

  test("a full prefix with nothing more on the server keeps later posts in the suffix, contiguously", () => {
    let history = empty;
    for (let step = 0; step < 10 && (step === 0 || history.more); step += 1) {
      history = extendHistory(history, server(MAX_PREFIX)(history.cursor));
    }
    expect(history.prefix).toHaveLength(MAX_PREFIX);
    expect(history.capped).toBe(false);
    history = addPosted(history, message(MAX_PREFIX + 1));
    expect(history.prefix).toHaveLength(MAX_PREFIX);
    expect(history.suffix.map((known) => known.sequence)).toEqual([MAX_PREFIX + 1]);
    history = extendHistory(history, server(MAX_PREFIX + 1)(history.cursor));
    expect(history.capped).toBe(true);
    expect(stored(history)).toHaveLength(MAX_PREFIX + 1);
  });

  test("a refresh that fetches posted messages merges them out of the suffix", () => {
    let history = extendHistory(empty, server(3)(0));
    history = addPosted(history, message(6));
    history = addPosted(history, message(5));
    expect(history.suffix.map((known) => known.sequence)).toEqual([5, 6]);
    history = extendHistory(history, server(5)(history.cursor));
    expect(history.prefix.map((known) => known.sequence)).toEqual([1, 2, 3, 4, 5]);
    expect(history.suffix.map((known) => known.sequence)).toEqual([6]);
    history = extendHistory(history, server(7)(history.cursor));
    expect(history.prefix.map((known) => known.sequence)).toEqual([1, 2, 3, 4, 5, 6, 7]);
    expect(history.suffix).toEqual([]);
  });
});
