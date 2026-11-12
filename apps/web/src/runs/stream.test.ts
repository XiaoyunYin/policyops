import { afterEach, describe, expect, test, vi } from "vitest";
import { ApiError } from "../api/client";
import { FakeApi, contextChanged, json, unauthenticated } from "../test/fakeApi";
import { CONTEXT, RUN_ID, SCOPE, byteStream, event, frame } from "../test/runFixtures";
import { SseParser, bounded, streamEvents, type StreamItem } from "./stream";

const options = (): { context: NonNullable<typeof CONTEXT>; signal: AbortSignal } => {
  if (CONTEXT === null) throw new Error("fixture");
  return { context: CONTEXT, signal: new AbortController().signal };
};
async function collect(source: AsyncIterable<StreamItem>): Promise<StreamItem[]> {
  const items: StreamItem[] = [];
  for await (const item of source) items.push(item);
  return items;
}
afterEach(() => { vi.useRealTimers(); });

describe("bounded SSE bytes", () => {
  test("split UTF-8, CRLF, multiline data, comments and partial EOF", async () => {
    const api = new FakeApi();
    const e = event(1);
    const data = JSON.stringify(e, null, 2).split("\n").map((v) => `data: ${v}`).join("\r\n");
    const wire = `: 😀 heartbeat\r\n\r\nid: 1\r\nevent: escalation.requested\r\n${data}\r\n\r\nid: 2\ndata: incomplete`;
    api.stream(`/api/v1/runs/${RUN_ID}/events`, () => byteStream(wire, 1));
    const items = await collect(streamEvents(SCOPE, 0, options()));
    expect(items).toEqual([{ kind: "heartbeat" }, { kind: "event", value: e }]);
    const request = api.calls[0];
    expect(request?.headers.get("PolicyOps-Expected-Workspace")).toBe(SCOPE.workspace_id);
    expect(request?.headers.get("PolicyOps-Expected-Principal")).toBe(CONTEXT?.principalId);
    expect(request?.headers.get("Last-Event-ID")).toBe("0");
    expect(request?.credentials).toBe("same-origin");
  });
  test("controls cannot carry a position; unsupported content is identifier-only", () => {
    const parser = new SseParser(SCOPE);
    const unsupported = { event_id: event(1).event_id, sequence: 1, event_type: "future", schema_version: "v2" };
    expect([...parser.feed(`id: 1\nevent: unsupported\ndata: ${JSON.stringify(unsupported)}\n\nevent: resync\ndata: {}\n\n`)]).toEqual([
      { kind: "event", value: unsupported }, { kind: "resync" },
    ]);
    expect(() => [...parser.feed("id: 2\nevent: reconnect\ndata: {}\n\n")]).toThrow(ApiError);
    expect(() => [...new SseParser(SCOPE).feed(`id: 1\nevent: unsupported\ndata: ${JSON.stringify({ ...unsupported, raw: "hidden" })}\n\n`)]).toThrow(ApiError);
  });
  test.each([
    ["wrong id", (e: ReturnType<typeof event>) => `id: 2\nevent: ${e.payload.type}\ndata: ${JSON.stringify(e)}\n\n`],
    ["wrong discriminant", (e: ReturnType<typeof event>) => `id: 1\nevent: run.stopped\ndata: ${JSON.stringify(e)}\n\n`],
    ["unknown event version", (e: ReturnType<typeof event>) => frame({ ...e, event_version: 2 } as never)],
    ["unsafe sequence", (e: ReturnType<typeof event>) => frame({ ...e, sequence: 9007199254740992 })],
    ["foreign scope", (e: ReturnType<typeof event>) => frame({ ...e, scope: { ...e.scope, case_id: RUN_ID } })],
  ] as const)("rejects %s", (_name, wire) => {
    expect(() => [...new SseParser(SCOPE).feed(wire(event(1))) ]).toThrow(ApiError);
  });
  test("bounds any line, frame and parser backlog", () => {
    expect(() => [...new SseParser(SCOPE).feed("x".repeat(65537))]).toThrow(ApiError);
    const parser = new SseParser(SCOPE);
    expect(() => {
      for (let i = 0; i < 10; i++) Array.from(parser.feed(`data: ${"x".repeat(8000)}\n`));
    }).toThrow(ApiError);
    expect(() => [...new SseParser(SCOPE).feed("x".repeat(131073))]).toThrow(ApiError);
  });
  test.each([unauthenticated, contextChanged, () => json(403, {}), () => json(404, {}), () => json(409, {})])(
    "retains typed refusal status", async (reply) => {
      const api = new FakeApi().on("GET", `/api/v1/runs/${RUN_ID}/events`, reply());
      await expect(collect(streamEvents(SCOPE, 0, options()))).rejects.toMatchObject({ kind: "http" });
      expect(api.calls).toHaveLength(1);
    });
  test("header timeout releases an abort-ignoring fetch; late body is cancelled", async () => {
    vi.useFakeTimers();
    const api = new FakeApi();
    const deferred = api.defer("GET", `/api/v1/runs/${RUN_ID}/events`);
    const cancel = vi.fn();
    const pending = collect(streamEvents(SCOPE, 0, options(), { headerMs: 10 }));
    const rejected = expect(pending).rejects.toMatchObject({ kind: "timeout" });
    await vi.advanceTimersByTimeAsync(11);
    await rejected;
    deferred.resolve(new Response(new ReadableStream({ cancel }), { headers: { "Content-Type": "text/event-stream" } }));
    await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
    expect(deferred.call?.signal?.aborted).toBe(true);
    expect(cancel).toHaveBeenCalledOnce();
  });
  test("idle timeout and abort release pending readers and timers", async () => {
    vi.useFakeTimers();
    const cancel = vi.fn();
    new FakeApi().stream(`/api/v1/runs/${RUN_ID}/events`, () => new ReadableStream({ cancel }));
    const pending = collect(streamEvents(SCOPE, 0, options(), { idleMs: 10 }));
    const rejected = expect(pending).rejects.toMatchObject({ kind: "timeout" });
    await vi.advanceTimersByTimeAsync(11); await rejected;
    expect(cancel).toHaveBeenCalledOnce();
    const local = new AbortController();
    const hang = bounded(new Promise<void>(() => undefined), local.signal, 1000);
    const aborted = expect(hang).rejects.toMatchObject({ kind: "cancelled" });
    local.abort(); await aborted;
    expect(vi.getTimerCount()).toBe(0);
  });
  test("large read chunks yield after 100 decoded events", async () => {
    const text = Array.from({ length: 10000 }, (_, i) => frame(event(i + 1))).join("");
    const api = new FakeApi().stream(`/api/v1/runs/${RUN_ID}/events`, () => byteStream(text, text.length));
    let processed = 0;
    let keyboardAt = -1;
    const keyboard = (): void => { keyboardAt = processed; };
    document.addEventListener("keydown", keyboard, { once: true });
    const timer = setTimeout(() => { document.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" })); }, 0);
    try {
      for await (const item of streamEvents(SCOPE, 0, options())) if (item.kind === "event") processed += 1;
      expect(processed).toBe(10000);
      expect(keyboardAt).toBeGreaterThan(0);
      expect(keyboardAt).toBeLessThan(10000);
      expect(api.calls[0]?.signal?.aborted).toBe(true);
    } finally { clearTimeout(timer); document.removeEventListener("keydown", keyboard); }
  });
});
