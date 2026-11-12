// Fetch SSE transport. Header and inactivity deadlines are distinct; no lifetime timeout on a healthy stream.
import { ApiError, EXPECTED_PRINCIPAL_HEADER, EXPECTED_WORKSPACE_HEADER, httpError,
  type BoundRequestOptions } from "../api/client";
import { bad, parseEvent, parseReplay, type ReplayItem, type Scope } from "./contracts";

export type StreamItem = { kind: "event"; value: ReplayItem } | { kind: "heartbeat" | "resync" | "reconnect" };
const LINE = 65536;
const BACKLOG = 131072;
const bytes = (v: string): number => new TextEncoder().encode(v).length;

/** Incremental parser, accepting LF/CRLF, split UTF-8 (decoded by the transport) and multiline data.
 * EOF discards unfinished frames. Identifier-only unsupported events never expose unknown content. */
export class SseParser {
  private pending = "";
  private data: string[] = [];
  private frameBytes = 0;
  private id: string | null = null;
  private event = "";
  constructor(private readonly scope: Scope) {}

  *feed(fragment: string): Generator<StreamItem> {
    // Transport supplies bounded decode fragments; do not retain a large read chunk as parser backlog.
    if (bytes(fragment) > BACKLOG) bad();
    this.pending += fragment;
    if (bytes(this.pending) + this.frameBytes > BACKLOG) bad();
    let newline: number;
    while ((newline = this.pending.indexOf("\n")) >= 0) {
      let line = this.pending.slice(0, newline);
      this.pending = this.pending.slice(newline + 1);
      if (line.endsWith("\r")) line = line.slice(0, -1);
      const length = bytes(line);
      if (length > LINE) bad();
      if (line === "") {
        const item = this.dispatch();
        this.data = []; this.frameBytes = 0; this.id = null; this.event = "";
        if (item !== null) yield item;
      } else if (line.startsWith(":")) {
        yield { kind: "heartbeat" };
      } else {
        this.frameBytes += length + 1;
        if (this.frameBytes > LINE) bad();
        const colon = line.indexOf(":");
        const name = colon < 0 ? line : line.slice(0, colon);
        let value = colon < 0 ? "" : line.slice(colon + 1);
        if (value.startsWith(" ")) value = value.slice(1);
        if (name === "data") this.data.push(value);
        else if (name === "id") { if (this.id !== null) bad(); this.id = value; }
        else if (name === "event") { if (this.event !== "") bad(); this.event = value; }
      }
    }
    if (bytes(this.pending) > LINE) bad();
  }

  private dispatch(): StreamItem | null {
    if (this.data.length === 0 && this.event === "" && this.id === null) return null;
    if (this.event === "resync" || this.event === "reconnect") {
      if (this.id !== null || this.data.join("\n") !== "{}") bad();
      return { kind: this.event };
    }
    if (this.id === null || !/^[1-9][0-9]{0,15}$/.test(this.id)) bad();
    const seq = Number(this.id);
    if (!Number.isSafeInteger(seq)) bad();
    let value: unknown;
    try { value = JSON.parse(this.data.join("\n")); } catch { return bad(); }
    const event = this.event === "unsupported" ? parseReplay(value, this.scope) : parseEvent(value, this.scope);
    if (event.sequence !== seq || ("payload" in event ? event.payload.type !== this.event : this.event !== "unsupported")) bad();
    return { kind: "event", value: event };
  }
}

/** Settle even if a fetch or reader ignores abort. Every detached rejection has a handler. */
export function bounded<T>(pending: Promise<T>, signal: AbortSignal, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const cleanup = (): void => { clearTimeout(timer); signal.removeEventListener("abort", abort); };
    const abort = (): void => { cleanup(); reject(new ApiError("cancelled")); };
    const timer = setTimeout(() => { cleanup(); reject(new ApiError("timeout")); }, Math.max(0, ms));
    if (signal.aborted) { pending.catch(() => undefined); abort(); return; }
    signal.addEventListener("abort", abort, { once: true });
    pending.then((v) => { cleanup(); resolve(v); }, (e: unknown) => { cleanup(); reject(e instanceof ApiError ? e : new ApiError("network")); });
  });
}
export function delay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const abort = (): void => { clearTimeout(timer); signal.removeEventListener("abort", abort); reject(new ApiError("cancelled")); };
    const timer = setTimeout(() => { signal.removeEventListener("abort", abort); resolve(); }, ms);
    if (signal.aborted) abort(); else signal.addEventListener("abort", abort, { once: true });
  });
}

export async function* streamEvents(scope: Scope, after: number, options: BoundRequestOptions,
                                     settings: { headerMs?: number; idleMs?: number } = {}): AsyncGenerator<StreamItem> {
  const local = new AbortController();
  const abort = (): void => { local.abort(); };
  options.signal.addEventListener("abort", abort, { once: true });
  if (options.signal.aborted) local.abort();
  const signal = local.signal;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let response: Response | undefined;
  try {
    const headers = new Headers({ Accept: "text/event-stream", "Last-Event-ID": String(after),
      [EXPECTED_PRINCIPAL_HEADER]: options.context.principalId, [EXPECTED_WORKSPACE_HEADER]: options.context.workspaceId });
    const fetchPending = fetch(`/api/v1/runs/${scope.run_id}/events`, { headers, credentials: "same-origin",
      cache: "no-store", redirect: "error", signal });
    // A late response still owns a body; cancel it when the header wait has already been abandoned.
    void fetchPending.then((v) => { if (signal.aborted) void v.body?.cancel().catch(() => undefined); }, () => undefined);
    response = await bounded(fetchPending, signal, settings.headerMs ?? 15000);
    if (!response.ok) {
      let body = "";
      const started = performance.now();
      if (response.body !== null) {
        reader = response.body.getReader();
        const decoder = new TextDecoder();
        while (body.length <= 65536) {
          const chunk = await bounded(reader.read(), signal, (settings.headerMs ?? 15000) - (performance.now() - started));
          if (chunk.done) break;
          if (chunk.value.length > 65536) break;
          body += decoder.decode(chunk.value, { stream: true });
        }
      }
      throw httpError(response.status, body.length <= 65536 ? body : "");
    }
    if (response.status !== 200 || response.headers.get("Content-Type")?.split(";")[0]?.trim() !== "text/event-stream"
        || response.body === null) bad();
    reader = response.body.getReader();
    const parser = new SseParser(scope);
    const decoder = new TextDecoder("utf-8", { fatal: true });
    const idleMs = settings.idleMs ?? 45000;
    let lastFrame = performance.now();
    let batch = 0;
    for (;;) {
      const chunk = await bounded(reader.read(), signal, idleMs - (performance.now() - lastFrame));
      if (chunk.done) return; // EOF is not evidence of completion; the controller re-reads canonical state.
      for (let i = 0; i < chunk.value.length; i += 8192) {
        if (signal.aborted) throw new ApiError("cancelled");
        let fragment: string;
        try { fragment = decoder.decode(chunk.value.subarray(i, i + 8192), { stream: true }); } catch { return bad(); }
        for (const item of parser.feed(fragment)) {
          lastFrame = performance.now();
          yield item;
          batch += 1;
          if (batch === 100) { batch = 0; await delay(0, signal); }
        }
      }
    }
  } finally {
    local.abort();
    options.signal.removeEventListener("abort", abort);
    if (reader !== undefined) {
      void reader.cancel().catch(() => undefined);
      try { reader.releaseLock(); } catch { /* A hostile reader may still have an abandoned pending read. */ }
    } else if (response?.body !== null) void response?.body?.cancel().catch(() => undefined);
  }
}
