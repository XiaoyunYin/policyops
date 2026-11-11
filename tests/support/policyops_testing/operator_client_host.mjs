// Test-only Node host that runs the web app's actual API client (apps/web/src/api/client.ts) against a real Vite
// dev server and its /api proxy. Started and owned by policyops_testing.operator_client; not a product entry point.
//
// Usage: node operator_client_host.mjs <web-root>. The proxy target, cache and build directories come from the
// process environment exactly as for `npm run dev` (vite.config.ts is the unmodified production config; only the
// listen port is overridden to 0 so the OS chooses one). Protocol: one JSON object per line on stdin, one JSON
// reply per line on stdout; stderr carries bounded diagnostics. Credentials (the fixture session) arrive only over
// stdin and are never written to stdout, stderr or the wire log (the log records header presence and public IDs).
//
// Bounds: stdin is pulled (not buffered by readline) and framed with at most MAX_LINE bytes held per command; an
// over-long command is discarded to its newline and refused. At most MAX_BACKLOG commands wait; beyond that stdin is
// not read (stream backpressure). A reply over MAX_REPLY bytes is replaced by a small error. The wire log hashes at
// most MAX_TRACE_BYTES of a response body (every body the client's 1e6-character limit accepts fits); a longer or
// failed body read is marked and has no hash. Reading the traced copy is not deadline-bounded by this host: it
// ends with the body or with the client's own abort signal, and the copy tees at most MAX_TRACE_BYTES ahead.
//
// This is Node, not a browser: the fixture emulates the browser's Cookie and Origin headers and `document.cookie`
// (the readable CSRF cookie). It proves nothing about SameSite, CORS preflight or rendering.
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const MAX_LINE = 65_536;
export const MAX_BACKLOG = 4;
export const MAX_REPLY = 3_900_000;
export const MAX_TRACE_BYTES = 3_000_000; // >= 3 UTF-8 bytes for each of the client's 1e6 UTF-16 characters
const MAX_WIRE = 64;
const REQUEST_HEADERS = ["accept", "content-type", "idempotency-key", "if-match", "origin",
  "policyops-expected-principal", "policyops-expected-workspace"];
const RESPONSE_HEADERS = ["etag", "idempotent-replayed", "cache-control", "content-type", "referrer-policy",
  "x-content-type-options"];

const sha256 = (text) => createHash("sha256").update(text).digest("hex");
const diag = (text) => process.stderr.write(`${String(text).slice(0, 500)}\n`);

/** Serialise a reply, replacing one over `limit` bytes by a small refusal that keeps its id. */
export function encodeReply(value, limit = MAX_REPLY) {
  const line = `${JSON.stringify(value)}\n`;
  if (Buffer.byteLength(line) <= limit) { return line; }
  return `${JSON.stringify({ id: value?.id ?? null, ok: false, error: { name: "ReplyTooLarge" } })}\n`;
}

/** Newline framing that never holds more than `maxLine` bytes of one frame. `push(chunk)` returns the complete
 * frames in the chunk (`null` marks a discarded over-long frame); `end()` reports an unterminated tail. */
export function createFramer(maxLine = MAX_LINE) {
  let parts = [];
  let held = 0;
  let discarding = false;
  return {
    held: () => held,
    push(chunk) {
      const frames = [];
      let start = 0;
      while (start <= chunk.length) {
        const newline = chunk.indexOf(0x0a, start);
        const end = newline === -1 ? chunk.length : newline;
        if (!discarding && held + (end - start) > maxLine) { discarding = true; parts = []; held = 0; }
        if (!discarding && end > start) { parts.push(Buffer.from(chunk.subarray(start, end))); held += end - start; }
        if (newline === -1) { break; }
        frames.push(discarding ? null : Buffer.concat(parts, held).toString("utf8"));
        parts = []; held = 0; discarding = false;
        start = newline + 1;
      }
      return frames;
    },
    end() { const tail = held > 0 || discarding; parts = []; held = 0; discarding = false; return tail; },
  };
}

/** Hash at most `limit` bytes of a response copy. A body over the limit, or one whose read fails, gets no hash. */
export async function traceBody(stream, limit = MAX_TRACE_BYTES) {
  if (stream === null) { return { body_sha256: sha256(""), body_bytes: 0, body_complete: true }; }
  const hash = createHash("sha256");
  const reader = stream.getReader();
  let bytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) { return { body_sha256: hash.digest("hex"), body_bytes: bytes, body_complete: true }; }
      bytes += value.byteLength;
      if (bytes > limit) {
        reader.cancel().catch(() => {});
        return { body_sha256: null, body_bytes_at_least: bytes, body_complete: false, body_truncated: true };
      }
      hash.update(value);
    }
  } catch (error) {
    return { body_sha256: null, body_bytes_at_least: bytes, body_complete: false,
      body_read_error: String(error?.name).slice(0, 80) };
  }
}

async function main(webRoot) {
  const reply = (value) => process.stdout.write(encodeReply(value));
  const realFetch = globalThis.fetch;
  const fixture = { origin: null, sessionCookie: null, csrfCookie: null, wire: [], wireDropped: 0 };

  // The browser would add Cookie and Origin itself and resolve the relative path against the page origin. The
  // target is held to the owned front origin (and the /api prefix), and the client's own redirect: "error" is kept.
  globalThis.document = { get cookie() { return fixture.csrfCookie ?? ""; } };
  globalThis.fetch = async (input, init = {}) => {
    if (typeof input !== "string" || fixture.origin === null || fixture.sessionCookie === null) {
      throw new TypeError("fixture fetch: not configured or not a relative path");
    }
    const url = new URL(input, fixture.origin);
    if (url.origin !== fixture.origin || !url.pathname.startsWith("/api/") || init.redirect !== "error") {
      throw new TypeError("fixture fetch: target outside the owned front origin");
    }
    const headers = new Headers(init.headers);
    headers.set("Cookie", fixture.sessionCookie);
    const method = String(init.method ?? "GET");
    if (method !== "GET") {
      headers.set("Origin", fixture.origin);
    }
    const body = typeof init.body === "string" ? init.body : "";
    const entry = { method, path: `${url.pathname}${url.search}`, request: { headers: {}, body_sha256: sha256(body),
      body_bytes: Buffer.byteLength(body) }, status: null, response: { headers: {}, body_sha256: null,
      body_bytes: null } };
    for (const name of REQUEST_HEADERS) {
      if (headers.has(name)) { entry.request.headers[name] = headers.get(name); }
    }
    entry.request.has_cookie = headers.has("cookie");
    entry.request.has_csrf = headers.has("x-csrf-token");
    entry.request.csrf_matches_readable_cookie = headers.get("x-csrf-token") === (fixture.csrfValue ?? null);
    if (fixture.wire.length < MAX_WIRE) { fixture.wire.push(entry); } else { fixture.wireDropped += 1; }
    const response = await realFetch(url, { ...init, headers });
    entry.status = response.status;
    Object.assign(entry.response, await traceBody(response.clone().body));
    for (const name of RESPONSE_HEADERS) {
      if (response.headers.has(name)) { entry.response.headers[name] = response.headers.get(name); }
    }
    entry.response.sets_cookie = response.headers.has("set-cookie");
    return response;
  };

  const viteUrl = pathToFileURL(createRequire(path.join(webRoot, "package.json")).resolve("vite")).href;
  const { createServer } = await import(viteUrl);
  const stderrLogger = {
    hasWarned: false, info() {}, warn: diag, warnOnce: diag, error: diag, clearScreen() {}, hasErrorLogged: () => false,
  };
  const vite = await createServer({
    root: webRoot, configFile: path.join(webRoot, "vite.config.ts"), configLoader: "native", customLogger: stderrLogger,
    clearScreen: false, server: { port: 0, strictPort: false, open: false },
  });
  let closed = false;
  async function shutdown(code) {
    if (!closed) {
      closed = true;
      try { await vite.close(); } catch (error) { diag(`vite close failed: ${error?.name}`); code ||= 1; }
    }
    process.exit(code);
  }
  let client;
  try {
    await vite.listen();
    const address = vite.httpServer?.address();
    if (address === null || typeof address === "string" || address.address !== "127.0.0.1") {
      throw new Error("vite did not bind a loopback port");
    }
    fixture.origin = `http://127.0.0.1:${String(address.port)}`;
    // The actual client, executed (not reimplemented) through Vite's transform pipeline.
    client = await vite.ssrLoadModule("/src/api/client.ts");
  } catch (error) {
    diag(`startup failed: ${error?.name}: ${error?.message}`);
    await shutdown(3);
  }
  reply({ ready: true, origin: fixture.origin });

  const FUNCTIONS = {
    getMe: (a, o) => client.getMe(o),
    getCase: (a, o) => client.getCase(a.case_id, o),
    listCases: (a, o) => client.listCases(o, a.query ?? {}),
    listMessages: (a, o) => client.listMessages(a.case_id, a.after, o),
    createCase: (a, o) => client.createCase(a.key, o),
    postMessage: (a, o) => client.postMessage(a.case_id, a.message, a.key, a.if_match, o),
    startRun: (a, o) => client.startRun(a.case_id, a.key, a.if_match, o),
  };

  function describeError(error) {
    const known = error instanceof client.ApiError;
    return { api_error: known, kind: known ? error.kind : "other", status: known ? error.status : null,
      code: known ? error.code : null, rule_id: known ? error.ruleId : null, detail: known ? error.detail : null,
      retryable: known ? error.retryable : null, correlation_id: known ? error.correlationId : null,
      stale_version: known ? error.staleVersion : false, runtime_unconfigured: known ? error.runtimeUnconfigured : false,
      context_changed: known ? error.contextChanged : false, unauthenticated: known ? error.unauthenticated : false,
      name: known ? "ApiError" : String(error?.name).slice(0, 80) };
  }

  async function handle(command) {
    if (command.cmd === "session") {
      // `csrf` is the readable cookie's value; `session` the HttpOnly cookie's (never visible to the client code).
      fixture.sessionCookie = `${command.session_cookie_name}=${command.session}`;
      fixture.csrfCookie = `${command.csrf_cookie_name}=${command.csrf}`;
      fixture.csrfValue = command.csrf;
      return { ok: true };
    }
    if (command.cmd === "call") {
      const run = FUNCTIONS[command.fn];
      if (run === undefined) { return { ok: false, error: { name: "UnknownFunction" } }; }
      const args = command.args ?? {};
      const options = { signal: new AbortController().signal, timeoutMs: 15_000 };
      if (args.context !== undefined) {
        const context = client.expectedContextOf({ principal_id: args.context.principal_id,
          workspace_id: args.context.workspace_id, workspaces: [] });
        if (context === null) { return { ok: false, error: { name: "NoContext" } }; }
        options.context = context;
      }
      fixture.wire = [];
      fixture.wireDropped = 0;
      try {
        const value = await run(args, options);
        return { ok: true, value, wire: fixture.wire, wire_dropped: fixture.wireDropped };
      } catch (error) {
        return { ok: false, error: describeError(error), wire: fixture.wire, wire_dropped: fixture.wireDropped };
      }
    }
    if (command.cmd === "parse_me_context") {
      const context = client.expectedContextOf(client.parseMe(command.me));
      return { ok: true, value: context };
    }
    return { ok: false, error: { name: "UnknownCommand" } };
  }

  async function answer(line) {
    let id = null;
    try {
      if (line === null) { throw new RangeError("command too long"); }
      const command = JSON.parse(line);
      id = command.id ?? null;
      reply({ id, ...(await handle(command)) });
    } catch (error) {
      reply({ id, ok: false, error: { name: String(error?.name).slice(0, 80) } });
    }
  }

  // Pull stdin only while fewer than MAX_BACKLOG commands wait; commands run one at a time, in order.
  const framer = createFramer();
  const waiting = [];
  let pending = null; // frames of the last chunk not yet admitted to `waiting`
  let busy = false;
  let ended = false;
  function pump() {
    while (waiting.length < MAX_BACKLOG) {
      if (pending === null || pending.length === 0) {
        const chunk = process.stdin.read();
        if (chunk === null) { break; }
        pending = framer.push(chunk);
        continue;
      }
      waiting.push(pending.shift());
    }
    if (!busy && waiting.length > 0) {
      busy = true;
      answer(waiting.shift()).finally(() => { busy = false; pump(); });
    } else if (!busy && ended && waiting.length === 0 && (pending === null || pending.length === 0)) {
      if (framer.end()) { diag("stdin ended inside a command; it was discarded"); }
      void shutdown(0);
    }
  }
  process.stdin.on("readable", pump);
  process.stdin.on("end", () => { ended = true; pump(); });
}

if (import.meta.main) {
  const [webRoot] = process.argv.slice(2);
  if (!webRoot || !path.isAbsolute(webRoot)) {
    process.stderr.write("usage: node operator_client_host.mjs <absolute web root>\n");
    process.exit(2);
  }
  await main(webRoot);
}
