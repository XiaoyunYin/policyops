// Test-only fake of the API's fetch boundary, with typed contract fixtures. Fixtures are typed from the generated
// schema, so contract drift fails the type check. Requests are matched on method and path; one-shot replies (including
// deferred ones resolved later by the test) take precedence over standing replies. Unmatched requests fail.

import type { CasePage, CaseView, ErrorCode, ErrorEnvelope, MembershipOut, MeOut, Role, WorkspaceOut } from "../api/client";
import { installFake } from "./network";

export const WORKSPACE_A: WorkspaceOut = {
  workspace_id: "0a0a0a0a-0000-4000-8000-00000000000a", slug: "north", name: "North support", roles: ["analyst"],
};
export const WORKSPACE_B: WorkspaceOut = {
  workspace_id: "0b0b0b0b-0000-4000-8000-00000000000b", slug: "south", name: "South support", roles: ["analyst"],
};
export const PRINCIPAL = "11111111-1111-4111-8111-111111111111";
export const OTHER_PRINCIPAL = "22222222-2222-4222-8222-222222222222";

export function me(options: { roles?: Role[]; workspace?: WorkspaceOut | null; workspaces?: WorkspaceOut[];
                              principal?: string } = {}): MeOut {
  const roles = options.roles ?? ["analyst"];
  const workspaces = (options.workspaces ?? [WORKSPACE_A, WORKSPACE_B]).map((choice) => ({ ...choice, roles }));
  const workspace = options.workspace === undefined ? WORKSPACE_A : options.workspace;
  return { principal_id: options.principal ?? PRINCIPAL, workspace_id: workspace?.workspace_id ?? null, roles: workspace === null ? [] : roles,
           workspaces };
}

export function caseView(index: number, scenario: string): CaseView {
  return {
    case_id: `c0000000-0000-4000-8000-${String(index).padStart(12, "0")}`, scenario, status: "open",
    customer_bound: false, version: 1, created_at: "2026-11-01T09:00:00Z", updated_at: "2026-11-02T10:30:00Z",
  };
}

export function casePage(...items: CaseView[]): CasePage {
  return { items, next_cursor: null };
}

export function members(...entries: MembershipOut[]): MembershipOut[] {
  return entries;
}

export function envelope(code: ErrorCode, detail: string, retryable = false): ErrorEnvelope {
  return { code, detail, retryable, rule_id: null, correlation_id: "5f0c2d1e-7a3b-4c8d-9e6f-0123456789ab",
           schema_version: "policyops.error/v1" };
}

export function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

export function noContent(): Response {
  return new Response(null, { status: 204 });
}

export function unauthenticated(): Response {
  return json(401, envelope("unauthenticated", "Sign in again."));
}

export function contextChanged(): Response {
  return json(409, envelope("context_changed", "Your sign-in or selected workspace changed in another window, so this "
    + "request was not applied. Reload to continue."));
}

export interface RecordedCall {
  method: string;
  path: string;
  url: string;
  headers: Headers;
  body: unknown;
  signal: AbortSignal | null;
  credentials: RequestCredentials | undefined;
}

type Reply = Response | Error | ((call: RecordedCall) => Response | Promise<Response>);

export interface Deferred {
  /** The call that consumed this reply, once it arrived. */
  readonly call: RecordedCall | null;
  resolve(reply: Response | Error): void;
}

export class FakeApi {
  readonly calls: RecordedCall[] = [];
  private readonly standing = new Map<string, Reply>();
  private readonly once = new Map<string, (Reply | DeferredReply)[]>();

  constructor() {
    installFake("fetch", (input: RequestInfo | URL, init?: RequestInit) => this.fetch(input, init));
  }

  /** Standing reply for every matching request. */
  on(method: string, path: string, reply: Reply): this {
    this.standing.set(`${method} ${path}`, reply);
    return this;
  }

  /** One-shot reply for the next matching request. */
  next(method: string, path: string, reply: Reply): this {
    const key = `${method} ${path}`;
    this.once.set(key, [...(this.once.get(key) ?? []), reply]);
    return this;
  }

  /** A fresh stream per request: never clone/tee a live body into an unread backlog. */
  stream(path: string, factory: (call: RecordedCall) => ReadableStream<Uint8Array>): this {
    return this.on("GET", path, (call) => new Response(factory(call), {
      headers: { "Content-Type": "text/event-stream" },
    }));
  }

  /** One-shot reply the test resolves later; the fake does not react to the request's abort signal. */
  defer(method: string, path: string): Deferred {
    const deferred = new DeferredReply();
    const key = `${method} ${path}`;
    this.once.set(key, [...(this.once.get(key) ?? []), deferred]);
    return deferred;
  }

  callsTo(method: string, path: string): RecordedCall[] {
    return this.calls.filter((call) => call.method === method && call.path === path);
  }

  private async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const parsed = new URL(url, "http://app.test");
    const method = (init?.method ?? "GET").toUpperCase();
    const rawBody = init?.body;
    const call: RecordedCall = {
      method, path: parsed.pathname, url, headers: new Headers(init?.headers),
      body: typeof rawBody === "string" ? JSON.parse(rawBody) : undefined, signal: init?.signal ?? null,
      credentials: init?.credentials,
    };
    this.calls.push(call);
    const key = `${method} ${parsed.pathname}`;
    const queued = this.once.get(key);
    const reply = queued !== undefined && queued.length > 0 ? queued.shift() : this.standing.get(key);
    if (reply === undefined) {
      throw new Error(`unexpected request ${key}`);
    }
    if (reply instanceof DeferredReply) {
      return reply.consume(call);
    }
    if (reply instanceof Error) {
      throw reply;
    }
    // A body can be read once; a standing reply is served as a fresh copy each time.
    return typeof reply === "function" ? reply(call) : reply.clone();
  }
}

class DeferredReply implements Deferred {
  call: RecordedCall | null = null;
  private settle: ((reply: Response | Error) => void) | null = null;
  private pending: Response | Error | null = null;

  consume(call: RecordedCall): Promise<Response> {
    this.call = call;
    return new Promise<Response | Error>((resolve) => {
      if (this.pending !== null) {
        resolve(this.pending);
      } else {
        this.settle = resolve;
      }
    }).then((reply) => {
      if (reply instanceof Error) {
        throw reply;
      }
      return reply;
    });
  }

  resolve(reply: Response | Error): void {
    if (this.settle !== null) {
      this.settle(reply);
    } else {
      this.pending = reply;
    }
  }
}

export function setCsrfCookie(value: string | null): void {
  document.cookie = value === null
    ? "policyops_csrf_local=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/"
    : `policyops_csrf_local=${value}; path=/`;
}
