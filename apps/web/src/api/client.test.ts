import { afterEach, describe, expect, test, vi } from "vitest";

import { FakeApi, WORKSPACE_A, WORKSPACE_B, casePage, envelope, json, me, members, noContent,
         setCsrfCookie } from "../test/fakeApi";
import { ApiError, CSRF_HEADER, EXPECTED_PRINCIPAL_HEADER, EXPECTED_WORKSPACE_HEADER, MAX_RESPONSE_CHARS,
         expectedContextOf, getMe, listCases, listMembers, loginHref, logout, readCsrfToken, sameContext,
         selectWorkspace, type BoundRequestOptions, type ExpectedContext } from "./client";

const live = (): { signal: AbortSignal } => ({ signal: new AbortController().signal });
function contextOf(workspace = WORKSPACE_A): ExpectedContext {
  const context = expectedContextOf(me({ workspace }));
  if (context === null) {
    throw new Error("fixture context");
  }
  return context;
}
const bound = (): BoundRequestOptions => ({ ...live(), context: contextOf() });

async function failure(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ApiError) {
      return error;
    }
    throw error;
  }
  throw new Error("expected the request to fail");
}

afterEach(() => {
  setCsrfCookie(null);
  vi.useRealTimers();
});

describe("CSRF and request headers", () => {
  test("unsafe requests carry the token read at send time; reads carry none", async () => {
    const api = new FakeApi().on("POST", "/api/v1/auth/workspace", noContent())
      .on("POST", "/api/v1/auth/logout", noContent()).on("GET", "/api/v1/me", json(200, me()));
    setCsrfCookie("first-token");
    await selectWorkspace("0b0b0b0b-0000-4000-8000-00000000000b", live());
    setCsrfCookie("rotated-token"); // the server rotates it on workspace selection
    await logout(live());
    await getMe(live());

    const [select, signOut, read] = api.calls;
    expect(select?.headers.get(CSRF_HEADER)).toBe("first-token");
    expect(select?.body).toEqual({ workspace_id: "0b0b0b0b-0000-4000-8000-00000000000b" });
    expect(select?.headers.get("Content-Type")).toBe("application/json");
    expect(signOut?.headers.get(CSRF_HEADER)).toBe("rotated-token");
    expect(read?.headers.has(CSRF_HEADER)).toBe(false);
    // Origin is left to the browser; credentials stay same-origin.
    expect(api.calls.every((call) => !call.headers.has("Origin") && call.credentials === "same-origin")).toBe(true);
  });

  test("without a CSRF cookie the request is still sent, unsigned, for the server to refuse", async () => {
    const api = new FakeApi().on("POST", "/api/v1/auth/logout",
      json(403, envelope("forbidden", "The CSRF token is not valid.")));
    const error = await failure(logout(live()));
    expect(api.calls[0]?.headers.has(CSRF_HEADER)).toBe(false);
    expect([error.kind, error.status, error.code]).toEqual(["http", 403, "forbidden"]);
  });

  test("the secure cookie name wins over the local one", () => {
    expect(readCsrfToken("policyops_csrf_local=local; __Host-policyops_csrf=secure")).toBe("secure");
    expect(readCsrfToken("other=1; policyops_csrf_local=local")).toBe("local");
    expect(readCsrfToken("policyops_csrf_local=")).toBeNull();
  });
});

describe("failures", () => {
  test("an error envelope becomes plain, bounded text with its reference", async () => {
    const detail = `<b>markup stays text</b>\u0007${"x".repeat(400)}`;
    new FakeApi().on("GET", "/api/v1/me", json(409, { ...envelope("conflict", detail, true) }));
    const error = await failure(getMe(live()));
    expect(error.code).toBe("conflict");
    expect(error.retryable).toBe(true);
    expect(error.correlationId).toBe("5f0c2d1e-7a3b-4c8d-9e6f-0123456789ab");
    expect(error.detail?.startsWith("<b>markup stays text</b> x")).toBe(true);
    expect(error.detail?.length).toBe(300);
  });

  test("a non-JSON or unrecognised error body keeps only the status", async () => {
    new FakeApi().next("GET", "/api/v1/me", new Response("<html>bad gateway</html>", { status: 502 }))
      .next("GET", "/api/v1/me", json(500, { code: "made_up", detail: "x", retryable: false }))
      .next("GET", "/api/v1/me", json(400, { ...envelope("invalid_input", "No."), correlation_id: "not-a-uuid" }));
    const proxy = await failure(getMe(live()));
    expect([proxy.kind, proxy.status, proxy.code, proxy.detail]).toEqual(["http", 502, null, null]);
    expect((await failure(getMe(live()))).code).toBeNull();
    expect((await failure(getMe(live()))).correlationId).toBeNull();
  });

  test("a 401 without an envelope still reads as unauthenticated", async () => {
    new FakeApi().on("GET", "/api/v1/me", new Response("", { status: 401 }));
    expect((await failure(getMe(live()))).unauthenticated).toBe(true);
  });

  test("network failure, unreadable success and oversized bodies are distinguished", async () => {
    new FakeApi().next("GET", "/api/v1/me", new TypeError("Failed to fetch"))
      .next("GET", "/api/v1/me", new Response("{not json", { status: 200 }))
      .next("GET", "/api/v1/me", json(200, { principal_id: 7 }))
      .next("GET", "/api/v1/me", new Response("x".repeat(MAX_RESPONSE_CHARS + 1), { status: 200 }));
    expect((await failure(getMe(live()))).kind).toBe("network");
    expect((await failure(getMe(live()))).kind).toBe("malformed");
    expect((await failure(getMe(live()))).kind).toBe("malformed");
    expect((await failure(getMe(live()))).kind).toBe("malformed");
  });

  test("unknown roles grant nothing", async () => {
    new FakeApi().on("GET", "/api/v1/me", json(200, { ...me({ roles: ["analyst"] }), roles: ["analyst", "owner"] }));
    expect((await getMe(live())).roles).toEqual(["analyst"]);
  });

  test("a case page with an unknown status is refused rather than shown", async () => {
    new FakeApi().on("GET", "/api/v1/cases", json(200, { items: [{ status: "deleted" }], next_cursor: null }));
    expect((await failure(listCases(bound()))).kind).toBe("malformed");
  });
});

describe("expected context", () => {
  test("bound endpoints send both headers from the captured context; global ones send neither", async () => {
    const api = new FakeApi().on("GET", "/api/v1/cases", json(200, casePage()))
      .on("GET", "/api/v1/workspace/members", json(200, members())).on("GET", "/api/v1/me", json(200, me()))
      .on("POST", "/api/v1/auth/workspace", noContent()).on("POST", "/api/v1/auth/logout", noContent());
    await listCases(bound());
    await listMembers({ ...live(), context: contextOf(WORKSPACE_B) });
    await getMe(live());
    await selectWorkspace(WORKSPACE_B.workspace_id, live());
    await logout(live());
    const sent = api.calls.map((call) => [call.path, call.headers.get(EXPECTED_PRINCIPAL_HEADER),
                                          call.headers.get(EXPECTED_WORKSPACE_HEADER)]);
    const principal = me().principal_id;
    expect(sent).toEqual([
      ["/api/v1/cases", principal, WORKSPACE_A.workspace_id],
      ["/api/v1/workspace/members", principal, WORKSPACE_B.workspace_id],
      ["/api/v1/me", null, null], ["/api/v1/auth/workspace", null, null], ["/api/v1/auth/logout", null, null],
    ]);
  });

  test("a bound call without a context does not type-check", () => {
    // @ts-expect-error -- workspace-bound endpoints require the expected context
    const unbound = (): Promise<unknown> => listCases(live());
    // @ts-expect-error -- a plain object is not an ExpectedContext (only expectedContextOf creates one)
    const forged = (): Promise<unknown> => listCases({ ...live(), context: { principalId: "p", workspaceId: "w" } });
    expect([typeof unbound, typeof forged]).toEqual(["function", "function"]);
  });

  test("a context exists only for a selected workspace with canonical IDs", () => {
    expect(expectedContextOf(me({ workspace: null }))).toBeNull();
    expect(expectedContextOf({ ...me(), principal_id: "not-a-uuid" })).toBeNull();
    expect(expectedContextOf({ ...me(), workspace_id: WORKSPACE_A.workspace_id.toUpperCase() })).toBeNull();
    expect(expectedContextOf({ ...me(), workspace_id: "{0a0a0a0a-0000-4000-8000-00000000000a}" })).toBeNull();
    const context = contextOf();
    expect(Object.isFrozen(context)).toBe(true);
    expect(sameContext(context, contextOf())).toBe(true);
    expect(sameContext(context, contextOf(WORKSPACE_B))).toBe(false);
    expect(sameContext(context, null)).toBe(false);
  });

  test("only an explicit 409 context_changed is a context change; other conflicts stay resource-level", async () => {
    const api = new FakeApi();
    const outcomes: [Response, boolean][] = [
      [json(409, envelope("context_changed", "Your session changed.")), true],
      [json(409, envelope("stale_version", "The case changed.")), false],
      [json(409, envelope("conflict", "Already decided.")), false],
      [json(409, { detail: "no envelope" }), false],
      [json(400, envelope("context_changed", "wrong status")), false],
      [json(401, envelope("unauthenticated", "Sign in again.")), false],
    ];
    for (const [reply, expected] of outcomes) {
      api.next("GET", "/api/v1/cases", reply);
      const error = await failure(listCases(bound()));
      expect(error.contextChanged).toBe(expected);
    }
  });
});

describe("abort and timeout", () => {
  test("an abort settles the request at once even if fetch ignores the signal", async () => {
    const api = new FakeApi();
    api.defer("GET", "/api/v1/me"); // never resolved
    const controller = new AbortController();
    const pending = failure(getMe({ signal: controller.signal }));
    controller.abort();
    expect((await pending).kind).toBe("cancelled");
    expect(api.calls[0]?.signal?.aborted).toBe(true);
  });

  test("a request with no answer times out as uncertain, not as a refusal", async () => {
    vi.useFakeTimers();
    const api = new FakeApi();
    api.defer("POST", "/api/v1/auth/workspace");
    const pending = failure(selectWorkspace("0b0b0b0b-0000-4000-8000-00000000000b",
                                            { signal: new AbortController().signal, timeoutMs: 1000 }));
    await vi.advanceTimersByTimeAsync(1000);
    const error = await pending;
    expect([error.kind, error.status]).toEqual(["timeout", null]);
    expect(api.calls[0]?.signal?.aborted).toBe(true);
  });
});

test("the sign-in link carries the return path as a query parameter", () => {
  expect(loginHref("/cases/abc")).toBe("/api/v1/auth/login?return_to=%2Fcases%2Fabc");
});
