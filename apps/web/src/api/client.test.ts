import { afterEach, describe, expect, test, vi } from "vitest";

import { FakeApi, envelope, json, me, noContent, setCsrfCookie } from "../test/fakeApi";
import { ApiError, CSRF_HEADER, MAX_RESPONSE_CHARS, getMe, listCases, loginHref, logout, readCsrfToken,
         selectWorkspace } from "./client";

const live = (): { signal: AbortSignal } => ({ signal: new AbortController().signal });

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
    expect((await failure(listCases(live()))).kind).toBe("malformed");
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
