// Small typed client for the same-origin PolicyOps API, built on the generated contract types in schema.d.ts.
//
// The session cookie is HttpOnly and never visible here. Unsafe requests carry the CSRF token from its readable
// cookie, read at send time because the server rotates it when a workspace is selected. The browser supplies the
// Origin header itself (scripts cannot set it). Every failure becomes an ApiError carrying plain text only; response
// bodies are bounded before parsing and never rendered as markup.
//
// A request settles as soon as its signal aborts or its timeout passes, even when the underlying fetch ignores the
// signal. A cancelled or timed-out unsafe request is not evidence that the server did not apply it.

import type { components, operations, paths } from "./schema";

type Schemas = components["schemas"];
export type MeOut = Schemas["MeOut"];
export type WorkspaceOut = Schemas["WorkspaceOut"];
export type Role = Schemas["Role"];
export type CasePage = Schemas["CasePage"];
export type CaseView = Schemas["CaseView"];
export type CaseStatus = Schemas["CaseStatus"];
export type MembershipOut = Schemas["MembershipOut"];
export type ErrorCode = Schemas["ErrorCode"];
export type ErrorEnvelope = Schemas["ErrorEnvelope"];

type ApiPath = keyof paths;
type JsonBody<Op extends keyof operations> = operations[Op]["responses"] extends { 200: { content: { "application/json": infer T } } }
  ? T
  : never;

const ME_PATH = "/api/v1/me" satisfies ApiPath;
const CASES_PATH = "/api/v1/cases" satisfies ApiPath;
const MEMBERS_PATH = "/api/v1/workspace/members" satisfies ApiPath;
const WORKSPACE_PATH = "/api/v1/auth/workspace" satisfies ApiPath;
const LOGOUT_PATH = "/api/v1/auth/logout" satisfies ApiPath;
const LOGIN_PATH = "/api/v1/auth/login" satisfies ApiPath;

/** CSRF cookie names: `__Host-` when the API uses secure cookies, the local name otherwise. */
export const CSRF_COOKIES = ["__Host-policyops_csrf", "policyops_csrf_local"] as const;
export const CSRF_HEADER = "X-CSRF-Token";
export const REQUEST_TIMEOUT_MS = 15_000;
/** Upper bound on a response body this client will parse (characters). */
export const MAX_RESPONSE_CHARS = 1_000_000;
const MAX_DETAIL_CHARS = 300;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Exhaustive by construction: a code added to the contract fails the type check until it is listed here.
const ERROR_CODES: Record<ErrorCode, true> = {
  invalid_input: true, unauthenticated: true, forbidden: true, not_found: true, conflict: true, stale_version: true,
  expired: true, customer_not_authenticated: true, customer_mismatch: true, policy_denied: true,
  policy_unsupported: true, consent_required: true, consent_ambiguous: true, approval_required: true,
  separation_of_duties: true, protocol_violation: true, upstream_money_precision: true, rate_limited: true,
  unavailable: true, internal: true,
};
const ROLES: Record<Role, true> = { analyst: true, reviewer: true, admin: true, auditor: true };
const CASE_STATUSES: Record<CaseStatus, true> = { open: true, in_progress: true, resolved: true, closed: true };

/**
 * `http`: the server answered with a non-2xx status. `network`: no response arrived. `timeout`: no response within
 * the client's limit. `malformed`: a response arrived but could not be read. `cancelled`: the caller aborted.
 */
export type FailureKind = "http" | "network" | "timeout" | "malformed" | "cancelled";

export class ApiError extends Error {
  override name = "ApiError";

  constructor(
    readonly kind: FailureKind,
    readonly status: number | null = null,
    readonly code: ErrorCode | null = null,
    /** Server-authored plain text from a well-formed envelope, truncated; never markup. */
    readonly detail: string | null = null,
    readonly correlationId: string | null = null,
    readonly retryable = false,
  ) {
    super(status === null ? `API request failed (${kind})` : `API request failed (${kind} ${String(status)})`);
  }

  get unauthenticated(): boolean {
    return this.kind === "http" && this.status === 401;
  }
}

export function toApiError(error: unknown): ApiError {
  return error instanceof ApiError ? error : new ApiError("network");
}

export interface RequestOptions {
  signal: AbortSignal;
  timeoutMs?: number;
}

export function readCsrfToken(cookies: string = document.cookie): string | null {
  const values = new Map<string, string>();
  for (const part of cookies.split(";")) {
    const separator = part.indexOf("=");
    if (separator > 0) {
      values.set(part.slice(0, separator).trim(), part.slice(separator + 1).trim());
    }
  }
  for (const name of CSRF_COOKIES) {
    const value = values.get(name);
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function plainText(value: string): string {
  // eslint-disable-next-line no-control-regex -- strip control characters from server text before display
  const cleaned = value.replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
  return cleaned.length > MAX_DETAIL_CHARS ? `${cleaned.slice(0, MAX_DETAIL_CHARS - 1)}…` : cleaned;
}

function httpError(status: number, text: string): ApiError {
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(text);
  } catch {
    // Not JSON (e.g. a proxy page): keep only the status.
  }
  if (isRecord(parsed)) {
    const { code, detail, correlation_id: correlationId, retryable } = parsed;
    if (typeof code === "string" && Object.hasOwn(ERROR_CODES, code) && typeof detail === "string"
        && typeof retryable === "boolean") {
      return new ApiError("http", status, code as ErrorCode, plainText(detail),
        typeof correlationId === "string" && UUID.test(correlationId) ? correlationId.toLowerCase() : null, retryable);
    }
  }
  return new ApiError("http", status);
}

async function send(method: "GET" | "POST", path: string, body: unknown, options: RequestOptions): Promise<string> {
  const { signal, timeoutMs = REQUEST_TIMEOUT_MS } = options;
  const local = new AbortController();
  let timedOut = false;
  const failure = (): ApiError =>
    new ApiError(signal.aborted ? "cancelled" : timedOut ? "timeout" : "network");
  const timer = setTimeout(() => {
    timedOut = true;
    local.abort();
  }, timeoutMs);
  const forward = (): void => {
    local.abort();
  };
  signal.addEventListener("abort", forward, { once: true });
  if (signal.aborted) {
    local.abort();
  }

  const headers = new Headers({ Accept: "application/json" });
  if (body !== undefined) {
    headers.set("Content-Type", "application/json");
  }
  if (method !== "GET") {
    const token = readCsrfToken();
    if (token !== null) {
      headers.set(CSRF_HEADER, token);
    }
  }

  const exchange = async (): Promise<{ status: number; text: string }> => {
    const response = await fetch(path, {
      method,
      headers,
      body: body === undefined ? null : JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: local.signal,
    });
    const text = await response.text();
    return { status: response.status, text };
  };

  try {
    const { status, text } = await new Promise<{ status: number; text: string }>((resolve, reject) => {
      if (local.signal.aborted) {
        reject(failure());
        return;
      }
      local.signal.addEventListener("abort", () => {
        reject(failure());
      }, { once: true });
      exchange().then(resolve, () => {
        reject(failure());
      });
    });
    if (text.length > MAX_RESPONSE_CHARS) {
      throw new ApiError("malformed", status);
    }
    if (status < 200 || status > 299) {
      throw httpError(status, text);
    }
    return text;
  } finally {
    clearTimeout(timer);
    signal.removeEventListener("abort", forward);
  }
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new ApiError("malformed", 200);
  }
}

function malformed(): never {
  throw new ApiError("malformed", 200);
}

function roles(value: unknown): Role[] {
  if (!Array.isArray(value)) {
    malformed();
  }
  // Unknown roles grant nothing in this client (least privilege); the server stays authoritative.
  return value.filter((role): role is Role => typeof role === "string" && Object.hasOwn(ROLES, role));
}

function workspace(value: unknown): WorkspaceOut {
  if (!isRecord(value) || typeof value["workspace_id"] !== "string" || typeof value["slug"] !== "string"
      || typeof value["name"] !== "string") {
    malformed();
  }
  return { workspace_id: value["workspace_id"], slug: value["slug"], name: value["name"], roles: roles(value["roles"]) };
}

export function parseMe(value: unknown): MeOut {
  if (!isRecord(value) || typeof value["principal_id"] !== "string" || !Array.isArray(value["workspaces"])) {
    malformed();
  }
  const workspaceId = value["workspace_id"];
  if (workspaceId !== null && typeof workspaceId !== "string") {
    malformed();
  }
  return {
    principal_id: value["principal_id"],
    workspace_id: workspaceId,
    roles: roles(value["roles"]),
    workspaces: value["workspaces"].map(workspace),
  };
}

function caseView(value: unknown): CaseView {
  if (!isRecord(value) || typeof value["case_id"] !== "string" || typeof value["scenario"] !== "string"
      || typeof value["status"] !== "string" || !Object.hasOwn(CASE_STATUSES, value["status"])
      || typeof value["customer_bound"] !== "boolean" || typeof value["version"] !== "number"
      || typeof value["created_at"] !== "string" || typeof value["updated_at"] !== "string") {
    malformed();
  }
  return {
    case_id: value["case_id"], scenario: value["scenario"], status: value["status"] as CaseStatus,
    customer_bound: value["customer_bound"], version: value["version"], created_at: value["created_at"],
    updated_at: value["updated_at"],
  };
}

function casePage(value: unknown): CasePage {
  if (!isRecord(value) || !Array.isArray(value["items"])) {
    malformed();
  }
  const cursor = value["next_cursor"];
  if (cursor !== null && typeof cursor !== "string") {
    malformed();
  }
  return { items: value["items"].map(caseView), next_cursor: cursor };
}

function membership(value: unknown): MembershipOut {
  if (!isRecord(value) || typeof value["membership_id"] !== "string" || typeof value["principal_id"] !== "string"
      || typeof value["role"] !== "string" || !Object.hasOwn(ROLES, value["role"])
      || typeof value["active"] !== "boolean") {
    malformed();
  }
  return { membership_id: value["membership_id"], principal_id: value["principal_id"], role: value["role"] as Role,
           active: value["active"] };
}

export async function getMe(options: RequestOptions): Promise<JsonBody<"me">> {
  return parseMe(parseJson(await send("GET", ME_PATH, undefined, options)));
}

export const CASE_PAGE_LIMIT = 25;

export async function listCases(options: RequestOptions): Promise<JsonBody<"list_cases">> {
  const query = new URLSearchParams({ limit: String(CASE_PAGE_LIMIT) });
  return casePage(parseJson(await send("GET", `${CASES_PATH}?${query.toString()}`, undefined, options)));
}

export async function listMembers(options: RequestOptions): Promise<JsonBody<"members">> {
  const value = parseJson(await send("GET", MEMBERS_PATH, undefined, options));
  return Array.isArray(value) ? value.map(membership) : malformed();
}

export async function selectWorkspace(workspaceId: string, options: RequestOptions): Promise<void> {
  const body: Schemas["SelectWorkspaceIn"] = { workspace_id: workspaceId };
  await send("POST", WORKSPACE_PATH, body, options);
}

export async function logout(options: RequestOptions): Promise<void> {
  await send("POST", LOGOUT_PATH, undefined, options);
}

/** Full-page sign-in navigation; `returnTo` must already be a safe local path (see safeReturnTo). */
export function loginHref(returnTo: string): string {
  const query = { return_to: returnTo } satisfies NonNullable<operations["login"]["parameters"]["query"]>;
  return `${LOGIN_PATH}?${new URLSearchParams(query).toString()}`;
}
