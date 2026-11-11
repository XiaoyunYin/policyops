// Small typed client for the same-origin PolicyOps API, built on the generated contract types in schema.d.ts.
//
// The session cookie is HttpOnly and never visible here. Unsafe requests carry the CSRF token from its readable
// cookie, read at send time because the server rotates it when a workspace is selected. The browser supplies the
// Origin header itself (scripts cannot set it). Every failure becomes an ApiError carrying plain text only; response
// bodies are bounded before parsing and never rendered as markup.
//
// A request settles as soon as its signal aborts or its timeout passes, even when the underlying fetch ignores the
// signal. A cancelled or timed-out unsafe request is not evidence that the server did not apply it.
//
// Workspace-bound endpoints take BoundRequestOptions: the principal and workspace this tab's own /me reported, sent as
// PolicyOps-Expected-Principal/-Workspace. The server refuses (409 context_changed) when the shared session cookie
// now belongs to another principal or workspace, so a request is never applied under a context the tab did not show.
// The headers are a refusal precondition, never a selector. A context_changed refusal is definitive (the requested
// operation was not applied); a cancelled, timed-out or lost write stays unknown and keeps its original context.

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
export type MessageView = Schemas["MessageView"];
export type MessagePage = Schemas["MessagePage"];
export type MessagePosted = Schemas["MessagePosted"];
export type MessageIn = Schemas["MessageIn"];
export type StaffMessageSource = MessageIn["source"];
export type MessageSource = MessageView["source"];
export type RunView = Schemas["RunView"];

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
const RULE_ID = /^[a-z][a-z0-9_.-]{0,63}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** The server's canonical UUID spelling, the only one the expected-context headers accept. */
const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

type BoundHeaders = keyof NonNullable<operations["list_cases"]["parameters"]["header"]>;
export const EXPECTED_PRINCIPAL_HEADER = "PolicyOps-Expected-Principal" satisfies BoundHeaders;
export const EXPECTED_WORKSPACE_HEADER = "PolicyOps-Expected-Workspace" satisfies BoundHeaders;

// Exhaustive by construction: a code added to the contract fails the type check until it is listed here.
const ERROR_CODES: Record<ErrorCode, true> = {
  invalid_input: true, unauthenticated: true, forbidden: true, not_found: true, conflict: true, stale_version: true,
  expired: true, customer_not_authenticated: true, customer_mismatch: true, policy_denied: true,
  policy_unsupported: true, consent_required: true, consent_ambiguous: true, approval_required: true,
  separation_of_duties: true, protocol_violation: true, upstream_money_precision: true, rate_limited: true,
  unavailable: true, internal: true, context_changed: true,
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
    /** The server's stable refusal rule (for example `api.stale_version`), when the envelope carried a valid one. */
    readonly ruleId: string | null = null,
  ) {
    super(status === null ? `API request failed (${kind})` : `API request failed (${kind} ${String(status)})`);
  }

  get unauthenticated(): boolean {
    return this.kind === "http" && this.status === 401;
  }

  /** The server refused because the session is no longer this tab's principal or workspace; nothing was applied. */
  get contextChanged(): boolean {
    return this.kind === "http" && this.status === 409 && this.code === "context_changed";
  }

  /** The write's If-Match no longer names the case's current version (checked after any idempotent replay). */
  get staleVersion(): boolean {
    return this.kind === "http" && this.status === 409 && this.code === "stale_version"
      && this.ruleId === "api.stale_version";
  }

  /** No investigation runtime is installed on this server, so no run was started (checked after any replay). */
  get runtimeUnconfigured(): boolean {
    return this.kind === "http" && this.status === 503 && this.code === "unavailable"
      && this.ruleId === "runtime.unconfigured";
  }

  /** The case already has an active run (checked after any replay); this request did not start one. */
  get runActive(): boolean {
    return this.kind === "http" && this.status === 409 && this.code === "conflict" && this.ruleId === "api.run_active";
  }
}

export function toApiError(error: unknown): ApiError {
  return error instanceof ApiError ? error : new ApiError("network");
}

export interface RequestOptions {
  signal: AbortSignal;
  timeoutMs?: number;
}

declare const contextBrand: unique symbol;

/** The principal and workspace a request is composed for. Only `expectedContextOf` creates one. */
export interface ExpectedContext {
  readonly principalId: string;
  readonly workspaceId: string;
  readonly [contextBrand]: true;
}

/** Options for a workspace-bound endpoint: the context is required, so an unbound call does not type-check. */
export interface BoundRequestOptions extends RequestOptions {
  readonly context: ExpectedContext;
}

/** The expected context from a server-validated /me, or null when no workspace is selected (or the IDs are not
 *  canonical UUIDs, which the server never sends). */
export function expectedContextOf(me: MeOut): ExpectedContext | null {
  const { principal_id: principalId, workspace_id: workspaceId } = me;
  if (workspaceId === null || !CANONICAL_UUID.test(principalId) || !CANONICAL_UUID.test(workspaceId)) {
    return null;
  }
  return Object.freeze({ principalId, workspaceId }) as ExpectedContext;
}

export function sameContext(a: ExpectedContext | null, b: ExpectedContext | null): boolean {
  return a !== null && b !== null && a.principalId === b.principalId && a.workspaceId === b.workspaceId;
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
    const { code, detail, correlation_id: correlationId, retryable, rule_id: ruleId } = parsed;
    if (typeof code === "string" && Object.hasOwn(ERROR_CODES, code) && typeof detail === "string"
        && typeof retryable === "boolean") {
      return new ApiError("http", status, code as ErrorCode, plainText(detail),
        typeof correlationId === "string" && UUID.test(correlationId) ? correlationId.toLowerCase() : null, retryable,
        typeof ruleId === "string" && RULE_ID.test(ruleId) ? ruleId : null);
    }
  }
  return new ApiError("http", status);
}

/** What a write sends beyond its body: its operation identity and, for an existing case, the version it is based on. */
export interface WriteHeaders {
  readonly idempotencyKey: string;
  readonly ifMatch: number | null;
}

interface Exchange {
  readonly status: number;
  readonly text: string;
  readonly headers: Headers;
}

async function send(method: "GET" | "POST", path: string, body: unknown, options: RequestOptions,
                    context: ExpectedContext | null): Promise<string> {
  return (await exchangeWith(method, path, body, options, context, null)).text;
}

async function exchangeWith(method: "GET" | "POST", path: string, body: unknown, options: RequestOptions,
                            context: ExpectedContext | null, write: WriteHeaders | null): Promise<Exchange> {
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
  if (context !== null) {
    headers.set(EXPECTED_PRINCIPAL_HEADER, context.principalId);
    headers.set(EXPECTED_WORKSPACE_HEADER, context.workspaceId);
  }
  if (write !== null) {
    headers.set("Idempotency-Key", write.idempotencyKey);
    if (write.ifMatch !== null) {
      headers.set("If-Match", `"${String(write.ifMatch)}"`);
    }
  }

  const exchange = async (): Promise<Exchange> => {
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
    return { status: response.status, text, headers: response.headers };
  };

  try {
    const result = await new Promise<Exchange>((resolve, reject) => {
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
    const { status, text } = result;
    if (text.length > MAX_RESPONSE_CHARS) {
      throw new ApiError("malformed", status);
    }
    if (status < 200 || status > 299) {
      throw httpError(status, text);
    }
    return result;
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
  if (!isRecord(value) || typeof value["case_id"] !== "string" || !CANONICAL_UUID.test(value["case_id"])
      || !isVersion(value["version"]) || typeof value["scenario"] !== "string"
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
  if (value["items"].length > CASE_PAGE_LIMIT || (cursor !== null && (cursor.length === 0 || cursor.length > 400))) {
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
  return parseMe(parseJson(await send("GET", ME_PATH, undefined, options, null)));
}

export const CASE_PAGE_LIMIT = 25;

export interface CaseQuery {
  readonly status?: CaseStatus | null;
  readonly cursor?: string | null;
}

/** One page of the queue, optionally filtered by status and continued from a server cursor. */
export async function listCases(options: BoundRequestOptions, query: CaseQuery = {}): Promise<JsonBody<"list_cases">> {
  const params = new URLSearchParams({ limit: String(CASE_PAGE_LIMIT) });
  const status = query.status ?? null;
  if (status !== null) {
    params.set("status", status);
  }
  if (query.cursor != null) {
    params.set("cursor", query.cursor);
  }
  const page = casePage(parseJson(await send("GET", `${CASES_PATH}?${params.toString()}`, undefined, options,
                                             options.context)));
  return status !== null && page.items.some((item) => item.status !== status) ? malformed() : page;
}

export async function listMembers(options: BoundRequestOptions): Promise<JsonBody<"members">> {
  const value = parseJson(await send("GET", MEMBERS_PATH, undefined, options, options.context));
  return Array.isArray(value) ? value.map(membership) : malformed();
}

export async function selectWorkspace(workspaceId: string, options: RequestOptions): Promise<void> {
  const body: Schemas["SelectWorkspaceIn"] = { workspace_id: workspaceId };
  await send("POST", WORKSPACE_PATH, body, options, null);
}

export async function logout(options: RequestOptions): Promise<void> {
  await send("POST", LOGOUT_PATH, undefined, options, null);
}

// -- cases, conversation and runs -------------------------------------------------------------------------------
//
// Reads validate that every returned ID belongs to the requested resource. Writes carry an Idempotency-Key (the
// operation's identity, chosen once by the caller and repeated unchanged on an explicit retry) and, for an existing
// case, If-Match with the case version the request was composed against. A write result is accepted only with its
// expected status, a strict body, an ETag agreeing with the body's version and a valid Idempotent-Replayed header
// (absent on a fresh result, "true" on a replay). Anything else is `malformed`: a response arrived, so the write may
// well have applied, and the caller must treat its outcome as unknown.

const MESSAGE_SOURCES: Record<MessageSource, true> = {
  seeded: true, simulated_customer: true, operator_entered_customer: true, staff_note: true, agent: true,
};
const RUN_STATES: Record<RunView["state"], true> = {
  queued: true, running: true, waiting_input: true, waiting_approval: true, reconciling: true, succeeded: true,
  failed: true, cancelled: true, budget_exceeded: true,
};
const STRONG_ETAG = /^"([1-9][0-9]{0,15})"$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const MAX_VERSION = 2 ** 53;
/** Server bound on one message page. */
export const MESSAGE_PAGE_LIMIT = 200;
const MAX_MESSAGE_TEXT = 4000;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,128}$/;

function isVersion(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1 && value <= MAX_VERSION;
}

function caseIdOk(value: unknown): value is string {
  return typeof value === "string" && CANONICAL_UUID.test(value);
}

function casePath(caseId: string, suffix = ""): string {
  if (!caseIdOk(caseId)) {
    // A route parameter that is not a canonical case ID is never sent; it reads as missing.
    throw new ApiError("http", 404, "not_found");
  }
  return `${CASES_PATH}/${caseId}${suffix}`;
}

function messageView(value: unknown, caseId: string): MessageView {
  if (!isRecord(value) || !caseIdOk(value["message_id"]) || value["case_id"] !== caseId
      || (value["entered_by"] !== null && !caseIdOk(value["entered_by"]))
      || !isVersion(value["sequence"]) || typeof value["source"] !== "string"
      || !Object.hasOwn(MESSAGE_SOURCES, value["source"]) || typeof value["text"] !== "string"
      || value["text"].length === 0 || value["text"].length > 2 * MAX_MESSAGE_TEXT
      || typeof value["text_sha256"] !== "string" || !SHA256_HEX.test(value["text_sha256"])
      || typeof value["created_at"] !== "string") {
    malformed();
  }
  return {
    message_id: value["message_id"], case_id: caseId, entered_by: value["entered_by"], sequence: value["sequence"],
    source: value["source"] as MessageSource, text: value["text"], text_sha256: value["text_sha256"],
    created_at: value["created_at"],
  };
}

function messagePage(value: unknown, caseId: string, after: number): MessagePage {
  if (!isRecord(value) || !Array.isArray(value["items"]) || value["items"].length > MESSAGE_PAGE_LIMIT) {
    malformed();
  }
  const items = value["items"].map((item) => messageView(item, caseId));
  let previous = after;
  for (const item of items) {
    if (item.sequence <= previous) {
      malformed(); // out of order, duplicated or not after the requested sequence
    }
    previous = item.sequence;
  }
  const next = value["next_after_sequence"];
  if (next !== null && (!isVersion(next) || items.length === 0 || next !== previous)) {
    malformed();
  }
  return { items, next_after_sequence: next };
}

function runView(value: unknown, caseId: string): RunView {
  if (!isRecord(value) || !caseIdOk(value["run_id"]) || value["case_id"] !== caseId
      || !isVersion(value["case_version"]) || !isVersion(value["version"]) || value["mode"] !== "workbench"
      || typeof value["state"] !== "string" || !Object.hasOwn(RUN_STATES, value["state"])
      || (value["initiated_by"] !== null && !caseIdOk(value["initiated_by"]))
      || typeof value["event_highwater"] !== "number" || !Number.isSafeInteger(value["event_highwater"])
      || typeof value["config_sha256"] !== "string" || typeof value["graph_sha256"] !== "string"
      || typeof value["prompt_sha256"] !== "string" || typeof value["created_at"] !== "string"
      || typeof value["updated_at"] !== "string" || typeof value["deadline_at"] !== "string") {
    malformed();
  }
  return {
    run_id: value["run_id"], case_id: caseId, case_version: value["case_version"], version: value["version"],
    mode: "workbench", state: value["state"] as RunView["state"], initiated_by: value["initiated_by"],
    event_highwater: value["event_highwater"], config_sha256: value["config_sha256"],
    graph_sha256: value["graph_sha256"], prompt_sha256: value["prompt_sha256"], created_at: value["created_at"],
    updated_at: value["updated_at"], deadline_at: value["deadline_at"],
  };
}

/** The version a strong ETag names, or null when the header is absent or not exactly one strong version. */
function etagVersion(headers: Headers): number | null {
  const match = STRONG_ETAG.exec(headers.get("ETag") ?? "");
  const version = match === null ? Number.NaN : Number(match[1]);
  return isVersion(version) ? version : null;
}

function replayedHeader(headers: Headers): boolean {
  const value = headers.get("Idempotent-Replayed");
  if (value === null) {
    return false;
  }
  return value === "true" ? true : malformed();
}

/** A validated write result. `replayed`: the server returned the stored original result of this same request. */
export interface Written<T> {
  readonly value: T;
  readonly replayed: boolean;
}

function written<T>(result: Exchange, expectedStatus: number, parse: (value: unknown) => T,
                    version: (value: T) => number): Written<T> {
  if (result.status !== expectedStatus) {
    malformed();
  }
  const value = parse(parseJson(result.text));
  if (etagVersion(result.headers) !== version(value)) {
    malformed();
  }
  return { value, replayed: replayedHeader(result.headers) };
}

function writeHeaders(idempotencyKey: string, ifMatch: number | null): WriteHeaders {
  if (!IDEMPOTENCY_KEY.test(idempotencyKey) || (ifMatch !== null && !isVersion(ifMatch))) {
    throw new ApiError("malformed"); // a caller bug; nothing is sent
  }
  return { idempotencyKey, ifMatch };
}

/** A case and the version its strong ETag names (they must agree). */
export async function getCase(caseId: string, options: BoundRequestOptions): Promise<CaseView> {
  const path = casePath(caseId);
  const result = await exchangeWith("GET", path, undefined, options, options.context, null);
  const value = caseView(parseJson(result.text));
  if (value.case_id !== caseId || etagVersion(result.headers) !== value.version) {
    malformed();
  }
  return value;
}

/** Messages after `after`, in sequence order (at most MESSAGE_PAGE_LIMIT). */
export async function listMessages(caseId: string, after: number, options: BoundRequestOptions,
): Promise<MessagePage> {
  if (!Number.isSafeInteger(after) || after < 0 || after > MAX_VERSION) {
    throw new ApiError("malformed");
  }
  const params = new URLSearchParams({ after_sequence: String(after), limit: String(MESSAGE_PAGE_LIMIT) });
  const path = `${casePath(caseId, "/messages")}?${params.toString()}`;
  return messagePage(parseJson(await send("GET", path, undefined, options, options.context)), caseId, after);
}

export async function createCase(idempotencyKey: string, options: BoundRequestOptions): Promise<Written<CaseView>> {
  const body: Schemas["CreateCaseIn"] = { scenario: "retail" };
  const result = await exchangeWith("POST", CASES_PATH, body, options, options.context,
                                    writeHeaders(idempotencyKey, null));
  return written(result, 201, caseView, (value) => value.version);
}

/** Post a staff note or an operator-entered customer message against case version `ifMatch`. The returned message
 *  must be the one this request describes (same case, source and text) and the case must be at a newer version. */
export async function postMessage(caseId: string, message: MessageIn, idempotencyKey: string, ifMatch: number,
                                  options: BoundRequestOptions): Promise<Written<MessagePosted>> {
  const path = casePath(caseId, "/messages");
  const body: MessageIn = { source: message.source, text: message.text };
  const result = await exchangeWith("POST", path, body, options, options.context,
                                    writeHeaders(idempotencyKey, ifMatch));
  return written(result, 201, (value): MessagePosted => {
    if (!isRecord(value)) {
      malformed();
    }
    const posted = { message: messageView(value["message"], caseId), case: caseView(value["case"]) };
    if (posted.case.case_id !== caseId || posted.case.version <= ifMatch || posted.message.source !== body.source
        || posted.message.text !== body.text) {
      malformed();
    }
    return posted;
  }, (value) => value.case.version);
}

/** Start a workbench investigation on case version `ifMatch`. */
export async function startRun(caseId: string, idempotencyKey: string, ifMatch: number,
                               options: BoundRequestOptions): Promise<Written<RunView>> {
  const path = casePath(caseId, "/runs");
  const body: Schemas["StartRunIn"] = { mode: "workbench" };
  const result = await exchangeWith("POST", path, body, options, options.context,
                                    writeHeaders(idempotencyKey, ifMatch));
  return written(result, 202, (value) => runView(value, caseId), (value) => value.version);
}

/** Full-page sign-in navigation; `returnTo` must already be a safe local path (see safeReturnTo). */
export function loginHref(returnTo: string): string {
  const query = { return_to: returnTo } satisfies NonNullable<operations["login"]["parameters"]["query"]>;
  return `${LOGIN_PATH}?${new URLSearchParams(query).toString()}`;
}
