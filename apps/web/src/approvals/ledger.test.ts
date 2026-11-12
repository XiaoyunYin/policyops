import { afterEach, describe, expect, test, vi } from "vitest";
import { expectedContextOf, type MeOut } from "../api/client";
import { WriteLedger, type LedgerSession } from "../api/writes";
import type { Scope, SessionState } from "../session/controller";
import { OTHER_PRINCIPAL, WORKSPACE_B, envelope, json, me } from "../test/fakeApi";
import { CASE, CITATION_ID, PROPOSAL_ID, RUN_ID } from "../test/runFixtures";
import { DECIDE_PATH, PAYLOAD, decision, fixture } from "./fixtures.test-support";

function session() {
  let profile = me({ roles: ["reviewer"] }); let generation = 1;
  let abort = new AbortController(); const listeners = new Set<() => void>();
  const state = (): SessionState => ({ status: "ready", me: profile, generation, notice: null });
  const s: LedgerSession = { scope: () => ({ context: expectedContextOf(profile), generation, signal: abort.signal }),
    isCurrent: (scope: Scope) => scope.generation === generation && !scope.signal.aborted,
    getState: state, subscribe: (listener) => { listeners.add(listener); return () => { listeners.delete(listener); }; },
    reportUnauthenticated: () => undefined, reportContextChanged: () => undefined, reportSuccess: () => undefined };
  return { session: s, change(next: MeOut) { abort.abort(); abort = new AbortController(); generation++; profile = next; for (const listener of listeners) listener(); } };
}
const spec = { kind: "decision", caseId: CASE.case_id, runId: RUN_ID, ifMatch: null, payload: null,
  decision: { proposalId: PROPOSAL_ID, payload: PAYLOAD, consentId: CITATION_ID } } as const;
async function flush() { for (let i = 0; i < 30; i++) await Promise.resolve(); }
afterEach(() => { vi.useRealTimers(); });
describe("decision ledger identity and uncertainty", () => {
  test("approve and reject share a synchronous duplicate guard for this version", async () => {
    const api = fixture(); const pending = api.defer("POST", DECIDE_PATH); const s = session(); const ledger = new WriteLedger(s.session);
    expect("entry" in ledger.begin(spec)).toBe(true);
    expect(ledger.begin({ ...spec, decision: { ...spec.decision, payload: { ...PAYLOAD, decision: "reject" } } })).toEqual({ refused: "duplicate" });
    expect(api.callsTo("POST", DECIDE_PATH)).toHaveLength(1);
    pending.resolve(json(201, decision(PAYLOAD))); await flush(); expect(ledger.getSnapshot()[0]?.phase).toBe("applied"); ledger.dispose();
  });
  test("timeout then later 403 preserves unknown; explicit identical retry validates canonical replay", async () => {
    vi.useFakeTimers(); const api = fixture(); api.defer("POST", DECIDE_PATH);
    api.next("POST", DECIDE_PATH, json(403, envelope("forbidden", "Role revoked.")));
    api.next("POST", DECIDE_PATH, () => new Response(JSON.stringify(decision(PAYLOAD)), { status: 200, headers: { "Idempotent-Replayed": "true" } }));
    const s = session(); const ledger = new WriteLedger(s.session, { timeoutMs: 100 }); ledger.begin(spec);
    await vi.advanceTimersByTimeAsync(101); expect(ledger.getSnapshot()[0]?.phase).toBe("unknown");
    expect(api.callsTo("POST", DECIDE_PATH)).toHaveLength(1);
    const id = ledger.getSnapshot()[0]?.id ?? 0; expect(ledger.retry(id)).toBe(true); await flush();
    expect(ledger.getSnapshot()[0]?.phase).toBe("unknown"); expect(ledger.getSnapshot()[0]?.failure?.status).toBe(403);
    expect(ledger.retry(id)).toBe(true); await flush(); expect(ledger.getSnapshot()[0]?.phase).toBe("applied");
    expect(api.callsTo("POST", DECIDE_PATH).map((c) => c.body)).toEqual([PAYLOAD, PAYLOAD, PAYLOAD]); ledger.dispose();
  });
  test.each(["wrong digest", "wrong version", "wrong reviewer", "wrong reason", "wrong consent", "wrong case", "missing replay header"])("malformed 2xx %s stays unknown", async (which) => {
    const api = fixture(); const d = decision(PAYLOAD);
    if (which === "wrong digest") d.action_digest = "b".repeat(64);
    if (which === "wrong version") d.proposal_version++;
    if (which === "wrong reviewer") d.principal_id = OTHER_PRINCIPAL;
    if (which === "wrong reason") d.reason = "different";
    if (which === "wrong consent") d.consent_id = RUN_ID;
    if (which === "wrong case") d.scope = { ...d.scope, case_id: RUN_ID };
    api.on("POST", DECIDE_PATH, json(which === "missing replay header" ? 200 : 201, d));
    const ledger = new WriteLedger(session().session); ledger.begin(spec); await flush();
    expect(ledger.getSnapshot()[0]?.phase).toBe("unknown"); ledger.dispose();
  });
  test("503 decision_outcome_unknown remains unconfirmed and never retries automatically", async () => {
    const api = fixture(); api.on("POST", DECIDE_PATH, json(503, { ...envelope("unavailable", "Commit outcome unknown.", true), rule_id: "api.decision_outcome_unknown" }));
    const ledger = new WriteLedger(session().session); ledger.begin(spec); await flush();
    expect(ledger.getSnapshot()[0]?.phase).toBe("unknown"); expect(api.callsTo("POST", DECIDE_PATH)).toHaveLength(1); ledger.dispose();
  });
  test("context rotation strips reason/payload/failure; returning cannot restore retry or a late result", async () => {
    const api = fixture(); const pending = api.defer("POST", DECIDE_PATH); const s = session(); const ledger = new WriteLedger(s.session);
    ledger.begin(spec); s.change(me({ workspace: WORKSPACE_B, principal: OTHER_PRINCIPAL }));
    expect(ledger.getSnapshot()[0]?.decision).toBeNull(); expect(JSON.stringify(ledger.getSnapshot())).not.toContain(PAYLOAD.reason);
    pending.resolve(json(201, decision(PAYLOAD))); await flush();
    expect(ledger.getSnapshot()[0]?.result).toBeNull(); s.change(me({ roles: ["reviewer"] }));
    const e = ledger.getSnapshot()[0]; expect(e).toBeDefined(); if (e !== undefined) expect(ledger.canRetry(e)).toBe(false);
    expect(api.callsTo("POST", DECIDE_PATH)).toHaveLength(1); ledger.dispose();
  });
});
