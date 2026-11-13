import { test, expect, type BrowserContext, type Page, type TestInfo } from "@playwright/test";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";
import { closeContexts } from "./cleanup";

interface Scenario {
  case_id: string; run_id: string; proposal_id: string; proposal_version: number;
  action_digest: string; case_version_before: number;
}
interface Execution {
  run_id: string; operation_id: string; state: string; attempts: number;
  receipt_sha256: string | null; remote_receipt_sha256: string | null;
}
interface Inspection { executions: Execution[]; case_version: number; pending_outcomes: number }
const repo = resolve(import.meta.dirname, "../../..");

function compose(service: "worker", mode: "seed"): Scenario;
function compose(service: "worker", mode: "inspect", caseId: string): Inspection;
function compose(service: "seed-demo", mode: "foreign"): { foreign_case_id: string };
function compose(service: string, mode: string, caseId?: string): unknown {
  const project = process.env["COMPOSE_PROJECT_NAME"];
  if (project === undefined || !/^policyops-[a-z0-9-]+$/.test(project)) throw new Error("Set an explicit policyops-* COMPOSE_PROJECT_NAME");
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(OPENAI_|ANTHROPIC_|VITE_|PG)/i.test(key)));
  const done = spawnSync("docker", ["compose", "--project-name", project, "--file", resolve(repo, "compose.yaml"),
    "run", "--rm", "--no-deps", "--entrypoint", "python", service, "-B", "infra/compose/scenario.py", mode,
    ...(caseId === undefined ? [] : ["--case-id", caseId])],
    { env, encoding: "utf8", timeout: 45_000, maxBuffer: 1024 * 1024 });
  if (done.status !== 0) throw new Error(`Scenario ${mode} failed (exit ${String(done.status)}): ${done.stdout.slice(-2000)}`);
  return JSON.parse(done.stdout.trim()) as unknown;
}

async function signIn(page: Page, name: "alice" | "bob" | "carol", path: string): Promise<void> {
  const secrets = process.env["POLICYOPS_SECRETS_DIR"];
  if (secrets === undefined) throw new Error("Set POLICYOPS_SECRETS_DIR for this disposable Compose project");
  await page.goto(path);
  await page.getByRole("link", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(/\/dex\//);
  // Dex's password connector uses a real HTML form; no token/cookie injection or HTTP mocking.
  await page.locator('input[name="login"]').fill(`${name}@example.invalid`);
  try {
    await page.locator('input[name="password"]').fill(readFileSync(resolve(secrets, name), "utf8").trim());
  } catch {
    // Playwright's ordinary fill error can quote the argument. Never retain a password in a reporter error.
    throw new Error("Dex password entry failed");
  }
  await page.getByRole("button", { name: /log ?in|sign ?in/i }).click();
  const chooser = page.getByRole("heading", { name: "Choose a workspace", exact: true });
  const target = page.getByRole("heading", { name: "Presented action", exact: true });
  await expect(chooser.or(target)).toBeVisible();
  if (await chooser.isVisible()) {
    const selected = page.waitForResponse((response) => response.request().method() === "POST"
      && new URL(response.url()).pathname === "/api/v1/auth/workspace", { timeout: 20_000 });
    await page.getByRole("button", { name: /Fictional retail demo/ }).click();
    expect((await selected).status()).toBe(204);
    await expect(target).toBeVisible();
  }
  await page.goto(path);
  await expect(target).toBeVisible();
}

interface UserContext {
  name: string; context: BrowserContext; page: Page; tracing: boolean;
  responses: { method: string; path: string; status: number }[]; dropped: number;
}
async function userContext(browser: import("@playwright/test").Browser, baseURL: string, name: string): Promise<UserContext> {
  const context = await browser.newContext({ baseURL });
  // These contexts bypass the configured page fixture, so set their action/navigation bounds explicitly.
  context.setDefaultTimeout(15_000);
  context.setDefaultNavigationTimeout(20_000);
  let page: Page;
  try { page = await context.newPage(); }
  catch (error) { await context.close().catch(() => { /* Preserve the page-creation failure. */ }); throw error; }
  const entry: UserContext = { name, context, page, tracing: false, responses: [], dropped: 0 };
  page.on("response", (response) => {
    const path = new URL(response.url()).pathname;
    if (!/^\/(api|dex)(\/|$)/.test(path)) return;
    if (entry.responses.length === 256) { entry.responses.shift(); entry.dropped += 1; }
    entry.responses.push({ method: response.request().method(), path, status: response.status() });
  });
  return entry;
}
async function failureDiagnostics(contexts: UserContext[], info: TestInfo): Promise<void> {
  for (const entry of contexts) {
    // Only pathname, bounded visible headings and response metadata. Never read cookies, bodies or headers.
    const headings = await entry.page.getByRole("heading").evaluateAll((nodes) => nodes
      .filter((node) => node instanceof HTMLElement && node.checkVisibility({ checkVisibilityCSS: true, checkOpacity: true }))
      .slice(0, 32).map((node) => node.textContent.slice(0, 160))).catch(() => ["[unavailable]"]);
    const secrets = process.env["POLICYOPS_SECRETS_DIR"];
    let body = JSON.stringify({ context: entry.name, pathname: new URL(entry.page.url()).pathname,
      headings, responses: entry.responses, dropped: entry.dropped }, null, 2);
    if (secrets !== undefined) {
      for (const name of ["alice", "bob", "carol", "client_secret", "retail_key"]) {
        const secret = readFileSync(resolve(secrets, name), "utf8").trim();
        if (secret !== "") body = body.replaceAll(secret, "[REDACTED]");
      }
    }
    const path = info.outputPath(`${entry.name}-diagnostics.json`);
    writeFileSync(path, body);
    await info.attach(`${entry.name}-diagnostics`, { path, contentType: "application/json" });
  }
}

async function observe(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const observed = { csp: 0, events: [] as string[] };
    Object.assign(window, { policyopsE2E: observed });
    document.addEventListener("securitypolicyviolation", () => { observed.csp += 1; });
    const original = window.fetch.bind(window);
    window.fetch = async (...args) => {
      const response = await original(...args);
      if (!response.headers.get("content-type")?.startsWith("text/event-stream") || response.body === null) return response;
      let tail = "";
      const decoder = new TextDecoder();
      const stream = new TransformStream<Uint8Array, Uint8Array>({ transform(chunk, controller) {
        tail = (tail + decoder.decode(chunk, { stream: true })).slice(-131072);
        for (const match of tail.matchAll(/(?:^|\n)event: ?([^\r\n]+)/g)) {
          if (match[1] !== undefined && !observed.events.includes(match[1])) observed.events.push(match[1]);
        }
        controller.enqueue(chunk);
      } });
      return new Response(response.body.pipeThrough(stream), { status: response.status, headers: response.headers });
    };
  });
}
async function observations(page: Page): Promise<{ csp: number; events: string[] }> {
  return page.evaluate(() => (window as unknown as { policyopsE2E: { csp: number; events: string[] } }).policyopsE2E);
}

test("customer consent, exact reviewer approval and factual simulator outcome through Caddy and Dex", { tag: "@t38-consent-drill" }, async ({ browser, baseURL }, info) => {
  if (baseURL === undefined) throw new Error("browser origin absent");
  const scenario = compose("worker", "seed");
  const foreign = compose("seed-demo", "foreign");
  const casePath = `/cases/${scenario.case_id}/runs/${scenario.run_id}`;
  const reviewPath = `/approvals/${scenario.proposal_id}/versions/${String(scenario.proposal_version)}`;
  const contexts: UserContext[] = [];
  const consoleCsp: string[] = [];
  let primaryFailed = false;
  try {
    for (const name of ["alice", "bob", "carol"] as const) {
      const entry = await userContext(browser, baseURL, name); contexts.push(entry);
      const { context, page } = entry;
      page.on("console", (message) => { if (/content.security.policy|\bCSP\b|refused to (execute|connect|load)/i.test(message.text())) consoleCsp.push(name); });
      await observe(page);
      await signIn(page, name, casePath);
      // Start after passwords and OIDC codes leave the browser. Network metadata is sanitized at closure.
      await context.tracing.start({ screenshots: false, snapshots: false, sources: false }); entry.tracing = true;
    }
    const alice = contexts[0]?.page, bob = contexts[1]?.page, carol = contexts[2]?.page;
    if (alice === undefined || bob === undefined || carol === undefined) throw new Error("browser contexts absent");
    const documentResponse = await bob.request.get("/", { timeout: 15_000 });
    expect(documentResponse.status()).toBe(200);
    expect(documentResponse.headers()["content-security-policy"]).toContain("script-src 'self'");
    expect(documentResponse.headers()["content-security-policy"]).toContain("frame-ancestors 'none'");
    expect(documentResponse.headers()["x-content-type-options"]).toBe("nosniff");
    expect(documentResponse.headers()["x-frame-options"]).toBe("DENY");
    expect(documentResponse.headers()["referrer-policy"]).toBe("no-referrer");
    const scripts = await bob.locator("script[src]").evaluateAll((nodes) => nodes.map((node) => node.getAttribute("src") ?? ""));
    expect(scripts.length).toBeGreaterThan(0);
    for (const src of scripts) {
      const js = await bob.request.get(src, { timeout: 15_000 }); expect(js.status()).toBe(200);
      expect(await js.text()).not.toMatch(/sourceMappingURL/);
      const map = await bob.request.get(`${src}.map`, { timeout: 15_000 });
      // SPA fallback may return HTML 200; it must never return an actual source map.
      expect(map.headers()["content-type"]).not.toContain("json");
      expect(await map.text()).not.toMatch(/"sources"\s*:|"mappings"\s*:/);
    }
    await expect(alice.getByRole("heading", { name: "Presented action" })).toBeVisible();
    await expect(alice.getByText(scenario.action_digest, { exact: true })).toBeVisible();
    await expect(carol.getByRole("textbox", { name: "Message", exact: true })).toHaveCount(0);
    await expect(carol.getByRole("button", { name: "Cancel investigation" })).toHaveCount(0);
    for (const page of [alice, carol]) {
      await page.goto(reviewPath);
      await expect(page.getByText(/Inspection only/)).toBeVisible();
      await expect(page.getByRole("button", { name: "Approve…", exact: true })).toHaveCount(0);
      await expect(page.getByRole("textbox", { name: "Decision reason" })).toHaveCount(0);
      const denied = await page.evaluate(async (proposal) => {
        const me = await (await fetch("/api/v1/me")).json() as { principal_id: string; workspace_id: string };
        const csrf = document.cookie.split("; ").find((value) => value.startsWith("policyops_csrf_local="))?.split("=")[1];
        const response = await fetch(`/api/v1/proposals/${proposal.proposal_id}/decision`, { method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": decodeURIComponent(csrf ?? ""),
            "PolicyOps-Expected-Principal": me.principal_id, "PolicyOps-Expected-Workspace": me.workspace_id },
          body: JSON.stringify({ proposal_version: proposal.proposal_version, action_digest: proposal.action_digest,
            decision: "approve", reason: "Role denial probe for the fictional demo." }) });
        const body = await response.json() as { code: string; rule_id: string };
        return { status: response.status, code: body.code, rule: body.rule_id };
      }, scenario);
      expect(denied).toEqual({ status: 403, code: "forbidden", rule: "auth.role" });
    }
    await alice.goto(casePath);
    await expect(alice.getByText(/Activity live/)).toBeVisible();
    const source = alice.getByRole("radio", { name: "Customer message, entered by me" });
    await source.focus();
    await source.press("Space");
    await expect(source).toBeChecked();
    await alice.getByRole("textbox", { name: "Message", exact: true }).fill("yes");
    await alice.getByRole("button", { name: "Post customer message…", exact: true }).click();
    await alice.getByRole("button", { name: "Confirm post", exact: true }).click();
    await expect.poll(async () => (await observations(alice)).events).toContain("consent.recorded");
    await expect(alice.getByRole("region", { name: "Presented action", exact: true })).toContainText("Entered by staff (simulation) ·");
    await bob.goto(reviewPath);
    await expect(bob.getByRole("region", { name: "Customer consent", exact: true })).toContainText("Entered by staff (simulation)");
    await expect(bob.locator(".approval-identity")).toContainText(scenario.action_digest);
    await bob.getByRole("textbox", { name: "Decision reason" }).fill("Verified exact address, customer consent and policy.");
    await bob.getByRole("button", { name: "Approve…", exact: true }).click();
    await expect(bob.getByRole("alertdialog")).toContainText(scenario.action_digest);
    const decision = bob.waitForResponse((response) => response.request().method() === "POST" && response.url().includes("/decision"), { timeout: 20_000 });
    await bob.getByRole("button", { name: "Confirm approval", exact: true }).click();
    expect((await decision).status()).toBe(201);
    const approveOnly = process.env["POLICYOPS_E2E_APPROVE_ONLY"] === "1";
    if (!approveOnly) {
      await expect(bob.getByRole("heading", { name: "Action committed — receipt recorded", exact: true })).toBeVisible();
      await expect.poll(async () => (await observations(alice)).events).toContain("execution.changed");
      const truth = compose("worker", "inspect", scenario.case_id);
      const row = truth.executions.find((item) => item.run_id === scenario.run_id);
      expect(row?.state).toBe("succeeded"); expect(row?.attempts).toBe(1);
      expect(row?.receipt_sha256).toMatch(/^[a-f0-9]{64}$/);
      expect(row?.receipt_sha256).toBe(row?.remote_receipt_sha256);
      expect(truth.case_version).toBe(scenario.case_version_before + 1);
      await expect(bob.getByRole("region", { name: "Action outcome", exact: true })).toContainText(row?.operation_id ?? "missing");
      await expect(bob.getByRole("region", { name: "Action outcome", exact: true })).toContainText(row?.receipt_sha256 ?? "missing");
    }
    for (const { page } of contexts) {
      expect((await observations(page)).csp).toBe(0);
      // The SPA document for /cases/{id} is always 200; the boundary under test is the API response.
      const refused = page.waitForResponse((response) => new URL(response.url()).pathname === `/api/v1/cases/${foreign.foreign_case_id}`, { timeout: 20_000 });
      await page.goto(`/cases/${foreign.foreign_case_id}`);
      const response = await refused; expect(response.status()).toBe(404);
      expect((await response.json() as { code: string }).code).toBe("not_found");
      await expect(page.getByRole("heading", { name: "Not found", exact: true })).toBeVisible();
      expect((await observations(page)).csp).toBe(0);
    }
    expect(consoleCsp).toEqual([]);
    const manifest = process.env["POLICYOPS_E2E_MANIFEST"];
    if (manifest !== undefined) {
      const root = process.env["POLICYOPS_TEMP_DIR"];
      if (root === undefined || !isAbsolute(manifest) || relative(root, manifest).startsWith("..") || relative(root, manifest) === "") {
        throw new Error("Scenario manifest must be a file under POLICYOPS_TEMP_DIR");
      }
      writeFileSync(manifest, JSON.stringify(scenario));
    }
  } catch (error) {
    primaryFailed = true;
    await failureDiagnostics(contexts, info).catch(() => {
      info.annotations.push({ type: "secondary diagnostic", description: "Per-context failure diagnostics unavailable" });
    });
    throw error;
  } finally {
    await closeContexts(contexts, info, primaryFailed);
  }
});

test("two real reviewer browsers race for one exact decision", async ({ browser, baseURL }, info) => {
  if (baseURL === undefined) throw new Error("browser origin absent");
  const scenario = compose("worker", "seed");
  const contexts: UserContext[] = [];
  let primaryFailed = false;
  try {
    const pages: Page[] = [];
    for (const [index, name] of (["alice", "bob", "bob"] as const).entries()) {
      const entry = await userContext(browser, baseURL, `${name}-${String(index)}`); contexts.push(entry);
      const { page } = entry; pages.push(page);
      await signIn(page, name, `/cases/${scenario.case_id}/runs/${scenario.run_id}`);
    }
    const alice = pages[0], first = pages[1], second = pages[2];
    if (alice === undefined || first === undefined || second === undefined) throw new Error("race contexts absent");
    const source = alice.getByRole("radio", { name: "Customer message, entered by me" });
    await source.focus();
    await source.press("Space");
    await expect(source).toBeChecked();
    await alice.getByRole("textbox", { name: "Message", exact: true }).fill("yes");
    await alice.getByRole("button", { name: "Post customer message…", exact: true }).click();
    const consent = alice.waitForResponse((response) => response.request().method() === "POST" && response.url().includes("/messages"), { timeout: 20_000 });
    await alice.getByRole("button", { name: "Confirm post", exact: true }).click();
    expect((await consent).status()).toBe(201);
    for (const [index, page] of [first, second].entries()) {
      await page.goto(`/approvals/${scenario.proposal_id}/versions/${String(scenario.proposal_version)}`);
      await page.getByRole("textbox", { name: "Decision reason" }).fill(`Exact proposal checked in reviewer window ${String(index)}.`);
      await page.getByRole("button", { name: "Approve…", exact: true }).click();
      await expect(page.getByRole("alertdialog")).toContainText(scenario.action_digest);
    }
    const replies = [first, second].map((page) => page.waitForResponse((response) => response.request().method() === "POST" && response.url().includes("/decision"), { timeout: 20_000 }));
    await Promise.all([first, second].map((page) => page.getByRole("button", { name: "Confirm approval", exact: true }).click()));
    expect((await Promise.all(replies)).map((response) => response.status()).sort()).toEqual([201, 409]);
    await expect.poll(() => compose("worker", "inspect", scenario.case_id).executions.find((row) => row.run_id === scenario.run_id)?.state).toBe("succeeded");
    const state = compose("worker", "inspect", scenario.case_id);
    expect(state.executions.filter((row) => row.run_id === scenario.run_id)).toHaveLength(1);
    expect(state.case_version).toBe(scenario.case_version_before + 1);
  } catch (error) {
    primaryFailed = true;
    await failureDiagnostics(contexts, info).catch(() => {
      info.annotations.push({ type: "secondary diagnostic", description: "Per-context failure diagnostics unavailable" });
    });
    throw error;
  } finally {
    await closeContexts(contexts, info, primaryFailed);
  }
});
