import { expect, type Browser, type BrowserContext, type Locator, type Page } from "@playwright/test";
import { setTimeout as hold } from "node:timers/promises";
import type { components } from "../src/api/schema";
import { ACTION_TIMEOUT, restrictPage } from "./browser.ts";
import { capture, VIEWPORT, within } from "./capture.ts";

type Schema = components["schemas"];
export type Fixture = Schema["ProposalSummaryView"];
type Role = "analyst" | "reviewer";
const check = expect.configure({ timeout: ACTION_TIMEOUT });
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const WORKSPACE = "Fictional retail demo";
const CASES = "/api/v1/cases";
const PROPOSALS = "/api/v1/proposals";

export async function read<T>(context: BrowserContext, path: string, user?: Session): Promise<T> {
  const response = await context.request.get(path, {
    timeout: ACTION_TIMEOUT, maxRedirects: 0, maxRetries: 0,
    headers: user === undefined ? {} : { "PolicyOps-Expected-Principal": user.principal,
      "PolicyOps-Expected-Workspace": user.workspace },
  });
  try {
    if (response.status() !== 200) throw new Error(`Demo API read failed (HTTP ${String(response.status())})`);
    return await within(response.json() as Promise<T>, "Reading demo API response");
  } finally {
    await within(response.dispose(), "Releasing demo API response");
  }
}

export interface Session {
  readonly principal: string;
  readonly workspace: string;
  readonly cookies: Awaited<ReturnType<BrowserContext["storageState"]>>["cookies"];
}

export async function identity(context: BrowserContext, role: Role) {
  const me = await read<Schema["MeOut"]>(context, "/api/v1/me");
  if (!UUID.test(me.principal_id) || me.workspace_id === null || !UUID.test(me.workspace_id)
      || !me.workspaces.some((space) => space.workspace_id === me.workspace_id && space.name === WORKSPACE)
      || me.roles.length !== 1 || !me.roles.includes(role)) {
    throw new Error(`Expected the fictional demo workspace and ${role} role`);
  }
  return { principal: me.principal_id, workspace: me.workspace_id };
}

export async function newContext(browser: Browser, origin: string): Promise<BrowserContext> {
  return await within(browser.newContext({ baseURL: origin, viewport: VIEWPORT, deviceScaleFactor: 1,
    serviceWorkers: "block", reducedMotion: "reduce", acceptDownloads: false,
    // Recordings must not inherit the recording machine's locale or time zone.
    locale: "en-US", timezoneId: "UTC" }), "Opening browser context");
}

export async function signIn(browser: Browser, origin: string, name: "alice" | "bob", role: Role, password: string,
  discover: boolean) {
  const context = await newContext(browser, origin);
  try {
    const page = await within(context.newPage(), "Opening sign-in page");
    const guard = await restrictPage(context, page, origin, true);
    let session: Session;
    try {
      await page.goto("/cases");
      await page.getByRole("link", { name: "Sign in", exact: true }).click();
      await page.waitForURL((url) => url.origin === origin && url.pathname.startsWith("/dex/"));
      await page.locator('input[name="login"]').fill(`${name}@example.invalid`);
      await page.locator('input[name="password"]').fill(password);
      await page.getByRole("button", { name: /log ?in|sign ?in/i }).click();
      const chooser = page.getByRole("heading", { name: "Choose a workspace", exact: true });
      const cases = page.getByRole("heading", { name: "Cases", exact: true });
      await check(chooser.or(cases)).toBeVisible();
      if (await chooser.isVisible()) await page.getByRole("button", { name: WORKSPACE, exact: false }).click();
      await check(cases).toBeVisible();
      guard.check();
      // Capture state in memory only, without Playwright's optional storage-state file.
      const user = await identity(context, role);
      const { cookies } = await within(context.storageState(), "Reading session state");
      session = { ...user, cookies };
    } catch {
      // Playwright errors can include fill arguments, login URLs and authentication form details.
      throw new Error(`Dex sign-in or workspace verification failed for ${name}`);
    }
    const fixture = discover ? await newestPending(context, session) : null;
    return { session, fixture };
  } finally {
    await within(context.close(), "Closing sign-in context");
  }
}

async function newestPending(context: BrowserContext, user: Session): Promise<Fixture> {
  // The case queue is newest first. Its fixture rows are titled “retail”, so disambiguate using
  // the case's exact proposals. Bound discovery to the same eight pages as the browser queue.
  const deadline = performance.now() + 60_000;
  const requireTime = (): void => {
    if (performance.now() > deadline) throw new Error("Pending case discovery reached its time limit");
  };
  let cursor: string | null = null;
  for (let i = 0; i < 8; i += 1) {
    requireTime();
    const cases: Schema["CasePage"] = await read(context, `${CASES}?limit=25${cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`}`, user);
    for (const row of cases.items) {
      if (row.scenario !== "retail" || !row.customer_bound || !UUID.test(row.case_id)) continue;
      requireTime();
      const proposals = await read<Schema["ProposalPage"]>(context, `${CASES}/${row.case_id}/proposals?limit=100`, user);
      if (proposals.next_cursor !== null) throw new Error("Case proposal history exceeded the discovery limit");
      const candidate = proposals.items.filter((item) => item.tool === "modify_user_address"
        && item.state === "awaiting_consent").at(-1);
      if (candidate === undefined) continue;
      if (candidate.case_id === row.case_id && UUID.test(candidate.run_id) && UUID.test(candidate.proposal_id)
          && Number.isSafeInteger(candidate.proposal_version) && candidate.proposal_version > 0
          && DIGEST.test(candidate.action_digest)) return candidate;
      throw new Error("Pending proposal identity was malformed");
    }
    cursor = cases.next_cursor;
    if (cursor === null) break;
  }
  throw new Error("No pending address-change fixture requiring consent was found in the case queue");
}

export async function verifyFixture(context: BrowserContext, user: Session, fixture: Fixture, postedId?: string): Promise<void> {
  const detail = await read<Schema["ProposalDetailView"]>(context,
    `${PROPOSALS}/${fixture.proposal_id}?version=${String(fixture.proposal_version)}`, user);
  const { proposal, consent } = detail;
  const expectedState = postedId === undefined ? "awaiting_consent" : "awaiting_decision";
  const remaining = Date.parse(proposal.expires_at) - Date.parse(detail.server_time);
  if (detail.state !== expectedState || detail.presentation === null || detail.decision !== null
      || proposal.proposal_id !== fixture.proposal_id || proposal.proposal_version !== fixture.proposal_version
      || proposal.action_digest !== fixture.action_digest || proposal.action.tool !== fixture.tool
      || proposal.scope.case_id !== fixture.case_id || proposal.scope.run_id !== fixture.run_id
      || proposal.scope.workspace_id !== user.workspace) throw new Error("The selected proposal changed; stop recording");
  if (postedId === undefined ? consent !== null : consent?.customer_message_id !== postedId
      || consent.customer_message_text !== "yes" || consent.message_source !== "operator_entered_customer") {
    throw new Error("The selected proposal has unexpected customer consent; stop recording");
  }
  if (!Number.isFinite(remaining) || remaining < (postedId === undefined ? 50_000 : 5_000)) {
    throw new Error("The selected proposal is too close to expiry for the remaining recording steps");
  }
}

export async function caption(page: Page, text: string): Promise<void> {
  await within(page.evaluate((content) => {
    let overlay = document.getElementById("policyops-demo-caption");
    if (overlay === null) {
      overlay = document.createElement("div");
      overlay.id = "policyops-demo-caption";
      overlay.setAttribute("aria-hidden", "true");
      Object.assign(overlay.style, { position: "fixed", bottom: "16px", left: "50%", transform: "translateX(-50%)",
        zIndex: "2147483647", pointerEvents: "none", background: "#12263b", color: "#fff",
        padding: "10px 20px", borderRadius: "8px", font: "600 19px system-ui, sans-serif", whiteSpace: "nowrap" });
      document.body.append(overlay);
    }
    overlay.textContent = content;
  }, text), "Drawing walkthrough caption");
}

export async function center(target: Locator): Promise<void> {
  await check(target).toBeVisible();
  await within(target.evaluate((node) => { node.scrollIntoView({ block: "center", behavior: "instant" }); }), "Framing walkthrough step");
}

export async function submitOnce<T>(page: Page, guard: Awaited<ReturnType<typeof restrictPage>>, path: string,
  button: string, label: string, statusCode = 201): Promise<T> {
  guard.allowOnce(path);
  try {
    const [response] = await Promise.all([
      page.waitForResponse((entry) => entry.request().method() === "POST" && new URL(entry.url()).pathname === path),
      page.getByRole("button", { name: button, exact: true }).click(),
    ]);
    guard.check();
    if (response.status() !== statusCode || response.headers()["idempotent-replayed"] !== undefined) {
      throw new Error(`HTTP ${String(response.status())}`);
    }
    return await within(response.json() as Promise<T>, `Reading ${label} confirmation`);
  } catch (error) {
    const status = error instanceof Error && /^HTTP \d{3}$/.test(error.message) ? ` (${error.message})` : "";
    throw new Error(`${label} was not verified${status}. It may have committed. Inspect the same proposal before any new run.`, { cause: error });
  }
}

export async function walkthrough(browser: Browser, origin: string, passwords: { alice: string; bob: string }) {
  console.log("Signing in outside the recording and selecting a pending fictional fixture");
  const bob = (await signIn(browser, origin, "bob", "reviewer", passwords.bob, false)).session;
  const { session: alice, fixture } = await signIn(browser, origin, "alice", "analyst", passwords.alice, true);
  if (fixture === null || alice.principal === bob.principal || alice.workspace !== bob.workspace) {
    throw new Error("Expected distinct analyst and reviewer sessions in the same fictional workspace");
  }
  const casePath = `/cases/${fixture.case_id}`;
  const reviewPath = `/approvals/${fixture.proposal_id}/versions/${String(fixture.proposal_version)}`;
  console.log(`Recording case ${fixture.case_id} / proposal ${fixture.proposal_id} v${String(fixture.proposal_version)}`);

  const encoderContext = await newContext(browser, origin);
  try {
    const encoder = await within(encoderContext.newPage(), "Opening isolated video encoder");
    const context = await newContext(browser, origin);
    try {
      const page = await within(context.newPage(), "Opening recorded page");
      const guard = await restrictPage(context, page, origin, false);
      await within(context.addCookies(alice.cookies), "Loading Alice's session cookies");
      await page.goto("/cases");
      const current = await identity(context, "analyst");
      if (current.principal !== alice.principal || current.workspace !== alice.workspace) throw new Error("Alice session changed");
      const table = page.getByRole("table", { name: "Cases", exact: true });
      await check(table).toBeVisible();
      const link = table.locator(`a[href="${casePath}"]`);
      for (let i = 0; i < 7 && await link.count() === 0; i += 1) {
        const more = page.getByRole("button", { name: "Load more", exact: true });
        await more.click();
        await check(page.getByRole("button", { name: "Loading…", exact: true })).toBeHidden();
      }
      await center(link);
      await caption(page, "1/4  Alice opens a pending fictional case");
      const recording = await capture(page, encoder);
      try {
        await hold(6_000);
        await link.click();
        const run = page.locator(`a.run-option[href="${casePath}/runs/${fixture.run_id}"]`);
        await run.click();
        const action = page.getByRole("region", { name: "Presented action", exact: true });
        await check(action).toContainText(fixture.action_digest);
        await check(action.getByRole("link", { name: "Inspect exact proposal and staff review" })).toHaveAttribute("href", reviewPath);
        await center(action.locator(".message-text"));
        await caption(page, "1/4  Alice reviews the presented address change");
        await hold(8_000);
        await center(action.getByRole("heading", { name: "Sealed resource versions" }));
        await caption(page, "1/4  The action is bound to the digest and resource versions");
        await hold(6_000);
        const evidence = action.getByRole("link", { name: /^Inspect source / }).first();
        if (await evidence.isVisible()) {
          await evidence.click();
          const viewer = page.getByRole("region", { name: "Historical evidence", exact: true });
          await center(viewer.locator(".evidence-excerpt"));
          await caption(page, "1/4  Alice inspects the recorded evidence");
          await hold(4_000);
          await viewer.getByRole("link", { name: "Close evidence", exact: true }).click();
        } else {
          await action.getByRole("link", { name: "Inspect exact proposal and staff review" }).click();
          const policy = page.getByRole("region", { name: "Policy binding", exact: true });
          await center(policy);
          await caption(page, "1/4  Alice inspects the policy and sealed resource versions");
          await hold(4_000);
          await page.getByRole("link", { name: "Open case investigation", exact: true }).click();
        }

        const source = page.getByRole("radio", { name: "Customer message, entered by me" });
        const message = page.getByRole("textbox", { name: "Message", exact: true });
        await center(message);
        await caption(page, "2/4  Alice enters the customer's reply as a simulation");
        await source.focus();
        await source.press("Space");
        await check(source).toBeChecked();
        await message.fill("yes");
        await hold(6_000);
        await check(action).toContainText("No current customer consent recorded.");
        await page.getByRole("button", { name: "Post customer message…", exact: true }).click();
        await hold(4_000);
        await verifyFixture(context, alice, fixture);
        recording.check();
        const posted = await submitOnce<Schema["policyops__services__cases__MessagePosted"]>(page, guard,
          `${CASES}/${fixture.case_id}/messages`, "Confirm post", "Consent message submission");
        if (posted.case.case_id !== fixture.case_id || !UUID.test(posted.message.message_id)
            || posted.message.source !== "operator_entered_customer" || posted.message.text !== "yes") {
          throw new Error("Unexpected consent response. Inspect the same proposal before any new run.");
        }
        console.log("Consent message recorded for the selected case");
        await check(action).toContainText("Entered by staff (simulation) ·");
        await center(action.getByRole("heading", { name: "Customer consent" }));
        await hold(5_000);

        await within(context.clearCookies(), "Clearing Alice's cookies");
        await within(context.addCookies(bob.cookies), "Loading Bob's session cookies");
        const reviewer = await identity(context, "reviewer");
        if (reviewer.principal !== bob.principal || reviewer.workspace !== bob.workspace) throw new Error("Bob session changed");
        await page.goto(reviewPath);
        await caption(page, "3/4  Bob verifies the same sealed action digest");
        const digest = page.locator(".approval-identity").getByText(fixture.action_digest, { exact: true });
        await center(digest);
        await hold(6_000);
        const consent = page.getByRole("region", { name: "Customer consent", exact: true });
        await check(consent).toContainText("Entered by staff (simulation)");
        await check(consent.getByText("yes", { exact: true })).toBeVisible();
        await center(consent);
        await caption(page, "3/4  Bob checks the recorded simulated consent");
        await hold(6_000);
        const reason = page.getByRole("textbox", { name: "Decision reason" });
        await center(reason);
        await caption(page, "3/4  Bob gives a reason and confirms staff approval");
        await reason.fill("Verified exact address, customer consent and policy.");
        await hold(3_000);
        await page.getByRole("button", { name: "Approve…", exact: true }).click();
        await check(page.getByRole("alertdialog")).toContainText(fixture.action_digest);
        await hold(4_000);
        await verifyFixture(context, bob, fixture, posted.message.message_id);
        recording.check();
        const decision = await submitOnce<Schema["ApprovalDecision"]>(page, guard,
          `${PROPOSALS}/${fixture.proposal_id}/decision`, "Confirm approval", "Approval submission");
        if (decision.proposal_id !== fixture.proposal_id || decision.proposal_version !== fixture.proposal_version
            || decision.action_digest !== fixture.action_digest || decision.principal_id !== bob.principal
            || decision.decision !== "approve") {
          throw new Error("Unexpected approval response. Inspect the same proposal before any new run.");
        }
        console.log("Approval recorded. Waiting for the simulator receipt");

        const outcome = page.getByRole("region", { name: "Action outcome", exact: true });
        await expect(outcome.getByRole("heading", { name: "Action committed — receipt recorded" })).toBeVisible({ timeout: 20_000 });
        await check(outcome.locator("dt").filter({ hasText: /^Operation ID$/ }).locator("+ dd")).toHaveText(/\S/);
        await check(outcome.locator("dt").filter({ hasText: /^Receipt reference · SHA-256$/ }).locator("+ dd")).toHaveText(DIGEST);
        await center(outcome);
        await caption(page, "4/4  The retail simulator commits and returns a receipt");
        const poster = await page.screenshot({ type: "png", timeout: ACTION_TIMEOUT });
        await hold(12_000);
        guard.check();
        return { poster, ...await recording.finish() };
      } finally {
        recording.cancel();
      }
    } finally {
      await within(context.close(), "Closing recorded context");
    }
  } finally {
    await within(encoderContext.close(), "Closing video encoder");
  }
}
