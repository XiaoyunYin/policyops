import type { BrowserContext, Page } from "@playwright/test";
import { within } from "./capture.ts";

export const ACTION_TIMEOUT = 10_000;
const NAVIGATION_TIMEOUT = 15_000;

export async function restrictPage(context: BrowserContext, page: Page, origin: string, auth: boolean) {
  page.setDefaultTimeout(ACTION_TIMEOUT);
  page.setDefaultNavigationTimeout(NAVIGATION_TIMEOUT);
  const session = await within(context.newCDPSession(page), "Attaching request guard");
  let blocked = false;
  let allowedPost: string | undefined;
  session.on("Fetch.requestPaused", (event) => {
    const url = new URL(event.request.url);
    const dex = url.pathname === "/dex" || url.pathname.startsWith("/dex/");
    const read = event.request.method === "GET" || event.request.method === "HEAD";
    const post = event.request.method === "POST";
    const onOrigin = url.origin === origin && url.username === "" && url.password === "";
    // Fetch interception is per network request, including redirect hops. Only auth pages reach Dex.
    const allowed = onOrigin && (auth
      ? read || (post && (dex || url.pathname === "/api/v1/auth/workspace"))
      : !dex && !url.pathname.startsWith("/api/v1/auth/") && (read
        || (post && event.redirectedRequestId === undefined && url.search === "" && url.pathname === allowedPost)));
    if (allowed && !auth && post) allowedPost = undefined;
    if (!allowed) blocked = true;
    const requestId = event.requestId;
    const operation = allowed ? session.send("Fetch.continueRequest", { requestId })
      : session.send("Fetch.failRequest", { requestId, errorReason: "BlockedByClient" });
    void operation.catch(() => { blocked = true; });
  });
  await within(session.send("Fetch.enable", { patterns: [{ urlPattern: "*", requestStage: "Request" }] }),
    "Enabling request guard");
  const check = (): void => {
    if (blocked) throw new Error("Browser request guard blocked a request or lost interception");
  };
  return {
    check,
    allowOnce(path: string): void {
      check();
      if (allowedPost !== undefined) throw new Error("A browser write is already armed");
      allowedPost = path;
    },
  };
}
