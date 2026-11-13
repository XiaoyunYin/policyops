import { defineConfig } from "@playwright/test";
import { isAbsolute, relative, resolve } from "node:path";

const root = process.env["POLICYOPS_TEMP_DIR"];
if (root === undefined || !isAbsolute(root) || !relative(resolve(import.meta.dirname, "../.."), root).startsWith("..")) {
  throw new Error("Set POLICYOPS_TEMP_DIR to an absolute directory outside the checkout");
}
const origin = new URL(process.env["POLICYOPS_E2E_ORIGIN"] ?? "http://127.0.0.1:8080");
if (origin.protocol !== "http:" || origin.hostname !== "127.0.0.1" || origin.pathname !== "/"
    || origin.username !== "" || origin.password !== "" || origin.search !== "" || origin.hash !== "") {
  throw new Error("POLICYOPS_E2E_ORIGIN must be a plain http://127.0.0.1 loopback origin matching Compose");
}
const output = resolve(root, "tests", "T38b", process.env["POLICYOPS_E2E_RUN"] ?? `browser-${String(Date.now())}`);
if (!relative(resolve(root, "tests", "T38b"), output) || relative(resolve(root, "tests", "T38b"), output).startsWith("..")) {
  throw new Error("POLICYOPS_E2E_RUN escapes the browser output root");
}

export default defineConfig({
  // Keep the whole flow bounded; individual actions and navigations must fail before this limit.
  testDir: "./e2e", fullyParallel: false, workers: 1, retries: 0, timeout: 120_000,
  outputDir: output, reporter: [["./e2e/reporter.ts", { output }]],
  expect: { timeout: 20_000 },
  use: { baseURL: origin.origin, browserName: "chromium", headless: true,
    actionTimeout: 15_000, navigationTimeout: 20_000,
    trace: "off", screenshot: "off", video: "off" }, // Auth is never recorded. Sanitized post-login traces below.
});
