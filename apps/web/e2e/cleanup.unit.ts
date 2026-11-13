import type { BrowserContext, TestInfo } from "@playwright/test";
import { spawnSync } from "node:child_process";
import { existsSync, unlinkSync, writeFileSync } from "node:fs";
import { beforeEach, expect, test, vi } from "vitest";

import { closeContexts } from "./cleanup";
import PrivateReporter from "./reporter";

vi.mock("node:child_process", () => ({ spawnSync: vi.fn() }));
vi.mock("node:fs", () => ({ existsSync: vi.fn(), unlinkSync: vi.fn(), mkdirSync: vi.fn(),
  readdirSync: vi.fn(), readFileSync: vi.fn(), writeFileSync: vi.fn() }));

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(existsSync).mockReturnValue(true);
  vi.mocked(spawnSync).mockReturnValue({ status: 0 } as ReturnType<typeof spawnSync>);
});

function fixture(status: TestInfo["status"] = "passed", tracing = true) {
  const stop = vi.fn<BrowserContext["tracing"]["stop"]>().mockResolvedValue(undefined);
  const close = vi.fn<BrowserContext["close"]>().mockResolvedValue(undefined);
  const entry = { name: "alice", tracing, context: { tracing: { stop }, close } as unknown as BrowserContext };
  const info = { status, expectedStatus: "passed" as const,
    annotations: [] as TestInfo["annotations"], outputPath: (name: string) => name };
  return { entry, info, stop, close };
}

test.each(["failed", "timedOut"] as const)("trace stop cannot replace the original %s error", async (status) => {
  const { entry, info, stop, close } = fixture(status);
  stop.mockRejectedValue(new Error("private exception details"));
  const primary = new Error("original consent step failure");
  const run = async () => {
    try { throw primary; }
    finally { await closeContexts([entry], info, true); }
  };
  await expect(run()).rejects.toBe(primary);
  expect(info.annotations).toEqual([{ type: "secondary diagnostic", description: "alice: post-login trace collection failed" }]);
  expect(spawnSync).not.toHaveBeenCalled();
  expect(unlinkSync).toHaveBeenCalledWith("alice-raw.zip");
  expect(close).toHaveBeenCalledOnce();
});

test("timeout status preserves failure even before the catch flag is set", async () => {
  const { entry, info, stop } = fixture("timedOut");
  stop.mockRejectedValue(new Error("trace target closed"));
  await expect(closeContexts([entry], info, false)).resolves.toBeUndefined();
  expect(info.annotations).toHaveLength(1);
});

test("login remains untraced; all contexts close despite a close failure", async () => {
  const first = fixture("failed", false), next = fixture("failed", false);
  next.entry.name = "bob";
  first.close.mockRejectedValue(new Error("private closure error"));
  await closeContexts([first.entry, next.entry], first.info, true);
  expect(first.stop).not.toHaveBeenCalled();
  expect(next.stop).not.toHaveBeenCalled();
  expect(spawnSync).not.toHaveBeenCalled();
  expect(next.close).toHaveBeenCalledOnce();
  expect(first.info.annotations).toEqual([{ type: "secondary diagnostic", description: "alice: browser context closure failed" }]);
});

test("post-login traces still pass through the existing bounded sanitizer", async () => {
  const { entry, info, close } = fixture();
  await closeContexts([entry], info, false);
  expect(spawnSync).toHaveBeenCalledWith(expect.any(String),
    ["-B", expect.stringMatching(/[\\/]scripts[\\/]redact_playwright\.py$/), "alice-raw.zip", "alice-trace.zip"],
    { encoding: "utf8", timeout: 30_000 });
  expect(info.annotations).toEqual([]);
  expect(unlinkSync).toHaveBeenCalledWith("alice-raw.zip");
  expect(close).toHaveBeenCalledOnce();
});

test("sanitizer failure fails a successful test after every context is closed", async () => {
  const first = fixture(), next = fixture();
  next.entry.name = "bob";
  vi.mocked(spawnSync).mockReturnValueOnce({ status: 1 } as ReturnType<typeof spawnSync>);
  await expect(closeContexts([first.entry, next.entry], first.info, false)).rejects.toThrow("Post-login cleanup failed");
  expect(first.info.annotations).toEqual([{ type: "secondary diagnostic", description: "alice: post-login trace sanitization failed" }]);
  expect(first.close).toHaveBeenCalledOnce();
  expect(next.close).toHaveBeenCalledOnce();
});

test("failed raw removal is secondary and still closes the context", async () => {
  const { entry, info, close } = fixture("failed");
  vi.mocked(unlinkSync).mockImplementationOnce(() => { throw new Error("access denied"); });
  await closeContexts([entry], info, true);
  expect(info.annotations).toEqual([{ type: "secondary diagnostic", description: "alice: raw trace removal failed" }]);
  expect(close).toHaveBeenCalledOnce();
});

test("reporter retains the primary timeout separately from cleanup diagnostics", () => {
  vi.mocked(existsSync).mockReturnValue(false);
  const reporter = new PrivateReporter({ output: "unused-mocked-output" });
  reporter.onTestEnd({ title: "consent step" } as Parameters<PrivateReporter["onTestEnd"]>[0], {
    status: "timedOut", duration: 120_000, attachments: [], errors: [{ message: "original consent timeout" }],
    parallelIndex: 0, workerIndex: 0, retry: 0, startTime: new Date(0), stdout: [], stderr: [], steps: [],
    annotations: [{ type: "secondary diagnostic", description: "alice: post-login trace collection failed" }],
  });
  reporter.onEnd({ status: "failed", startTime: new Date(0), duration: 120_000 });
  expect(writeFileSync).toHaveBeenCalledWith(expect.stringMatching(/results\.json$/),
    expect.stringContaining('"errors": [\n        "original consent timeout"'));
  expect(writeFileSync).toHaveBeenCalledWith(expect.any(String),
    expect.stringContaining('"secondaryDiagnostics": [\n        "alice: post-login trace collection failed"'));
});
