import type { BrowserContext, TestInfo } from "@playwright/test";
import { spawnSync } from "node:child_process";
import { existsSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";

interface ContextToClose { name: string; context: Pick<BrowserContext, "tracing" | "close">; tracing: boolean }
type CleanupInfo = Pick<TestInfo, "outputPath" | "annotations" | "status" | "expectedStatus">;

export async function closeContexts(contexts: ContextToClose[], info: CleanupInfo, primaryFailed: boolean): Promise<void> {
  const failures: string[] = [];
  const secondary = (name: string, stage: string): void => {
    failures.push(`${name}: ${stage} failed`);
    // Fixed labels only: exception messages can contain credentials or OIDC URLs.
    info.annotations.push({ type: "secondary diagnostic", description: `${name}: ${stage} failed` });
  };
  for (const { name, context, tracing } of contexts) {
    const raw = info.outputPath(`${name}-raw.zip`), safe = info.outputPath(`${name}-trace.zip`);
    let stage = "post-login trace collection";
    try {
      if (tracing) {
        await context.tracing.stop({ path: raw });
        stage = "post-login trace sanitization";
        const sanitized = spawnSync(process.env["POLICYOPS_PYTHON"] ?? "python",
          ["-B", resolve(import.meta.dirname, "../../../scripts/redact_playwright.py"), raw, safe],
          { encoding: "utf8", timeout: 30_000 });
        if (sanitized.status !== 0) throw new Error("Trace sanitization failed");
      }
    } catch {
      secondary(name, stage);
    } finally {
      try { if (existsSync(raw)) unlinkSync(raw); }
      catch { secondary(name, "raw trace removal"); }
      try { await context.close(); }
      catch { secondary(name, "browser context closure"); }
    }
  }
  // Cleanup can fail an otherwise successful test, but can never replace the original failure or timeout.
  if (failures.length > 0 && !primaryFailed && info.status === info.expectedStatus) {
    throw new Error("Post-login cleanup failed; see secondary diagnostics");
  }
}
