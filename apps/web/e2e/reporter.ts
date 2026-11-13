// Private, bounded diagnostics: authentication errors can contain URLs/call arguments even with tracing off.
import type { FullConfig, FullResult, Reporter, Suite, TestCase, TestError, TestResult } from "@playwright/test/reporter";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

export default class PrivateReporter implements Reporter {
  private readonly rows: { title: string; status: string; duration: number; errors: string[];
    diagnostics: { name: string; path: string }[]; secondaryDiagnostics: string[] }[] = [];
  private readonly failures: string[] = [];
  private collected = 0;
  private readonly secrets: string[];
  private readonly options: { output: string };
  constructor(options: { output: string }) {
    this.options = options;
    const directory = process.env["POLICYOPS_SECRETS_DIR"];
    this.secrets = directory === undefined || !existsSync(directory) ? []
      : ["alice", "bob", "carol", "client_secret", "retail_key"].map((name) => readFileSync(resolve(directory, name), "utf8").trim()).filter(Boolean);
  }
  onBegin(config: FullConfig, suite: Suite): void {
    this.collected = suite.allTests().length;
    process.stdout.write(`Collected ${String(this.collected)} browser tests; ${String(config.workers)} worker(s)\n`);
  }
  private safe(text: string): string {
    for (const secret of this.secrets) text = text.replaceAll(secret, "[REDACTED]");
    return text.replace(/https?:\/\/[^\s<>"')]+/g, (raw) => {
      try { const url = new URL(raw); return `${url.origin}${url.pathname}`; } catch { return "[REDACTED URL]"; }
    }).replace(/\b(Bearer\s+)[^\s]+/gi, "$1[REDACTED]")
      .replace(/\b(password|cookie|authorization|code|state|nonce|token)\s*[=:]\s*[^\s,;]+/gi, "$1=[REDACTED]");
  }
  onTestEnd(test: TestCase, result: TestResult): void {
    const errors = result.errors.map((error) => this.safe(error.message ?? error.value ?? "Browser check failed").slice(-16000));
    const diagnostics = result.attachments.filter((item) => item.name.endsWith("-diagnostics") && item.path !== undefined)
      .map((item) => ({ name: item.name, path: this.safe(item.path ?? "") }));
    const secondaryDiagnostics = result.annotations.filter((item) => item.type === "secondary diagnostic")
      .map((item) => this.safe(item.description ?? "Cleanup diagnostic unavailable"));
    this.rows.push({ title: test.title, status: result.status, duration: result.duration, errors, diagnostics, secondaryDiagnostics });
    process.stdout.write(`${result.status}: ${test.title}\n${errors.join("\n")}\n`);
  }
  onError(error: TestError): void {
    this.failures.push(this.safe(error.message ?? error.value ?? "Runner failed").slice(-16000));
  }
  onEnd(result: FullResult): void {
    // Playwright writes an error-context Markdown artifact automatically. Retain only sanitized text.
    const sanitizeFiles = (directory: string): void => {
      if (!existsSync(directory)) return;
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const path = resolve(directory, entry.name);
        if (entry.isSymbolicLink()) throw new Error("Linked browser artifact refused");
        if (entry.isDirectory()) sanitizeFiles(path);
        else if (/\.(md|txt|json|log)$/.test(entry.name)) writeFileSync(path, this.safe(readFileSync(path, "utf8")));
      }
    };
    sanitizeFiles(this.options.output);
    mkdirSync(this.options.output, { recursive: true });
    writeFileSync(resolve(this.options.output, "results.json"), JSON.stringify({
      status: result.status, collected: this.collected, tests: this.rows, runnerErrors: this.failures,
    }, null, 2));
  }
}
