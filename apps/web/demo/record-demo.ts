import { lookup } from "node:dns/promises";
import { mkdir, mkdtemp, readFile, realpath, rm, rmdir, writeFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { parseArgs } from "node:util";
import { within } from "./capture.ts";
import { browserEnv, demoOrigin, isWithin, liveCasePath, outputPath, rejectLoopbackAddresses } from "./guards.ts";

async function password(dir: string, name: "alice" | "bob"): Promise<string> {
  try {
    const value = (await readFile(resolve(dir, name), "utf8")).trim();
    if (value.length > 0) return value;
  } catch { /* Report the expected filename without printing file contents or an OS error. */ }
  throw new Error(`Read a nonempty public demo password from ${name} in --password-dir`);
}

async function cleanRun(root: string, run: string, published: boolean, live: boolean): Promise<void> {
  const resolvedRun = await realpath(run);
  if (run !== resolvedRun || !isWithin(root, resolvedRun)) {
    throw new Error("Recording directory changed during the run; inspect it before cleanup");
  }
  const scratch = resolve(run, "chromium");
  const resolvedScratch = await realpath(scratch).catch((error: unknown) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  });
  if (resolvedScratch !== null) {
    if (resolvedScratch !== scratch) throw new Error("Chromium scratch directory changed; inspect it before cleanup");
    await rm(resolvedScratch, { recursive: true });
  }
  if (!published) {
    await rm(resolve(run, "policyops-demo.webm"), { force: true });
    await rm(resolve(run, "policyops-demo.png"), { force: true });
    if (live) await rm(resolve(run, "summary.json"), { force: true });
    await rmdir(resolvedRun);
  }
}

async function main(): Promise<void> {
  const { values } = parseArgs({ options: { local: { type: "boolean" }, "password-dir": { type: "string" },
    help: { type: "boolean" }, mode: { type: "string" }, case: { type: "string" }, "output-dir": { type: "string" } } });
  const live = values.mode === "live-agent";
  if (values.mode !== undefined && !live) throw new Error("Use --mode live-agent for the local live-agent recorder");
  if (live && values.help) {
    console.log("node demo/record-demo.ts --mode live-agent --local --case /cases/<uuid> --password-dir <absolute directory> --output-dir <absolute directory>");
    return;
  }
  if (values.help) {
    console.log("node demo/record-demo.ts --password-dir <absolute directory> [--local]");
    console.log("Set POLICYOPS_DEMO_ORIGIN and POLICYOPS_TEMP_DIR. Output goes to POLICYOPS_TEMP_DIR/N12/<run>/.");
    return;
  }
  if (live && values.local !== true) throw new Error("The live-agent recorder requires --local");
  if (!live && (values.case !== undefined || values["output-dir"] !== undefined)) {
    throw new Error("--case and --output-dir require --mode live-agent");
  }
  const origin = demoOrigin(process.env["POLICYOPS_DEMO_ORIGIN"], values.local === true);
  const checkout = await realpath(resolve(import.meta.dirname, "../../.."));
  const subdir = live ? "live-agent" : "N12";
  const configuredRoot = (live ? values["output-dir"] : process.env["POLICYOPS_TEMP_DIR"]) ?? "";
  if (live && (!isAbsolute(configuredRoot) || isWithin(checkout, resolve(configuredRoot)))) {
    throw new Error("--output-dir must be an absolute directory outside the checkout");
  }
  outputPath(configuredRoot, checkout, subdir);
  const root = await realpath(configuredRoot);
  const output = outputPath(root, checkout, subdir);
  const livePath = live ? liveCasePath(values.case) : undefined;
  const dir = values["password-dir"];
  if (dir === undefined || !isAbsolute(dir)) throw new Error("Supply --password-dir as an absolute directory");
  const [alice, bob] = await Promise.all([password(dir, "alice"), password(dir, "bob")]);
  if (values.local !== true) {
    const addresses = await within(lookup(new URL(origin).hostname, { all: true }), "Resolving HTTPS demo hostname");
    rejectLoopbackAddresses(addresses.map(({ address }) => address));
  }

  await mkdir(output, { recursive: true });
  const parent = await realpath(output);
  if (!isWithin(root, parent) || isWithin(checkout, parent) || parent === root) {
    throw new Error(`The ${subdir} output directory resolves outside the allowed output tree`);
  }
  const run = await mkdtemp(resolve(parent, "run-"));
  const scratch = resolve(run, "chromium");
  const videoPath = resolve(run, "policyops-demo.webm");
  const posterPath = resolve(run, "policyops-demo.png");
  let published = false;
  try {
    await mkdir(scratch);
    // Playwright's driver uses the current process temp directory for its temporary profile.
    Object.assign(process.env, { TEMP: scratch, TMP: scratch, TMPDIR: scratch });
    delete process.env["DEBUG"];
    delete process.env["PWDEBUG"];
    const { chromium } = await import("@playwright/test");
    const { walkthrough } = await import("./walkthrough.ts");
    const browser = await chromium.launch({ headless: true, timeout: 20_000,
      args: ["--no-proxy-server"], env: browserEnv(process.env, scratch) });
    if (livePath !== undefined) {
      const recording = await (async () => {
        try {
          const { liveWalkthrough } = await import("./live-agent.ts");
          return await liveWalkthrough(browser, origin, { alice, bob }, livePath);
        } finally {
          await within(browser.close(), "Closing Chromium", 15_000);
        }
      })();
      await writeFile(videoPath, recording.data, { flag: "wx" });
      const summaryPath = resolve(run, "summary.json");
      await writeFile(summaryPath, JSON.stringify(recording.summary, null, 2) + "\n", { flag: "wx" });
      published = true;
      console.log(`WebM ${videoPath} (${String(recording.data.length)} bytes, ${recording.seconds.toFixed(2)} s)`);
      console.log(`Summary ${summaryPath}`);
      if (recording.summary.outcome !== "committed") {
        console.error(`Live-agent recorder stopped (${recording.summary.outcome})`);
        process.exitCode = 1;
      }
      return;
    }
    const recording = await (async () => {
      try {
        return await walkthrough(browser, origin, { alice, bob });
      } finally {
        await within(browser.close(), "Closing Chromium", 15_000);
      }
    })();
    await writeFile(videoPath, recording.data, { flag: "wx" });
    await writeFile(posterPath, recording.poster, { flag: "wx" });
    published = true;
    console.log(`WebM ${videoPath} (${String(recording.data.length)} bytes, ${recording.seconds.toFixed(2)} s)`);
    console.log(`Poster ${posterPath} (${String(recording.poster.length)} bytes, 1280×720)`);
  } finally {
    await cleanRun(root, run, published, live);
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message.split("\n", 1)[0] : "Unexpected recorder failure";
  console.error(`Demo recorder stopped. ${message ?? "Unexpected recorder failure"}`);
  process.exitCode = 1;
});
