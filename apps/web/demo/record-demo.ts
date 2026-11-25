import { lookup } from "node:dns/promises";
import { mkdir, mkdtemp, readFile, realpath, rm, rmdir, writeFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { parseArgs } from "node:util";
import { within } from "./capture.ts";
import { browserEnv, demoOrigin, isWithin, outputPath, rejectLoopbackAddresses } from "./guards.ts";

async function password(dir: string, name: "alice" | "bob"): Promise<string> {
  try {
    const value = (await readFile(resolve(dir, name), "utf8")).trim();
    if (value.length > 0) return value;
  } catch { /* Report the expected filename without printing file contents or an OS error. */ }
  throw new Error(`Read a nonempty public demo password from ${name} in --password-dir`);
}

async function cleanRun(root: string, run: string, published: boolean): Promise<void> {
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
    await rmdir(resolvedRun);
  }
}

async function main(): Promise<void> {
  const { values } = parseArgs({ options: { local: { type: "boolean" }, "password-dir": { type: "string" },
    help: { type: "boolean" } } });
  if (values.help) {
    console.log("node demo/record-demo.ts --password-dir <absolute directory> [--local]");
    console.log("Set POLICYOPS_DEMO_ORIGIN and POLICYOPS_TEMP_DIR. Output goes to POLICYOPS_TEMP_DIR/N12/<run>/.");
    return;
  }
  const origin = demoOrigin(process.env["POLICYOPS_DEMO_ORIGIN"], values.local === true);
  const checkout = await realpath(resolve(import.meta.dirname, "../../.."));
  const configuredRoot = process.env["POLICYOPS_TEMP_DIR"] ?? "";
  outputPath(configuredRoot, checkout, "N12");
  const root = await realpath(configuredRoot);
  const output = outputPath(root, checkout, "N12");
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
    throw new Error("The N12 output directory resolves outside the allowed output tree");
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
    await cleanRun(root, run, published);
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message.split("\n", 1)[0] : "Unexpected recorder failure";
  console.error(`Demo recorder stopped. ${message ?? "Unexpected recorder failure"}`);
  process.exitCode = 1;
});
