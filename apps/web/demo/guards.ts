import { isIP } from "node:net";
import { isAbsolute, relative, resolve, sep } from "node:path";

export function demoOrigin(raw: string | undefined, local: boolean): string {
  // Check the raw authority too: URL normalizes dot segments, empty userinfo and empty query markers.
  if (raw === undefined || !/^https?:\/\/[^/@?#\\\s]+$/.test(raw)) {
    throw new Error("Set POLICYOPS_DEMO_ORIGIN to a bare origin without credentials or a trailing slash");
  }
  const url = new URL(raw);
  const host = url.hostname.replace(/^\[|\]$|\.$/g, "");
  const valid = local
    ? url.protocol === "http:" && /^http:\/\/127\.0\.0\.1(?::[0-9]+)?$/.test(raw)
    : url.protocol === "https:" && isIP(host) === 0 && host !== "localhost.localdomain"
      && host !== "localhost" && !host.endsWith(".localhost");
  if (!valid) throw new Error("Use a public HTTPS hostname, or http://127.0.0.1 with --local");
  return url.origin;
}

export function rejectLoopbackAddresses(addresses: readonly string[]): void {
  const loopback = addresses.some((address) => {
    if (isIP(address) === 4) return address.startsWith("127.") || address === "0.0.0.0";
    if (isIP(address) !== 6) return false;
    const host = new URL(`http://[${address.split("%", 1)[0] ?? ""}]`).hostname;
    return host === "[::1]" || host === "[::]" || /^\[::ffff:7f[0-9a-f]{2}:[0-9a-f]+\]$/.test(host);
  });
  if (loopback) throw new Error("The HTTPS hostname resolves to a loopback address. Use --local for Compose");
}

export function isWithin(parent: string, path: string): boolean {
  const child = relative(parent, path);
  return child !== ".." && !child.startsWith(`..${sep}`) && !isAbsolute(child);
}

export function outputPath(root: string, checkout: string, child: string): string {
  if (!isAbsolute(root) || isWithin(checkout, root)) {
    throw new Error("POLICYOPS_TEMP_DIR must be absolute and outside the checkout");
  }
  const path = resolve(root, child);
  if (isAbsolute(child) || relative(root, path) === "" || !isWithin(root, path) || isWithin(checkout, path)) {
    throw new Error("Recording output must stay under POLICYOPS_TEMP_DIR and outside the checkout");
  }
  return path;
}

const BROWSER_ENV = new Set(["PATH", "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "PATHEXT", "LANG", "LC_ALL"]);

export function browserEnv(env: NodeJS.ProcessEnv, temp: string): Record<string, string> {
  const filtered: Record<string, string> = { TEMP: temp, TMP: temp, TMPDIR: temp,
    HOME: temp, USERPROFILE: temp, XDG_CACHE_HOME: temp, XDG_CONFIG_HOME: temp };
  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined && BROWSER_ENV.has(key.toUpperCase())) filtered[key] = value;
  }
  return filtered;
}

export const MAX_VIDEO_BYTES = 12_000_000;

export function validateVideo(seconds: number, bytes: number): void {
  if (!Number.isSafeInteger(bytes) || bytes <= 0 || bytes > MAX_VIDEO_BYTES) {
    throw new Error(`Video size ${String(bytes)} bytes is outside 1–${String(MAX_VIDEO_BYTES)} bytes`);
  }
  if (!Number.isFinite(seconds) || seconds < 30 || seconds > 120) {
    throw new Error(`Video duration ${seconds.toFixed(2)} s is outside 30–120 s`);
  }
}
