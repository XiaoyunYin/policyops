/// <reference types="vitest/config" />
import { isAbsolute } from "node:path";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Build output and caches go to process-local paths outside the checkout
// (set by scripts/devenv.py); refuse to fall back to repository defaults.
function externalPath(name: string): string {
  const value = process.env[name];
  if (value === undefined || !isAbsolute(value)) {
    throw new Error(`${name} must be an absolute path; run through scripts/devenv.py`);
  }
  return value;
}

// The browser talks only to the Vite origin; /api is forwarded to the API, which must be on this machine. The
// target is limited to a loopback IP so a stray variable cannot send session cookies elsewhere.
const LOOPBACK_API_HOSTS = new Set(["127.0.0.1", "[::1]"]);

function apiProxyTarget(): string {
  const raw = process.env["POLICYOPS_API_PROXY_TARGET"] ?? "http://127.0.0.1:8000";
  const url = URL.canParse(raw) ? new URL(raw) : null;
  if (
    url === null ||
    url.protocol !== "http:" ||
    !LOOPBACK_API_HOSTS.has(url.hostname) ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new Error("POLICYOPS_API_PROXY_TARGET must be an http origin on 127.0.0.1 or [::1], e.g. http://127.0.0.1:8000");
  }
  return url.origin;
}

const cacheDir = externalPath("POLICYOPS_WEB_CACHE_DIR");

export default defineConfig({
  plugins: [react()],
  cacheDir,
  server: {
    // POLICYOPS_PUBLIC_ORIGIN must equal this origin: the browser's own Origin header is forwarded unchanged
    // (changeOrigin only rewrites Host) and the API compares it exactly.
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "^/api(/|$)": { target: apiProxyTarget(), changeOrigin: false },
    },
  },
  build: {
    outDir: externalPath("POLICYOPS_WEB_BUILD_DIR"),
    emptyOutDir: true,
    sourcemap: false,
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}", "e2e/**/*.unit.ts", "demo/**/*.unit.ts"],
    setupFiles: ["src/test/setup.ts"],
    restoreMocks: true,
    sequence: { shuffle: false },
    fsModuleCachePath: `${cacheDir}/vitest-modules`,
  },
});
