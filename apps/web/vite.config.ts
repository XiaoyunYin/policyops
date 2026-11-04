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

const cacheDir = externalPath("POLICYOPS_WEB_CACHE_DIR");

export default defineConfig({
  plugins: [react()],
  cacheDir,
  build: {
    outDir: externalPath("POLICYOPS_WEB_BUILD_DIR"),
    emptyOutDir: true,
    sourcemap: false,
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["src/test/setup.ts"],
    restoreMocks: true,
    sequence: { shuffle: false },
    fsModuleCachePath: `${cacheDir}/vitest-modules`,
  },
});
