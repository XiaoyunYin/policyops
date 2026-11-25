// @vitest-environment node
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { browserEnv, demoOrigin, MAX_VIDEO_BYTES, outputPath, rejectLoopbackAddresses, validateVideo } from "./guards.ts";

describe("demo target", () => {
  it("accepts a bare public HTTPS origin", () => {
    expect(demoOrigin("https://example.test", false)).toBe("https://example.test");
  });

  it.each([
    undefined, "http://example.test", "https://user@example.test", "https://@example.test",
    "https://example.test/", "https://example.test/dex", "https://example.test/a/..",
    "https://example.test?", "https://example.test?q=1", "https://example.test#", "https://example.test#fragment",
    "https://192.0.2.1", "https://[2001:db8::1]", "https://127.0.0.1", "https://127.1", "https://2130706433",
    "https://[::1]", "https://localhost.", "https://demo.localhost", "http://127.0.0.1:8080",
  ])("rejects %s as a live origin", (origin) => {
    expect(() => demoOrigin(origin, false)).toThrow();
  });

  it("limits --local to the Compose loopback HTTP address", () => {
    expect(demoOrigin("http://127.0.0.1:8080", true)).toBe("http://127.0.0.1:8080");
    for (const origin of ["http://localhost:8080", "http://127.1:8080", "http://127.0.0.1:8080/dex", "https://example.test"]) {
      expect(() => demoOrigin(origin, true)).toThrow();
    }
  });

  it("rejects public-mode DNS results that resolve to loopback", () => {
    expect(() => { rejectLoopbackAddresses(["192.0.2.1", "2001:db8::1"]); }).not.toThrow();
    for (const address of ["127.0.0.2", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1"]) {
      expect(() => { rejectLoopbackAddresses(["192.0.2.1", address]); }).toThrow(/loopback/);
    }
  });
});

describe("recording output", () => {
  const parent = resolve("assignment");
  const checkout = resolve(parent, "checkout");
  const temp = resolve(parent, "scratch");

  it("accepts a child under an external temp root", () => {
    expect(outputPath(temp, checkout, "N12/run-01")).toBe(resolve(temp, "N12/run-01"));
  });

  it("rejects roots and outputs inside the checkout", () => {
    expect(() => outputPath(checkout, checkout, "N12")).toThrow();
    expect(() => outputPath(resolve(checkout, "scratch"), checkout, "N12")).toThrow();
    expect(() => outputPath(parent, checkout, "checkout/N12")).toThrow();
  });

  it("rejects relative roots, absolute children and parent escapes", () => {
    expect(() => outputPath("scratch", checkout, "N12")).toThrow();
    expect(() => outputPath(temp, checkout, resolve(temp, "N12"))).toThrow();
    expect(() => outputPath(temp, checkout, "../scratch-other/N12")).toThrow();
    expect(() => outputPath(temp, checkout, "N12/..")).toThrow();
  });

  it("enforces the encoded duration and size, including the inclusive limits", () => {
    expect(() => { validateVideo(30, 1); }).not.toThrow();
    expect(() => { validateVideo(120, MAX_VIDEO_BYTES); }).not.toThrow();
    for (const seconds of [29.99, 120.01, Number.POSITIVE_INFINITY, Number.NaN]) {
      expect(() => { validateVideo(seconds, 100); }).toThrow(/duration/);
    }
    for (const bytes of [0, 1.5, MAX_VIDEO_BYTES + 1, Number.NaN]) {
      expect(() => { validateVideo(60, bytes); }).toThrow(/size/);
    }
  });
});

it("gives Chromium only allowlisted OS variables and the recorder scratch paths", () => {
  const filtered = browserEnv({ Path: "system-path", SystemRoot: "system-root", TEMP: "parent-temp",
    openai_example: "x", ANTHROPIC_example: "x", ViTe_example: "x", PgExample: "x", AWS_PROFILE: "x",
    POLICYOPS_DEMO_ORIGIN: "https://example.test" }, "recorder-temp");
  expect(filtered).toEqual({ Path: "system-path", SystemRoot: "system-root", TEMP: "recorder-temp", TMP: "recorder-temp",
    TMPDIR: "recorder-temp", HOME: "recorder-temp", USERPROFILE: "recorder-temp", XDG_CACHE_HOME: "recorder-temp",
    XDG_CONFIG_HOME: "recorder-temp" });
});
