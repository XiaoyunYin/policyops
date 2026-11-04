// Test-only network guard for the browser globals the app could use: fetch, XMLHttpRequest, WebSocket and
// EventSource. Each is replaced by a blocker; every blocked attempt is recorded so a test fails even when the
// code under test swallows the error. The setup file installs the blockers as soon as it is evaluated, before any
// test file or application module is imported, and again before each test. A test may install a fake for one
// global; fakes are reset after each test.
//
// Limitation: this covers these globals only. Node modules imported directly by a test (node:http, node:net)
// are not intercepted, and jsdom does not load subresources (images, scripts) unless configured to.

export const GUARDED = ["fetch", "XMLHttpRequest", "WebSocket", "EventSource"] as const;
export type GuardedGlobal = (typeof GUARDED)[number];

export class NetworkBlockedError extends Error {
  override name = "NetworkBlockedError";
}

const attempts: string[] = [];
const blockers = new WeakSet<object>();

function define(name: GuardedGlobal, value: unknown): void {
  Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
}

function blocker(name: GuardedGlobal): unknown {
  const refuse = (target: unknown): NetworkBlockedError => {
    const attempt = `${name}(${typeof target === "string" ? target : String(target)})`;
    attempts.push(attempt);
    return new NetworkBlockedError(`${attempt} is blocked in tests; install a fake with installFake()`);
  };
  if (name === "fetch") {
    return (input: unknown) => Promise.reject(refuse(input instanceof Request ? input.url : input));
  }
  if (name === "XMLHttpRequest") {
    // Construction is allowed so that code can configure a request; open() is the network boundary.
    return class BlockedXMLHttpRequest {
      open(_method: string, url: string | URL): void {
        throw refuse(String(url));
      }
      send(): void {
        throw refuse("send without open");
      }
    };
  }
  return class BlockedSocket {
    constructor(url: string | URL) {
      throw refuse(String(url));
    }
    close(): void {
      // unreachable: construction always throws
    }
  };
}

export function blockNetwork(): void {
  for (const name of GUARDED) {
    const value = blocker(name) as object;
    blockers.add(value);
    define(name, value);
  }
}

/** Whether the global currently installed under `name` is this module's blocker. */
export function isBlocked(name: GuardedGlobal): boolean {
  const value: unknown = Reflect.get(globalThis, name);
  return typeof value === "function" && blockers.has(value);
}

export function installFake(name: GuardedGlobal, fake: unknown): void {
  define(name, fake);
}

/** Returns and clears the recorded blocked attempts (for tests that expect a block). */
export function takeBlockedAttempts(): string[] {
  return attempts.splice(0, attempts.length);
}

export function verifyNoBlockedAttempts(): void {
  const unexpected = takeBlockedAttempts();
  if (unexpected.length > 0) {
    throw new Error(`unexpected network attempts: ${unexpected.join(", ")}`);
  }
}
