import { cleanup } from "@testing-library/react";
import { afterEach, beforeEach } from "vitest";

import { blockNetwork, verifyNoBlockedAttempts } from "./network";

// Installed now, while the setup file is evaluated: test files and the modules they import are evaluated after
// this, so import-time network calls hit the blockers too. Hooks only run once tests start.
blockNetwork();

beforeEach(() => {
  blockNetwork();
});

afterEach(() => {
  try {
    // Testing Library only cleans up automatically with Vitest globals, which this project does not enable.
    cleanup();
    verifyNoBlockedAttempts();
  } finally {
    blockNetwork(); // drop any fake the test installed
  }
});
