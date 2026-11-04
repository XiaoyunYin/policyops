import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";

import { App } from "./App";

test("renders the workbench heading without claiming unimplemented features", () => {
  render(<App />);
  expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("PolicyOps");
  expect(screen.getByText(/not implemented yet/)).toBeTruthy();
});
