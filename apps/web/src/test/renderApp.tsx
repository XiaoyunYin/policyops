import { act, render } from "@testing-library/react";
import { StrictMode } from "react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router";

import { App } from "../App";

function LocationProbe() {
  return <span data-testid="location" hidden>{useLocation().pathname}</span>;
}

export function renderApp(path = "/cases", { strict = false }: { strict?: boolean } = {}) {
  const user = userEvent.setup();
  const tree = (
    <MemoryRouter initialEntries={[path]}>
      <App />
      <LocationProbe />
    </MemoryRouter>
  );
  const view = render(strict ? <StrictMode>{tree}</StrictMode> : tree);
  return { user, ...view };
}

/** Let pending promise callbacks (fake replies, state updates) run inside act. */
export async function settle(): Promise<void> {
  await act(async () => {
    for (let round = 0; round < 5; round += 1) {
      await Promise.resolve();
    }
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
}

export async function becomeVisible(): Promise<void> {
  Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true });
  await act(async () => {
    document.dispatchEvent(new Event("visibilitychange"));
    await Promise.resolve();
  });
}
