// Workspace shell: skip link, header (workspace switcher, roles, account menu), primary navigation and the main
// landmark. Navigation entries follow the role union; the server still checks every request.

import { useEffect, useRef, useState, type ReactNode } from "react";
// Per-component entry points: the package root (and its Popover entry) also export Group and OverlayArrow, whose
// declarations do not type-check under this project's exactOptionalPropertyTypes with library checking enabled.
import { Button } from "react-aria-components/Button";
import { Dialog, Heading } from "react-aria-components/Dialog";
import { ListBox, ListBoxItem } from "react-aria-components/ListBox";
import { Menu, MenuItem, MenuTrigger } from "react-aria-components/Menu";
import { Modal, ModalOverlay } from "react-aria-components/Modal";
import { Label, Popover, Select, SelectValue } from "react-aria-components/Select";
import { NavLink, useLocation, useNavigate } from "react-router";

import { expectedContextOf, sameContext, type MeOut } from "../api/client";
import { isUnresolved } from "../api/writes";
import type { SessionNotice } from "../session/controller";
import { capabilities, roleSummary } from "../session/permissions";
import { useSessionController, useWriteEntries } from "../session/SessionProvider";
import { SessionNoticeBanner } from "./screens";

export const PAGE_HEADING_ID = "page-heading";

function focusPageHeading(): void {
  document.getElementById(PAGE_HEADING_ID)?.focus();
}

function WorkspaceSwitcher({ me }: { me: MeOut }) {
  const controller = useSessionController();
  const navigate = useNavigate();
  const current = me.workspaces.find((choice) => choice.workspace_id === me.workspace_id);
  if (me.workspaces.length < 2) {
    // Long names are clipped visually by CSS; the full name stays in the text and in the tooltip.
    return (
      <p className="workspace-name">
        <span className="muted">Workspace</span>
        {" "}
        <span className="workspace-name-text" title={current?.name}>{current?.name}</span>
      </p>
    );
  }
  return (
    <Select
      className="workspace-select"
      value={me.workspace_id}
      onChange={(key) => {
        if (typeof key === "string" && key !== me.workspace_id) {
          controller.switchWorkspace(key);
          // Resource paths belong to the previous workspace; start the new one at its case list.
          void navigate("/cases");
        }
      }}
    >
      <Label className="workspace-label">Workspace</Label>
      <Button className="select-button">
        <SelectValue />
        <span className="chevron" aria-hidden="true" />
      </Button>
      <Popover className="popover">
        <ListBox className="listbox" items={me.workspaces}>
          {(choice) => (
            <ListBoxItem className="listbox-item" id={choice.workspace_id} textValue={choice.name}>
              {choice.name}
            </ListBoxItem>
          )}
        </ListBox>
      </Popover>
    </Select>
  );
}

// Signing out while a write of this principal and workspace is unresolved asks first: it neither cancels that request
// nor keeps the text retained for retrying it. The warning names no request, count or other context's activity.
function AccountMenu({ me }: { me: MeOut }) {
  const controller = useSessionController();
  const entries = useWriteEntries();
  const [confirming, setConfirming] = useState(false);
  const context = expectedContextOf(me);
  const pending = entries.some((entry) => isUnresolved(entry) && sameContext(entry.context, context));
  return (
    <>
      <MenuTrigger>
        <Button className="button button-quiet account-button" aria-label="Account">
          <span className="avatar" aria-hidden="true" />
          <span className="chevron" aria-hidden="true" />
        </Button>
        <Popover className="popover" placement="bottom end">
          <Menu className="menu" onAction={(key) => {
            if (key === "sign-out") {
              if (pending) {
                setConfirming(true);
              } else {
                controller.signOut();
              }
            }
          }}>
            <MenuItem className="menu-item" id="sign-out">Sign out</MenuItem>
          </Menu>
        </Popover>
      </MenuTrigger>
      <ModalOverlay className="modal-overlay" isOpen={confirming} onOpenChange={setConfirming} isDismissable>
        <Modal className="modal">
          <Dialog className="dialog" role="alertdialog">
            <Heading slot="title">Sign out before your request is confirmed?</Heading>
            <p>Something you sent hasn't been confirmed yet. Signing out doesn't cancel it, so it may still be applied.
              Any message text kept here for retrying it will be lost.</p>
            <div className="actions">
              <Button className="button button-primary" autoFocus onPress={() => {
                setConfirming(false);
              }}>Keep working</Button>
              <Button className="button" onPress={() => {
                setConfirming(false);
                controller.signOut();
              }}>Sign out anyway</Button>
            </div>
          </Dialog>
        </Modal>
      </ModalOverlay>
    </>
  );
}

export function AppShell({ me, notice, children }: { me: MeOut; notice: SessionNotice | null; children: ReactNode }) {
  const can = capabilities(me.roles);
  const location = useLocation();
  const shownPath = useRef(location.pathname);

  useEffect(() => {
    // Move focus to the new page's heading after in-app navigation, and when the shell appears with focus lost
    // (e.g. after a workspace switch removed the focused control).
    if (shownPath.current !== location.pathname) {
      shownPath.current = location.pathname;
      const state = location.state as { focusCitation?: unknown } | null;
      const target = typeof state?.focusCitation === "string"
        ? document.getElementById(`citation-${state.focusCitation}`) : null;
      if (target !== null) target.focus(); else focusPageHeading();
    }
  }, [location.pathname, location.state]);

  useEffect(() => {
    if (document.activeElement === null || document.activeElement === document.body) {
      focusPageHeading();
    }
  }, []);

  return (
    <div className="shell">
      <a className="skip-link" href="#main" onClick={(event) => {
        event.preventDefault();
        document.getElementById("main")?.focus();
      }}>Skip to main content</a>
      <header className="topbar">
        <p className="brand">
          <span className="brand-mark" aria-hidden="true" />
          PolicyOps
        </p>
        <WorkspaceSwitcher me={me} />
        <p className="roles">
          <span className="visually-hidden">Your roles: </span>
          <span className="roles-text">{roleSummary(me.roles)}</span>
          {can.has("operateCases") ? null : <span className="badge">Read-only</span>}
        </p>
        <AccountMenu me={me} />
      </header>
      <div className="shell-body">
        <nav className="sidenav" aria-label="Primary">
          <ul>
            {can.has("readCases") ? <li><NavLink className="nav-link" to="/cases">Cases</NavLink></li> : null}
            {can.has("decideProposals") ? (
              <li><NavLink className="nav-link" to="/approvals">Approvals</NavLink></li>
            ) : null}
            {can.has("manageMembers") ? (
              <li><NavLink className="nav-link" to="/members">Members</NavLink></li>
            ) : null}
          </ul>
        </nav>
        <main className="content" id="main" tabIndex={-1}>
          {notice !== null ? <SessionNoticeBanner notice={notice} /> : null}
          {children}
        </main>
      </div>
    </div>
  );
}
