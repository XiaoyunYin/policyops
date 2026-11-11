// Full-page screens for session states outside a selected workspace. None of them shows workspace data.

import type { ReactNode } from "react";
import { Button } from "react-aria-components/Button";
import { Dialog, Heading } from "react-aria-components/Dialog";
import { Modal, ModalOverlay } from "react-aria-components/Modal";
import { useLocation } from "react-router";

import { loginHref, type ApiError, type MeOut } from "../api/client";
import type { SessionNotice } from "../session/controller";
import { roleSummary } from "../session/permissions";
import { DEFAULT_RETURN_PATH, safeReturnTo } from "../session/returnTo";
import { useSessionController } from "../session/SessionProvider";
import { ErrorPanel, Status, describeError, useDocumentTitle } from "../ui/feedback";

function Brand() {
  return (
    <p className="brand brand-centered">
      <span className="brand-mark" aria-hidden="true" />
      PolicyOps
    </p>
  );
}

function CenteredPage({ title, children }: { title: string; children: ReactNode }) {
  useDocumentTitle(title);
  return (
    <main className="center-page" id="main" tabIndex={-1}>
      <div className="card">
        <Brand />
        {children}
      </div>
    </main>
  );
}

export function LoadingScreen({ label, title }: { label: string; title: string }) {
  useDocumentTitle(title);
  return (
    <main className="center-page" id="main" tabIndex={-1}>
      <Status label={label} />
    </main>
  );
}

export function SignInScreen({ byUser }: { byUser: boolean }) {
  const location = useLocation();
  const returnTo = byUser ? DEFAULT_RETURN_PATH : safeReturnTo(location.pathname);
  return (
    <CenteredPage title="Sign in">
      <h1>{byUser ? "You've signed out" : "Sign in to PolicyOps"}</h1>
      <p className="muted">
        {byUser ? "Sign in again to return to your workspace." : "Use your organization account to continue."}
      </p>
      <a className="button button-primary" href={loginHref(returnTo)}>Sign in</a>
    </CenteredPage>
  );
}

/**
 * The session could not be loaded, or a recovered view was refused again. `retryable` describes the failed request
 * and is not consulted: the action here only reloads /me (a read) under a new generation and replays no earlier write.
 */
export function BootFailedScreen({ error }: { error: ApiError }) {
  const controller = useSessionController();
  return (
    <CenteredPage title="Unavailable">
      <h1>PolicyOps couldn't load your session</h1>
      <ErrorPanel error={error} />
      <Button className="button" onPress={() => {
        controller.boot();
      }}>Reload session</Button>
    </CenteredPage>
  );
}

function SignOutButton() {
  const controller = useSessionController();
  return (
    <Button className="button" onPress={() => {
      controller.signOut();
    }}>Sign out</Button>
  );
}

export function NoWorkspaceScreen({ notice }: { notice: SessionNotice | null }) {
  return (
    <CenteredPage title="No workspace access">
      <h1>No workspace access</h1>
      {notice !== null ? <SessionNoticeBanner notice={notice} /> : null}
      <p className="muted">
        Your account isn't a member of any workspace yet. Ask a workspace administrator to add you.
      </p>
      <SignOutButton />
    </CenteredPage>
  );
}

export function SessionNoticeBanner({ notice }: { notice: SessionNotice }) {
  if (notice.kind === "contextChanged") {
    // Generic on purpose: true for a principal or a workspace change, and it repeats nothing from the earlier view.
    return (
      <div className="banner" role="status">
        <p className="banner-title">Your session changed in another window</p>
        <p>This window now shows your current sign-in and workspace. The earlier view was cleared, and earlier
          changes were not retried.</p>
      </div>
    );
  }
  return (
    <div className="banner banner-error" role="alert">
      <p className="banner-title">Couldn't switch to {notice.workspaceName}</p>
      <p>{describeError(notice.error).body}</p>
    </div>
  );
}

export function ChooseWorkspaceScreen({ me, notice }: { me: MeOut; notice: SessionNotice | null }) {
  const controller = useSessionController();
  return (
    <CenteredPage title="Choose a workspace">
      <h1>Choose a workspace</h1>
      {notice !== null ? <SessionNoticeBanner notice={notice} /> : null}
      <ul className="workspace-choices" aria-label="Workspaces">
        {me.workspaces.map((choice) => (
          <li key={choice.workspace_id}>
            <Button className="workspace-choice" onPress={() => {
              controller.switchWorkspace(choice.workspace_id);
            }}>
              <span className="workspace-choice-name">{choice.name}</span>
              <span className="workspace-choice-roles">{roleSummary(choice.roles)}</span>
            </Button>
          </li>
        ))}
      </ul>
      <SignOutButton />
    </CenteredPage>
  );
}

export function ExpiredScreen({ returnTo }: { returnTo: string }) {
  useDocumentTitle("Session ended");
  return (
    <div className="center-page">
      {/* Not dismissable: the only way forward is signing in again. */}
      <ModalOverlay className="modal-overlay" isOpen isDismissable={false} isKeyboardDismissDisabled>
        <Modal className="modal">
          <Dialog className="dialog" role="alertdialog">
            <Heading slot="title">Your session ended</Heading>
            <p>Sign in again to continue.</p>
            <a className="button button-primary" href={loginHref(returnTo)}>Sign in again</a>
          </Dialog>
        </Modal>
      </ModalOverlay>
    </div>
  );
}

export function SignOutUnconfirmedScreen() {
  const controller = useSessionController();
  return (
    <CenteredPage title="Sign-out not confirmed">
      <h1>Sign-out not confirmed</h1>
      <p className="muted">
        PolicyOps couldn't confirm that you signed out. Your session may still be active in this browser.
      </p>
      <Button className="button button-primary" onPress={() => {
        controller.signOut();
      }}>Try signing out again</Button>
    </CenteredPage>
  );
}
