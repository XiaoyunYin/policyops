import { Navigate, Route, Routes } from "react-router";

import { SessionProvider, useSessionState } from "./session/SessionProvider";
import { AppShell } from "./shell/AppShell";
import { ApprovalsPage, CaseDetailPage, CasesPage, MembersPage, NotFoundPage } from "./shell/pages";
import {
  BootFailedScreen,
  ChooseWorkspaceScreen,
  ExpiredScreen,
  LoadingScreen,
  NoWorkspaceScreen,
  SignInScreen,
  SignOutUnconfirmedScreen,
} from "./shell/screens";

function SessionGate() {
  const state = useSessionState();
  switch (state.status) {
    case "booting":
      return <LoadingScreen title="Loading" label="Loading PolicyOps…" />;
    case "bootFailed":
      return <BootFailedScreen error={state.error} />;
    case "signedOut":
      return <SignInScreen byUser={state.byUser} />;
    case "noWorkspace":
      return <NoWorkspaceScreen notice={state.notice} />;
    case "chooseWorkspace":
      return <ChooseWorkspaceScreen me={state.me} notice={state.notice} />;
    case "reconciling":
      return <LoadingScreen title="Reloading session" label="Your session changed. Reloading…" />;
    case "switching":
      return <LoadingScreen title="Switching workspace" label={`Switching to ${state.workspaceName}…`} />;
    case "expired":
      return <ExpiredScreen returnTo={state.returnTo} />;
    case "signingOut":
      return <LoadingScreen title="Signing out" label="Signing out…" />;
    case "signOutUnconfirmed":
      return <SignOutUnconfirmedScreen />;
    case "ready":
      // Keyed by generation: nothing from an earlier session context survives into a new one.
      return (
        <AppShell key={state.generation} me={state.me} notice={state.notice}>
          <Routes>
            <Route path="/" element={<Navigate to="/cases" replace />} />
            <Route path="/cases" element={<CasesPage me={state.me} />} />
            <Route path="/cases/:caseId" element={<CaseDetailPage me={state.me} />} />
            <Route path="/approvals" element={<ApprovalsPage me={state.me} />} />
            <Route path="/members" element={<MembersPage me={state.me} />} />
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </AppShell>
      );
  }
}

/** The application inside a router (BrowserRouter in main.tsx; MemoryRouter in tests). */
export function App() {
  return (
    <SessionProvider>
      <SessionGate />
    </SessionProvider>
  );
}
