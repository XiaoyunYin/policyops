// Presentation-only mirror of the server's role x action matrix (policyops.domain.roles). Roles combine by union.
// Admins manage memberships but do not decide proposals unless they also hold the reviewer role. The server remains
// the authority: hiding a control never replaces its check, and every 403/404 is still shown as a refusal.

import type { Role } from "../api/client";

export type Capability =
  | "readCases"
  | "operateCases"
  | "decideProposals"
  | "manageMembers"
  | "readAudit"
  | "readEvaluations";

const OPERATE: readonly Capability[] = ["readCases", "operateCases"];

const GRANTS: Readonly<Record<Role, readonly Capability[]>> = {
  analyst: OPERATE,
  reviewer: [...OPERATE, "decideProposals", "readAudit", "readEvaluations"],
  admin: [...OPERATE, "manageMembers", "readAudit", "readEvaluations"],
  auditor: ["readCases", "readAudit", "readEvaluations"],
};

export function capabilities(roles: readonly Role[]): ReadonlySet<Capability> {
  return new Set(roles.flatMap((role) => GRANTS[role]));
}

export const ROLE_LABELS: Readonly<Record<Role, string>> = {
  analyst: "Analyst",
  reviewer: "Reviewer",
  admin: "Admin",
  auditor: "Auditor",
};

const ROLE_ORDER: readonly Role[] = ["analyst", "reviewer", "admin", "auditor"];

export function roleSummary(roles: readonly Role[]): string {
  const labels = ROLE_ORDER.filter((role) => roles.includes(role)).map((role) => ROLE_LABELS[role]);
  return labels.length === 0 ? "No role" : labels.join(", ");
}
