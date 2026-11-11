import { describe, expect, test } from "vitest";

import type { Role } from "../api/client";
import { capabilities, roleSummary, type Capability } from "./permissions";
import { safeReturnTo } from "./returnTo";

describe("role union mirrors the server matrix", () => {
  const cases: [Role[], Capability[]][] = [
    [["analyst"], ["readCases", "operateCases"]],
    [["reviewer"], ["readCases", "operateCases", "decideProposals", "readAudit", "readEvaluations"]],
    [["admin"], ["readCases", "operateCases", "manageMembers", "readAudit", "readEvaluations"]],
    [["auditor"], ["readCases", "readAudit", "readEvaluations"]],
    [["reviewer", "admin"],
     ["readCases", "operateCases", "decideProposals", "manageMembers", "readAudit", "readEvaluations"]],
    [["auditor", "analyst"], ["readCases", "readAudit", "readEvaluations", "operateCases"]],
    [[], []],
  ];
  test.each(cases)("%j", (roles, expected) => {
    expect([...capabilities(roles)].sort()).toEqual([...expected].sort());
  });

  test("admin alone never decides proposals", () => {
    expect(capabilities(["admin"]).has("decideProposals")).toBe(false);
    expect(capabilities(["admin", "auditor", "analyst"]).has("decideProposals")).toBe(false);
  });

  test("roles are listed in a stable order", () => {
    expect(roleSummary(["admin", "reviewer"])).toBe("Reviewer, Admin");
    expect(roleSummary([])).toBe("No role");
  });
});

describe("sign-in return path", () => {
  test.each([
    ["/cases", "/cases"],
    ["/cases/0a0a-1", "/cases/0a0a-1"],
    ["/members", "/members"],
    ["/", "/cases"],
    ["//evil.example", "/cases"],
    ["https://evil.example/cases", "/cases"],
    ["/\\evil.example", "/cases"],
    ["/cases/../api/v1/auth/logout", "/cases"],
    ["/./cases", "/cases"],
    ["/api/v1/me", "/cases"],
    ["/cases?x=1", "/cases"],
    ["/cases/", "/cases"],
    ["/cases/%2e%2e", "/cases"],
    ["/cases\u0000", "/cases"],
    [`/${"a".repeat(200)}`, "/cases"],
    [null, "/cases"],
  ])("%j -> %s", (input, expected) => {
    expect(safeReturnTo(input)).toBe(expected);
  });

  test("paths up to the server's limit are kept", () => {
    const path = `/${"a".repeat(199)}`;
    expect(safeReturnTo(path)).toBe(path);
  });
});
