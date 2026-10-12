import { describe, expect, it } from "vitest";
import { assignableRoles, roleAtLeast } from "../permissions";

describe("hiérarchie des rôles", () => {
  it("un ADMIN ne peut ni attribuer OWNER ni gérer un OWNER", () => {
    expect(roleAtLeast("ADMIN", "OWNER")).toBe(false);
    expect(assignableRoles("ADMIN")).toEqual(["ADMIN", "EDITOR", "VIEWER"]);
  });

  it("un OWNER peut tout attribuer", () => {
    expect(assignableRoles("OWNER")).toEqual(["OWNER", "ADMIN", "EDITOR", "VIEWER"]);
  });

  it("sans rôle, rien n'est attribuable", () => {
    expect(roleAtLeast(null, "VIEWER")).toBe(false);
    expect(assignableRoles(undefined)).toEqual([]);
  });
});
