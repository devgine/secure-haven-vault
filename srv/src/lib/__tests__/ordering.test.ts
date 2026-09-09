import { describe, expect, it } from "vitest";
import {
  applyFolderPlan,
  applySecretPlan,
  canDropFolderInto,
  descendantSet,
  destinationLabel,
  reorderIds,
  resolveDrop,
  siblingFolders,
  siblingSecrets,
} from "../ordering";
import type { FolderDto, SecretListItem } from "../types";

function f(id: string, parentId: string | null, name: string, position = 0): FolderDto {
  return {
    id,
    workspaceId: "ws",
    parentId,
    name,
    description: null,
    icon: null,
    color: null,
    position,
    secretCount: 0,
    createdAt: "2026-01-01T00:00:00.000Z",
  };
}

function s(id: string, folderId: string | null, name: string, position = 0): SecretListItem {
  return {
    id,
    workspaceId: "ws",
    folderId,
    position,
    type: "LOGIN",
    name,
    username: null,
    url: null,
    description: null,
    tags: [],
    favorite: false,
    expiresAt: null,
    notifyBeforeDays: null,
    updatedAt: "2026-01-01T00:00:00.000Z",
  };
}

// a ─ b ─ d
//   └ c
// e (racine)
const folders = [
  f("a", null, "Infra", 0),
  f("b", "a", "Prod", 0),
  f("d", "b", "EU", 0),
  f("c", "a", "Staging", 1),
  f("e", null, "Clients", 1),
];

const secrets = [
  s("s1", null, "Root A", 0),
  s("s2", null, "Root B", 1),
  s("s3", "a", "Infra 1", 0),
  s("s4", "a", "Infra 2", 1),
];

describe("reorderIds", () => {
  it("déplace un élément vers le bas", () => {
    expect(reorderIds(["1", "2", "3", "4"], ["1"], 3)).toEqual(["2", "3", "1", "4"]);
  });
  it("déplace un élément vers le haut", () => {
    expect(reorderIds(["1", "2", "3"], ["3"], 0)).toEqual(["3", "1", "2"]);
  });
  it("déplace plusieurs éléments en conservant leur ordre", () => {
    expect(reorderIds(["1", "2", "3", "4"], ["1", "3"], 4)).toEqual(["2", "4", "1", "3"]);
  });
  it("borne l'index", () => {
    expect(reorderIds(["1", "2"], ["2"], 99)).toEqual(["1", "2"]);
    expect(reorderIds(["1", "2"], ["2"], -5)).toEqual(["2", "1"]);
  });
  it("est idempotent quand la position ne change pas", () => {
    expect(reorderIds(["1", "2", "3"], ["2"], 1)).toEqual(["1", "2", "3"]);
  });
});

describe("hiérarchie", () => {
  it("calcule la descendance", () => {
    expect([...descendantSet(folders, "a")].sort()).toEqual(["a", "b", "c", "d"]);
  });
  it("interdit de déposer un groupe dans lui-même ou sa descendance", () => {
    expect(canDropFolderInto(folders, "a", "d")).toBe(false);
    expect(canDropFolderInto(folders, "a", "a")).toBe(false);
    expect(canDropFolderInto(folders, "a", null)).toBe(true);
    expect(canDropFolderInto(folders, "d", "e")).toBe(true);
  });
  it("trie les frères par position", () => {
    expect(siblingFolders(folders, "a").map((x) => x.id)).toEqual(["b", "c"]);
    expect(siblingSecrets(secrets, null).map((x) => x.id)).toEqual(["s1", "s2"]);
  });
  it("affiche un chemin lisible", () => {
    expect(destinationLabel(folders, "d")).toBe("Infra / Prod / EU");
    expect(destinationLabel(folders, null)).toBe("Racine du coffre");
  });
});

describe("resolveDrop", () => {
  it("réordonne un groupe avant un frère", () => {
    const res = resolveDrop({
      folders,
      secrets,
      item: { kind: "folder", ids: ["c"] },
      target: { kind: "folder", id: "b", edge: "before" },
    });
    expect(res.plan).toEqual({ kind: "folder", ids: ["c"], parentId: "a", index: 0 });
  });

  it("imbrique un groupe déposé au centre d'un autre", () => {
    const res = resolveDrop({
      folders,
      secrets,
      item: { kind: "folder", ids: ["e"] },
      target: { kind: "folder", id: "b", edge: "inside" },
    });
    expect(res.plan).toMatchObject({ parentId: "b", index: 1 });
  });

  it("refuse un groupe déposé dans sa descendance", () => {
    const res = resolveDrop({
      folders,
      secrets,
      item: { kind: "folder", ids: ["a"] },
      target: { kind: "folder", id: "d", edge: "inside" },
    });
    expect(res.plan).toBeNull();
    expect(res.error).toMatch(/lui-même|descendance/i);
  });

  it("refuse un doublon de nom à la destination", () => {
    const withDup = [...folders, f("z", "e", "Prod", 0)];
    const res = resolveDrop({
      folders: withDup,
      secrets,
      item: { kind: "folder", ids: ["z"] },
      target: { kind: "folder", id: "a", edge: "inside" },
    });
    expect(res.plan).toBeNull();
  });

  it("déplace des secrets dans un groupe", () => {
    const res = resolveDrop({
      folders,
      secrets,
      item: { kind: "secret", ids: ["s1", "s2"] },
      target: { kind: "folder", id: "a", edge: "inside" },
    });
    expect(res.plan).toEqual({ kind: "secret", ids: ["s1", "s2"], parentId: "a", index: 2 });
  });

  it("réordonne un secret après un voisin", () => {
    const res = resolveDrop({
      folders,
      secrets,
      item: { kind: "secret", ids: ["s3"] },
      target: { kind: "secret", id: "s4", edge: "after" },
    });
    expect(res.plan).toEqual({ kind: "secret", ids: ["s3"], parentId: "a", index: 2 });
  });

  it("renvoie à la racine du coffre", () => {
    const res = resolveDrop({
      folders,
      secrets,
      item: { kind: "secret", ids: ["s3"] },
      target: { kind: "root", id: null, edge: "inside" },
    });
    expect(res.plan).toMatchObject({ parentId: null, index: 2 });
  });

  it("refuse de mélanger groupes et secrets sur un bord", () => {
    const res = resolveDrop({
      folders,
      secrets,
      item: { kind: "folder", ids: ["e"] },
      target: { kind: "secret", id: "s1", edge: "before" },
    });
    expect(res.plan).toBeNull();
  });
});

describe("application optimiste", () => {
  it("renumérote les groupes du conteneur cible", () => {
    const next = applyFolderPlan(folders, { kind: "folder", ids: ["c"], parentId: "a", index: 0 });
    expect(siblingFolders(next, "a").map((x) => x.id)).toEqual(["c", "b"]);
  });

  it("déplace un secret et renumérote", () => {
    const next = applySecretPlan(secrets, {
      kind: "secret",
      ids: ["s1"],
      parentId: "a",
      index: 0,
    });
    expect(siblingSecrets(next, "a").map((x) => x.id)).toEqual(["s1", "s3", "s4"]);
    expect(siblingSecrets(next, null).map((x) => x.id)).toEqual(["s2"]);
  });

  it("ne modifie aucune donnée du secret hors position et groupe", () => {
    const next = applySecretPlan(secrets, { kind: "secret", ids: ["s1"], parentId: "a", index: 0 });
    const before = secrets.find((x) => x.id === "s1")!;
    const after = next.find((x) => x.id === "s1")!;
    expect({ ...after, folderId: null, position: 0 }).toEqual(before);
  });
});
