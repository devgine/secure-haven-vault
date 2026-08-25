import { describe, expect, it } from "vitest";
import {
  buildFolderTree,
  flattenTree,
  folderAncestry,
  folderPathLabel,
  moveTargets,
  subtreeIds,
} from "../folders";
import type { FolderDto } from "../types";

function f(id: string, parentId: string | null, name: string, count = 0, position = 0): FolderDto {
  return {
    id,
    workspaceId: "ws",
    parentId,
    name,
    description: null,
    icon: null,
    color: null,
    position,
    secretCount: count,
    createdAt: new Date().toISOString(),
  };
}

const folders: FolderDto[] = [
  f("a", null, "Infra", 1, 0),
  f("b", "a", "Prod", 2, 0),
  f("c", "a", "Staging", 3, 1),
  f("d", "b", "Bases", 4, 0),
  f("e", null, "Perso", 5, 1),
];

describe("arborescence de groupes", () => {
  it("construit un arbre trié par position", () => {
    const tree = buildFolderTree(folders);
    expect(tree.map((n) => n.id)).toEqual(["a", "e"]);
    expect(tree[0]!.children.map((n) => n.id)).toEqual(["b", "c"]);
    expect(tree[0]!.children[0]!.children[0]!.id).toBe("d");
  });

  it("cumule les compteurs récursivement", () => {
    const tree = buildFolderTree(folders);
    expect(tree[0]!.totalCount).toBe(1 + 2 + 3 + 4);
    expect(tree[1]!.totalCount).toBe(5);
  });

  it("calcule la profondeur d'affichage", () => {
    const flat = flattenTree(buildFolderTree(folders));
    expect(flat.map((n) => `${n.id}:${n.depth}`)).toEqual(["a:0", "b:1", "d:2", "c:1", "e:0"]);
  });

  it("expose le fil d'Ariane et le chemin lisible", () => {
    expect(folderAncestry(folders, "d").map((x) => x.name)).toEqual(["Infra", "Prod", "Bases"]);
    expect(folderPathLabel(folders, "d")).toBe("Infra / Prod / Bases");
    expect(folderPathLabel(folders, null)).toBe("Racine");
  });

  it("récupère un sous-arbre complet", () => {
    expect([...subtreeIds(folders, "a")].sort()).toEqual(["a", "b", "c", "d"]);
    expect([...subtreeIds(folders, "d")]).toEqual(["d"]);
  });

  it("interdit un déplacement dans sa propre descendance", () => {
    expect(moveTargets(folders, "a").map((x) => x.id)).toEqual(["e"]);
  });

  it("tolère un parent manquant sans boucler", () => {
    const orphan = [...folders, f("z", "inconnu", "Orphelin")];
    const tree = buildFolderTree(orphan);
    expect(tree.map((n) => n.id)).toContain("z");
    expect(folderAncestry(orphan, "z").map((n) => n.id)).toEqual(["z"]);
  });
});
