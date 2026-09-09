// Helpers d'arborescence de groupes — client-safe (aucun accès base).
import type { FolderDto, FolderNode } from "./types";

/** Construit l'arbre trié à partir de la liste plate renvoyée par le serveur. */
export function buildFolderTree(folders: FolderDto[]): FolderNode[] {
  const byId = new Map<string, FolderNode>();
  for (const f of folders) {
    byId.set(f.id, { ...f, children: [], depth: 0, totalCount: f.secretCount });
  }
  const roots: FolderNode[] = [];
  for (const node of byId.values()) {
    const parent = node.parentId ? byId.get(node.parentId) : undefined;
    if (parent) parent.children.push(node);
    else roots.push(node);
  }
  const sortRec = (nodes: FolderNode[], depth: number): number => {
    nodes.sort((a, b) => a.position - b.position || a.name.localeCompare(b.name, "fr"));
    let total = 0;
    for (const n of nodes) {
      n.depth = depth;
      n.totalCount = n.secretCount + sortRec(n.children, depth + 1);
      total += n.totalCount;
    }
    return total;
  };
  sortRec(roots, 0);
  return roots;
}

/** Aplatit l'arbre en respectant l'ordre d'affichage. */
export function flattenTree(nodes: FolderNode[]): FolderNode[] {
  const out: FolderNode[] = [];
  const walk = (list: FolderNode[]) => {
    for (const n of list) {
      out.push(n);
      walk(n.children);
    }
  };
  walk(nodes);
  return out;
}

/** Chemin (du plus ancien au plus proche) menant à un groupe. */
export function folderAncestry(folders: FolderDto[], folderId: string | null): FolderDto[] {
  if (!folderId) return [];
  const byId = new Map(folders.map((f) => [f.id, f]));
  const path: FolderDto[] = [];
  let current = byId.get(folderId);
  const seen = new Set<string>();
  while (current && !seen.has(current.id)) {
    seen.add(current.id);
    path.unshift(current);
    current = current.parentId ? byId.get(current.parentId) : undefined;
  }
  return path;
}

export function folderPathLabel(folders: FolderDto[], folderId: string | null): string {
  const path = folderAncestry(folders, folderId);
  return path.length ? path.map((f) => f.name).join(" / ") : "Racine";
}

/** Ids d'un groupe et de toute sa descendance (filtrage récursif côté client). */
export function subtreeIds(folders: FolderDto[], folderId: string): Set<string> {
  const childrenOf = new Map<string, string[]>();
  for (const f of folders) {
    if (!f.parentId) continue;
    const list = childrenOf.get(f.parentId) ?? [];
    list.push(f.id);
    childrenOf.set(f.parentId, list);
  }
  const out = new Set<string>([folderId]);
  const stack = [folderId];
  while (stack.length) {
    const id = stack.pop()!;
    for (const child of childrenOf.get(id) ?? []) {
      if (out.has(child)) continue;
      out.add(child);
      stack.push(child);
    }
  }
  return out;
}

/** Groupes autorisés comme destination (exclut le groupe et sa descendance). */
export function moveTargets(folders: FolderDto[], excludeId?: string): FolderDto[] {
  const banned = excludeId ? subtreeIds(folders, excludeId) : new Set<string>();
  return folders.filter((f) => !banned.has(f.id));
}
