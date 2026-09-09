// Organisation manuelle (glisser-déposer) — helpers PURS, client-safe.
// Aucune donnée sensible n'est manipulée ici : uniquement des identifiants,
// des noms de groupes et des positions.
import type { FolderDto, SecretListItem } from "./types";

/** Délai avant dépliage automatique d'un groupe replié survolé (configurable). */
export const DRAG_HOVER_EXPAND_DELAY_MS = Number(
  import.meta.env?.["VITE_DRAG_HOVER_EXPAND_DELAY_MS"] ?? 700,
);

export type DragKind = "folder" | "secret";
export type DropEdge = "before" | "after" | "inside";

export interface DragItemRef {
  kind: DragKind;
  /** Un ou plusieurs éléments (sélection multiple de secrets). */
  ids: string[];
}

export interface DropTargetRef {
  /** "root" = zone racine du coffre. */
  kind: DragKind | "root";
  id: string | null;
  edge: DropEdge;
}

export interface DropPlan {
  kind: DragKind;
  ids: string[];
  parentId: string | null;
  index: number;
}

export interface DropResolution {
  plan: DropPlan | null;
  /** Raison du refus, affichable à l'utilisateur. */
  error: string | null;
}

/** Ids du groupe et de toute sa descendance. */
export function descendantSet(folders: FolderDto[], folderId: string): Set<string> {
  const out = new Set<string>([folderId]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const f of folders) {
      if (f.parentId && out.has(f.parentId) && !out.has(f.id)) {
        out.add(f.id);
        grew = true;
      }
    }
  }
  return out;
}

/** Groupes enfants directs, triés dans l'ordre d'affichage. */
export function siblingFolders(folders: FolderDto[], parentId: string | null): FolderDto[] {
  return folders
    .filter((f) => (f.parentId ?? null) === parentId)
    .sort((a, b) => a.position - b.position || a.name.localeCompare(b.name, "fr"));
}

/** Secrets directement rattachés à un groupe (ou à la racine), triés. */
export function siblingSecrets(
  secrets: SecretListItem[],
  folderId: string | null,
): SecretListItem[] {
  return secrets
    .filter((s) => (s.folderId ?? null) === folderId)
    .sort((a, b) => a.position - b.position || a.name.localeCompare(b.name, "fr"));
}

/**
 * Retire les éléments déplacés d'une liste de frères puis les réinsère à
 * l'index demandé. Renvoie l'ordre complet du conteneur cible.
 */
export function reorderIds(
  siblingIds: string[],
  movedIds: string[],
  index: number,
): string[] {
  const moved = movedIds.filter((id) => id.length > 0);
  const rest = siblingIds.filter((id) => !moved.includes(id));
  const removedBefore = siblingIds
    .slice(0, index)
    .filter((id) => moved.includes(id)).length;
  const at = Math.max(0, Math.min(rest.length, index - removedBefore));
  return [...rest.slice(0, at), ...moved, ...rest.slice(at)];
}

/** Un groupe ne peut jamais être déposé dans lui-même ni dans sa descendance. */
export function canDropFolderInto(
  folders: FolderDto[],
  folderId: string,
  targetParentId: string | null,
): boolean {
  if (!targetParentId) return true;
  if (targetParentId === folderId) return false;
  return !descendantSet(folders, folderId).has(targetParentId);
}

/**
 * Traduit une intention de dépôt (élément survolé + bord) en opération
 * concrète « conteneur + index ». C'est le cœur testable du glisser-déposer :
 * l'UI ne décide rien d'autre.
 */
export function resolveDrop(params: {
  folders: FolderDto[];
  secrets: SecretListItem[];
  item: DragItemRef;
  target: DropTargetRef;
}): DropResolution {
  const { folders, secrets, item, target } = params;
  if (item.ids.length === 0) return { plan: null, error: "Aucun élément sélectionné" };

  // Conteneur visé
  let parentId: string | null;
  let index: number;

  if (target.kind === "root") {
    parentId = null;
    index =
      item.kind === "folder"
        ? siblingFolders(folders, null).length
        : siblingSecrets(secrets, null).length;
  } else if (target.edge === "inside") {
    if (target.kind !== "folder" || !target.id) {
      return { plan: null, error: "Dépôt impossible ici" };
    }
    parentId = target.id;
    index =
      item.kind === "folder"
        ? siblingFolders(folders, parentId).length
        : siblingSecrets(secrets, parentId).length;
  } else {
    // Dépôt entre deux éléments : on reste dans le conteneur du voisin.
    if (target.kind !== item.kind || !target.id) {
      return { plan: null, error: "Réordonnancement impossible entre types différents" };
    }
    if (item.kind === "folder") {
      const neighbour = folders.find((f) => f.id === target.id);
      if (!neighbour) return { plan: null, error: "Cible introuvable" };
      parentId = neighbour.parentId ?? null;
      const list = siblingFolders(folders, parentId).map((f) => f.id);
      const at = list.indexOf(neighbour.id);
      index = target.edge === "before" ? at : at + 1;
    } else {
      const neighbour = secrets.find((s) => s.id === target.id);
      if (!neighbour) return { plan: null, error: "Cible introuvable" };
      parentId = neighbour.folderId ?? null;
      const list = siblingSecrets(secrets, parentId).map((s) => s.id);
      const at = list.indexOf(neighbour.id);
      index = target.edge === "before" ? at : at + 1;
    }
  }

  if (item.kind === "folder") {
    if (item.ids.length !== 1) return { plan: null, error: "Un seul groupe à la fois" };
    const id = item.ids[0]!;
    if (!canDropFolderInto(folders, id, parentId)) {
      return { plan: null, error: "Impossible de déplacer un groupe dans lui-même" };
    }
    const clash = siblingFolders(folders, parentId).find(
      (f) => f.id !== id && f.name.toLowerCase() === (folders.find((x) => x.id === id)?.name ?? "").toLowerCase(),
    );
    if (clash) return { plan: null, error: "Un groupe porte déjà ce nom à cet emplacement" };
  }

  return { plan: { kind: item.kind, ids: item.ids, parentId, index }, error: null };
}

/** Applique un plan localement (UI optimiste) sur la liste plate des groupes. */
export function applyFolderPlan(folders: FolderDto[], plan: DropPlan): FolderDto[] {
  const ordered = reorderIds(
    siblingFolders(folders, plan.parentId)
      .filter((f) => !plan.ids.includes(f.id))
      .map((f) => f.id),
    plan.ids,
    plan.index,
  );
  return folders.map((f) => {
    if (plan.ids.includes(f.id)) {
      return { ...f, parentId: plan.parentId, position: ordered.indexOf(f.id) };
    }
    const at = ordered.indexOf(f.id);
    return at >= 0 ? { ...f, position: at } : f;
  });
}

/** Applique un plan localement sur la liste des secrets. */
export function applySecretPlan(
  secrets: SecretListItem[],
  plan: DropPlan,
): SecretListItem[] {
  const ordered = reorderIds(
    siblingSecrets(secrets, plan.parentId)
      .filter((s) => !plan.ids.includes(s.id))
      .map((s) => s.id),
    plan.ids,
    plan.index,
  );
  return secrets.map((s) => {
    if (plan.ids.includes(s.id)) {
      return { ...s, folderId: plan.parentId, position: ordered.indexOf(s.id) };
    }
    const at = ordered.indexOf(s.id);
    return at >= 0 ? { ...s, position: at } : s;
  });
}

/** Libellé de destination « A / B / C » — jamais de valeur sensible. */
export function destinationLabel(
  folders: FolderDto[],
  parentId: string | null,
  rootLabel = "Racine du coffre",
): string {
  if (!parentId) return rootLabel;
  const byId = new Map(folders.map((f) => [f.id, f]));
  const parts: string[] = [];
  let cur = byId.get(parentId);
  const seen = new Set<string>();
  while (cur && !seen.has(cur.id)) {
    seen.add(cur.id);
    parts.unshift(cur.name);
    cur = cur.parentId ? byId.get(cur.parentId) : undefined;
  }
  return parts.join(" / ") || rootLabel;
}
