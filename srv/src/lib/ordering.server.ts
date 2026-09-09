// Organisation manuelle — logique SERVER ONLY.
// Toute opération est atomique (transaction + verrou du coffre) et versionnée :
// deux utilisateurs qui réorganisent le même coffre ne peuvent pas s'écraser.
import type postgres from "postgres";
import { getDb } from "./db.server";
import {
  MAX_FOLDER_DEPTH,
  descendantIds,
  folderDepth,
  folderPath,
  getFolder,
  nameTaken,
  subtreeHeight,
} from "./folders.server";

type Tx = postgres.Sql | postgres.TransactionSql;

export class OrderConflictError extends Error {
  constructor() {
    super("Un autre utilisateur a modifié l'organisation de ce coffre.");
    this.name = "OrderConflictError";
  }
}

export interface MoveRequest {
  workspaceId: string;
  userId: string;
  kind: "folder" | "secret";
  ids: string[];
  parentId: string | null;
  index: number;
  /** -1 : pas de contrôle de version (appels internes). */
  expectedVersion: number;
}

export interface MoveOutcome {
  version: number;
  moved: number;
  /** Chemin lisible de destination — jamais de valeur sensible. */
  destination: string;
  sourceParents: (string | null)[];
  /** Vrai si l'élément n'a pas changé de conteneur (simple réordonnancement). */
  reorderOnly: boolean;
}

export async function currentTreeVersion(workspaceId: string): Promise<number> {
  const rows = await getDb()<{ tree_version: number }[]>`
    SELECT tree_version FROM workspaces WHERE id = ${workspaceId}
  `;
  return rows[0]?.tree_version ?? 0;
}

async function renumberFolders(tx: Tx, workspaceId: string, parentId: string | null) {
  const rows = parentId
    ? await tx<{ id: string }[]>`
        SELECT id FROM secret_folders
        WHERE workspace_id = ${workspaceId} AND parent_id = ${parentId} AND deleted_at IS NULL
        ORDER BY position ASC, lower(name) ASC
      `
    : await tx<{ id: string }[]>`
        SELECT id FROM secret_folders
        WHERE workspace_id = ${workspaceId} AND parent_id IS NULL AND deleted_at IS NULL
        ORDER BY position ASC, lower(name) ASC
      `;
  for (let i = 0; i < rows.length; i++) {
    await tx`UPDATE secret_folders SET position = ${i} WHERE id = ${rows[i]!.id}`;
  }
}

async function renumberSecrets(tx: Tx, workspaceId: string, folderId: string | null) {
  const rows = folderId
    ? await tx<{ id: string }[]>`
        SELECT id FROM secrets
        WHERE workspace_id = ${workspaceId} AND folder_id = ${folderId} AND deleted_at IS NULL
        ORDER BY position ASC, lower(name) ASC
      `
    : await tx<{ id: string }[]>`
        SELECT id FROM secrets
        WHERE workspace_id = ${workspaceId} AND folder_id IS NULL AND deleted_at IS NULL
        ORDER BY position ASC, lower(name) ASC
      `;
  for (let i = 0; i < rows.length; i++) {
    await tx`UPDATE secrets SET position = ${i} WHERE id = ${rows[i]!.id}`;
  }
}

function splice(siblingIds: string[], movedIds: string[], index: number): string[] {
  const rest = siblingIds.filter((id) => !movedIds.includes(id));
  const removedBefore = siblingIds.slice(0, index).filter((id) => movedIds.includes(id)).length;
  const at = Math.max(0, Math.min(rest.length, index - removedBefore));
  return [...rest.slice(0, at), ...movedIds, ...rest.slice(at)];
}

/**
 * Déplace/réordonne des groupes ou des secrets. Ne touche JAMAIS au contenu
 * d'un secret : seules les colonnes folder_id / parent_id / position changent.
 */
export async function moveItems(req: MoveRequest): Promise<MoveOutcome> {
  const sql = getDb();
  return sql.begin(async (tx) => {
    const ws = await tx<{ id: string; tree_version: number }[]>`
      SELECT id, tree_version FROM workspaces
      WHERE id = ${req.workspaceId} AND deleted_at IS NULL AND disabled = false
      FOR UPDATE
    `;
    if (!ws[0]) throw new Error("Coffre introuvable");
    const version = ws[0].tree_version;
    if (req.expectedVersion >= 0 && req.expectedVersion !== version) {
      throw new OrderConflictError();
    }

    const parentId = req.parentId;
    if (parentId) {
      const parent = await getFolder(tx, parentId);
      if (!parent || parent.workspace_id !== req.workspaceId) {
        throw new Error("Groupe de destination introuvable");
      }
    }

    const sourceParents: (string | null)[] = [];

    if (req.kind === "folder") {
      if (req.ids.length !== 1) throw new Error("Un seul groupe à la fois");
      const id = req.ids[0]!;
      const folder = await getFolder(tx, id);
      if (!folder || folder.workspace_id !== req.workspaceId) throw new Error("Groupe introuvable");
      sourceParents.push(folder.parent_id);

      if (parentId) {
        if (parentId === id) throw new Error("Impossible de déplacer un groupe dans lui-même");
        const forbidden = await descendantIds(tx, id);
        if (forbidden.includes(parentId)) {
          throw new Error("Impossible de déplacer un groupe dans sa propre descendance");
        }
        if ((await folderDepth(tx, parentId)) + (await subtreeHeight(tx, id)) > MAX_FOLDER_DEPTH) {
          throw new Error(`Profondeur maximale atteinte (${MAX_FOLDER_DEPTH} niveaux)`);
        }
      }
      if (
        parentId !== folder.parent_id &&
        (await nameTaken(tx, req.workspaceId, parentId, folder.name, id))
      ) {
        throw new Error("Un groupe porte déjà ce nom à cet emplacement");
      }

      await tx`UPDATE secret_folders SET parent_id = ${parentId} WHERE id = ${id}`;

      const siblings = parentId
        ? await tx<{ id: string }[]>`
            SELECT id FROM secret_folders
            WHERE workspace_id = ${req.workspaceId} AND parent_id = ${parentId} AND deleted_at IS NULL
            ORDER BY position ASC, lower(name) ASC
          `
        : await tx<{ id: string }[]>`
            SELECT id FROM secret_folders
            WHERE workspace_id = ${req.workspaceId} AND parent_id IS NULL AND deleted_at IS NULL
            ORDER BY position ASC, lower(name) ASC
          `;
      const ordered = splice(siblings.map((r) => r.id), [id], req.index);
      for (let i = 0; i < ordered.length; i++) {
        await tx`UPDATE secret_folders SET position = ${i} WHERE id = ${ordered[i]!}`;
      }
      if (folder.parent_id !== parentId) {
        await renumberFolders(tx, req.workspaceId, folder.parent_id);
      }
    } else {
      const rows = await tx<{ id: string; folder_id: string | null }[]>`
        SELECT id, folder_id FROM secrets
        WHERE workspace_id = ${req.workspaceId} AND deleted_at IS NULL
          AND id = ANY(${tx.array(req.ids)}::uuid[])
      `;
      if (rows.length !== req.ids.length) throw new Error("Secret introuvable dans ce coffre");
      for (const r of rows) sourceParents.push(r.folder_id);

      await tx`
        UPDATE secrets SET folder_id = ${parentId}
        WHERE workspace_id = ${req.workspaceId} AND id = ANY(${tx.array(req.ids)}::uuid[])
      `;
      const siblings = parentId
        ? await tx<{ id: string }[]>`
            SELECT id FROM secrets
            WHERE workspace_id = ${req.workspaceId} AND folder_id = ${parentId} AND deleted_at IS NULL
            ORDER BY position ASC, lower(name) ASC
          `
        : await tx<{ id: string }[]>`
            SELECT id FROM secrets
            WHERE workspace_id = ${req.workspaceId} AND folder_id IS NULL AND deleted_at IS NULL
            ORDER BY position ASC, lower(name) ASC
          `;
      // On conserve l'ordre demandé par le client pour la sélection multiple.
      const ordered = splice(siblings.map((r) => r.id), req.ids, req.index);
      for (let i = 0; i < ordered.length; i++) {
        await tx`UPDATE secrets SET position = ${i} WHERE id = ${ordered[i]!}`;
      }
      for (const src of new Set(sourceParents)) {
        if (src !== parentId) await renumberSecrets(tx, req.workspaceId, src);
      }
    }

    const bumped = await tx<{ tree_version: number }[]>`
      UPDATE workspaces SET tree_version = tree_version + 1
      WHERE id = ${req.workspaceId} RETURNING tree_version
    `;

    return {
      version: bumped[0]!.tree_version,
      moved: req.ids.length,
      destination: parentId ? await folderPath(tx, parentId) : "Racine du coffre",
      sourceParents,
      reorderOnly: sourceParents.every((p) => p === parentId),
    } satisfies MoveOutcome;
  });
}
