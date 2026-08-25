// Groupes (arborescence) — helpers SERVER ONLY.
// Toute vérification d'accès est faite par les fonctions serveur appelantes
// (requireWorkspacePermission) : ces helpers supposent l'autorisation acquise.
import type postgres from "postgres";
import { getDb } from "./db.server";

type Tx = postgres.Sql | postgres.TransactionSql;

export interface FolderRow {
  id: string;
  workspace_id: string;
  parent_id: string | null;
  name: string;
  description: string | null;
  icon: string | null;
  color: string | null;
  position: number;
  created_at: Date | string;
}

export const MAX_FOLDER_DEPTH = 20;

/** Renvoie le dossier et vérifie qu'il appartient bien au coffre attendu. */
export async function getFolder(
  tx: Tx,
  folderId: string,
): Promise<FolderRow | null> {
  const rows = await tx<FolderRow[]>`
    SELECT id, workspace_id, parent_id, name, description, icon, color, position, created_at
    FROM secret_folders WHERE id = ${folderId} AND deleted_at IS NULL
  `;
  return rows[0] ?? null;
}

/** Ids du dossier et de toute sa descendance (protège des cycles). */
export async function descendantIds(tx: Tx, folderId: string): Promise<string[]> {
  const rows = await tx<{ id: string }[]>`
    WITH RECURSIVE tree AS (
      SELECT id FROM secret_folders WHERE id = ${folderId}
      UNION ALL
      SELECT f.id FROM secret_folders f JOIN tree t ON f.parent_id = t.id
    )
    SELECT id FROM tree
  `;
  return rows.map((r) => r.id);
}

/** Profondeur d'un dossier (racine = 1). */
export async function folderDepth(tx: Tx, folderId: string): Promise<number> {
  const rows = await tx<{ depth: number }[]>`
    WITH RECURSIVE up AS (
      SELECT id, parent_id, 1 AS depth FROM secret_folders WHERE id = ${folderId}
      UNION ALL
      SELECT f.id, f.parent_id, up.depth + 1
      FROM secret_folders f JOIN up ON up.parent_id = f.id
    )
    SELECT max(depth)::int AS depth FROM up
  `;
  return rows[0]?.depth ?? 1;
}

/** Hauteur du sous-arbre sous un dossier (feuille = 1). */
export async function subtreeHeight(tx: Tx, folderId: string): Promise<number> {
  const rows = await tx<{ height: number }[]>`
    WITH RECURSIVE tree AS (
      SELECT id, 1 AS depth FROM secret_folders WHERE id = ${folderId}
      UNION ALL
      SELECT f.id, t.depth + 1 FROM secret_folders f JOIN tree t ON f.parent_id = t.id
    )
    SELECT max(depth)::int AS height FROM tree
  `;
  return rows[0]?.height ?? 1;
}

/** Chemin lisible « A / B / C » d'un dossier. */
export async function folderPath(tx: Tx, folderId: string): Promise<string> {
  const rows = await tx<{ name: string; depth: number }[]>`
    WITH RECURSIVE up AS (
      SELECT id, parent_id, name, 1 AS depth FROM secret_folders WHERE id = ${folderId}
      UNION ALL
      SELECT f.id, f.parent_id, f.name, up.depth + 1
      FROM secret_folders f JOIN up ON up.parent_id = f.id
    )
    SELECT name, depth FROM up ORDER BY depth DESC
  `;
  return rows.map((r) => r.name).join(" / ");
}

/** Position suivante disponible sous un parent. */
export async function nextPosition(
  tx: Tx,
  workspaceId: string,
  parentId: string | null,
): Promise<number> {
  const rows = parentId
    ? await tx<{ pos: number | null }[]>`
        SELECT max(position) AS pos FROM secret_folders
        WHERE workspace_id = ${workspaceId} AND parent_id = ${parentId} AND deleted_at IS NULL
      `
    : await tx<{ pos: number | null }[]>`
        SELECT max(position) AS pos FROM secret_folders
        WHERE workspace_id = ${workspaceId} AND parent_id IS NULL AND deleted_at IS NULL
      `;
  return (rows[0]?.pos ?? -1) + 1;
}

export async function nameTaken(
  tx: Tx,
  workspaceId: string,
  parentId: string | null,
  name: string,
  excludeId?: string,
): Promise<boolean> {
  const exclude = excludeId ?? "00000000-0000-0000-0000-000000000000";
  const rows = parentId
    ? await tx<{ id: string }[]>`
        SELECT id FROM secret_folders
        WHERE workspace_id = ${workspaceId} AND parent_id = ${parentId}
          AND lower(name) = lower(${name}) AND id <> ${exclude} AND deleted_at IS NULL
        LIMIT 1
      `
    : await tx<{ id: string }[]>`
        SELECT id FROM secret_folders
        WHERE workspace_id = ${workspaceId} AND parent_id IS NULL
          AND lower(name) = lower(${name}) AND id <> ${exclude} AND deleted_at IS NULL
        LIMIT 1
      `;
  return rows.length > 0;
}

/** Compte des secrets directement rattachés à chaque dossier du coffre. */
export async function directSecretCounts(
  workspaceId: string,
): Promise<Record<string, number>> {
  const rows = await getDb()<{ folder_id: string; count: string }[]>`
    SELECT folder_id, count(*)::text AS count
    FROM secrets
    WHERE workspace_id = ${workspaceId} AND deleted_at IS NULL AND folder_id IS NOT NULL
    GROUP BY folder_id
  `;
  const out: Record<string, number> = {};
  for (const r of rows) out[r.folder_id] = Number(r.count);
  return out;
}
