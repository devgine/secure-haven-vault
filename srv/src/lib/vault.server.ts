// Server-only helpers for vault authorization and encryption key management.
// Autorisation applicative (SQL direct, pas de RLS) : chaque accès sensible
// passe par requireWorkspacePermission / requireSuperAdmin.
import { getDb, type Tx } from "./db.server";
import {
  roleHasPermission,
  type Permission,
  type WorkspaceRole,
} from "./permissions";
import { encryptField, generateDek, getKeyProvider, secretContext } from "./crypto.server";

export async function getWorkspaceRole(
  userId: string,
  workspaceId: string,
): Promise<WorkspaceRole | null> {
  const rows = await getDb()<{ role: WorkspaceRole }[]>`
    SELECT m.role
    FROM workspace_members m
    JOIN workspaces w ON w.id = m.workspace_id
    WHERE m.user_id = ${userId}
      AND m.workspace_id = ${workspaceId}
      AND w.disabled = false
      AND w.deleted_at IS NULL
    LIMIT 1
  `;
  return rows[0]?.role ?? null;
}

/**
 * Central authorization gate. Every sensitive server function calls this:
 * it verifies workspace membership + the exact permission, server-side,
 * regardless of what the client claims. Disabled/soft-deleted workspaces
 * resolve to no role, which denies access for everyone.
 */
export async function requireWorkspacePermission(
  userId: string,
  workspaceId: string,
  permission: Permission,
): Promise<WorkspaceRole> {
  const role = await getWorkspaceRole(userId, workspaceId);
  let allowViewerReveal = false;
  if (role === "VIEWER" && (permission === "secret.reveal" || permission === "secret.copy")) {
    const rows = await getDb()<{ allow_viewer_reveal: boolean }[]>`
      SELECT allow_viewer_reveal FROM workspaces WHERE id = ${workspaceId}
    `;
    allowViewerReveal = rows[0]?.allow_viewer_reveal === true;
  }
  if (!roleHasPermission(role, permission, { allowViewerReveal })) {
    throw new Error("Forbidden");
  }
  return role as WorkspaceRole;
}

export async function isSuperAdmin(userId: string): Promise<boolean> {
  const rows = await getDb()<{ ok: boolean }[]>`
    SELECT EXISTS (
      SELECT 1 FROM user_roles WHERE user_id = ${userId} AND role = 'SUPER_ADMIN'
    ) AS ok
  `;
  return rows[0]?.ok === true;
}

export async function requireSuperAdmin(userId: string): Promise<void> {
  if (!(await isSuperAdmin(userId))) throw new Error("Forbidden");
}

/**
 * Returns the raw DEK for a workspace, creating and wrapping it on first use.
 * La table encryption_keys n'est jamais exposée au client.
 */
export async function getOrCreateDek(workspaceId: string): Promise<Uint8Array> {
  const provider = getKeyProvider();
  const sql = getDb();
  const existing = await sql<{ wrapped_dek: string }[]>`
    SELECT wrapped_dek FROM encryption_keys WHERE workspace_id = ${workspaceId}
  `;
  if (existing[0]?.wrapped_dek) {
    return provider.unwrapKey(existing[0].wrapped_dek, workspaceId);
  }
  const dek = generateDek();
  const wrapped = await provider.wrapKey(dek, workspaceId);
  // Création concurrente : la première ligne gagne, les autres la relisent.
  const inserted = await sql<{ wrapped_dek: string }[]>`
    INSERT INTO encryption_keys (workspace_id, wrapped_dek)
    VALUES (${workspaceId}, ${wrapped})
    ON CONFLICT (workspace_id) DO NOTHING
    RETURNING wrapped_dek
  `;
  if (inserted[0]) return dek;
  const winner = await sql<{ wrapped_dek: string }[]>`
    SELECT wrapped_dek FROM encryption_keys WHERE workspace_id = ${workspaceId}
  `;
  if (winner[0]?.wrapped_dek) return provider.unwrapKey(winner[0].wrapped_dek, workspaceId);
  throw new Error("Failed to initialize workspace encryption key");
}

export interface PlainField {
  label: string;
  fieldType: string;
  isSensitive: boolean;
  value: string;
}

/** Chiffre et insère les champs d'un secret (valeurs liées au secret par AAD). */
export async function writeSecretFields(
  tx: Tx,
  dek: Uint8Array,
  secretId: string,
  fields: PlainField[],
  startPosition = 0,
): Promise<void> {
  let position = startPosition;
  for (const field of fields) {
    const ciphertext = await encryptField(dek, field.value, secretContext(secretId));
    await tx`
      INSERT INTO secret_fields (secret_id, label, field_type, is_sensitive, ciphertext, position)
      VALUES (${secretId}, ${field.label.slice(0, 100)}, ${field.fieldType}, ${field.isSensitive}, ${ciphertext}, ${position})
    `;
    position += 1;
  }
}

/**
 * Vérifie qu'un dossier appartient bien au coffre : sans ce contrôle, un
 * secret pourrait être rattaché au dossier d'un coffre étranger.
 */
export async function assertFolderInWorkspace(
  tx: Tx,
  folderId: string | null | undefined,
  workspaceId: string,
): Promise<void> {
  if (!folderId) return;
  const rows = await tx<{ id: string }[]>`
    SELECT id FROM secret_folders
    WHERE id = ${folderId} AND workspace_id = ${workspaceId} AND deleted_at IS NULL
  `;
  if (!rows[0]) throw new Error("Groupe introuvable dans ce coffre");
}
