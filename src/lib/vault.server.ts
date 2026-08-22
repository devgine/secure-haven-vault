// Server-only helpers for vault authorization and encryption key management.
// Autorisation applicative (SQL direct) — il n'y a plus de RLS : chaque accès
// sensible passe par requireWorkspacePermission / requireSuperAdmin.
import { getDb } from "./db.server";
import {
  roleHasPermission,
  type Permission,
  type WorkspaceRole,
} from "./permissions";
import { generateDek, getKeyProvider } from "./crypto.server";

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
    return provider.unwrapKey(existing[0].wrapped_dek);
  }
  const dek = generateDek();
  const wrapped = await provider.wrapKey(dek);
  try {
    await sql`
      INSERT INTO encryption_keys (workspace_id, wrapped_dek)
      VALUES (${workspaceId}, ${wrapped})
    `;
    return dek;
  } catch {
    // Concurrent creation: re-read the winning row.
    const retry = await sql<{ wrapped_dek: string }[]>`
      SELECT wrapped_dek FROM encryption_keys WHERE workspace_id = ${workspaceId}
    `;
    if (retry[0]?.wrapped_dek) return provider.unwrapKey(retry[0].wrapped_dek);
    throw new Error("Failed to initialize workspace encryption key");
  }
}
