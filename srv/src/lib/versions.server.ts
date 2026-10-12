// Historique restaurable des secrets — SERVER ONLY.
//
// Chaque ligne de secret_versions porte un instantané complet du secret tel
// qu'il était APRÈS le changement (métadonnées + valeurs), chiffré sous la DEK
// du coffre et lié au secret par AAD. Restaurer une version revient à
// réappliquer son instantané, ce qui crée une nouvelle version : l'historique
// n'est jamais réécrit.
import type { Tx } from "./db.server";
import { decryptField, encryptField, secretContext, versionContext } from "./crypto.server";
import type { PlainField } from "./vault.server";

/** Nombre d'instantanés conservés par secret (les plus anciens sont purgés). */
export const MAX_SNAPSHOTS_PER_SECRET = 20;

export interface SecretSnapshot {
  type: string;
  name: string;
  username: string | null;
  url: string | null;
  description: string | null;
  tags: string[];
  expiresAt: string | null;
  notifyBeforeDays: number | null;
  folderId: string | null;
  fields: PlainField[];
}

async function readCurrentState(
  tx: Tx,
  dek: Uint8Array,
  secretId: string,
): Promise<SecretSnapshot | null> {
  const rows = await tx<
    {
      type: string;
      name: string;
      username: string | null;
      url: string | null;
      description: string | null;
      tags: string[] | null;
      expires_at: Date | string | null;
      notify_before_days: number | null;
      folder_id: string | null;
    }[]
  >`
    SELECT type, name, username, url, description, tags, expires_at, notify_before_days, folder_id
    FROM secrets WHERE id = ${secretId}
  `;
  const row = rows[0];
  if (!row) return null;
  const fields = await tx<
    { label: string; field_type: string; is_sensitive: boolean; ciphertext: string }[]
  >`
    SELECT label, field_type, is_sensitive, ciphertext
    FROM secret_fields WHERE secret_id = ${secretId}
    ORDER BY position ASC
  `;
  const plain: PlainField[] = [];
  for (const f of fields) {
    plain.push({
      label: f.label,
      fieldType: f.field_type,
      isSensitive: f.is_sensitive,
      value: await decryptField(dek, f.ciphertext, secretContext(secretId)),
    });
  }
  return {
    type: row.type,
    name: row.name,
    username: row.username,
    url: row.url,
    description: row.description,
    tags: row.tags ?? [],
    expiresAt: row.expires_at ? new Date(row.expires_at).toISOString() : null,
    notifyBeforeDays: row.notify_before_days,
    folderId: row.folder_id,
    fields: plain,
  };
}

async function encryptSnapshot(
  dek: Uint8Array,
  secretId: string,
  snapshot: SecretSnapshot,
): Promise<string> {
  return encryptField(dek, JSON.stringify(snapshot), versionContext(secretId));
}

/**
 * À appeler AVANT de modifier un secret : si sa dernière version n'a pas
 * d'instantané (secret antérieur à l'historique restaurable), on fige l'état
 * courant pour qu'il reste récupérable après la modification.
 */
export async function ensureBaselineSnapshot(
  tx: Tx,
  dek: Uint8Array,
  secretId: string,
): Promise<void> {
  const latest = await tx<{ id: string; has_snapshot: boolean }[]>`
    SELECT id, snapshot IS NOT NULL AS has_snapshot FROM secret_versions
    WHERE secret_id = ${secretId}
    ORDER BY version DESC, changed_at DESC LIMIT 1
  `;
  if (latest[0]?.has_snapshot) return;
  const state = await readCurrentState(tx, dek, secretId);
  if (!state) return;
  const snapshot = await encryptSnapshot(dek, secretId, state);
  if (latest[0]) {
    await tx`UPDATE secret_versions SET snapshot = ${snapshot} WHERE id = ${latest[0].id}`;
  } else {
    await tx`
      INSERT INTO secret_versions (secret_id, version, action, changed_fields, snapshot)
      VALUES (${secretId}, 1, 'baseline', ${tx.array([] as string[])}, ${snapshot})
    `;
  }
}

/**
 * À appeler APRÈS avoir écrit le nouvel état : ajoute la version suivante avec
 * son instantané, puis purge les instantanés au-delà de la rétention.
 */
export async function recordVersion(
  tx: Tx,
  dek: Uint8Array,
  secretId: string,
  action: string,
  userId: string,
  changedFields: string[] = [],
): Promise<number> {
  const state = await readCurrentState(tx, dek, secretId);
  const snapshot = state ? await encryptSnapshot(dek, secretId, state) : null;
  const rows = await tx<{ version: number }[]>`
    INSERT INTO secret_versions (secret_id, version, action, changed_by, changed_fields, snapshot)
    VALUES (
      ${secretId},
      (SELECT coalesce(max(version), 0) + 1 FROM secret_versions WHERE secret_id = ${secretId}),
      ${action}, ${userId}, ${tx.array(changedFields)}, ${snapshot}
    )
    RETURNING version
  `;
  const version = rows[0]!.version;
  await tx`
    UPDATE secret_versions SET snapshot = NULL
    WHERE secret_id = ${secretId}
      AND snapshot IS NOT NULL
      AND version <= ${version - MAX_SNAPSHOTS_PER_SECRET}
  `;
  return version;
}

export async function loadSnapshot(
  tx: Tx,
  dek: Uint8Array,
  secretId: string,
  versionId: string,
): Promise<{ version: number; snapshot: SecretSnapshot } | null> {
  const rows = await tx<{ version: number; snapshot: string | null }[]>`
    SELECT version, snapshot FROM secret_versions
    WHERE id = ${versionId} AND secret_id = ${secretId}
  `;
  const row = rows[0];
  if (!row?.snapshot) return null;
  const json = await decryptField(dek, row.snapshot, versionContext(secretId));
  return { version: row.version, snapshot: JSON.parse(json) as SecretSnapshot };
}
