// Import KeePass — logique serveur. SERVER ONLY.
//
// Le serveur ne reçoit JAMAIS le fichier .kdbx, le mot de passe maître ni le
// fichier clé : uniquement les entrées sélectionnées, après confirmation.
// Chaque valeur reçue est immédiatement chiffrée (AES-256-GCM, DEK du coffre)
// avant d'être écrite. Aucune valeur n'est journalisée.

import type postgres from "postgres";
import { getDb } from "./db.server";
import { encryptField } from "./crypto.server";
import { getOrCreateDek, requireWorkspacePermission } from "./vault.server";
import type { DuplicateCriterion, DuplicateStrategy } from "./keepass/types";
import type { ImportItemPayload } from "./keepass/mapping";

export const MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024;
export const MAX_BATCH_ITEMS = 50;

type Tx = postgres.Sql | postgres.TransactionSql;

/** Crée (ou réutilise) l'arborescence de dossiers. Idempotent par nom+parent. */
export async function ensureFolderPath(
  tx: Tx,
  workspaceId: string,
  rootFolderId: string | null,
  path: string[],
): Promise<{ folderId: string | null; created: number }> {
  let parent: string | null = rootFolderId;
  let created = 0;
  for (const rawName of path) {
    const name = rawName.trim().slice(0, 120) || "Groupe";
    // Réutilise un groupe natif existant portant le même nom au même niveau :
    // l'arborescence KeePass fusionne proprement avec celle du coffre.
    const found = parent
      ? await tx<{ id: string }[]>`
          SELECT id FROM secret_folders
          WHERE workspace_id = ${workspaceId} AND parent_id = ${parent}
            AND lower(name) = lower(${name}) AND deleted_at IS NULL
          LIMIT 1
        `
      : await tx<{ id: string }[]>`
          SELECT id FROM secret_folders
          WHERE workspace_id = ${workspaceId} AND parent_id IS NULL
            AND lower(name) = lower(${name}) AND deleted_at IS NULL
          LIMIT 1
        `;
    if (found[0]) {
      parent = found[0].id;
      continue;
    }
    const inserted = await tx<{ id: string }[]>`
      INSERT INTO secret_folders (workspace_id, parent_id, name)
      VALUES (${workspaceId}, ${parent}, ${name})
      ON CONFLICT DO NOTHING
      RETURNING id
    `;
    if (inserted[0]) {
      parent = inserted[0].id;
      created += 1;
    } else {
      const retry = parent
        ? await tx<{ id: string }[]>`
            SELECT id FROM secret_folders
            WHERE workspace_id = ${workspaceId} AND parent_id = ${parent}
              AND lower(name) = lower(${name}) AND deleted_at IS NULL
            LIMIT 1
          `
        : await tx<{ id: string }[]>`
            SELECT id FROM secret_folders
            WHERE workspace_id = ${workspaceId} AND parent_id IS NULL
              AND lower(name) = lower(${name}) AND deleted_at IS NULL
            LIMIT 1
          `;
      parent = retry[0]!.id;
    }
  }
  return { folderId: parent, created };
}

export async function ensureRootFolder(
  tx: Tx,
  workspaceId: string,
  name: string,
): Promise<{ folderId: string; created: number }> {
  const existing = await tx<{ id: string }[]>`
    SELECT id FROM secret_folders
    WHERE workspace_id = ${workspaceId} AND parent_id IS NULL AND lower(name) = lower(${name})
    LIMIT 1
  `;
  if (existing[0]) return { folderId: existing[0].id, created: 0 };
  const inserted = await tx<{ id: string }[]>`
    INSERT INTO secret_folders (workspace_id, parent_id, name)
    VALUES (${workspaceId}, NULL, ${name})
    ON CONFLICT DO NOTHING
    RETURNING id
  `;
  if (inserted[0]) return { folderId: inserted[0].id, created: 1 };
  const retry = await tx<{ id: string }[]>`
    SELECT id FROM secret_folders
    WHERE workspace_id = ${workspaceId} AND parent_id IS NULL AND lower(name) = lower(${name})
    LIMIT 1
  `;
  return { folderId: retry[0]!.id, created: 0 };
}

/**
 * Détection de doublon sur des métadonnées uniquement.
 * Les mots de passe ne sont jamais comparés (ils sont chiffrés côté serveur).
 */
export async function findDuplicate(
  tx: Tx,
  workspaceId: string,
  folderId: string | null,
  item: ImportItemPayload,
  criteria: DuplicateCriterion[],
): Promise<string | null> {
  const byName = criteria.includes("name");
  const byUser = criteria.includes("username");
  const byUrl = criteria.includes("url");
  const byFolder = criteria.includes("folder");
  if (!byName && !byUser && !byUrl) return null;
  const rows = await tx<{ id: string }[]>`
    SELECT id FROM secrets
    WHERE workspace_id = ${workspaceId}
      AND deleted_at IS NULL
      AND (${!byFolder} OR folder_id IS NOT DISTINCT FROM ${folderId})
      AND (${!byName} OR lower(name) = lower(${item.name}))
      AND (${!byUser} OR lower(coalesce(username, '')) = lower(${item.username ?? ""}))
      AND (${!byUrl} OR lower(coalesce(url, '')) = lower(${item.url ?? ""}))
    ORDER BY updated_at DESC
    LIMIT 1
  `;
  return rows[0]?.id ?? null;
}

async function writeFields(
  tx: Tx,
  dek: Uint8Array,
  secretId: string,
  fields: ImportItemPayload["fields"],
  startPosition = 0,
): Promise<void> {
  let position = startPosition;
  for (const field of fields) {
    const ciphertext = await encryptField(dek, field.value);
    await tx`
      INSERT INTO secret_fields (secret_id, label, field_type, is_sensitive, ciphertext, position)
      VALUES (${secretId}, ${field.label.slice(0, 100)}, ${field.fieldType}, ${field.isSensitive}, ${ciphertext}, ${position})
    `;
    position += 1;
  }
}

async function writeAttachments(
  tx: Tx,
  dek: Uint8Array,
  secretId: string,
  attachments: ImportItemPayload["attachments"],
): Promise<{ stored: number; warnings: string[] }> {
  let stored = 0;
  const warnings: string[] = [];
  for (const att of attachments) {
    if (att.size > MAX_ATTACHMENT_SIZE) {
      warnings.push(`Pièce jointe trop volumineuse ignorée pour une entrée importée.`);
      continue;
    }
    const ciphertext = await encryptField(dek, att.dataB64);
    await tx`
      INSERT INTO secret_attachments (secret_id, filename, mime_type, size_bytes, ciphertext)
      VALUES (${secretId}, ${att.filename.slice(0, 200)}, ${att.mimeType}, ${att.size}, ${ciphertext})
    `;
    stored += 1;
  }
  return { stored, warnings };
}

export interface BatchResult {
  imported: number;
  skipped: number;
  replaced: number;
  merged: number;
  failed: number;
  attachments: number;
  folders: number;
  warnings: string[];
}

export interface BatchParams {
  userId: string;
  jobId: string;
  items: ImportItemPayload[];
  strategy: DuplicateStrategy;
  criteria: DuplicateCriterion[];
}

/**
 * Traite un lot. Chaque entrée est écrite dans sa propre transaction :
 * l'import reste reprenable (une panne n'annule que l'entrée en cours) et
 * idempotent (contrainte unique sur import_items.client_key).
 */
export async function runImportBatch(params: BatchParams): Promise<BatchResult> {
  const sql = getDb();
  const jobs = await sql<
    { id: string; user_id: string; workspace_id: string; root_folder_id: string | null; status: string }[]
  >`
    SELECT id, user_id, workspace_id, root_folder_id, status FROM import_jobs WHERE id = ${params.jobId}
  `;
  const job = jobs[0];
  if (!job || job.user_id !== params.userId) throw new Error("Not found");
  if (job.status === "completed") throw new Error("Import déjà terminé");

  // Re-vérification serveur à CHAQUE lot : une requête forgée ne peut pas
  // écrire dans un coffre dont l'utilisateur n'est pas membre habilité.
  await requireWorkspacePermission(params.userId, job.workspace_id, "secret.import");
  await requireWorkspacePermission(params.userId, job.workspace_id, "secret.create");

  const dek = await getOrCreateDek(job.workspace_id);
  const result: BatchResult = {
    imported: 0,
    skipped: 0,
    replaced: 0,
    merged: 0,
    failed: 0,
    attachments: 0,
    folders: 0,
    warnings: [],
  };

  for (const item of params.items.slice(0, MAX_BATCH_ITEMS)) {
    try {
      const outcome = await sql.begin(async (tx) => {
        // Idempotence : si la clé a déjà été traitée, on ne réécrit rien.
        const claim = await tx<{ id: string }[]>`
          INSERT INTO import_items (job_id, client_key, status)
          VALUES (${params.jobId}, ${item.clientKey}, 'pending')
          ON CONFLICT (job_id, client_key) DO NOTHING
          RETURNING id
        `;
        if (!claim[0]) return "duplicate-run" as const;

        const { folderId, created } = await ensureFolderPath(
          tx,
          job.workspace_id,
          job.root_folder_id,
          item.path,
        );
        result.folders += created;

        const existingId = await findDuplicate(
          tx,
          job.workspace_id,
          folderId,
          item,
          params.criteria,
        );

        if (existingId && params.strategy === "skip") {
          await tx`UPDATE import_items SET status = 'skipped', secret_id = ${existingId} WHERE job_id = ${params.jobId} AND client_key = ${item.clientKey}`;
          return "skipped" as const;
        }

        if (existingId && params.strategy === "merge") {
          await requireWorkspacePermission(params.userId, job.workspace_id, "secret.update");
          const existingLabels = await tx<{ label: string }[]>`
            SELECT label FROM secret_fields WHERE secret_id = ${existingId}
          `;
          const known = new Set(existingLabels.map((f) => f.label.toLowerCase()));
          const missing = item.fields.filter((f) => !known.has(f.label.toLowerCase()));
          await writeFields(tx, dek, existingId, missing, existingLabels.length);
          await tx`
            UPDATE secrets SET
              username = COALESCE(username, ${item.username}),
              url = COALESCE(url, ${item.url}),
              description = COALESCE(description, ${item.description}),
              updated_by = ${params.userId}
            WHERE id = ${existingId}
          `;
          await tx`
            INSERT INTO secret_versions (secret_id, version, action, changed_by, changed_fields)
            VALUES (${existingId}, 1, 'import.merge', ${params.userId}, ${tx.array(missing.map((f) => f.label))})
          `;
          await tx`UPDATE import_items SET status = 'merged', secret_id = ${existingId} WHERE job_id = ${params.jobId} AND client_key = ${item.clientKey}`;
          return "merged" as const;
        }

        if (existingId && params.strategy === "replace") {
          await requireWorkspacePermission(params.userId, job.workspace_id, "secret.update");
          // Version récupérable : l'ancienne entrée est mise à la corbeille,
          // jamais supprimée définitivement.
          await tx`UPDATE secrets SET deleted_at = now(), updated_by = ${params.userId} WHERE id = ${existingId}`;
          await tx`
            INSERT INTO secret_versions (secret_id, version, action, changed_by, changed_fields)
            VALUES (${existingId}, 1, 'import.replaced', ${params.userId}, ${tx.array([] as string[])})
          `;
        }

        const inserted = await tx<{ id: string }[]>`
          INSERT INTO secrets (workspace_id, folder_id, type, name, username, url, description, tags,
                               icon, source_created_at, source_modified_at, created_by, updated_by)
          VALUES (${job.workspace_id}, ${folderId}, ${item.type}, ${item.name.slice(0, 200)},
                  ${item.username}, ${item.url}, ${item.description}, ${tx.array(item.tags)},
                  ${item.icon}, ${item.sourceCreatedAt}, ${item.sourceModifiedAt},
                  ${params.userId}, ${params.userId})
          RETURNING id
        `;
        const secretId = inserted[0]!.id;
        await writeFields(tx, dek, secretId, item.fields);
        const att = await writeAttachments(tx, dek, secretId, item.attachments);
        result.attachments += att.stored;
        result.warnings.push(...att.warnings);
        await tx`
          INSERT INTO secret_versions (secret_id, version, action, changed_by, changed_fields)
          VALUES (${secretId}, 1, 'import.created', ${params.userId}, ${tx.array([] as string[])})
        `;
        const status = existingId && params.strategy === "replace" ? "replaced" : "imported";
        await tx`UPDATE import_items SET status = ${status}, secret_id = ${secretId} WHERE job_id = ${params.jobId} AND client_key = ${item.clientKey}`;
        return status as "replaced" | "imported";
      });

      if (outcome === "imported") result.imported += 1;
      else if (outcome === "replaced") result.replaced += 1;
      else if (outcome === "merged") result.merged += 1;
      else if (outcome === "skipped") result.skipped += 1;
    } catch {
      // Aucune donnée de l'entrée n'est journalisée (ni nom, ni valeur).
      result.failed += 1;
      await sql`
        UPDATE import_items SET status = 'failed', message = 'error'
        WHERE job_id = ${params.jobId} AND client_key = ${item.clientKey}
      `;
    }
  }

  await sql`
    UPDATE import_jobs SET
      imported_count = imported_count + ${result.imported},
      skipped_count = skipped_count + ${result.skipped},
      replaced_count = replaced_count + ${result.replaced},
      merged_count = merged_count + ${result.merged},
      failed_count = failed_count + ${result.failed},
      attachment_count = attachment_count + ${result.attachments},
      folder_count = folder_count + ${result.folders}
    WHERE id = ${params.jobId}
  `;

  return result;
}
