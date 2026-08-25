// Fonctions serveur d'import KeePass — fichier volontairement mince
// (déclarations uniquement, la logique vit dans import.server.ts).
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "./auth-middleware";
import { getDb, iso } from "./db.server";
import { audit } from "./audit.server";
import { requireWorkspacePermission } from "./vault.server";
import { ensureRootFolder, runImportBatch } from "./import.server";
import type { ImportItemPayload } from "./keepass/mapping";

const criterion = z.enum(["name", "username", "url", "folder"]);
const strategy = z.enum(["skip", "copy", "replace", "merge"]);

const itemSchema = z.object({
  clientKey: z.string().min(1).max(200),
  path: z.array(z.string().max(120)).max(20),
  type: z.enum(["LOGIN", "API_KEY", "TOKEN", "SSH_KEY", "DATABASE", "SECURE_NOTE", "CUSTOM"]),
  name: z.string().min(1).max(200),
  username: z.string().max(500).nullable(),
  url: z.string().max(2000).nullable(),
  description: z.string().max(20000).nullable(),
  tags: z.array(z.string().min(1).max(50)).max(30),
  icon: z.string().max(50).nullable(),
  sourceCreatedAt: z.string().nullable(),
  sourceModifiedAt: z.string().nullable(),
  fields: z
    .array(
      z.object({
        label: z.string().min(1).max(100),
        fieldType: z.enum(["text", "secret", "password", "url", "username", "date", "totp", "textarea"]),
        isSensitive: z.boolean(),
        value: z.string().max(200000),
      }),
    )
    .max(100),
  attachments: z
    .array(
      z.object({
        filename: z.string().min(1).max(200),
        mimeType: z.string().max(120),
        size: z.number().int().min(0),
        dataB64: z.string().max(14_000_000),
      }),
    )
    .max(20),
});

/** Coffres où l'utilisateur a réellement le droit d'importer (vérifié en base). */
export const listImportTargets = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    const rows = await getDb()<
      { id: string; name: string; is_personal: boolean; role: string }[]
    >`
      SELECT w.id, w.name, w.is_personal, m.role
      FROM workspace_members m
      JOIN workspaces w ON w.id = m.workspace_id
      WHERE m.user_id = ${context.userId}
        AND w.disabled = false AND w.deleted_at IS NULL
        AND m.role IN ('OWNER', 'ADMIN', 'EDITOR')
      ORDER BY w.is_personal DESC, w.name ASC
    `;
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      isPersonal: r.is_personal === true,
      role: r.role,
    }));
  });

export const startImportJob = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z
      .object({
        workspaceId: z.string().uuid(),
        // "new" : nouveau groupe racine ; "existing" : sous un groupe existant ;
        // "root" : l'arborescence KeePass est recréée à la racine du coffre.
        rootMode: z.enum(["new", "existing", "root"]).optional(),
        rootFolderName: z.string().min(1).max(120).optional(),
        rootFolderId: z.string().uuid().nullable().optional(),
        strategy,
        criteria: z.array(criterion).min(1).max(4),
        plannedEntries: z.number().int().min(0).max(100000),
      })
      .parse(input),
  )
  .handler(async ({ data, context }) => {
    const { userId } = context;
    await requireWorkspacePermission(userId, data.workspaceId, "secret.import");
    await requireWorkspacePermission(userId, data.workspaceId, "secret.create");
    await requireWorkspacePermission(userId, data.workspaceId, "folder.create");
    if (data.strategy === "replace" || data.strategy === "merge") {
      await requireWorkspacePermission(userId, data.workspaceId, "secret.update");
    }

    const sql = getDb();
    const mode = data.rootMode ?? "new";
    let folderId: string | null = null;
    if (mode === "new") {
      const name = data.rootFolderName?.trim() || "Import KeePass";
      folderId = (await ensureRootFolder(sql, data.workspaceId, name)).folderId;
    } else if (mode === "existing") {
      if (!data.rootFolderId) throw new Error("Groupe de destination requis");
      const rows = await sql<{ id: string }[]>`
        SELECT id FROM secret_folders
        WHERE id = ${data.rootFolderId} AND workspace_id = ${data.workspaceId} AND deleted_at IS NULL
      `;
      if (!rows[0]) throw new Error("Groupe de destination introuvable");
      folderId = rows[0].id;
    }
    const rows = await sql<{ id: string; created_at: Date | string }[]>`
      INSERT INTO import_jobs (user_id, workspace_id, root_folder_id, duplicate_strategy, planned_entries)
      VALUES (${userId}, ${data.workspaceId}, ${folderId}, ${data.strategy}, ${data.plannedEntries})
      RETURNING id, created_at
    `;
    const job = rows[0]!;
    // Journal : métadonnées uniquement, jamais de contenu importé.
    await audit({
      userId,
      workspaceId: data.workspaceId,
      action: "import.started",
      targetType: "import_job",
      targetId: job.id,
      targetLabel: `keepass:${data.strategy}:${data.plannedEntries}`,
    });
    return { jobId: job.id, rootFolderId: folderId, createdAt: iso(job.created_at) };
  });

export const importBatch = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z
      .object({
        jobId: z.string().uuid(),
        strategy,
        criteria: z.array(criterion).min(1).max(4),
        items: z.array(itemSchema).min(1).max(50),
      })
      .parse(input),
  )
  .handler(async ({ data, context }) =>
    runImportBatch({
      userId: context.userId,
      jobId: data.jobId,
      strategy: data.strategy,
      criteria: data.criteria,
      items: data.items as ImportItemPayload[],
    }),
  );

export const finishImportJob = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({ jobId: z.string().uuid(), status: z.enum(["completed", "aborted"]) }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const sql = getDb();
    const rows = await sql<
      {
        id: string;
        user_id: string;
        workspace_id: string;
        imported_count: number;
        skipped_count: number;
        replaced_count: number;
        merged_count: number;
        failed_count: number;
        attachment_count: number;
        folder_count: number;
      }[]
    >`
      UPDATE import_jobs SET status = ${data.status}
      WHERE id = ${data.jobId} AND user_id = ${context.userId}
      RETURNING id, user_id, workspace_id, imported_count, skipped_count, replaced_count,
                merged_count, failed_count, attachment_count, folder_count
    `;
    const job = rows[0];
    if (!job) throw new Error("Not found");
    await audit({
      userId: context.userId,
      workspaceId: job.workspace_id,
      action: "import.finished",
      targetType: "import_job",
      targetId: job.id,
      targetLabel: `imported=${job.imported_count};failed=${job.failed_count}`,
      result: job.failed_count > 0 ? "failure" : "success",
    });
    return {
      imported: job.imported_count,
      skipped: job.skipped_count,
      replaced: job.replaced_count,
      merged: job.merged_count,
      failed: job.failed_count,
      attachments: job.attachment_count,
      folders: job.folder_count,
    };
  });

/** Reprise : clés déjà traitées, pour ne rien réimporter deux fois. */
export const getImportProgress = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) => z.object({ jobId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const sql = getDb();
    const jobs = await sql<{ id: string; status: string }[]>`
      SELECT id, status FROM import_jobs WHERE id = ${data.jobId} AND user_id = ${context.userId}
    `;
    if (!jobs[0]) throw new Error("Not found");
    const items = await sql<{ client_key: string; status: string }[]>`
      SELECT client_key, status FROM import_items WHERE job_id = ${data.jobId}
    `;
    return {
      status: jobs[0].status,
      processed: items.filter((i) => i.status !== "failed").map((i) => i.client_key),
    };
  });
