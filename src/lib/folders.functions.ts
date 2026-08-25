// Groupes natifs d'un coffre — fonctions serveur (déclarations minces).
// Chaque appel revérifie la permission côté serveur : le client ne décide rien.
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "./auth-middleware";
import { getDb, iso } from "./db.server";
import { audit } from "./audit.server";
import { requireWorkspacePermission } from "./vault.server";
import {
  MAX_FOLDER_DEPTH,
  descendantIds,
  directSecretCounts,
  folderDepth,
  folderPath,
  getFolder,
  nameTaken,
  nextPosition,
  subtreeHeight,
} from "./folders.server";
import type { FolderDto } from "./types";

export const listFolders = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({ workspaceId: z.string().uuid() }).parse(input),
  )
  .handler(async ({ data, context }): Promise<FolderDto[]> => {
    await requireWorkspacePermission(context.userId, data.workspaceId, "workspace.read");
    const rows = await getDb()<
      {
        id: string;
        parent_id: string | null;
        name: string;
        description: string | null;
        icon: string | null;
        color: string | null;
        position: number;
        created_at: Date | string;
      }[]
    >`
      SELECT id, parent_id, name, description, icon, color, position, created_at
      FROM secret_folders
      WHERE workspace_id = ${data.workspaceId} AND deleted_at IS NULL
      ORDER BY position ASC, lower(name) ASC
    `;
    const counts = await directSecretCounts(data.workspaceId);
    return rows.map((r) => ({
      id: r.id,
      workspaceId: data.workspaceId,
      parentId: r.parent_id,
      name: r.name,
      description: r.description,
      icon: r.icon,
      color: r.color,
      position: r.position,
      secretCount: counts[r.id] ?? 0,
      createdAt: iso(r.created_at),
    }));
  });

export const createFolder = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z
      .object({
        workspaceId: z.string().uuid(),
        parentId: z.string().uuid().nullable().optional(),
        name: z.string().min(1).max(120),
        description: z.string().max(500).nullable().optional(),
        icon: z.string().max(50).nullable().optional(),
        color: z.string().max(30).nullable().optional(),
      })
      .parse(input),
  )
  .handler(async ({ data, context }) => {
    const { userId } = context;
    await requireWorkspacePermission(userId, data.workspaceId, "folder.create");
    const sql = getDb();
    const parentId = data.parentId ?? null;
    if (parentId) {
      const parent = await getFolder(sql, parentId);
      if (!parent || parent.workspace_id !== data.workspaceId) throw new Error("Groupe parent introuvable");
      if ((await folderDepth(sql, parentId)) >= MAX_FOLDER_DEPTH) {
        throw new Error(`Profondeur maximale atteinte (${MAX_FOLDER_DEPTH} niveaux)`);
      }
    }
    const name = data.name.trim();
    if (await nameTaken(sql, data.workspaceId, parentId, name)) {
      throw new Error("Un groupe portant ce nom existe déjà à cet emplacement");
    }
    const position = await nextPosition(sql, data.workspaceId, parentId);
    const rows = await sql<{ id: string }[]>`
      INSERT INTO secret_folders (workspace_id, parent_id, name, description, icon, color, position, created_by)
      VALUES (${data.workspaceId}, ${parentId}, ${name}, ${data.description ?? null},
              ${data.icon ?? null}, ${data.color ?? null}, ${position}, ${userId})
      RETURNING id
    `;
    const id = rows[0]!.id;
    await audit({
      userId,
      workspaceId: data.workspaceId,
      action: "folder.created",
      targetType: "folder",
      targetId: id,
      targetLabel: await folderPath(sql, id),
    });
    return { id };
  });

export const updateFolder = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z
      .object({
        folderId: z.string().uuid(),
        name: z.string().min(1).max(120),
        description: z.string().max(500).nullable().optional(),
        icon: z.string().max(50).nullable().optional(),
        color: z.string().max(30).nullable().optional(),
      })
      .parse(input),
  )
  .handler(async ({ data, context }) => {
    const sql = getDb();
    const folder = await getFolder(sql, data.folderId);
    if (!folder) throw new Error("Groupe introuvable");
    await requireWorkspacePermission(context.userId, folder.workspace_id, "folder.manage");
    const name = data.name.trim();
    if (await nameTaken(sql, folder.workspace_id, folder.parent_id, name, folder.id)) {
      throw new Error("Un groupe portant ce nom existe déjà à cet emplacement");
    }
    await sql`
      UPDATE secret_folders
      SET name = ${name}, description = ${data.description ?? null},
          icon = ${data.icon ?? null}, color = ${data.color ?? null}
      WHERE id = ${data.folderId}
    `;
    await audit({
      userId: context.userId,
      workspaceId: folder.workspace_id,
      action: "folder.updated",
      targetType: "folder",
      targetId: folder.id,
      targetLabel: await folderPath(sql, folder.id),
    });
    return { ok: true };
  });

export const moveFolder = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z
      .object({
        folderId: z.string().uuid(),
        parentId: z.string().uuid().nullable(),
        position: z.number().int().min(0).max(10000).optional(),
      })
      .parse(input),
  )
  .handler(async ({ data, context }) => {
    const sql = getDb();
    const folder = await getFolder(sql, data.folderId);
    if (!folder) throw new Error("Groupe introuvable");
    await requireWorkspacePermission(context.userId, folder.workspace_id, "folder.manage");

    const parentId = data.parentId;
    if (parentId) {
      const parent = await getFolder(sql, parentId);
      if (!parent || parent.workspace_id !== folder.workspace_id) throw new Error("Groupe cible introuvable");
      // Anti-cycle : on ne déplace jamais un groupe dans sa propre descendance.
      const forbidden = await descendantIds(sql, folder.id);
      if (forbidden.includes(parentId)) throw new Error("Impossible de déplacer un groupe dans lui-même");
      const depth = await folderDepth(sql, parentId);
      const height = await subtreeHeight(sql, folder.id);
      if (depth + height > MAX_FOLDER_DEPTH) {
        throw new Error(`Profondeur maximale atteinte (${MAX_FOLDER_DEPTH} niveaux)`);
      }
    }
    if (
      parentId !== folder.parent_id &&
      (await nameTaken(sql, folder.workspace_id, parentId, folder.name, folder.id))
    ) {
      throw new Error("Un groupe portant ce nom existe déjà à cet emplacement");
    }
    const position =
      data.position ?? (await nextPosition(sql, folder.workspace_id, parentId));
    await sql`
      UPDATE secret_folders SET parent_id = ${parentId}, position = ${position}
      WHERE id = ${folder.id}
    `;
    await audit({
      userId: context.userId,
      workspaceId: folder.workspace_id,
      action: "folder.moved",
      targetType: "folder",
      targetId: folder.id,
      targetLabel: await folderPath(sql, folder.id),
    });
    return { ok: true };
  });

export const reorderFolders = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z
      .object({
        workspaceId: z.string().uuid(),
        orderedIds: z.array(z.string().uuid()).max(500),
      })
      .parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireWorkspacePermission(context.userId, data.workspaceId, "folder.manage");
    const sql = getDb();
    await sql.begin(async (tx) => {
      for (let i = 0; i < data.orderedIds.length; i++) {
        await tx`
          UPDATE secret_folders SET position = ${i}
          WHERE id = ${data.orderedIds[i]!} AND workspace_id = ${data.workspaceId}
        `;
      }
    });
    return { ok: true };
  });

export const deleteFolder = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z
      .object({
        folderId: z.string().uuid(),
        // "detach" : le contenu remonte au parent ; "trash" : suppression récursive
        // (les secrets partent à la corbeille, jamais détruits).
        mode: z.enum(["detach", "trash"]),
      })
      .parse(input),
  )
  .handler(async ({ data, context }) => {
    const sql = getDb();
    const folder = await getFolder(sql, data.folderId);
    if (!folder) throw new Error("Groupe introuvable");
    await requireWorkspacePermission(context.userId, folder.workspace_id, "folder.manage");
    if (data.mode === "trash") {
      await requireWorkspacePermission(context.userId, folder.workspace_id, "secret.delete");
    }
    const path = await folderPath(sql, folder.id);
    const ids = await descendantIds(sql, folder.id);

    const counts = await sql.begin(async (tx) => {
      if (data.mode === "detach") {
        // Contenu remonté d'un cran : sous-groupes et secrets rejoignent le parent.
        const moved = await tx<{ id: string }[]>`
          UPDATE secrets SET folder_id = ${folder.parent_id}, updated_by = ${context.userId}
          WHERE folder_id = ${folder.id} AND deleted_at IS NULL
          RETURNING id
        `;
        await tx`
          UPDATE secret_folders SET parent_id = ${folder.parent_id}
          WHERE parent_id = ${folder.id} AND deleted_at IS NULL
        `;
        await tx`DELETE FROM secret_folders WHERE id = ${folder.id}`;
        return { secrets: moved.length, folders: 1 };
      }
      const trashed = await tx<{ id: string }[]>`
        UPDATE secrets SET deleted_at = now(), updated_by = ${context.userId}
        WHERE folder_id = ANY(${tx.array(ids)}) AND deleted_at IS NULL
        RETURNING id
      `;
      await tx`UPDATE secret_folders SET deleted_at = now() WHERE id = ANY(${tx.array(ids)})`;
      return { secrets: trashed.length, folders: ids.length };
    });

    await audit({
      userId: context.userId,
      workspaceId: folder.workspace_id,
      action: data.mode === "trash" ? "folder.deleted.recursive" : "folder.deleted",
      targetType: "folder",
      targetId: folder.id,
      targetLabel: `${path} (${counts.folders} groupes, ${counts.secrets} secrets)`,
    });
    return counts;
  });

export const moveSecrets = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z
      .object({
        workspaceId: z.string().uuid(),
        secretIds: z.array(z.string().uuid()).min(1).max(500),
        folderId: z.string().uuid().nullable(),
      })
      .parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireWorkspacePermission(context.userId, data.workspaceId, "secret.update");
    const sql = getDb();
    if (data.folderId) {
      const target = await getFolder(sql, data.folderId);
      if (!target || target.workspace_id !== data.workspaceId) throw new Error("Groupe cible introuvable");
    }
    const moved = await sql<{ id: string }[]>`
      UPDATE secrets SET folder_id = ${data.folderId}, updated_by = ${context.userId}
      WHERE workspace_id = ${data.workspaceId}
        AND deleted_at IS NULL
        AND id = ANY(${sql.array(data.secretIds)})
      RETURNING id
    `;
    await audit({
      userId: context.userId,
      workspaceId: data.workspaceId,
      action: "secret.moved",
      targetType: "folder",
      targetId: data.folderId,
      targetLabel: `${moved.length} secrets → ${data.folderId ? await folderPath(sql, data.folderId) : "Racine"}`,
    });
    return { moved: moved.length };
  });
