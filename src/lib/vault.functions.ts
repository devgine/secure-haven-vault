import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "./auth-middleware";
import { getDb, iso, isoOrNull } from "./db.server";
import { isSuperAdmin, requireWorkspacePermission } from "./vault.server";
import { decryptField, encryptField } from "./crypto.server";
import { getOrCreateDek } from "./vault.server";
import { audit } from "./audit.server";
import type {
  RevealedField,
  SecretDetail,
  SecretListItem,
  SecretVersionDto,
  WorkspaceDto,
} from "./types";

const fieldInput = z.object({
  label: z.string().min(1).max(100),
  fieldType: z.enum(["text", "secret", "password", "url", "username", "date", "totp", "textarea"]),
  isSensitive: z.boolean(),
  value: z.string().max(65536),
});

const secretInput = z.object({
  workspaceId: z.string().uuid(),
  type: z.enum(["LOGIN", "API_KEY", "TOKEN", "SSH_KEY", "DATABASE", "SECURE_NOTE", "CUSTOM"]),
  name: z.string().min(1).max(200),
  username: z.string().max(500).optional(),
  url: z.string().max(2000).optional(),
  description: z.string().max(5000).optional(),
  tags: z.array(z.string().min(1).max(50)).max(30).optional(),
  expiresAt: z.string().nullable().optional(),
  notifyBeforeDays: z.number().int().min(1).max(365).nullable().optional(),
  fields: z.array(fieldInput).max(100),
});

interface SecretRow {
  id: string;
  workspace_id: string;
  type: SecretListItem["type"];
  name: string;
  username: string | null;
  url: string | null;
  description: string | null;
  tags: string[] | null;
  favorite: boolean;
  expires_at: Date | string | null;
  notify_before_days: number | null;
  updated_at: Date | string;
  created_at?: Date | string;
  created_by?: string | null;
  updated_by?: string | null;
  workspace_name?: string | null;
}

function mapSecret(row: SecretRow): SecretListItem {
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    workspaceName: row.workspace_name ?? undefined,
    type: row.type,
    name: row.name,
    username: row.username,
    url: row.url,
    description: row.description,
    tags: row.tags ?? [],
    favorite: row.favorite === true,
    expiresAt: isoOrNull(row.expires_at),
    notifyBeforeDays: row.notify_before_days,
    updatedAt: iso(row.updated_at),
  };
}

// Colonnes listées explicitement (postgres.js ne permet pas d'injecter du SQL
// dynamique sûr pour une liste de colonnes).

export const getSessionInfo = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    const { userId } = context;
    const sql = getDb();
    const [profiles, superAdmin] = await Promise.all([
      sql<
        {
          id: string;
          email: string | null;
          display_name: string | null;
          lock_timeout_minutes: number;
          theme: string;
        }[]
      >`
        SELECT id, email, display_name, lock_timeout_minutes, theme
        FROM profiles WHERE id = ${userId}
      `,
      isSuperAdmin(userId),
    ]);
    const profile = profiles[0];
    return {
      userId,
      email: profile?.email ?? context.userEmail,
      displayName: profile?.display_name ?? null,
      lockTimeoutMinutes: profile?.lock_timeout_minutes ?? 15,
      theme: profile?.theme ?? "system",
      isSuperAdmin: superAdmin,
    };
  });

export const listWorkspaces = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    const { userId } = context;
    const rows = await getDb()<
      {
        role: WorkspaceDto["role"];
        id: string;
        name: string;
        description: string | null;
        is_personal: boolean;
        owner_id: string;
        disabled: boolean;
        allow_viewer_reveal: boolean;
        created_at: Date | string;
      }[]
    >`
      SELECT m.role, w.id, w.name, w.description, w.is_personal, w.owner_id,
             w.disabled, w.allow_viewer_reveal, w.created_at
      FROM workspace_members m
      JOIN workspaces w ON w.id = m.workspace_id
      WHERE m.user_id = ${userId}
        AND w.disabled = false
        AND w.deleted_at IS NULL
    `;
    const out: WorkspaceDto[] = rows.map((r) => ({
      id: r.id,
      name: r.name,
      description: r.description,
      isPersonal: r.is_personal === true,
      ownerId: r.owner_id,
      disabled: r.disabled === true,
      allowViewerReveal: r.allow_viewer_reveal === true,
      role: r.role,
      createdAt: iso(r.created_at),
    }));
    out.sort((a, b) => Number(b.isPersonal) - Number(a.isPersonal) || a.name.localeCompare(b.name));
    return out;
  });

export const createWorkspace = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({ name: z.string().min(1).max(100), description: z.string().max(500).optional() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { userId } = context;
    const sql = getDb();
    const workspaceId = await sql.begin(async (tx) => {
      const inserted = await tx<{ id: string }[]>`
        INSERT INTO workspaces (name, description, owner_id)
        VALUES (${data.name}, ${data.description ?? null}, ${userId})
        RETURNING id
      `;
      const id = inserted[0]!.id;
      await tx`
        INSERT INTO workspace_members (workspace_id, user_id, role)
        VALUES (${id}, ${userId}, 'OWNER')
      `;
      return id;
    });
    await audit({ userId, workspaceId, action: "workspace.created", targetType: "workspace", targetId: workspaceId, targetLabel: data.name });
    return { id: workspaceId };
  });

export const updateWorkspace = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({
      workspaceId: z.string().uuid(),
      name: z.string().min(1).max(100),
      description: z.string().max(500).nullable().optional(),
      allowViewerReveal: z.boolean(),
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { userId } = context;
    await requireWorkspacePermission(userId, data.workspaceId, "workspace.update");
    await getDb()`
      UPDATE workspaces
      SET name = ${data.name},
          description = ${data.description ?? null},
          allow_viewer_reveal = ${data.allowViewerReveal}
      WHERE id = ${data.workspaceId}
    `;
    await audit({ userId, workspaceId: data.workspaceId, action: "workspace.updated", targetType: "workspace", targetId: data.workspaceId, targetLabel: data.name });
    return { ok: true };
  });

export const deleteWorkspace = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) => z.object({ workspaceId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const { userId } = context;
    await requireWorkspacePermission(userId, data.workspaceId, "workspace.delete");
    const rows = await getDb()<{ is_personal: boolean; name: string }[]>`
      SELECT is_personal, name FROM workspaces WHERE id = ${data.workspaceId}
    `;
    const ws = rows[0];
    if (ws?.is_personal) throw new Error("The personal vault cannot be deleted");
    await getDb()`
      UPDATE workspaces SET deleted_at = now() WHERE id = ${data.workspaceId}
    `;
    await audit({ userId, workspaceId: data.workspaceId, action: "workspace.deleted", targetType: "workspace", targetId: data.workspaceId, targetLabel: ws?.name ?? null });
    return { ok: true };
  });

export const listSecrets = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({ workspaceId: z.string().uuid(), trashed: z.boolean().optional() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { userId } = context;
    await requireWorkspacePermission(userId, data.workspaceId, "secret.read");
    const sql = getDb();
    const rows = data.trashed
      ? await sql<SecretRow[]>`
          SELECT id, workspace_id, type, name, username, url, description, tags,
                 favorite, expires_at, notify_before_days, updated_at
          FROM secrets
          WHERE workspace_id = ${data.workspaceId} AND deleted_at IS NOT NULL
          ORDER BY updated_at DESC
        `
      : await sql<SecretRow[]>`
          SELECT id, workspace_id, type, name, username, url, description, tags,
                 favorite, expires_at, notify_before_days, updated_at
          FROM secrets
          WHERE workspace_id = ${data.workspaceId} AND deleted_at IS NULL
          ORDER BY updated_at DESC
        `;
    return rows.map(mapSecret);
  });

export const searchSecrets = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({
      query: z.string().max(120).optional(),
      favoritesOnly: z.boolean().optional(),
      recentOnly: z.boolean().optional(),
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { userId } = context;
    const sql = getDb();
    const q = (data.query ?? "").trim().slice(0, 120);
    const limit = data.recentOnly ? 10 : 100;
    const favoritesOnly = data.favoritesOnly === true;

    // Périmètre : uniquement les coffres actifs dont l'utilisateur est membre.
    const rows = q
      ? await sql<SecretRow[]>`
          SELECT s.id, s.workspace_id, s.type, s.name, s.username, s.url, s.description,
                 s.tags, s.favorite, s.expires_at, s.notify_before_days, s.updated_at,
                 w.name AS workspace_name
          FROM secrets s
          JOIN workspaces w ON w.id = s.workspace_id
          JOIN workspace_members m ON m.workspace_id = s.workspace_id AND m.user_id = ${userId}
          WHERE s.deleted_at IS NULL
            AND w.disabled = false AND w.deleted_at IS NULL
            AND (${!favoritesOnly} OR s.favorite = true)
            AND (
              s.name ILIKE ${"%" + q + "%"}
              OR s.username ILIKE ${"%" + q + "%"}
              OR s.url ILIKE ${"%" + q + "%"}
              OR s.description ILIKE ${"%" + q + "%"}
              OR s.tags @> ${sql.array([q])}
            )
          ORDER BY s.updated_at DESC
          LIMIT ${limit}
        `
      : await sql<SecretRow[]>`
          SELECT s.id, s.workspace_id, s.type, s.name, s.username, s.url, s.description,
                 s.tags, s.favorite, s.expires_at, s.notify_before_days, s.updated_at,
                 w.name AS workspace_name
          FROM secrets s
          JOIN workspaces w ON w.id = s.workspace_id
          JOIN workspace_members m ON m.workspace_id = s.workspace_id AND m.user_id = ${userId}
          WHERE s.deleted_at IS NULL
            AND w.disabled = false AND w.deleted_at IS NULL
            AND (${!favoritesOnly} OR s.favorite = true)
          ORDER BY s.updated_at DESC
          LIMIT ${limit}
        `;
    return rows.map(mapSecret);
  });

export const getSecret = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) => z.object({ secretId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const { userId } = context;
    const sql = getDb();
    const rows = await sql<SecretRow[]>`
      SELECT id, workspace_id, type, name, username, url, description, tags,
             favorite, expires_at, notify_before_days, updated_at,
             created_at, created_by, updated_by
      FROM secrets
      WHERE id = ${data.secretId} AND deleted_at IS NULL
    `;
    const row = rows[0];
    if (!row) throw new Error("Not found");
    await requireWorkspacePermission(userId, row.workspace_id, "secret.read");

    const fields = await sql<
      { id: string; label: string; field_type: string; is_sensitive: boolean; position: number }[]
    >`
      SELECT id, label, field_type, is_sensitive, position
      FROM secret_fields
      WHERE secret_id = ${row.id}
      ORDER BY position ASC
    `;

    const detail: SecretDetail = {
      ...mapSecret(row),
      createdAt: iso(row.created_at),
      fields: fields.map((f) => ({
        id: f.id,
        label: f.label,
        fieldType: f.field_type as SecretDetail["fields"][number]["fieldType"],
        isSensitive: f.is_sensitive,
        position: f.position,
      })),
    };
    return detail;
  });

export const revealSecret = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({
      secretId: z.string().uuid(),
      action: z.enum(["reveal", "copy"]),
      fieldId: z.string().uuid().optional(),
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { userId } = context;
    const sql = getDb();
    const secrets = await sql<{ id: string; workspace_id: string; name: string }[]>`
      SELECT id, workspace_id, name FROM secrets
      WHERE id = ${data.secretId} AND deleted_at IS NULL
    `;
    const secret = secrets[0];
    if (!secret) throw new Error("Not found");
    await requireWorkspacePermission(
      userId,
      secret.workspace_id,
      data.action === "copy" ? "secret.copy" : "secret.reveal",
    );

    const dek = await getOrCreateDek(secret.workspace_id);
    const fields = data.fieldId
      ? await sql<
          { id: string; label: string; field_type: string; is_sensitive: boolean; ciphertext: string }[]
        >`
          SELECT id, label, field_type, is_sensitive, ciphertext
          FROM secret_fields
          WHERE secret_id = ${secret.id} AND id = ${data.fieldId}
          ORDER BY position ASC
        `
      : await sql<
          { id: string; label: string; field_type: string; is_sensitive: boolean; ciphertext: string }[]
        >`
          SELECT id, label, field_type, is_sensitive, ciphertext
          FROM secret_fields
          WHERE secret_id = ${secret.id}
          ORDER BY position ASC
        `;

    const revealed: RevealedField[] = [];
    for (const f of fields) {
      const value = await decryptField(dek, f.ciphertext);
      revealed.push({
        id: f.id,
        label: f.label,
        fieldType: f.field_type as RevealedField["fieldType"],
        isSensitive: f.is_sensitive,
        value,
      });
    }

    await audit({
      userId,
      workspaceId: secret.workspace_id,
      action: data.action === "copy" ? "secret.copied" : "secret.revealed",
      targetType: "secret",
      targetId: secret.id,
      targetLabel: secret.name,
    });
    return revealed;
  });

export const createSecret = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) => secretInput.parse(input))
  .handler(async ({ data, context }) => {
    const { userId } = context;
    await requireWorkspacePermission(userId, data.workspaceId, "secret.create");
    const sql = getDb();

    const inserted = await sql<{ id: string }[]>`
      INSERT INTO secrets (workspace_id, type, name, username, url, description, tags, expires_at, notify_before_days, created_by, updated_by)
      VALUES (
        ${data.workspaceId}, ${data.type}, ${data.name},
        ${data.username || null}, ${data.url || null}, ${data.description || null},
        ${sql.array(data.tags ?? [])},
        ${data.expiresAt || null}, ${data.notifyBeforeDays ?? null},
        ${userId}, ${userId}
      )
      RETURNING id
    `;
    const secretId = inserted[0]!.id;

    const dek = await getOrCreateDek(data.workspaceId);
    for (let i = 0; i < data.fields.length; i++) {
      const f = data.fields[i]!;
      await sql`
        INSERT INTO secret_fields (secret_id, label, field_type, is_sensitive, ciphertext, position)
        VALUES (${secretId}, ${f.label}, ${f.fieldType}, ${f.isSensitive}, ${await encryptField(dek, f.value)}, ${i})
      `;
    }

    await sql`
      INSERT INTO secret_versions (secret_id, version, action, changed_by, changed_fields)
      VALUES (${secretId}, 1, 'created', ${userId}, ${sql.array([] as string[])})
    `;
    await audit({ userId, workspaceId: data.workspaceId, action: "secret.created", targetType: "secret", targetId: secretId, targetLabel: data.name });
    return { id: secretId };
  });

export const updateSecret = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({ secretId: z.string().uuid() }).extend(secretInput.omit({ workspaceId: true }).shape).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { userId } = context;
    const sql = getDb();
    const rows = await sql<{ id: string; workspace_id: string; name: string }[]>`
      SELECT id, workspace_id, name FROM secrets
      WHERE id = ${data.secretId} AND deleted_at IS NULL
    `;
    const existing = rows[0];
    if (!existing) throw new Error("Not found");
    await requireWorkspacePermission(userId, existing.workspace_id, "secret.update");

    await sql`
      UPDATE secrets SET
        type = ${data.type},
        name = ${data.name},
        username = ${data.username || null},
        url = ${data.url || null},
        description = ${data.description || null},
        tags = ${sql.array(data.tags ?? [])},
        expires_at = ${data.expiresAt || null},
        notify_before_days = ${data.notifyBeforeDays ?? null},
        updated_by = ${userId}
      WHERE id = ${data.secretId}
    `;

    const dek = await getOrCreateDek(existing.workspace_id);
    await sql`DELETE FROM secret_fields WHERE secret_id = ${data.secretId}`;
    for (let i = 0; i < data.fields.length; i++) {
      const f = data.fields[i]!;
      await sql`
        INSERT INTO secret_fields (secret_id, label, field_type, is_sensitive, ciphertext, position)
        VALUES (${data.secretId}, ${f.label}, ${f.fieldType}, ${f.isSensitive}, ${await encryptField(dek, f.value)}, ${i})
      `;
    }

    const lastVersion = await sql<{ version: number }[]>`
      SELECT version FROM secret_versions
      WHERE secret_id = ${data.secretId}
      ORDER BY version DESC LIMIT 1
    `;
    await sql`
      INSERT INTO secret_versions (secret_id, version, action, changed_by, changed_fields)
      VALUES (
        ${data.secretId},
        ${(lastVersion[0]?.version ?? 0) + 1},
        'updated',
        ${userId},
        ${sql.array(["metadata", ...data.fields.map((f) => f.label)])}
      )
    `;
    await audit({ userId, workspaceId: existing.workspace_id, action: "secret.updated", targetType: "secret", targetId: data.secretId, targetLabel: data.name });
    return { ok: true };
  });

export const deleteSecret = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({ secretId: z.string().uuid(), mode: z.enum(["trash", "restore", "purge"]).default("trash") }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { userId } = context;
    const sql = getDb();
    const rows = await sql<{ id: string; workspace_id: string; name: string }[]>`
      SELECT id, workspace_id, name FROM secrets WHERE id = ${data.secretId}
    `;
    const existing = rows[0];
    if (!existing) throw new Error("Not found");
    await requireWorkspacePermission(userId, existing.workspace_id, "secret.delete");

    if (data.mode === "restore") {
      await sql`UPDATE secrets SET deleted_at = NULL WHERE id = ${data.secretId}`;
      await audit({ userId, workspaceId: existing.workspace_id, action: "secret.restored", targetType: "secret", targetId: existing.id, targetLabel: existing.name });
      return { ok: true };
    }
    if (data.mode === "purge") {
      await sql`DELETE FROM secrets WHERE id = ${data.secretId}`;
      await audit({ userId, workspaceId: existing.workspace_id, action: "secret.purged", targetType: "secret", targetId: existing.id, targetLabel: existing.name });
      return { ok: true };
    }
    await sql`UPDATE secrets SET deleted_at = now(), updated_by = ${userId} WHERE id = ${data.secretId}`;
    await audit({ userId, workspaceId: existing.workspace_id, action: "secret.deleted", targetType: "secret", targetId: existing.id, targetLabel: existing.name });
    return { ok: true };
  });

export const toggleFavorite = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({ secretId: z.string().uuid(), favorite: z.boolean() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { userId } = context;
    const sql = getDb();
    const rows = await sql<{ id: string; workspace_id: string }[]>`
      SELECT id, workspace_id FROM secrets
      WHERE id = ${data.secretId} AND deleted_at IS NULL
    `;
    const existing = rows[0];
    if (!existing) throw new Error("Not found");
    await requireWorkspacePermission(userId, existing.workspace_id, "secret.read");
    await sql`UPDATE secrets SET favorite = ${data.favorite} WHERE id = ${data.secretId}`;
    return { ok: true };
  });

export const getSecretVersions = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) => z.object({ secretId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const { userId } = context;
    const sql = getDb();
    const secrets = await sql<{ id: string; workspace_id: string }[]>`
      SELECT id, workspace_id FROM secrets WHERE id = ${data.secretId}
    `;
    const secret = secrets[0];
    if (!secret) throw new Error("Not found");
    await requireWorkspacePermission(userId, secret.workspace_id, "secret.read");

    const versions = await sql<
      {
        id: string;
        version: number;
        action: string;
        changed_fields: string[] | null;
        changed_at: Date | string;
        changed_by: string | null;
        changed_by_email: string | null;
      }[]
    >`
      SELECT v.id, v.version, v.action, v.changed_fields, v.changed_at, v.changed_by,
             p.email AS changed_by_email
      FROM secret_versions v
      LEFT JOIN profiles p ON p.id = v.changed_by
      WHERE v.secret_id = ${data.secretId}
      ORDER BY v.version DESC
      LIMIT 50
    `;
    const out: SecretVersionDto[] = versions.map((v) => ({
      id: v.id,
      version: v.version,
      action: v.action,
      changedByEmail: v.changed_by_email,
      changedFields: v.changed_fields ?? [],
      changedAt: iso(v.changed_at),
    }));
    return out;
  });
