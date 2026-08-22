import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import {
  getWorkspaceRole,
  isSuperAdmin,
  requireWorkspacePermission,
} from "./vault.server";
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
  fieldType: z.enum(["text", "secret", "password", "url", "username", "date", "textarea"]),
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

function mapSecret(row: Record<string, unknown>, workspaceName?: string): SecretListItem {
  return {
    id: row["id"] as string,
    workspaceId: row["workspace_id"] as string,
    workspaceName,
    type: row["type"] as SecretListItem["type"],
    name: row["name"] as string,
    username: (row["username"] as string | null) ?? null,
    url: (row["url"] as string | null) ?? null,
    description: (row["description"] as string | null) ?? null,
    tags: (row["tags"] as string[]) ?? [],
    favorite: row["favorite"] === true,
    expiresAt: (row["expires_at"] as string | null) ?? null,
    notifyBeforeDays: (row["notify_before_days"] as number | null) ?? null,
    updatedAt: row["updated_at"] as string,
  };
}

function sanitizeQuery(q: string): string {
  return q.replace(/[%_,().\\]/g, " ").trim().slice(0, 120);
}

export const getSessionInfo = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    const [{ data: profile }, superAdmin] = await Promise.all([
      supabase
        .from("profiles")
        .select("id, email, display_name, lock_timeout_minutes, theme")
        .eq("id", userId)
        .maybeSingle(),
      isSuperAdmin(supabase, userId),
    ]);
    return {
      userId,
      email: profile?.email ?? null,
      displayName: profile?.display_name ?? null,
      lockTimeoutMinutes: profile?.lock_timeout_minutes ?? 15,
      theme: profile?.theme ?? "system",
      isSuperAdmin: superAdmin,
    };
  });

export const listWorkspaces = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    const { data, error } = await supabase
      .from("workspace_members")
      .select("role, workspaces(id, name, description, is_personal, owner_id, disabled, allow_viewer_reveal, created_at)")
      .eq("user_id", userId);
    if (error) throw new Error("Failed to load workspaces");
    const out: WorkspaceDto[] = [];
    for (const row of data ?? []) {
      const ws = row.workspaces as unknown as Record<string, unknown> | null;
      if (!ws || ws["disabled"] === true) continue;
      out.push({
        id: ws["id"] as string,
        name: ws["name"] as string,
        description: (ws["description"] as string | null) ?? null,
        isPersonal: ws["is_personal"] === true,
        ownerId: ws["owner_id"] as string,
        disabled: ws["disabled"] === true,
        allowViewerReveal: ws["allow_viewer_reveal"] === true,
        role: row.role as WorkspaceDto["role"],
        createdAt: ws["created_at"] as string,
      });
    }
    out.sort((a, b) => Number(b.isPersonal) - Number(a.isPersonal) || a.name.localeCompare(b.name));
    return out;
  });

export const createWorkspace = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({ name: z.string().min(1).max(100), description: z.string().max(500).optional() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { userId } = context;
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: ws, error } = await supabaseAdmin
      .from("workspaces")
      .insert({ name: data.name, description: data.description ?? null, owner_id: userId })
      .select("id")
      .single();
    if (error || !ws) throw new Error("Failed to create workspace");
    const { error: memberError } = await supabaseAdmin
      .from("workspace_members")
      .insert({ workspace_id: ws.id, user_id: userId, role: "OWNER" });
    if (memberError) throw new Error("Failed to create workspace membership");
    await audit({ userId, workspaceId: ws.id, action: "workspace.created", targetType: "workspace", targetId: ws.id, targetLabel: data.name });
    return { id: ws.id };
  });

export const updateWorkspace = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({
      workspaceId: z.string().uuid(),
      name: z.string().min(1).max(100),
      description: z.string().max(500).nullable().optional(),
      allowViewerReveal: z.boolean(),
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await requireWorkspacePermission(supabase, userId, data.workspaceId, "workspace.update");
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { error } = await supabaseAdmin
      .from("workspaces")
      .update({ name: data.name, description: data.description ?? null, allow_viewer_reveal: data.allowViewerReveal })
      .eq("id", data.workspaceId);
    if (error) throw new Error("Failed to update workspace");
    await audit({ userId, workspaceId: data.workspaceId, action: "workspace.updated", targetType: "workspace", targetId: data.workspaceId, targetLabel: data.name });
    return { ok: true };
  });

export const deleteWorkspace = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => z.object({ workspaceId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await requireWorkspacePermission(supabase, userId, data.workspaceId, "workspace.delete");
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: ws } = await supabaseAdmin.from("workspaces").select("is_personal, name").eq("id", data.workspaceId).single();
    if (ws?.is_personal) throw new Error("The personal vault cannot be deleted");
    const { error } = await supabaseAdmin
      .from("workspaces")
      .update({ deleted_at: new Date().toISOString() })
      .eq("id", data.workspaceId);
    if (error) throw new Error("Failed to delete workspace");
    await audit({ userId, workspaceId: data.workspaceId, action: "workspace.deleted", targetType: "workspace", targetId: data.workspaceId, targetLabel: ws?.name ?? null });
    return { ok: true };
  });

export const listSecrets = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({ workspaceId: z.string().uuid(), trashed: z.boolean().optional() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await requireWorkspacePermission(supabase, userId, data.workspaceId, "secret.read");
    const cols =
      "id, workspace_id, type, name, username, url, description, tags, favorite, expires_at, notify_before_days, updated_at";
    if (data.trashed) {
      // RLS hides soft-deleted rows from the user client; the trash view is
      // permission-gated above and reads through the service role instead.
      const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
      const { data: rows, error } = await supabaseAdmin
        .from("secrets")
        .select(cols)
        .eq("workspace_id", data.workspaceId)
        .not("deleted_at", "is", null)
        .order("updated_at", { ascending: false });
      if (error) throw new Error("Failed to load secrets");
      return (rows ?? []).map((r) => mapSecret(r as Record<string, unknown>));
    }
    const { data: rows, error } = await supabase
      .from("secrets")
      .select(cols)
      .eq("workspace_id", data.workspaceId)
      .is("deleted_at", null)
      .order("updated_at", { ascending: false });
    if (error) throw new Error("Failed to load secrets");
    return (rows ?? []).map((r) => mapSecret(r as Record<string, unknown>));
  });

export const searchSecrets = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({
      query: z.string().max(120).optional(),
      favoritesOnly: z.boolean().optional(),
      recentOnly: z.boolean().optional(),
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { supabase } = context;
    const select =
      "id, workspace_id, type, name, username, url, description, tags, favorite, expires_at, notify_before_days, updated_at, workspaces(name)";
    let query = supabase.from("secrets").select(select).is("deleted_at", null);
    if (data.favoritesOnly) query = query.eq("favorite", true);
    query = query.order("updated_at", { ascending: false }).limit(data.recentOnly ? 10 : 100);

    const q = sanitizeQuery(data.query ?? "");
    const results = new Map<string, SecretListItem>();
    if (q) {
      const pattern = `%${q}%`;
      const [{ data: textRows, error }, { data: tagRows }] = await Promise.all([
        query.or(`name.ilike.${pattern},username.ilike.${pattern},url.ilike.${pattern},description.ilike.${pattern}`),
        supabase.from("secrets").select(select).is("deleted_at", null).contains("tags", [q]).limit(50),
      ]);
      if (error) throw new Error("Search failed");
      for (const r of [...(textRows ?? []), ...(tagRows ?? [])]) {
        const row = r as Record<string, unknown>;
        const ws = row["workspaces"] as { name: string } | null;
        results.set(row["id"] as string, mapSecret(row, ws?.name));
      }
    } else {
      const { data: rows, error } = await query;
      if (error) throw new Error("Search failed");
      for (const r of rows ?? []) {
        const row = r as Record<string, unknown>;
        const ws = row["workspaces"] as { name: string } | null;
        results.set(row["id"] as string, mapSecret(row, ws?.name));
      }
    }
    return Array.from(results.values());
  });

export const getSecret = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => z.object({ secretId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    // RLS on secrets enforces membership; the explicit permission check is
    // the primary gate and also blocks viewers without secret.read.
    const { data: row, error } = await supabase
      .from("secrets")
      .select("id, workspace_id, type, name, username, url, description, tags, favorite, expires_at, notify_before_days, created_at, updated_at, created_by, updated_by")
      .eq("id", data.secretId)
      .is("deleted_at", null)
      .maybeSingle();
    if (error) throw new Error("Failed to load secret");
    if (!row) throw new Error("Not found");
    await requireWorkspacePermission(supabase, userId, row.workspace_id, "secret.read");

    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: fields, error: fieldsError } = await supabaseAdmin
      .from("secret_fields")
      .select("id, label, field_type, is_sensitive, position")
      .eq("secret_id", row.id)
      .order("position", { ascending: true });
    if (fieldsError) throw new Error("Failed to load secret fields");

    const detail: SecretDetail = {
      ...mapSecret(row as Record<string, unknown>),
      createdAt: row.created_at,
      fields: (fields ?? []).map((f) => ({
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
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({
      secretId: z.string().uuid(),
      action: z.enum(["reveal", "copy"]),
      fieldId: z.string().uuid().optional(),
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: secret } = await supabaseAdmin
      .from("secrets")
      .select("id, workspace_id, name")
      .eq("id", data.secretId)
      .is("deleted_at", null)
      .maybeSingle();
    if (!secret) throw new Error("Not found");
    await requireWorkspacePermission(
      supabase,
      userId,
      secret.workspace_id,
      data.action === "copy" ? "secret.copy" : "secret.reveal",
    );

    const dek = await getOrCreateDek(secret.workspace_id);
    let fieldsQuery = supabaseAdmin
      .from("secret_fields")
      .select("id, label, field_type, is_sensitive, ciphertext, position")
      .eq("secret_id", secret.id)
      .order("position", { ascending: true });
    if (data.fieldId) fieldsQuery = fieldsQuery.eq("id", data.fieldId);
    const { data: fields, error } = await fieldsQuery;
    if (error) throw new Error("Failed to read secret");

    const revealed: RevealedField[] = [];
    for (const f of fields ?? []) {
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
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => secretInput.parse(input))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await requireWorkspacePermission(supabase, userId, data.workspaceId, "secret.create");
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");

    const { data: row, error } = await supabaseAdmin
      .from("secrets")
      .insert({
        workspace_id: data.workspaceId,
        type: data.type,
        name: data.name,
        username: data.username || null,
        url: data.url || null,
        description: data.description || null,
        tags: data.tags ?? [],
        expires_at: data.expiresAt || null,
        notify_before_days: data.notifyBeforeDays ?? null,
        created_by: userId,
        updated_by: userId,
      })
      .select("id")
      .single();
    if (error || !row) throw new Error("Failed to create secret");

    const dek = await getOrCreateDek(data.workspaceId);
    const fieldRows = [];
    for (let i = 0; i < data.fields.length; i++) {
      const f = data.fields[i]!;
      fieldRows.push({
        secret_id: row.id,
        label: f.label,
        field_type: f.fieldType,
        is_sensitive: f.isSensitive,
        ciphertext: await encryptField(dek, f.value),
        position: i,
      });
    }
    if (fieldRows.length > 0) {
      const { error: fieldsError } = await supabaseAdmin.from("secret_fields").insert(fieldRows);
      if (fieldsError) throw new Error("Failed to store secret fields");
    }

    await supabaseAdmin.from("secret_versions").insert({
      secret_id: row.id,
      version: 1,
      action: "created",
      changed_by: userId,
      changed_fields: [],
    });
    await audit({ userId, workspaceId: data.workspaceId, action: "secret.created", targetType: "secret", targetId: row.id, targetLabel: data.name });
    return { id: row.id };
  });

export const updateSecret = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({ secretId: z.string().uuid() }).extend(secretInput.omit({ workspaceId: true }).shape).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: existing } = await supabaseAdmin
      .from("secrets")
      .select("id, workspace_id, name")
      .eq("id", data.secretId)
      .is("deleted_at", null)
      .maybeSingle();
    if (!existing) throw new Error("Not found");
    await requireWorkspacePermission(supabase, userId, existing.workspace_id, "secret.update");

    const { error } = await supabaseAdmin
      .from("secrets")
      .update({
        type: data.type,
        name: data.name,
        username: data.username || null,
        url: data.url || null,
        description: data.description || null,
        tags: data.tags ?? [],
        expires_at: data.expiresAt || null,
        notify_before_days: data.notifyBeforeDays ?? null,
        updated_by: userId,
      })
      .eq("id", data.secretId);
    if (error) throw new Error("Failed to update secret");

    const dek = await getOrCreateDek(existing.workspace_id);
    await supabaseAdmin.from("secret_fields").delete().eq("secret_id", data.secretId);
    const fieldRows = [];
    for (let i = 0; i < data.fields.length; i++) {
      const f = data.fields[i]!;
      fieldRows.push({
        secret_id: data.secretId,
        label: f.label,
        field_type: f.fieldType,
        is_sensitive: f.isSensitive,
        ciphertext: await encryptField(dek, f.value),
        position: i,
      });
    }
    if (fieldRows.length > 0) {
      const { error: fieldsError } = await supabaseAdmin.from("secret_fields").insert(fieldRows);
      if (fieldsError) throw new Error("Failed to store secret fields");
    }

    const { data: lastVersion } = await supabaseAdmin
      .from("secret_versions")
      .select("version")
      .eq("secret_id", data.secretId)
      .order("version", { ascending: false })
      .limit(1)
      .maybeSingle();
    await supabaseAdmin.from("secret_versions").insert({
      secret_id: data.secretId,
      version: (lastVersion?.version ?? 0) + 1,
      action: "updated",
      changed_by: userId,
      changed_fields: ["metadata", ...data.fields.map((f) => f.label)],
    });
    await audit({ userId, workspaceId: existing.workspace_id, action: "secret.updated", targetType: "secret", targetId: data.secretId, targetLabel: data.name });
    return { ok: true };
  });

export const deleteSecret = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({ secretId: z.string().uuid(), mode: z.enum(["trash", "restore", "purge"]).default("trash") }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: existing } = await supabaseAdmin
      .from("secrets")
      .select("id, workspace_id, name, deleted_at")
      .eq("id", data.secretId)
      .maybeSingle();
    if (!existing) throw new Error("Not found");
    await requireWorkspacePermission(supabase, userId, existing.workspace_id, "secret.delete");

    if (data.mode === "restore") {
      await supabaseAdmin.from("secrets").update({ deleted_at: null }).eq("id", data.secretId);
      await audit({ userId, workspaceId: existing.workspace_id, action: "secret.restored", targetType: "secret", targetId: existing.id, targetLabel: existing.name });
      return { ok: true };
    }
    if (data.mode === "purge") {
      await supabaseAdmin.from("secrets").delete().eq("id", data.secretId);
      await audit({ userId, workspaceId: existing.workspace_id, action: "secret.purged", targetType: "secret", targetId: existing.id, targetLabel: existing.name });
      return { ok: true };
    }
    await supabaseAdmin.from("secrets").update({ deleted_at: new Date().toISOString(), updated_by: userId }).eq("id", data.secretId);
    await audit({ userId, workspaceId: existing.workspace_id, action: "secret.deleted", targetType: "secret", targetId: existing.id, targetLabel: existing.name });
    return { ok: true };
  });

export const toggleFavorite = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({ secretId: z.string().uuid(), favorite: z.boolean() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: existing } = await supabaseAdmin
      .from("secrets")
      .select("id, workspace_id")
      .eq("id", data.secretId)
      .is("deleted_at", null)
      .maybeSingle();
    if (!existing) throw new Error("Not found");
    await requireWorkspacePermission(supabase, userId, existing.workspace_id, "secret.read");
    await supabaseAdmin.from("secrets").update({ favorite: data.favorite }).eq("id", data.secretId);
    return { ok: true };
  });

export const getSecretVersions = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => z.object({ secretId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: secret } = await supabaseAdmin
      .from("secrets")
      .select("id, workspace_id")
      .eq("id", data.secretId)
      .maybeSingle();
    if (!secret) throw new Error("Not found");
    await requireWorkspacePermission(supabase, userId, secret.workspace_id, "secret.read");
    const { data: versions, error } = await supabaseAdmin
      .from("secret_versions")
      .select("id, version, action, changed_fields, changed_at, changed_by")
      .eq("secret_id", data.secretId)
      .order("version", { ascending: false })
      .limit(50);
    if (error) throw new Error("Failed to load history");
    const userIds = Array.from(new Set((versions ?? []).map((v) => v.changed_by).filter(Boolean))) as string[];
    const { data: profiles } = userIds.length
      ? await supabaseAdmin.from("profiles").select("id, email").in("id", userIds)
      : { data: [] };
    const emailById = new Map((profiles ?? []).map((p) => [p.id, p.email]));
    const out: SecretVersionDto[] = (versions ?? []).map((v) => ({
      id: v.id,
      version: v.version,
      action: v.action,
      changedByEmail: v.changed_by ? (emailById.get(v.changed_by) ?? null) : null,
      changedFields: v.changed_fields ?? [],
      changedAt: v.changed_at,
    }));
    return out;
  });
