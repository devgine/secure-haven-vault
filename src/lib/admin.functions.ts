import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { requireSuperAdmin } from "./vault.server";
import { audit } from "./audit.server";
import type { AuditLogDto } from "./types";

export interface AdminUserDto {
  id: string;
  email: string | null;
  displayName: string | null;
  appRole: "SUPER_ADMIN" | "USER";
  banned: boolean;
  createdAt: string | null;
  lastSignInAt: string | null;
}

export interface AdminWorkspaceDto {
  id: string;
  name: string;
  isPersonal: boolean;
  disabled: boolean;
  ownerEmail: string | null;
  memberCount: number;
  secretCount: number;
  createdAt: string;
}

export const getAdminOverview = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    await requireSuperAdmin(supabase, userId);
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const [users, workspaces, secrets, recentLogins, failedLogins] = await Promise.all([
      supabaseAdmin.from("profiles").select("id", { count: "exact", head: true }),
      supabaseAdmin.from("workspaces").select("id", { count: "exact", head: true }).is("deleted_at", null),
      supabaseAdmin.from("secrets").select("id", { count: "exact", head: true }).is("deleted_at", null),
      supabaseAdmin.from("audit_logs").select("id", { count: "exact", head: true }).eq("action", "auth.login").gte("created_at", new Date(Date.now() - 24 * 3600 * 1000).toISOString()),
      supabaseAdmin.from("audit_logs").select("id", { count: "exact", head: true }).eq("action", "auth.login_failed").gte("created_at", new Date(Date.now() - 24 * 3600 * 1000).toISOString()),
    ]);
    return {
      userCount: users.count ?? 0,
      workspaceCount: workspaces.count ?? 0,
      secretCount: secrets.count ?? 0,
      loginsLast24h: recentLogins.count ?? 0,
      failedLoginsLast24h: failedLogins.count ?? 0,
    };
  });

export const listUsers = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    await requireSuperAdmin(supabase, userId);
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const [{ data: profiles }, { data: roles }, authList] = await Promise.all([
      supabaseAdmin.from("profiles").select("id, email, display_name, created_at"),
      supabaseAdmin.from("user_roles").select("user_id, role"),
      supabaseAdmin.auth.admin.listUsers({ perPage: 500 }),
    ]);
    const authById = new Map((authList.data?.users ?? []).map((u) => [u.id, u]));
    const superAdmins = new Set((roles ?? []).filter((r) => r.role === "SUPER_ADMIN").map((r) => r.user_id));
    const out: AdminUserDto[] = (profiles ?? []).map((p) => {
      const auth = authById.get(p.id);
      const bannedUntil = (auth as { banned_until?: string } | undefined)?.banned_until;
      const banned = bannedUntil ? new Date(bannedUntil).getTime() > Date.now() : false;
      return {
        id: p.id,
        email: p.email,
        displayName: p.display_name,
        appRole: superAdmins.has(p.id) ? "SUPER_ADMIN" : "USER",
        banned,
        createdAt: p.created_at ?? null,
        lastSignInAt: auth?.last_sign_in_at ?? null,
      };
    });
    out.sort((a, b) => (a.email ?? "").localeCompare(b.email ?? ""));
    return out;
  });

export const setUserBanned = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({ targetUserId: z.string().uuid(), banned: z.boolean() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await requireSuperAdmin(supabase, userId);
    if (data.targetUserId === userId) throw new Error("You cannot disable your own account");
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: profile } = await supabaseAdmin.from("profiles").select("email").eq("id", data.targetUserId).maybeSingle();
    const { error } = await supabaseAdmin.auth.admin.updateUserById(data.targetUserId, {
      ban_duration: data.banned ? "876000h" : "none",
    });
    if (error) throw new Error("Failed to update account status");
    await audit({
      userId,
      action: data.banned ? "users.banned" : "users.unbanned",
      targetType: "user",
      targetId: data.targetUserId,
      targetLabel: profile?.email ?? null,
    });
    return { ok: true };
  });

export const setUserAppRole = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({ targetUserId: z.string().uuid(), role: z.enum(["SUPER_ADMIN", "USER"]) }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await requireSuperAdmin(supabase, userId);
    if (data.targetUserId === userId && data.role !== "SUPER_ADMIN") {
      throw new Error("You cannot revoke your own admin role");
    }
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: profile } = await supabaseAdmin.from("profiles").select("email").eq("id", data.targetUserId).maybeSingle();
    if (data.role === "SUPER_ADMIN") {
      await supabaseAdmin
        .from("user_roles")
        .upsert({ user_id: data.targetUserId, role: "SUPER_ADMIN" }, { onConflict: "user_id,role" });
    } else {
      await supabaseAdmin.from("user_roles").delete().eq("user_id", data.targetUserId);
    }
    await audit({
      userId,
      action: "users.role_updated",
      targetType: "user",
      targetId: data.targetUserId,
      targetLabel: `${profile?.email ?? data.targetUserId} → ${data.role}`,
    });
    return { ok: true };
  });

export const deleteUserAccount = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => z.object({ targetUserId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await requireSuperAdmin(supabase, userId);
    if (data.targetUserId === userId) throw new Error("You cannot delete your own account");
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: profile } = await supabaseAdmin.from("profiles").select("email").eq("id", data.targetUserId).maybeSingle();
    const { error } = await supabaseAdmin.auth.admin.deleteUser(data.targetUserId);
    if (error) throw new Error("Failed to delete account");
    await audit({
      userId,
      action: "users.deleted",
      targetType: "user",
      targetId: data.targetUserId,
      targetLabel: profile?.email ?? null,
    });
    return { ok: true };
  });

export const listAllWorkspaces = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    await requireSuperAdmin(supabase, userId);
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: workspaces, error } = await supabaseAdmin
      .from("workspaces")
      .select("id, name, is_personal, disabled, owner_id, created_at")
      .is("deleted_at", null)
      .order("created_at", { ascending: false });
    if (error) throw new Error("Failed to load workspaces");
    const ownerIds = Array.from(new Set((workspaces ?? []).map((w) => w.owner_id)));
    const { data: owners } = ownerIds.length
      ? await supabaseAdmin.from("profiles").select("id, email").in("id", ownerIds)
      : { data: [] };
    const ownerEmail = new Map((owners ?? []).map((o) => [o.id, o.email]));

    const out: AdminWorkspaceDto[] = [];
    for (const w of workspaces ?? []) {
      const [members, secrets] = await Promise.all([
        supabaseAdmin.from("workspace_members").select("id", { count: "exact", head: true }).eq("workspace_id", w.id),
        supabaseAdmin.from("secrets").select("id", { count: "exact", head: true }).eq("workspace_id", w.id).is("deleted_at", null),
      ]);
      out.push({
        id: w.id,
        name: w.name,
        isPersonal: w.is_personal,
        disabled: w.disabled,
        ownerEmail: ownerEmail.get(w.owner_id) ?? null,
        memberCount: members.count ?? 0,
        secretCount: secrets.count ?? 0,
        createdAt: w.created_at,
      });
    }
    return out;
  });

export const setWorkspaceDisabled = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({ workspaceId: z.string().uuid(), disabled: z.boolean() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await requireSuperAdmin(supabase, userId);
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: ws } = await supabaseAdmin.from("workspaces").select("name").eq("id", data.workspaceId).maybeSingle();
    const { error } = await supabaseAdmin.from("workspaces").update({ disabled: data.disabled }).eq("id", data.workspaceId);
    if (error) throw new Error("Failed to update workspace");
    await audit({
      userId,
      workspaceId: data.workspaceId,
      action: data.disabled ? "workspaces.disabled" : "workspaces.enabled",
      targetType: "workspace",
      targetId: data.workspaceId,
      targetLabel: ws?.name ?? null,
    });
    return { ok: true };
  });

export const deleteWorkspaceAdmin = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => z.object({ workspaceId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await requireSuperAdmin(supabase, userId);
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: ws } = await supabaseAdmin.from("workspaces").select("name, is_personal").eq("id", data.workspaceId).maybeSingle();
    if (ws?.is_personal) throw new Error("Personal vaults cannot be deleted");
    const { error } = await supabaseAdmin
      .from("workspaces")
      .update({ deleted_at: new Date().toISOString() })
      .eq("id", data.workspaceId);
    if (error) throw new Error("Failed to delete workspace");
    await audit({
      userId,
      workspaceId: data.workspaceId,
      action: "workspaces.deleted",
      targetType: "workspace",
      targetId: data.workspaceId,
      targetLabel: ws?.name ?? null,
    });
    return { ok: true };
  });

export const listAuditLogs = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({
      action: z.string().max(100).optional(),
      workspaceId: z.string().uuid().optional(),
      limit: z.number().int().min(1).max(500).default(200),
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await requireSuperAdmin(supabase, userId);
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    let query = supabaseAdmin
      .from("audit_logs")
      .select("id, user_id, workspace_id, action, target_type, target_label, result, created_at")
      .order("created_at", { ascending: false })
      .limit(data.limit);
    if (data.action) query = query.eq("action", data.action);
    if (data.workspaceId) query = query.eq("workspace_id", data.workspaceId);
    const { data: rows, error } = await query;
    if (error) throw new Error("Failed to load audit logs");

    const userIds = Array.from(new Set((rows ?? []).map((r) => r.user_id).filter(Boolean))) as string[];
    const wsIds = Array.from(new Set((rows ?? []).map((r) => r.workspace_id).filter(Boolean))) as string[];
    const [{ data: profiles }, { data: workspaces }] = await Promise.all([
      userIds.length ? supabaseAdmin.from("profiles").select("id, email").in("id", userIds) : Promise.resolve({ data: [] }),
      wsIds.length ? supabaseAdmin.from("workspaces").select("id, name").in("id", wsIds) : Promise.resolve({ data: [] }),
    ]);
    const emailById = new Map((profiles ?? []).map((p) => [p.id, p.email]));
    const wsById = new Map((workspaces ?? []).map((w) => [w.id, w.name]));

    const out: AuditLogDto[] = (rows ?? []).map((r) => ({
      id: r.id,
      actorEmail: r.user_id ? (emailById.get(r.user_id) ?? null) : null,
      workspaceName: r.workspace_id ? (wsById.get(r.workspace_id) ?? null) : null,
      action: r.action,
      targetType: r.target_type,
      targetLabel: r.target_label,
      result: r.result,
      createdAt: r.created_at,
    }));
    return out;
  });
