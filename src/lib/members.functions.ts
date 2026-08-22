import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { requireWorkspacePermission } from "./vault.server";
import { audit } from "./audit.server";
import type { MemberDto } from "./types";

const workspaceRoleEnum = z.enum(["OWNER", "ADMIN", "EDITOR", "VIEWER"]);

async function oidcManagesPermissions(): Promise<boolean> {
  const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
  const { data } = await supabaseAdmin
    .from("oidc_providers")
    .select("permission_mode")
    .eq("enabled", true)
    .limit(1);
  return (data ?? []).some((p) => p.permission_mode !== "local");
}

export const listMembers = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => z.object({ workspaceId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await requireWorkspacePermission(supabase, userId, data.workspaceId, "member.read");
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: members, error } = await supabaseAdmin
      .from("workspace_members")
      .select("user_id, role, managed_by_oidc, created_at")
      .eq("workspace_id", data.workspaceId)
      .order("created_at", { ascending: true });
    if (error) throw new Error("Failed to load members");
    const ids = (members ?? []).map((m) => m.user_id);
    const { data: profiles } = ids.length
      ? await supabaseAdmin.from("profiles").select("id, email, display_name").in("id", ids)
      : { data: [] };
    const byId = new Map((profiles ?? []).map((p) => [p.id, p]));
    const out: MemberDto[] = (members ?? []).map((m) => {
      const p = byId.get(m.user_id);
      return {
        userId: m.user_id,
        email: p?.email ?? null,
        displayName: p?.display_name ?? null,
        role: m.role,
        managedByOidc: m.managed_by_oidc,
        createdAt: m.created_at,
      };
    });
    return out;
  });

export const addMember = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({
      workspaceId: z.string().uuid(),
      email: z.string().email().max(320),
      role: workspaceRoleEnum,
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await requireWorkspacePermission(supabase, userId, data.workspaceId, "member.invite");
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");

    const { data: ws } = await supabaseAdmin
      .from("workspaces")
      .select("is_personal, name")
      .eq("id", data.workspaceId)
      .single();
    if (ws?.is_personal) throw new Error("Members cannot be added to a personal vault");
    if (await oidcManagesPermissions()) {
      throw new Error("Memberships are managed by the identity provider");
    }

    const { data: profile } = await supabaseAdmin
      .from("profiles")
      .select("id, email")
      .ilike("email", data.email.trim())
      .maybeSingle();
    if (!profile) throw new Error("No account exists for this email address");

    const { error } = await supabaseAdmin.from("workspace_members").upsert(
      { workspace_id: data.workspaceId, user_id: profile.id, role: data.role, managed_by_oidc: false },
      { onConflict: "workspace_id,user_id" },
    );
    if (error) throw new Error("Failed to add member");
    await audit({
      userId,
      workspaceId: data.workspaceId,
      action: "member.added",
      targetType: "member",
      targetId: profile.id,
      targetLabel: profile.email,
    });
    return { ok: true };
  });

export const updateMemberRole = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({
      workspaceId: z.string().uuid(),
      targetUserId: z.string().uuid(),
      role: workspaceRoleEnum,
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await requireWorkspacePermission(supabase, userId, data.workspaceId, "member.update");
    if (await oidcManagesPermissions()) {
      throw new Error("Memberships are managed by the identity provider");
    }
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: target } = await supabaseAdmin
      .from("workspace_members")
      .select("role, managed_by_oidc")
      .eq("workspace_id", data.workspaceId)
      .eq("user_id", data.targetUserId)
      .maybeSingle();
    if (!target) throw new Error("Member not found");
    if (target.managed_by_oidc) throw new Error("This membership is managed by the identity provider");
    if (target.role === "OWNER" && data.role !== "OWNER") {
      const { count } = await supabaseAdmin
        .from("workspace_members")
        .select("id", { count: "exact", head: true })
        .eq("workspace_id", data.workspaceId)
        .eq("role", "OWNER");
      if ((count ?? 0) <= 1) throw new Error("A workspace must keep at least one owner");
    }
    const { error } = await supabaseAdmin
      .from("workspace_members")
      .update({ role: data.role })
      .eq("workspace_id", data.workspaceId)
      .eq("user_id", data.targetUserId);
    if (error) throw new Error("Failed to update role");
    await audit({
      userId,
      workspaceId: data.workspaceId,
      action: "member.role_updated",
      targetType: "member",
      targetId: data.targetUserId,
      targetLabel: data.role,
    });
    return { ok: true };
  });

export const removeMember = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({ workspaceId: z.string().uuid(), targetUserId: z.string().uuid() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await requireWorkspacePermission(supabase, userId, data.workspaceId, "member.delete");
    if (await oidcManagesPermissions()) {
      throw new Error("Memberships are managed by the identity provider");
    }
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: ws } = await supabaseAdmin
      .from("workspaces")
      .select("is_personal, owner_id")
      .eq("id", data.workspaceId)
      .single();
    if (ws?.is_personal) throw new Error("Members cannot be removed from a personal vault");
    if (ws?.owner_id === data.targetUserId) throw new Error("The workspace owner cannot be removed");
    const { error } = await supabaseAdmin
      .from("workspace_members")
      .delete()
      .eq("workspace_id", data.workspaceId)
      .eq("user_id", data.targetUserId);
    if (error) throw new Error("Failed to remove member");
    await audit({
      userId,
      workspaceId: data.workspaceId,
      action: "member.removed",
      targetType: "member",
      targetId: data.targetUserId,
    });
    return { ok: true };
  });
