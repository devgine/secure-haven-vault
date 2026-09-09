import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "./auth-middleware";
import { getDb, iso } from "./db.server";
import { requireWorkspacePermission } from "./vault.server";
import { audit } from "./audit.server";
import type { MemberDto } from "./types";

const workspaceRoleEnum = z.enum(["OWNER", "ADMIN", "EDITOR", "VIEWER"]);

async function oidcManagesPermissions(): Promise<boolean> {
  const rows = await getDb()<{ permission_mode: string }[]>`
    SELECT permission_mode FROM oidc_providers WHERE enabled = true LIMIT 5
  `;
  return rows.some((p) => p.permission_mode !== "local");
}

export const listMembers = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) => z.object({ workspaceId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const { userId } = context;
    await requireWorkspacePermission(userId, data.workspaceId, "member.read");
    const members = await getDb()<
      {
        user_id: string;
        role: MemberDto["role"];
        managed_by_oidc: boolean;
        created_at: Date | string;
        email: string | null;
        display_name: string | null;
      }[]
    >`
      SELECT m.user_id, m.role, m.managed_by_oidc, m.created_at,
             p.email, p.display_name
      FROM workspace_members m
      LEFT JOIN profiles p ON p.id = m.user_id
      WHERE m.workspace_id = ${data.workspaceId}
      ORDER BY m.created_at ASC
    `;
    const out: MemberDto[] = members.map((m) => ({
      userId: m.user_id,
      email: m.email,
      displayName: m.display_name,
      role: m.role,
      managedByOidc: m.managed_by_oidc,
      createdAt: iso(m.created_at),
    }));
    return out;
  });

export const addMember = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({
      workspaceId: z.string().uuid(),
      email: z.string().email().max(320),
      role: workspaceRoleEnum,
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { userId } = context;
    await requireWorkspacePermission(userId, data.workspaceId, "member.invite");
    const sql = getDb();

    const workspaces = await sql<{ is_personal: boolean; name: string }[]>`
      SELECT is_personal, name FROM workspaces WHERE id = ${data.workspaceId}
    `;
    if (workspaces[0]?.is_personal) throw new Error("Members cannot be added to a personal vault");
    if (await oidcManagesPermissions()) {
      throw new Error("Memberships are managed by the identity provider");
    }

    const profiles = await sql<{ id: string; email: string | null }[]>`
      SELECT id, email FROM profiles WHERE lower(email) = lower(${data.email.trim()})
    `;
    const profile = profiles[0];
    if (!profile) throw new Error("No account exists for this email address");

    await sql`
      INSERT INTO workspace_members (workspace_id, user_id, role, managed_by_oidc)
      VALUES (${data.workspaceId}, ${profile.id}, ${data.role}, false)
      ON CONFLICT (workspace_id, user_id)
      DO UPDATE SET role = EXCLUDED.role, managed_by_oidc = false
    `;
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
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({
      workspaceId: z.string().uuid(),
      targetUserId: z.string().uuid(),
      role: workspaceRoleEnum,
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { userId } = context;
    await requireWorkspacePermission(userId, data.workspaceId, "member.update");
    if (await oidcManagesPermissions()) {
      throw new Error("Memberships are managed by the identity provider");
    }
    const sql = getDb();
    const targets = await sql<{ role: string; managed_by_oidc: boolean }[]>`
      SELECT role, managed_by_oidc FROM workspace_members
      WHERE workspace_id = ${data.workspaceId} AND user_id = ${data.targetUserId}
    `;
    const target = targets[0];
    if (!target) throw new Error("Member not found");
    if (target.managed_by_oidc) throw new Error("This membership is managed by the identity provider");
    if (target.role === "OWNER" && data.role !== "OWNER") {
      const owners = await sql<{ count: string }[]>`
        SELECT count(*)::text AS count FROM workspace_members
        WHERE workspace_id = ${data.workspaceId} AND role = 'OWNER'
      `;
      if (Number(owners[0]?.count ?? 0) <= 1) {
        throw new Error("A workspace must keep at least one owner");
      }
    }
    await sql`
      UPDATE workspace_members SET role = ${data.role}
      WHERE workspace_id = ${data.workspaceId} AND user_id = ${data.targetUserId}
    `;
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
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({ workspaceId: z.string().uuid(), targetUserId: z.string().uuid() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { userId } = context;
    await requireWorkspacePermission(userId, data.workspaceId, "member.delete");
    if (await oidcManagesPermissions()) {
      throw new Error("Memberships are managed by the identity provider");
    }
    const sql = getDb();
    const workspaces = await sql<{ is_personal: boolean; owner_id: string }[]>`
      SELECT is_personal, owner_id FROM workspaces WHERE id = ${data.workspaceId}
    `;
    const ws = workspaces[0];
    if (ws?.is_personal) throw new Error("Members cannot be removed from a personal vault");
    if (ws?.owner_id === data.targetUserId) throw new Error("The workspace owner cannot be removed");
    await sql`
      DELETE FROM workspace_members
      WHERE workspace_id = ${data.workspaceId} AND user_id = ${data.targetUserId}
    `;
    await audit({
      userId,
      workspaceId: data.workspaceId,
      action: "member.removed",
      targetType: "member",
      targetId: data.targetUserId,
    });
    return { ok: true };
  });
