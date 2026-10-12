import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "./auth-middleware";
import { getDb, iso } from "./db.server";
import { requireWorkspacePermission } from "./vault.server";
import { audit } from "./audit.server";
import { roleAtLeast, type WorkspaceRole } from "./permissions";
import type { MemberDto } from "./types";

const workspaceRoleEnum = z.enum(["OWNER", "ADMIN", "EDITOR", "VIEWER"]);

async function oidcManagesPermissions(): Promise<boolean> {
  const rows = await getDb()<{ permission_mode: string }[]>`
    SELECT permission_mode FROM oidc_providers WHERE enabled = true LIMIT 5
  `;
  return rows.some((p) => p.permission_mode !== "local");
}

function assertCanAssign(actorRole: WorkspaceRole, role: WorkspaceRole): void {
  if (!roleAtLeast(actorRole, role)) {
    throw new Error("Vous ne pouvez pas attribuer un rôle supérieur au vôtre");
  }
}

function assertCanManage(actorRole: WorkspaceRole, targetRole: WorkspaceRole): void {
  if (!roleAtLeast(actorRole, targetRole)) {
    throw new Error("Vous ne pouvez pas modifier un membre dont le rôle est supérieur au vôtre");
  }
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
    const actorRole = await requireWorkspacePermission(userId, data.workspaceId, "member.invite");
    assertCanAssign(actorRole, data.role);
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

    // Un membre existant n'est jamais écrasé ici : son rôle se change via
    // updateMemberRole, qui applique les garde-fous de hiérarchie.
    const inserted = await sql<{ id: string }[]>`
      INSERT INTO workspace_members (workspace_id, user_id, role, managed_by_oidc)
      VALUES (${data.workspaceId}, ${profile.id}, ${data.role}, false)
      ON CONFLICT (workspace_id, user_id) DO NOTHING
      RETURNING id
    `;
    if (!inserted[0]) throw new Error("Cette personne est déjà membre du coffre");
    await audit({
      userId,
      workspaceId: data.workspaceId,
      action: "member.added",
      targetType: "member",
      targetId: profile.id,
      targetLabel: `${profile.email ?? ""} (${data.role})`,
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
    const actorRole = await requireWorkspacePermission(userId, data.workspaceId, "member.update");
    assertCanAssign(actorRole, data.role);
    if (await oidcManagesPermissions()) {
      throw new Error("Memberships are managed by the identity provider");
    }
    await getDb().begin(async (tx) => {
      // Verrouille les adhésions du coffre : le décompte des propriétaires
      // reste exact face à des modifications simultanées.
      const members = await tx<{ user_id: string; role: WorkspaceRole; managed_by_oidc: boolean }[]>`
        SELECT user_id, role, managed_by_oidc FROM workspace_members
        WHERE workspace_id = ${data.workspaceId}
        FOR UPDATE
      `;
      const target = members.find((m) => m.user_id === data.targetUserId);
      if (!target) throw new Error("Member not found");
      if (target.managed_by_oidc) throw new Error("This membership is managed by the identity provider");
      assertCanManage(actorRole, target.role);
      if (
        target.role === "OWNER" &&
        data.role !== "OWNER" &&
        members.filter((m) => m.role === "OWNER").length <= 1
      ) {
        throw new Error("A workspace must keep at least one owner");
      }
      await tx`
        UPDATE workspace_members SET role = ${data.role}
        WHERE workspace_id = ${data.workspaceId} AND user_id = ${data.targetUserId}
      `;
    });
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
    const actorRole = await requireWorkspacePermission(userId, data.workspaceId, "member.delete");
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
    await sql.begin(async (tx) => {
      const members = await tx<{ user_id: string; role: WorkspaceRole }[]>`
        SELECT user_id, role FROM workspace_members
        WHERE workspace_id = ${data.workspaceId}
        FOR UPDATE
      `;
      const target = members.find((m) => m.user_id === data.targetUserId);
      if (!target) throw new Error("Member not found");
      assertCanManage(actorRole, target.role);
      if (target.role === "OWNER" && members.filter((m) => m.role === "OWNER").length <= 1) {
        throw new Error("A workspace must keep at least one owner");
      }
      await tx`
        DELETE FROM workspace_members
        WHERE workspace_id = ${data.workspaceId} AND user_id = ${data.targetUserId}
      `;
    });
    await audit({
      userId,
      workspaceId: data.workspaceId,
      action: "member.removed",
      targetType: "member",
      targetId: data.targetUserId,
    });
    return { ok: true };
  });
