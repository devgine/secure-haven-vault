import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "./auth-middleware";
import { getDb, iso, isoOrNull } from "./db.server";
import { requireSuperAdmin } from "./vault.server";
import { audit, type AuditAction } from "./audit.server";
import type {
  AdminSecretEntry,
  AdminWorkspaceDetail,
  AdminWorkspaceMember,
  AuditLogDto,
  SessionDto,
  UserAdminDto,
  WorkspaceAdminDto,
} from "./types";

// ── Utilisateurs ────────────────────────────────────────────────────────────

export const listUsersAdmin = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    await requireSuperAdmin(context.userId);
    const sql = getDb();
    const users = await sql<{ id: string; email: string | null }[]>`
      SELECT id, email FROM users ORDER BY created_at ASC
    `;
    const roles = await sql<{ user_id: string; role: string }[]>`SELECT user_id, role FROM user_roles`;
    const profiles = await sql<{ id: string; display_name: string | null }[]>`
      SELECT id, display_name FROM profiles
    `;
    return users.map((u) => ({
      id: u.id,
      email: u.email,
      displayName: profiles.find((p) => p.id === u.id)?.display_name ?? null,
      isSuperAdmin: roles.some((r) => r.user_id === u.id && r.role === "SUPER_ADMIN"),
    }));
  });

export const getUserDetailAdmin = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) => z.object({ userId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    const sql = getDb();
    const users = await sql<{ id: string; email: string | null; created_at: Date | string; last_login_at: Date | string | null }[]>`
      SELECT id, email, created_at, last_login_at FROM users WHERE id = ${data.userId}
    `;
    const u = users[0];
    if (!u) throw new Error("Utilisateur introuvable");
    const roles = await sql<{ role: string }[]>`SELECT role FROM user_roles WHERE user_id = ${data.userId}`;
    const profiles = await sql<{ display_name: string | null }[]>`
      SELECT display_name FROM profiles WHERE id = ${data.userId}
    `;
    return {
      id: u.id,
      email: u.email,
      displayName: profiles[0]?.display_name ?? null,
      createdAt: iso(u.created_at),
      lastSignInAt: isoOrNull(u.last_login_at),
      isSuperAdmin: roles.some((r) => r.role === "SUPER_ADMIN"),
    };
  });

export const createUserAdmin = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({
      email: z.string().email().max(320),
      password: z.string().min(8).max(128),
      displayName: z.string().min(1).max(120).optional(),
      superAdmin: z.boolean().optional(),
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    const { createLocalUser } = await import("./session.server");
    const user = await createLocalUser(data.email, data.password, data.displayName);
    if (data.superAdmin) {
      await getDb()`
        INSERT INTO user_roles (user_id, role) VALUES (${user.id}, 'SUPER_ADMIN')
        ON CONFLICT (user_id, role) DO NOTHING
      `;
    }
    await audit({
      userId: context.userId,
      actorEmail: context.email,
      action: "admin.user_created" as AuditAction,
      targetType: "user",
      targetId: user.id,
      targetLabel: data.email,
    });
    return { id: user.id };
  });

export const setSuperAdminAdmin = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({ userId: z.string().uuid(), enabled: z.boolean() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    if (!data.enabled && data.userId === context.userId) {
      throw new Error("Vous ne pouvez pas retirer votre propre rôle SUPER_ADMIN");
    }
    const sql = getDb();
    if (data.enabled) {
      await sql`
        INSERT INTO user_roles (user_id, role) VALUES (${data.userId}, 'SUPER_ADMIN')
        ON CONFLICT (user_id, role) DO NOTHING
      `;
    } else {
      await sql`DELETE FROM user_roles WHERE user_id = ${data.userId} AND role = 'SUPER_ADMIN'`;
    }
    await audit({
      userId: context.userId,
      actorEmail: context.email,
      action: "admin.user_role_changed" as AuditAction,
      targetType: "user",
      targetId: data.userId,
      targetLabel: data.enabled ? "SUPER_ADMIN accordé" : "SUPER_ADMIN retiré",
    });
    return { ok: true };
  });

export const resetUserPasswordAdmin = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({ userId: z.string().uuid(), password: z.string().min(8).max(128) }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    const { hashPassword } = await import("./session.server");
    const hash = await hashPassword(data.password);
    const sql = getDb();
    await sql`UPDATE users SET password_hash = ${hash} WHERE id = ${data.userId}`;
    await sql`DELETE FROM sessions WHERE user_id = ${data.userId}`;
    await audit({
      userId: context.userId,
      actorEmail: context.email,
      action: "admin.password_reset" as AuditAction,
      targetType: "user",
      targetId: data.userId,
    });
    return { ok: true };
  });

export const deleteUserAdmin = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) => z.object({ userId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    if (data.userId === context.userId) {
      throw new Error("Vous ne pouvez pas supprimer votre propre compte");
    }
    const sql = getDb();
    const owned = await sql<{ count: string }[]>`
      SELECT count(*)::text AS count FROM workspaces
      WHERE owner_id = ${data.userId} AND deleted_at IS NULL
    `;
    if (Number(owned[0]?.count ?? 0) > 0) {
      throw new Error("Cet utilisateur possède encore des coffres — supprimez-les d'abord");
    }
    const target = await sql<{ email: string | null }[]>`SELECT email FROM users WHERE id = ${data.userId}`;
    await sql`DELETE FROM users WHERE id = ${data.userId}`;
    await audit({
      userId: context.userId,
      actorEmail: context.email,
      action: "admin.user_deleted" as AuditAction,
      targetType: "user",
      targetId: data.userId,
      targetLabel: target[0]?.email ?? null,
    });
    return { ok: true };
  });

// ── Coffres (vue administration) ────────────────────────────────────────────

export const listWorkspacesAdmin = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    await requireSuperAdmin(context.userId);
    const sql = getDb();
    const workspaces = await sql<
      {
        id: string;
        name: string;
        description: string | null;
        is_personal: boolean;
        disabled: boolean;
        allow_viewer_reveal: boolean;
        created_at: Date | string;
        owner_id: string;
      }[]
    >`
      SELECT id, name, description, is_personal, disabled, allow_viewer_reveal, created_at, owner_id
      FROM workspaces
      WHERE deleted_at IS NULL AND is_personal = false
      ORDER BY created_at DESC
    `;
    const owners = await sql<{ id: string; email: string | null }[]>`SELECT id, email FROM users`;
    const counts = await sql<{ workspace_id: string; member_count: string; secret_count: string }[]>`
      SELECT w.id AS workspace_id,
             (SELECT count(*) FROM workspace_members m WHERE m.workspace_id = w.id)::text AS member_count,
             (SELECT count(*) FROM secrets s WHERE s.workspace_id = w.id AND s.deleted_at IS NULL)::text AS secret_count
      FROM workspaces w
      WHERE w.deleted_at IS NULL AND w.is_personal = false
    `;
    const out: WorkspaceAdminDto[] = workspaces.map((w) => {
      const c = counts.find((x) => x.workspace_id === w.id);
      return {
        id: w.id,
        name: w.name,
        description: w.description,
        isPersonal: false,
        disabled: w.disabled,
        allowViewerReveal: w.allow_viewer_reveal,
        createdAt: iso(w.created_at),
        ownerEmail: owners.find((o) => o.id === w.owner_id)?.email ?? null,
        memberCount: Number(c?.member_count ?? 0),
        secretCount: Number(c?.secret_count ?? 0),
      };
    });
    return out;
  });

export const createWorkspaceAdmin = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({
      name: z.string().min(1).max(120),
      description: z.string().max(500).optional(),
      ownerId: z.string().uuid().optional(),
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    const ownerId = data.ownerId ?? context.userId;
    const sql = getDb();
    const rows = await sql<{ id: string }[]>`
      INSERT INTO workspaces (name, description, owner_id, is_personal)
      VALUES (${data.name.trim()}, ${data.description?.trim() || null}, ${ownerId}, false)
      RETURNING id
    `;
    const id = rows[0]!.id;
    await sql`
      INSERT INTO workspace_members (workspace_id, user_id, role)
      VALUES (${id}, ${ownerId}, 'OWNER')
      ON CONFLICT DO NOTHING
    `;
    await audit({
      userId: context.userId,
      actorEmail: context.email,
      action: "workspace.created",
      workspaceId: id,
      targetType: "workspace",
      targetId: id,
      targetLabel: data.name,
    });
    return { id };
  });

export const setWorkspaceDisabledAdmin = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({ workspaceId: z.string().uuid(), disabled: z.boolean() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    const sql = getDb();
    const rows = await sql<{ name: string; is_personal: boolean }[]>`
      UPDATE workspaces SET disabled = ${data.disabled}
      WHERE id = ${data.workspaceId} AND deleted_at IS NULL
      RETURNING name, is_personal
    `;
    const ws = rows[0];
    if (!ws) throw new Error("Coffre introuvable");
    if (ws.is_personal) throw new Error("Un coffre personnel ne peut pas être désactivé");
    await audit({
      userId: context.userId,
      actorEmail: context.email,
      action: data.disabled ? "workspace.disabled" : "workspace.enabled",
      workspaceId: data.workspaceId,
      targetType: "workspace",
      targetId: data.workspaceId,
      targetLabel: ws.name,
    });
    return { ok: true };
  });

export const deleteWorkspaceAdmin = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) => z.object({ workspaceId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    const sql = getDb();
    const rows = await sql<{ name: string; is_personal: boolean }[]>`
      UPDATE workspaces SET deleted_at = now()
      WHERE id = ${data.workspaceId} AND deleted_at IS NULL
      RETURNING name, is_personal
    `;
    const ws = rows[0];
    if (!ws) throw new Error("Coffre introuvable");
    if (ws.is_personal) throw new Error("Un coffre personnel ne peut pas être supprimé depuis l'administration");
    await sql`UPDATE secrets SET deleted_at = now() WHERE workspace_id = ${data.workspaceId} AND deleted_at IS NULL`;
    await audit({
      userId: context.userId,
      actorEmail: context.email,
      action: "workspace.deleted",
      workspaceId: data.workspaceId,
      targetType: "workspace",
      targetId: data.workspaceId,
      targetLabel: ws.name,
    });
    return { ok: true };
  });

export const getWorkspaceDetailAdmin = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) => z.object({ workspaceId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    const sql = getDb();
    const rows = await sql<
      {
        id: string;
        name: string;
        description: string | null;
        is_personal: boolean;
        disabled: boolean;
        allow_viewer_reveal: boolean;
        created_at: Date | string;
        owner_id: string;
        owner_email: string | null;
        member_count: string;
        secret_count: string;
      }[]
    >`
      SELECT w.id, w.name, w.description, w.is_personal, w.disabled, w.allow_viewer_reveal,
             w.created_at, w.owner_id, u.email AS owner_email,
             (SELECT count(*) FROM workspace_members m WHERE m.workspace_id = w.id)::text AS member_count,
             (SELECT count(*) FROM secrets s WHERE s.workspace_id = w.id AND s.deleted_at IS NULL)::text AS secret_count
      FROM workspaces w
      LEFT JOIN users u ON u.id = w.owner_id
      WHERE w.id = ${data.workspaceId} AND w.deleted_at IS NULL
    `;
    const w = rows[0];
    if (!w) throw new Error("Coffre introuvable");
    if (w.is_personal) throw new Error("Les coffres personnels ne sont pas administrables ici");

    const members = await sql<
      {
        user_id: string;
        role: AdminWorkspaceMember["role"];
        managed_by_oidc: boolean;
        created_at: Date | string;
        email: string | null;
        display_name: string | null;
      }[]
    >`
      SELECT m.user_id, m.role, m.managed_by_oidc, m.created_at, p.email, p.display_name
      FROM workspace_members m
      LEFT JOIN profiles p ON p.id = m.user_id
      WHERE m.workspace_id = ${data.workspaceId}
      ORDER BY m.created_at ASC
    `;
    const memberDtos: AdminWorkspaceMember[] = members.map((m) => ({
      userId: m.user_id,
      email: m.email,
      displayName: m.display_name,
      role: m.role,
      managedByOidc: m.managed_by_oidc,
      createdAt: iso(m.created_at),
    }));

    const secrets = await sql<
      { id: string; name: string; type: AdminSecretEntry["type"]; updated_at: Date | string }[]
    >`
      SELECT id, name, type, updated_at FROM secrets
      WHERE workspace_id = ${data.workspaceId} AND deleted_at IS NULL
      ORDER BY updated_at DESC LIMIT 200
    `;
    const secretEntries: AdminSecretEntry[] = secrets.map((s) => ({
      id: s.id,
      name: s.name,
      type: s.type,
      updatedAt: iso(s.updated_at),
    }));

    const detail: AdminWorkspaceDetail = {
      id: w.id,
      name: w.name,
      description: w.description,
      disabled: w.disabled,
      allowViewerReveal: w.allow_viewer_reveal,
      createdAt: iso(w.created_at),
      ownerEmail: w.owner_email,
      members: memberDtos,
      secrets: secretEntries,
    };
    return detail;
  });

export const addMemberAdmin = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({
      workspaceId: z.string().uuid(),
      email: z.string().email().max(320),
      role: z.enum(["OWNER", "ADMIN", "EDITOR", "VIEWER"]),
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    const sql = getDb();
    const profiles = await sql<{ id: string }[]>`
      SELECT id FROM profiles WHERE lower(email) = lower(${data.email.trim()})
    `;
    const profile = profiles[0];
    if (!profile) throw new Error("Aucun compte n'existe pour cette adresse");
    await sql`
      INSERT INTO workspace_members (workspace_id, user_id, role)
      VALUES (${data.workspaceId}, ${profile.id}, ${data.role})
      ON CONFLICT (workspace_id, user_id) DO UPDATE SET role = EXCLUDED.role
    `;
    await audit({
      userId: context.userId,
      actorEmail: context.email,
      action: "member.added",
      workspaceId: data.workspaceId,
      targetType: "member",
      targetId: profile.id,
      targetLabel: data.email,
    });
    return { ok: true };
  });

export const updateMemberRoleAdmin = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({
      workspaceId: z.string().uuid(),
      targetUserId: z.string().uuid(),
      role: z.enum(["OWNER", "ADMIN", "EDITOR", "VIEWER"]),
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    await getDb()`
      UPDATE workspace_members SET role = ${data.role}
      WHERE workspace_id = ${data.workspaceId} AND user_id = ${data.targetUserId}
    `;
    await audit({
      userId: context.userId,
      actorEmail: context.email,
      action: "member.role_updated",
      workspaceId: data.workspaceId,
      targetType: "member",
      targetId: data.targetUserId,
      targetLabel: data.role,
    });
    return { ok: true };
  });

export const removeMemberAdmin = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({ workspaceId: z.string().uuid(), targetUserId: z.string().uuid() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    const sql = getDb();
    const owners = await sql<{ owner_id: string }[]>`
      SELECT owner_id FROM workspaces WHERE id = ${data.workspaceId}
    `;
    if (owners[0]?.owner_id === data.targetUserId) {
      throw new Error("Le propriétaire du coffre ne peut pas être retiré");
    }
    await sql`
      DELETE FROM workspace_members
      WHERE workspace_id = ${data.workspaceId} AND user_id = ${data.targetUserId}
    `;
    await audit({
      userId: context.userId,
      actorEmail: context.email,
      action: "member.removed",
      workspaceId: data.workspaceId,
      targetType: "member",
      targetId: data.targetUserId,
    });
    return { ok: true };
  });

// ── Journal d'audit global ──────────────────────────────────────────────────

export const listAuditLogsAdmin = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({
      limit: z.number().int().min(1).max(500).optional(),
      workspaceId: z.string().uuid().optional(),
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    const sql = getDb();
    const limit = data.limit ?? 200;
    const rows = data.workspaceId
      ? await sql<
          {
            id: string;
            user_id: string | null;
            user_email: string | null;
            workspace_id: string | null;
            action: string;
            target_type: string | null;
            target_id: string | null;
            target_label: string | null;
            result: string;
            ip_address: string | null;
            user_agent: string | null;
            metadata: unknown;
            created_at: Date | string;
            workspace_name: string | null;
          }[]
        >`
          SELECT a.id, a.user_id, a.user_email, a.workspace_id, a.action, a.target_type,
                 a.target_id, a.target_label, a.result, a.ip_address, a.user_agent,
                 a.metadata, a.created_at, w.name AS workspace_name
          FROM audit_logs a
          LEFT JOIN workspaces w ON w.id = a.workspace_id
          WHERE a.workspace_id = ${data.workspaceId}
          ORDER BY a.created_at DESC LIMIT ${limit}
        `
      : await sql<
          {
            id: string;
            user_id: string | null;
            user_email: string | null;
            workspace_id: string | null;
            action: string;
            target_type: string | null;
            target_id: string | null;
            target_label: string | null;
            result: string;
            ip_address: string | null;
            user_agent: string | null;
            metadata: unknown;
            created_at: Date | string;
            workspace_name: string | null;
          }[]
        >`
          SELECT a.id, a.user_id, a.user_email, a.workspace_id, a.action, a.target_type,
                 a.target_id, a.target_label, a.result, a.ip_address, a.user_agent,
                 a.metadata, a.created_at, w.name AS workspace_name
          FROM audit_logs a
          LEFT JOIN workspaces w ON w.id = a.workspace_id
          ORDER BY a.created_at DESC LIMIT ${limit}
        `;
    const out: AuditLogDto[] = rows.map((r) => ({
      id: r.id,
      userId: r.user_id,
      userEmail: r.user_email,
      workspaceId: r.workspace_id,
      workspaceName: r.workspace_name,
      action: r.action as AuditLogDto["action"],
      targetType: r.target_type,
      targetId: r.target_id,
      targetLabel: r.target_label,
      result: r.result as AuditLogDto["result"],
      ipAddress: r.ip_address,
      userAgent: r.user_agent,
      metadata: (r.metadata ?? {}) as Record<string, unknown>,
      createdAt: iso(r.created_at),
    }));
    return out;
  });

// ── Sessions actives ────────────────────────────────────────────────────────

export const listSessionsAdmin = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) => z.object({ userId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    const rows = await getDb()<
      {
        id: string;
        created_at: Date | string;
        expires_at: Date | string;
        ip_address: string | null;
        user_agent: string | null;
      }[]
    >`
      SELECT id, created_at, expires_at, ip_address, user_agent
      FROM sessions
      WHERE user_id = ${data.userId} AND expires_at > now()
      ORDER BY created_at DESC
    `;
    const out: SessionDto[] = rows.map((s) => ({
      id: s.id,
      createdAt: iso(s.created_at),
      expiresAt: iso(s.expires_at),
      ipAddress: s.ip_address,
      userAgent: s.user_agent,
    }));
    return out;
  });

export const revokeUserSessionsAdmin = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) => z.object({ userId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    await getDb()`DELETE FROM sessions WHERE user_id = ${data.userId}`;
    await audit({
      userId: context.userId,
      actorEmail: context.email,
      action: "admin.sessions_revoked" as AuditAction,
      targetType: "user",
      targetId: data.userId,
    });
    return { ok: true };
  });

// ── Paramètres plateforme ───────────────────────────────────────────────────

export const getPlatformSettingsAdmin = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    await requireSuperAdmin(context.userId);
    const rows = await getDb<{ value: boolean }[]>`
      SELECT value FROM platform_settings WHERE key = 'signup_enabled'
    `;
    return { signupEnabled: rows[0]?.value !== false };
  });

export const setSignupEnabledAdmin = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) => z.object({ enabled: z.boolean() }).parse(input))
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    await getDb()`
      INSERT INTO platform_settings (key, value, updated_by, updated_at)
      VALUES ('signup_enabled', ${data.enabled}, ${context.userId}, now())
      ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()
    `;
    await audit({
      userId: context.userId,
      actorEmail: context.email,
      action: "admin.signup_toggled" as AuditAction,
      targetType: "platform",
      targetLabel: data.enabled ? "Inscription activée" : "Inscription désactivée",
    });
    return { ok: true };
  });
