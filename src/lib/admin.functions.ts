import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "./auth-middleware";
import { getDb, iso, isoOrNull } from "./db.server";
import { requireSuperAdmin } from "./vault.server";
import { audit } from "./audit.server";
import type { AuditLogDto } from "./types";

function toIso(v: Date | string): string {
  return v instanceof Date ? v.toISOString() : String(v);
}

// ── Vue d'ensemble ──────────────────────────────────────────────────────────

export const getAdminOverview = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    await requireSuperAdmin(context.userId);
    const sql = getDb();
    const rows = await sql<
      {
        user_count: string;
        workspace_count: string;
        secret_count: string;
        logins_24h: string;
        failed_logins_24h: string;
      }[]
    >`
      SELECT
        (SELECT count(*) FROM users)::text AS user_count,
        (SELECT count(*) FROM workspaces WHERE deleted_at IS NULL)::text AS workspace_count,
        (SELECT count(*) FROM secrets WHERE deleted_at IS NULL)::text AS secret_count,
        (SELECT count(*) FROM audit_logs WHERE action = 'auth.login' AND created_at > now() - interval '24 hours')::text AS logins_24h,
        (SELECT count(*) FROM audit_logs WHERE action = 'auth.login_failed' AND created_at > now() - interval '24 hours')::text AS failed_logins_24h
    `;
    const r = rows[0]!;
    return {
      userCount: Number(r.user_count),
      workspaceCount: Number(r.workspace_count),
      secretCount: Number(r.secret_count),
      loginsLast24h: Number(r.logins_24h),
      failedLoginsLast24h: Number(r.failed_logins_24h),
    };
  });

// ── Paramètres plateforme ───────────────────────────────────────────────────

export const getPlatformSettings = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    await requireSuperAdmin(context.userId);
    const rows = await getDb()<{ value: unknown }[]>`
      SELECT value FROM platform_settings WHERE key = 'signup_enabled'
    `;
    return { signupEnabled: rows[0]?.value !== false };
  });

export const setSignupEnabled = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) => z.object({ enabled: z.boolean() }).parse(input))
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    const sql = getDb();
    await sql`
      INSERT INTO platform_settings (key, value, updated_at)
      VALUES ('signup_enabled', ${sql.json(data.enabled)}::jsonb, now())
      ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
    `;
    await audit({
      userId: context.userId,
      actorEmail: context.userEmail,
      action: data.enabled ? "settings.signup_enabled" : "settings.signup_disabled",
      targetType: "platform",
      targetLabel: data.enabled ? "Inscription activée" : "Inscription désactivée",
    });
    return { ok: true };
  });

// ── Utilisateurs ────────────────────────────────────────────────────────────

export const listUsers = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    await requireSuperAdmin(context.userId);
    const sql = getDb();
    const users = await sql<
      {
        id: string;
        email: string | null;
        banned_until: Date | string | null;
        last_sign_in_at: Date | string | null;
        display_name: string | null;
      }[]
    >`
      SELECT u.id, u.email, u.banned_until, u.last_sign_in_at, p.display_name
      FROM users u
      LEFT JOIN profiles p ON p.id = u.id
      ORDER BY u.created_at ASC
    `;
    const roles = await sql<{ user_id: string; role: string }[]>`
      SELECT user_id, role FROM user_roles
    `;
    const now = Date.now();
    return users.map((u) => ({
      id: u.id,
      email: u.email,
      displayName: u.display_name,
      appRole: roles.some((r) => r.user_id === u.id && r.role === "SUPER_ADMIN")
        ? ("SUPER_ADMIN" as const)
        : ("USER" as const),
      banned: u.banned_until ? new Date(u.banned_until).getTime() > now : false,
      lastSignInAt: isoOrNull(u.last_sign_in_at),
    }));
  });

export const setUserAppRole = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({
      targetUserId: z.string().uuid(),
      role: z.enum(["SUPER_ADMIN", "USER"]),
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    if (data.role === "USER" && data.targetUserId === context.userId) {
      throw new Error("Vous ne pouvez pas retirer votre propre rôle SUPER_ADMIN");
    }
    const sql = getDb();
    if (data.role === "SUPER_ADMIN") {
      await sql`
        INSERT INTO user_roles (user_id, role) VALUES (${data.targetUserId}, 'SUPER_ADMIN')
        ON CONFLICT (user_id, role) DO NOTHING
      `;
    } else {
      await sql`
        DELETE FROM user_roles WHERE user_id = ${data.targetUserId} AND role = 'SUPER_ADMIN'
      `;
    }
    await audit({
      userId: context.userId,
      actorEmail: context.userEmail,
      action: "admin.user_role_changed",
      targetType: "user",
      targetId: data.targetUserId,
      targetLabel: data.role,
    });
    return { ok: true };
  });

export const setUserBanned = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({ targetUserId: z.string().uuid(), banned: z.boolean() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    if (data.banned && data.targetUserId === context.userId) {
      throw new Error("Vous ne pouvez pas désactiver votre propre compte");
    }
    const sql = getDb();
    await sql`
      UPDATE users
      SET banned_until = ${data.banned ? "2999-01-01T00:00:00Z" : null}
      WHERE id = ${data.targetUserId}
    `;
    if (data.banned) {
      await sql`DELETE FROM sessions WHERE user_id = ${data.targetUserId}`;
    }
    await audit({
      userId: context.userId,
      actorEmail: context.userEmail,
      action: data.banned ? "admin.user_banned" : "admin.user_unbanned",
      targetType: "user",
      targetId: data.targetUserId,
    });
    return { ok: true };
  });

export const deleteUserAccount = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({ targetUserId: z.string().uuid() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    if (data.targetUserId === context.userId) {
      throw new Error("Vous ne pouvez pas supprimer votre propre compte");
    }
    const sql = getDb();
    const target = await sql<{ email: string | null }[]>`
      SELECT email FROM users WHERE id = ${data.targetUserId}
    `;
    // Les coffres possédés (dont le coffre personnel) sont supprimés en cascade
    // avec le compte ; les secrets pointent ensuite sur NULL (ON DELETE SET NULL).
    await sql`DELETE FROM users WHERE id = ${data.targetUserId}`;
    await audit({
      userId: context.userId,
      actorEmail: context.userEmail,
      action: "admin.user_deleted",
      targetType: "user",
      targetId: data.targetUserId,
      targetLabel: target[0]?.email ?? null,
    });
    return { ok: true };
  });

// ── Coffres d'équipe ────────────────────────────────────────────────────────

export const listAllWorkspaces = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    await requireSuperAdmin(context.userId);
    const rows = await getDb()<
      {
        id: string;
        name: string;
        description: string | null;
        disabled: boolean;
        created_at: Date | string;
        owner_email: string | null;
        member_count: string;
        secret_count: string;
      }[]
    >`
      SELECT w.id, w.name, w.description, w.disabled, w.created_at,
             u.email AS owner_email,
             (SELECT count(*) FROM workspace_members m WHERE m.workspace_id = w.id)::text AS member_count,
             (SELECT count(*) FROM secrets s WHERE s.workspace_id = w.id AND s.deleted_at IS NULL)::text AS secret_count
      FROM workspaces w
      LEFT JOIN users u ON u.id = w.owner_id
      WHERE w.deleted_at IS NULL AND w.is_personal = false
      ORDER BY w.created_at DESC
    `;
    return rows.map((w) => ({
      id: w.id,
      name: w.name,
      description: w.description,
      isPersonal: false,
      disabled: w.disabled,
      createdAt: iso(w.created_at),
      ownerEmail: w.owner_email,
      memberCount: Number(w.member_count),
      secretCount: Number(w.secret_count),
    }));
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
      ON CONFLICT (workspace_id, user_id) DO NOTHING
    `;
    await audit({
      userId: context.userId,
      actorEmail: context.userEmail,
      action: "workspace.created",
      workspaceId: id,
      targetType: "workspace",
      targetId: id,
      targetLabel: data.name,
    });
    return { id };
  });

export const setWorkspaceDisabled = createServerFn({ method: "POST" })
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
      actorEmail: context.userEmail,
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
    if (ws.is_personal) {
      throw new Error("Un coffre personnel ne peut pas être supprimé depuis l'administration");
    }
    await sql`
      UPDATE secrets SET deleted_at = now()
      WHERE workspace_id = ${data.workspaceId} AND deleted_at IS NULL
    `;
    await audit({
      userId: context.userId,
      actorEmail: context.userEmail,
      action: "workspace.deleted",
      workspaceId: data.workspaceId,
      targetType: "workspace",
      targetId: data.workspaceId,
      targetLabel: ws.name,
    });
    return { ok: true };
  });

// ── Journal d'audit global ──────────────────────────────────────────────────

export const listAuditLogs = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({
      limit: z.number().int().min(1).max(500).optional(),
      action: z.string().max(120).optional(),
      workspaceId: z.string().uuid().optional(),
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    const sql = getDb();
    const limit = data.limit ?? 200;
    const action = data.action || null;
    const rows = await sql<
      {
        id: string;
        actor_email: string | null;
        workspace_id: string | null;
        action: string;
        target_type: string | null;
        target_label: string | null;
        result: string;
        created_at: Date | string;
        workspace_name: string | null;
      }[]
    >`
      SELECT a.id, a.actor_email, a.workspace_id, a.action, a.target_type,
             a.target_label, a.result, a.created_at, w.name AS workspace_name
      FROM audit_logs a
      LEFT JOIN workspaces w ON w.id = a.workspace_id
      WHERE (${action}::text IS NULL OR a.action = ${action})
        AND (${data.workspaceId ?? null}::uuid IS NULL OR a.workspace_id = ${data.workspaceId ?? null})
      ORDER BY a.created_at DESC
      LIMIT ${limit}
    `;
    const out: AuditLogDto[] = rows.map((r) => ({
      id: r.id,
      actorEmail: r.actor_email,
      workspaceName: r.workspace_name,
      action: r.action,
      targetType: r.target_type,
      targetLabel: r.target_label,
      result: r.result,
      createdAt: toIso(r.created_at),
    }));
    return out;
  });
