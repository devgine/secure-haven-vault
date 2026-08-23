import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "./auth-middleware";
import { getDb } from "./db.server";
import { requireSuperAdmin } from "./vault.server";
import { audit } from "./audit.server";
import type { GroupMappingDto, OidcProviderDto } from "./types";

const providerInput = z.object({
  displayName: z.string().min(1).max(120),
  issuerUrl: z.string().url().max(500),
  clientId: z.string().min(1).max(300),
  clientSecret: z.string().min(1).max(500),
  scopes: z.string().max(300).optional(),
  claimMapping: z
    .object({
      email: z.string().max(120).optional(),
      name: z.string().max(120).optional(),
      groups: z.string().max(120).optional(),
    })
    .optional(),
  groupMappings: z
    .array(
      z.object({
        idpGroup: z.string().min(1).max(200),
        workspaceId: z.string().uuid(),
        role: z.enum(["OWNER", "ADMIN", "EDITOR", "VIEWER"]),
      }),
    )
    .optional(),
  enabled: z.boolean().optional(),
  permissionMode: z.enum(["local", "hybrid", "oidc"]).optional(),
  defaultRole: z.enum(["ADMIN", "EDITOR", "VIEWER"]).optional(),
  defaultWorkspaceIds: z.array(z.string().uuid()).optional(),
});

interface ProviderRow {
  id: string;
  display_name: string;
  issuer_url: string;
  client_id: string;
  scopes: string;
  claim_mapping: Record<string, string>;
  enabled: boolean;
  permission_mode: "local" | "hybrid" | "oidc";
  default_role: "ADMIN" | "EDITOR" | "VIEWER" | null;
  default_workspace_ids: string[] | null;
  created_at: Date | string;
}

function toIso(v: Date | string): string {
  return v instanceof Date ? v.toISOString() : String(v);
}

async function loadProviders(): Promise<OidcProviderDto[]> {
  const sql = getDb();
  const providers = await sql<ProviderRow[]>`
    SELECT id, display_name, issuer_url, client_id, scopes, claim_mapping, enabled,
           permission_mode, default_role, default_workspace_ids, created_at
    FROM oidc_providers ORDER BY created_at ASC
  `;
  const mappings = await sql<
    {
      id: string;
      provider_id: string;
      idp_group: string;
      workspace_id: string;
      role: GroupMappingDto["role"];
      workspace_name: string | null;
    }[]
  >`
    SELECT m.id, m.provider_id, m.idp_group, m.workspace_id, m.role, w.name AS workspace_name
    FROM oidc_group_mappings m
    LEFT JOIN workspaces w ON w.id = m.workspace_id
    ORDER BY m.created_at ASC
  `;
  return providers.map((p) => ({
    id: p.id,
    displayName: p.display_name,
    issuerUrl: p.issuer_url,
    clientId: p.client_id,
    scopes: p.scopes,
    claimMapping: p.claim_mapping ?? {},
    enabled: p.enabled,
    permissionMode: p.permission_mode,
    defaultRole: p.default_role,
    defaultWorkspaceIds: p.default_workspace_ids ?? [],
    createdAt: toIso(p.created_at),
    groupMappings: mappings
      .filter((m) => m.provider_id === p.id)
      .map((m) => ({
        id: m.id,
        idpGroup: m.idp_group,
        workspaceId: m.workspace_id,
        role: m.role,
        workspaceName: m.workspace_name,
      })),
  }));
}

export const listOidcProviders = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    await requireSuperAdmin(context.userId);
    return loadProviders();
  });

export const upsertOidcProvider = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    providerInput.extend({ id: z.string().uuid().optional() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    const sql = getDb();
    let providerId = data.id;

    if (providerId) {
      const updated = await sql`
        UPDATE oidc_providers SET
          display_name = ${data.displayName},
          issuer_url = ${data.issuerUrl},
          client_id = ${data.clientId},
          client_secret = ${data.clientSecret},
          scopes = ${data.scopes ?? "openid email profile"},
          claim_mapping = ${sql.json((data.claimMapping ?? {}) as never)},
          enabled = ${data.enabled ?? true},
          permission_mode = ${data.permissionMode ?? "local"},
          default_role = ${data.defaultRole ?? null},
          default_workspace_ids = ${data.defaultWorkspaceIds ?? []},
          updated_at = now()
        WHERE id = ${providerId}
        RETURNING id
      `;
      if (!updated[0]) throw new Error("Provider not found");
    } else {
      const inserted = await sql<{ id: string }[]>`
        INSERT INTO oidc_providers (
          display_name, issuer_url, client_id, client_secret, scopes, claim_mapping,
          enabled, permission_mode, default_role, default_workspace_ids
        ) VALUES (
          ${data.displayName}, ${data.issuerUrl}, ${data.clientId}, ${data.clientSecret},
          ${data.scopes ?? "openid email profile"}, ${sql.json((data.claimMapping ?? {}) as never)},
          ${data.enabled ?? true}, ${data.permissionMode ?? "local"},
          ${data.defaultRole ?? null}, ${data.defaultWorkspaceIds ?? []}
        )
        RETURNING id
      `;
      providerId = inserted[0]!.id;
    }

    if (data.groupMappings) {
      await sql`DELETE FROM oidc_group_mappings WHERE provider_id = ${providerId}`;
      for (const m of data.groupMappings) {
        await sql`
          INSERT INTO oidc_group_mappings (provider_id, idp_group, workspace_id, role)
          VALUES (${providerId}, ${m.idpGroup}, ${m.workspaceId}, ${m.role})
        `;
      }
    }

    await audit({
      userId: context.userId,
      actorEmail: context.email,
      action: data.id ? "admin.oidc_updated" : "admin.oidc_created",
      targetType: "oidc_provider",
      targetId: providerId,
      targetLabel: data.displayName,
    });
    return { ok: true, id: providerId };
  });

export const deleteOidcProvider = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) => z.object({ id: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    const sql = getDb();
    const rows = await sql<{ display_name: string }[]>`
      DELETE FROM oidc_providers WHERE id = ${data.id} RETURNING display_name
    `;
    await audit({
      userId: context.userId,
      actorEmail: context.email,
      action: "admin.oidc_deleted",
      targetType: "oidc_provider",
      targetId: data.id,
      targetLabel: rows[0]?.display_name ?? null,
    });
    return { ok: true };
  });

export const setOidcEnabled = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({ id: z.string().uuid(), enabled: z.boolean() }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    await getDb()`
      UPDATE oidc_providers SET enabled = ${data.enabled}, updated_at = now()
      WHERE id = ${data.id}
    `;
    await audit({
      userId: context.userId,
      actorEmail: context.email,
      action: "admin.oidc_updated",
      targetType: "oidc_provider",
      targetId: data.id,
      targetLabel: data.enabled ? "enabled" : "disabled",
    });
    return { ok: true };
  });

/** Non authentifié : liste les providers actifs pour afficher les boutons SSO sur /auth. */
export const listEnabledOidcProviders = createServerFn({ method: "GET" }).handler(async () => {
  const rows = await getDb<{ id: string; display_name: string }[]>`
    SELECT id, display_name FROM oidc_providers WHERE enabled = true ORDER BY created_at ASC
  `;
  return rows.map((r) => ({ id: r.id, displayName: r.display_name }));
});
