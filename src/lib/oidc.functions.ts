import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "./auth-middleware";
import { getDb } from "./db.server";
import { requireSuperAdmin } from "./vault.server";
import { audit } from "./audit.server";

// Modèle mono-fournisseur : une seule ligne dans oidc_providers (Keycloak ou
// équivalent). Le secret client est chiffré sous la clé maître avant stockage.

const permissionModeEnum = z.enum(["local", "oidc", "hybrid"]);
const workspaceRoleEnum = z.enum(["OWNER", "ADMIN", "EDITOR", "VIEWER"]);

interface ProviderRow {
  id: string;
  name: string;
  enabled: boolean;
  issuer_url: string | null;
  client_id: string | null;
  client_secret_ciphertext: string | null;
  permission_mode: string;
}

async function getProviderRow() {
  const rows = await getDb()<ProviderRow[]>`
    SELECT id, name, enabled, issuer_url, client_id, client_secret_ciphertext, permission_mode
    FROM oidc_providers
    ORDER BY created_at ASC
    LIMIT 1
  `;
  return rows[0] ?? null;
}

export const getOidcProvider = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    await requireSuperAdmin(context.userId);
    const p = await getProviderRow();
    if (!p) return null;
    return {
      id: p.id,
      name: p.name,
      issuerUrl: p.issuer_url ?? "",
      clientId: p.client_id ?? "",
      clientSecretSet: Boolean(p.client_secret_ciphertext),
      enabled: p.enabled,
      permissionMode: p.permission_mode,
    };
  });

export const saveOidcProvider = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({
      name: z.string().min(1).max(120),
      issuerUrl: z.string().url().max(500),
      clientId: z.string().min(1).max(300),
      clientSecret: z.string().min(1).max(500).optional(),
      enabled: z.boolean(),
      permissionMode: permissionModeEnum,
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    const sql = getDb();
    const existing = await getProviderRow();

    let secretCiphertext: string | null = existing?.client_secret_ciphertext ?? null;
    if (data.clientSecret) {
      const { encryptWithMaster } = await import("./crypto.server");
      secretCiphertext = await encryptWithMaster(data.clientSecret);
    }
    if (!secretCiphertext) throw new Error("Le secret client est requis");

    if (existing) {
      await sql`
        UPDATE oidc_providers SET
          name = ${data.name},
          issuer_url = ${data.issuerUrl},
          client_id = ${data.clientId},
          client_secret_ciphertext = ${secretCiphertext},
          enabled = ${data.enabled},
          permission_mode = ${data.permissionMode}
        WHERE id = ${existing.id}
      `;
    } else {
      await sql`
        INSERT INTO oidc_providers (name, issuer_url, client_id, client_secret_ciphertext, enabled, permission_mode)
        VALUES (${data.name}, ${data.issuerUrl}, ${data.clientId}, ${secretCiphertext}, ${data.enabled}, ${data.permissionMode})
      `;
    }
    await audit({
      userId: context.userId,
      actorEmail: context.userEmail,
      action: "admin.oidc_updated",
      targetType: "oidc_provider",
      targetLabel: data.name,
    });
    return { ok: true };
  });

export const listOidcMappings = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    await requireSuperAdmin(context.userId);
    const rows = await getDb()<
      {
        id: string;
        oidc_group: string;
        workspace_id: string;
        workspace_role: "OWNER" | "ADMIN" | "EDITOR" | "VIEWER";
        workspace_name: string | null;
      }[]
    >`
      SELECT m.id, m.oidc_group, m.workspace_id, m.workspace_role, w.name AS workspace_name
      FROM oidc_group_mappings m
      LEFT JOIN workspaces w ON w.id = m.workspace_id
      ORDER BY m.created_at ASC
    `;
    return rows.map((m) => ({
      id: m.id,
      idpGroup: m.oidc_group,
      workspaceId: m.workspace_id,
      workspaceName: m.workspace_name,
      role: m.workspace_role,
    }));
  });

export const saveOidcMapping = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({
      idpGroup: z.string().min(1).max(200),
      workspaceId: z.string().uuid(),
      role: workspaceRoleEnum,
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    const provider = await getProviderRow();
    if (!provider) throw new Error("Configurez d'abord le fournisseur OIDC");
    const sql = getDb();
    await sql`
      INSERT INTO oidc_group_mappings (provider_id, oidc_group, workspace_id, workspace_role)
      VALUES (${provider.id}, ${data.idpGroup}, ${data.workspaceId}, ${data.role})
    `;
    await audit({
      userId: context.userId,
      actorEmail: context.userEmail,
      action: "admin.oidc_updated",
      targetType: "oidc_mapping",
      targetLabel: data.idpGroup,
    });
    return { ok: true };
  });

export const deleteOidcMapping = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) => z.object({ mappingId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    await requireSuperAdmin(context.userId);
    await getDb()`DELETE FROM oidc_group_mappings WHERE id = ${data.mappingId}`;
    await audit({
      userId: context.userId,
      actorEmail: context.userEmail,
      action: "admin.oidc_updated",
      targetType: "oidc_mapping",
      targetId: data.mappingId,
      targetLabel: "mapping supprimé",
    });
    return { ok: true };
  });

/** Non authentifié : noms des providers actifs, pour les boutons SSO de /auth. */
export const getPublicOidcProviders = createServerFn({ method: "GET" }).handler(async () => {
  const rows = await getDb()<{ name: string }[]>`
    SELECT name FROM oidc_providers WHERE enabled = true ORDER BY created_at ASC
  `;
  return rows.map((r) => r.name);
});
