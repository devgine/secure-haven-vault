import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { requireSuperAdmin } from "./vault.server";
import { encryptWithMaster } from "./crypto.server";
import { audit } from "./audit.server";
import type { WorkspaceRole } from "./permissions";

export interface OidcProviderDto {
  id: string;
  name: string;
  issuerUrl: string;
  clientId: string;
  clientSecretSet: boolean;
  enabled: boolean;
  permissionMode: "oidc" | "local" | "hybrid";
}

export interface OidcMappingDto {
  id: string;
  idpGroup: string;
  workspaceId: string;
  workspaceName: string;
  role: WorkspaceRole;
}

/** Public: the login page lists enabled SSO providers. */
export const getPublicOidcProviders = createServerFn({ method: "GET" }).handler(async () => {
  const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
  const { data } = await supabaseAdmin
    .from("oidc_providers")
    .select("name")
    .eq("enabled", true)
    .order("created_at", { ascending: true });
  return (data ?? []).map((p) => p.name);
});

export const getOidcProvider = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }): Promise<OidcProviderDto | null> => {
    const { supabase, userId } = context;
    await requireSuperAdmin(supabase, userId);
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data } = await supabaseAdmin
      .from("oidc_providers")
      .select("id, name, issuer_url, client_id, client_secret_ciphertext, enabled, permission_mode")
      .order("created_at", { ascending: true })
      .limit(1)
      .maybeSingle();
    if (!data) return null;
    return {
      id: data.id,
      name: data.name,
      issuerUrl: data.issuer_url ?? "",
      clientId: data.client_id ?? "",
      clientSecretSet: data.client_secret_ciphertext != null,
      enabled: data.enabled,
      permissionMode: data.permission_mode as OidcProviderDto["permissionMode"],
    };
  });

export const saveOidcProvider = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({
      name: z.string().min(1).max(100),
      issuerUrl: z.string().url().max(2000),
      clientId: z.string().min(1).max(500),
      clientSecret: z.string().max(2000).optional(),
      enabled: z.boolean(),
      permissionMode: z.enum(["oidc", "local", "hybrid"]),
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await requireSuperAdmin(supabase, userId);
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");

    const { data: existing } = await supabaseAdmin
      .from("oidc_providers")
      .select("id, client_secret_ciphertext")
      .order("created_at", { ascending: true })
      .limit(1)
      .maybeSingle();

    let ciphertext = existing?.client_secret_ciphertext ?? null;
    if (data.clientSecret && data.clientSecret.length > 0) {
      ciphertext = await encryptWithMaster(data.clientSecret);
    }
    if (!ciphertext) throw new Error("A client secret is required");

    const payload = {
      name: data.name,
      issuer_url: data.issuerUrl.replace(/\/$/, ""),
      client_id: data.clientId,
      client_secret_ciphertext: ciphertext,
      enabled: data.enabled,
      permission_mode: data.permissionMode,
    };
    const { error } = existing
      ? await supabaseAdmin.from("oidc_providers").update(payload).eq("id", existing.id)
      : await supabaseAdmin.from("oidc_providers").insert(payload);
    if (error) throw new Error("Failed to save provider");
    await audit({ userId, action: "oidc.provider_saved", targetType: "oidc_provider", targetLabel: data.name });
    return { ok: true };
  });

export const listOidcMappings = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }): Promise<OidcMappingDto[]> => {
    const { supabase, userId } = context;
    await requireSuperAdmin(supabase, userId);
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: provider } = await supabaseAdmin
      .from("oidc_providers")
      .select("id")
      .order("created_at", { ascending: true })
      .limit(1)
      .maybeSingle();
    if (!provider) return [];
    const { data } = await supabaseAdmin
      .from("oidc_group_mappings")
      .select("id, oidc_group, workspace_role, workspaces(id, name)")
      .eq("provider_id", provider.id)
      .order("oidc_group", { ascending: true });
    return (data ?? []).map((m) => {
      const ws = m.workspaces as unknown as { id: string; name: string } | null;
      return {
        id: m.id,
        idpGroup: m.oidc_group,
        workspaceId: ws?.id ?? "",
        workspaceName: ws?.name ?? "",
        role: (m.workspace_role ?? "VIEWER") as WorkspaceRole,
      };
    });
  });

export const saveOidcMapping = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) =>
    z.object({
      idpGroup: z.string().min(1).max(200),
      workspaceId: z.string().uuid(),
      role: z.enum(["OWNER", "ADMIN", "EDITOR", "VIEWER"]),
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await requireSuperAdmin(supabase, userId);
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: provider } = await supabaseAdmin
      .from("oidc_providers")
      .select("id")
      .order("created_at", { ascending: true })
      .limit(1)
      .maybeSingle();
    if (!provider) throw new Error("Configure an OIDC provider first");
    const { error } = await supabaseAdmin.from("oidc_group_mappings").upsert(
      {
        provider_id: provider.id,
        oidc_group: data.idpGroup,
        workspace_id: data.workspaceId,
        workspace_role: data.role,
      },
      { onConflict: "provider_id,oidc_group,workspace_id" },
    );
    if (error) throw new Error("Failed to save mapping");
    await audit({ userId, workspaceId: data.workspaceId, action: "oidc.mapping_saved", targetType: "oidc_mapping", targetLabel: data.idpGroup });
    return { ok: true };
  });

export const deleteOidcMapping = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: unknown) => z.object({ mappingId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await requireSuperAdmin(supabase, userId);
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { error } = await supabaseAdmin.from("oidc_group_mappings").delete().eq("id", data.mappingId);
    if (error) throw new Error("Failed to delete mapping");
    await audit({ userId, action: "oidc.mapping_deleted", targetType: "oidc_mapping", targetId: data.mappingId });
    return { ok: true };
  });
