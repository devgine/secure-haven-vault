// Server-only helpers for vault authorization and encryption key management.
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/integrations/supabase/types";
import { supabaseAdmin } from "@/integrations/supabase/client.server";
import {
  roleHasPermission,
  type Permission,
  type WorkspaceRole,
} from "./permissions";
import { generateDek, getKeyProvider } from "./crypto.server";

type UserClient = SupabaseClient<Database>;

export async function getWorkspaceRole(
  supabase: UserClient,
  userId: string,
  workspaceId: string,
): Promise<WorkspaceRole | null> {
  const { data, error } = await supabase.rpc("workspace_role_of", {
    _user_id: userId,
    _workspace_id: workspaceId,
  });
  if (error) throw new Error("Authorization check failed");
  return (data as WorkspaceRole | null) ?? null;
}

/**
 * Central authorization gate. Every sensitive server function calls this:
 * it verifies workspace membership + the exact permission, server-side,
 * regardless of what the client claims. Disabled/soft-deleted workspaces
 * resolve to no role, which denies access for everyone.
 */
export async function requireWorkspacePermission(
  supabase: UserClient,
  userId: string,
  workspaceId: string,
  permission: Permission,
): Promise<WorkspaceRole> {
  const role = await getWorkspaceRole(supabase, userId, workspaceId);
  let allowViewerReveal = false;
  if (role === "VIEWER" && (permission === "secret.reveal" || permission === "secret.copy")) {
    const { data: ws } = await supabaseAdmin
      .from("workspaces")
      .select("allow_viewer_reveal")
      .eq("id", workspaceId)
      .maybeSingle();
    allowViewerReveal = ws?.allow_viewer_reveal === true;
  }
  if (!roleHasPermission(role, permission, { allowViewerReveal })) {
    throw new Error("Forbidden");
  }
  return role as WorkspaceRole;
}

export async function requireSuperAdmin(
  supabase: UserClient,
  userId: string,
): Promise<void> {
  const { data, error } = await supabase.rpc("has_role", {
    _user_id: userId,
    _role: "SUPER_ADMIN",
  });
  if (error || data !== true) throw new Error("Forbidden");
}

export async function isSuperAdmin(
  supabase: UserClient,
  userId: string,
): Promise<boolean> {
  const { data } = await supabase.rpc("has_role", {
    _user_id: userId,
    _role: "SUPER_ADMIN",
  });
  return data === true;
}

/**
 * Returns the raw DEK for a workspace, creating and wrapping it on first use.
 * Service-role only: encryption_keys is never exposed to authenticated clients.
 */
export async function getOrCreateDek(workspaceId: string): Promise<Uint8Array> {
  const provider = getKeyProvider();
  const { data: existing } = await supabaseAdmin
    .from("encryption_keys")
    .select("wrapped_dek")
    .eq("workspace_id", workspaceId)
    .maybeSingle();
  if (existing?.wrapped_dek) {
    return provider.unwrapKey(existing.wrapped_dek);
  }
  const dek = generateDek();
  const wrapped = await provider.wrapKey(dek);
  const { error } = await supabaseAdmin.from("encryption_keys").insert({
    workspace_id: workspaceId,
    wrapped_dek: wrapped,
  });
  if (error) {
    // Concurrent creation: re-read the winning row.
    const { data: retry } = await supabaseAdmin
      .from("encryption_keys")
      .select("wrapped_dek")
      .eq("workspace_id", workspaceId)
      .maybeSingle();
    if (retry?.wrapped_dek) return provider.unwrapKey(retry.wrapped_dek);
    throw new Error("Failed to initialize workspace encryption key");
  }
  return dek;
}
