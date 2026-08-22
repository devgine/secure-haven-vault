import { createFileRoute } from "@tanstack/react-router";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { audit } from "@/lib/audit.server";

function errorRedirect(origin: string, message: string): Response {
  const url = new URL("/auth", origin);
  url.searchParams.set("sso_error", message);
  return new Response(null, { status: 302, headers: { Location: url.toString() } });
}

export const Route = createFileRoute("/api/public/oidc/callback")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const url = new URL(request.url);
        const origin = url.origin;
        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        const cookieState = request.headers
          .get("cookie")
          ?.split(";")
          .map((c) => c.trim())
          .find((c) => c.startsWith("oidc_state="))
          ?.split("=")[1];

        if (!code || !state || !cookieState || state !== cookieState) {
          return errorRedirect(origin, "invalid_state");
        }

        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const { data: provider } = await supabaseAdmin
          .from("oidc_providers")
          .select("id, issuer_url, client_id, client_secret_ciphertext, token_endpoint, permission_mode")
          .eq("enabled", true)
          .order("created_at", { ascending: true })
          .limit(1)
          .maybeSingle();
        if (!provider?.client_id || !provider.issuer_url || !provider.client_secret_ciphertext) {
          return errorRedirect(origin, "sso_not_configured");
        }

        let tokenEndpoint = provider.token_endpoint;
        let jwksUri: string | null = null;
        if (!tokenEndpoint || !jwksUri) {
          const discovery = await fetch(
            `${provider.issuer_url}/.well-known/openid-configuration`,
          ).then((r) => (r.ok ? r.json() : null));
          tokenEndpoint = tokenEndpoint ?? discovery?.token_endpoint ?? null;
          jwksUri = discovery?.jwks_uri ?? null;
        }
        if (!tokenEndpoint || !jwksUri) {
          return errorRedirect(origin, "discovery_failed");
        }

        const { decryptWithMaster } = await import("@/lib/crypto.server");
        const clientSecret = await decryptWithMaster(provider.client_secret_ciphertext);
        const redirectUri = `${origin}/api/public/oidc/callback`;

        const tokenResponse = await fetch(tokenEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: redirectUri,
            client_id: provider.client_id,
            client_secret: clientSecret,
          }),
        });
        if (!tokenResponse.ok) {
          await audit({ action: "auth.login_failed", targetType: "auth", result: "failure", targetLabel: "oidc_token_exchange" });
          return errorRedirect(origin, "token_exchange_failed");
        }
        const tokens = (await tokenResponse.json()) as { id_token?: string };
        if (!tokens.id_token) return errorRedirect(origin, "no_id_token");

        let claims;
        try {
          const jwks = createRemoteJWKSet(new URL(jwksUri));
          const verified = await jwtVerify(tokens.id_token, jwks, {
            issuer: provider.issuer_url,
            audience: provider.client_id,
          });
          claims = verified.payload;
        } catch {
          await audit({ action: "auth.login_failed", targetType: "auth", result: "failure", targetLabel: "oidc_invalid_token" });
          return errorRedirect(origin, "invalid_token");
        }

        const email = (claims["email"] as string | undefined)?.toLowerCase();
        if (!email) return errorRedirect(origin, "no_email_claim");

        const groupsClaim = (claims["groups"] as string[] | undefined) ??
          ((claims["realm_access"] as { roles?: string[] } | undefined)?.roles) ??
          [];
        const groups = Array.isArray(groupsClaim) ? groupsClaim : [];
        const displayName =
          (claims["name"] as string | undefined) ??
          (claims["preferred_username"] as string | undefined) ??
          email.split("@")[0] ??
          email;

        // Find or create the application user.
        const { data: existingProfile } = await supabaseAdmin
          .from("profiles")
          .select("id")
          .eq("email", email)
          .maybeSingle();
        let userId = existingProfile?.id ?? null;
        if (!userId) {
          const { data: created, error: createError } = await supabaseAdmin.auth.admin.createUser({
            email,
            email_confirm: true,
            user_metadata: { display_name: displayName },
          });
          if (createError || !created.user) {
            return errorRedirect(origin, "user_provisioning_failed");
          }
          userId = created.user.id;
        }

        // Synchronize workspace memberships from IdP group mappings.
        if (provider.permission_mode !== "local") {
          const { data: mappings } = await supabaseAdmin
            .from("oidc_group_mappings")
            .select("workspace_id, workspace_role, oidc_group")
            .eq("provider_id", provider.id)
            .in("oidc_group", groups.length ? groups : ["__none__"]);

          await supabaseAdmin
            .from("workspace_members")
            .delete()
            .eq("user_id", userId)
            .eq("managed_by_oidc", true);

          for (const m of mappings ?? []) {
            if (!m.workspace_id || !m.workspace_role) continue;
            // Never downgrade the owner of a personal vault.
            await supabaseAdmin.from("workspace_members").upsert(
              {
                workspace_id: m.workspace_id,
                user_id: userId,
                role: m.workspace_role,
                managed_by_oidc: true,
              },
              { onConflict: "workspace_id,user_id" },
            );
          }
        }

        // Issue a session for the verified SSO identity.
        const { data: linkData, error: linkError } = await supabaseAdmin.auth.admin.generateLink({
          type: "magiclink",
          email,
          options: { redirectTo: `${origin}/` },
        });
        if (linkError || !linkData.properties?.action_link) {
          return errorRedirect(origin, "session_failed");
        }

        await audit({
          userId,
          actorEmail: email,
          action: "auth.oidc_login",
          targetType: "auth",
          targetLabel: provider.issuer_url,
        });

        return new Response(null, {
          status: 302,
          headers: {
            Location: linkData.properties.action_link,
            "Set-Cookie": "oidc_state=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0",
            "Cache-Control": "no-store",
          },
        });
      },
    },
  },
});
