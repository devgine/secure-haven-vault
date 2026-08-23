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

        const { getDb } = await import("@/lib/db.server");
        const sql = getDb();
        const providerRows = await sql<
          {
            id: string;
            issuer_url: string | null;
            client_id: string | null;
            client_secret_ciphertext: string | null;
            token_endpoint: string | null;
            permission_mode: string;
          }[]
        >`
          SELECT id, issuer_url, client_id, client_secret_ciphertext, token_endpoint, permission_mode
          FROM oidc_providers
          WHERE enabled = true
          ORDER BY created_at ASC
          LIMIT 1
        `;
        const provider = providerRows[0];
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

        // Find or create the application user (compte provisionné sans mot de
        // passe local ; les inscriptions fermées bloquent aussi le SSO).
        const { findOrCreateOidcUser } = await import("@/lib/session.server");
        let userId: string;
        try {
          userId = await findOrCreateOidcUser(email, displayName);
        } catch (err) {
          const message = (err as Error).message;
          return errorRedirect(
            origin,
            message === "signup_disabled" ? "signup_disabled" : "user_provisioning_failed",
          );
        }

        // Compte bloqué : refus de la session.
        const userRows = await sql<{ banned_until: Date | string | null }[]>`
          SELECT banned_until FROM users WHERE id = ${userId}
        `;
        const bannedUntil = userRows[0]?.banned_until;
        if (bannedUntil && new Date(bannedUntil).getTime() > Date.now()) {
          await audit({
            userId,
            actorEmail: email,
            action: "auth.login_failed",
            targetType: "auth",
            result: "failure",
            targetLabel: "account_banned",
          });
          return errorRedirect(origin, "account_banned");
        }

        // Synchronize workspace memberships from IdP group mappings.
        if (provider.permission_mode !== "local") {
          const mappings = await sql<
            { workspace_id: string | null; workspace_role: string | null; oidc_group: string }[]
          >`
            SELECT workspace_id, workspace_role, oidc_group
            FROM oidc_group_mappings
            WHERE provider_id = ${provider.id}
              AND oidc_group = ANY(${groups.length ? groups : ["__none__"]})
          `;

          await sql`
            DELETE FROM workspace_members WHERE user_id = ${userId} AND managed_by_oidc = true
          `;

          for (const m of mappings) {
            if (!m.workspace_id || !m.workspace_role) continue;
            await sql`
              INSERT INTO workspace_members (workspace_id, user_id, role, managed_by_oidc)
              VALUES (${m.workspace_id}, ${userId}, ${m.workspace_role}::workspace_role, true)
              ON CONFLICT (workspace_id, user_id)
              DO UPDATE SET role = EXCLUDED.role, managed_by_oidc = true
            `;
          }
        }

        // Émet une session applicative (cookie httpOnly, empreinte SHA-256 en base).
        const { createSession } = await import("@/lib/session.server");
        const session = await createSession(userId);
        await sql`UPDATE users SET last_sign_in_at = now() WHERE id = ${userId}`;

        await audit({
          userId,
          actorEmail: email,
          action: "auth.oidc_login",
          targetType: "auth",
          targetLabel: provider.issuer_url,
        });

        const secure = url.protocol === "https:" ? "; Secure" : "";
        return new Response(null, {
          status: 302,
          headers: [
            ["Location", `${origin}/`],
            ["Set-Cookie", "oidc_state=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0"],
            [
              "Set-Cookie",
              `vault_session=${encodeURIComponent(session.token)}; Path=/; HttpOnly; SameSite=Lax${secure}; Max-Age=${7 * 24 * 3600}`,
            ],
            ["Cache-Control", "no-store"],
          ],
        });
      },
    },
  },
});
