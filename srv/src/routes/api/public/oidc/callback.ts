import { createFileRoute } from "@tanstack/react-router";
import { jwtVerify, type JWTPayload } from "jose";
import { audit } from "@/lib/audit.server";
import { roleAtLeast, type WorkspaceRole } from "@/lib/permissions";
import { SESSION_COOKIE, readCookieHeader } from "@/lib/session-cookie";

export const Route = createFileRoute("/api/public/oidc/callback")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const { getDb } = await import("@/lib/db.server");
        const {
          OIDC_CLIENT_SECRET_CONTEXT,
          OIDC_TX_COOKIE,
          clearTransactionCookie,
          discover,
          jwksFor,
          readTransaction,
          requireVerifiedEmail,
        } = await import("@/lib/oidc.server");
        const { isSecureOrigin, publicOrigin } = await import("@/lib/request.server");

        const origin = publicOrigin(request);
        const secure = isSecureOrigin(request);
        const fail = async (message: string, auditLabel?: string, actorEmail?: string) => {
          if (auditLabel) {
            await audit({
              action: "auth.login_failed",
              actorEmail: actorEmail ?? null,
              targetType: "auth",
              result: "failure",
              targetLabel: auditLabel,
            });
          }
          const target = new URL("/auth", origin);
          target.searchParams.set("sso_error", message);
          return new Response(null, {
            status: 302,
            headers: [
              ["Location", target.toString()],
              ["Set-Cookie", clearTransactionCookie(secure)],
              ["Cache-Control", "no-store"],
            ],
          });
        };

        const url = new URL(request.url);
        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        const tx = readTransaction(readCookieHeader(request.headers.get("cookie"), OIDC_TX_COOKIE));
        if (!code || !state || !tx || state !== tx.state) return fail("invalid_state");

        const sql = getDb();
        const providerRows = await sql<
          {
            id: string;
            issuer_url: string | null;
            client_id: string | null;
            client_secret_ciphertext: string | null;
            permission_mode: string;
          }[]
        >`
          SELECT id, issuer_url, client_id, client_secret_ciphertext, permission_mode
          FROM oidc_providers
          WHERE enabled = true
          ORDER BY created_at ASC
          LIMIT 1
        `;
        const provider = providerRows[0];
        if (!provider?.client_id || !provider.issuer_url || !provider.client_secret_ciphertext) {
          return fail("sso_not_configured");
        }

        const discovery = await discover(provider.issuer_url);
        if (!discovery) return fail("discovery_failed");

        const { decryptWithMaster } = await import("@/lib/crypto.server");
        const clientSecret = await decryptWithMaster(
          provider.client_secret_ciphertext,
          OIDC_CLIENT_SECRET_CONTEXT,
        );

        let idToken: string | undefined;
        try {
          const tokenResponse = await fetch(discovery.tokenEndpoint, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              grant_type: "authorization_code",
              code,
              redirect_uri: `${origin}/api/public/oidc/callback`,
              client_id: provider.client_id,
              client_secret: clientSecret,
              code_verifier: tx.codeVerifier,
            }),
            signal: AbortSignal.timeout(10_000),
          });
          if (tokenResponse.ok) {
            idToken = ((await tokenResponse.json()) as { id_token?: string }).id_token;
          }
        } catch {
          // Traité comme un échec d'échange ci-dessous.
        }
        if (!idToken) return fail("token_exchange_failed", "oidc_token_exchange");

        let claims: JWTPayload;
        try {
          const verified = await jwtVerify(idToken, jwksFor(discovery.jwksUri), {
            issuer: discovery.issuer,
            audience: provider.client_id,
          });
          claims = verified.payload;
        } catch {
          return fail("invalid_token", "oidc_invalid_token");
        }
        // Le jeton doit avoir été émis pour CETTE tentative de connexion.
        if (claims["nonce"] !== tx.nonce) return fail("invalid_token", "oidc_nonce_mismatch");

        const subject = claims.sub;
        const email = (claims["email"] as string | undefined)?.toLowerCase();
        if (!subject) return fail("invalid_token", "oidc_no_subject");
        if (!email) return fail("no_email_claim");
        // Sans email vérifié, n'importe quel utilisateur du fournisseur pourrait
        // revendiquer l'adresse d'un compte existant.
        if (requireVerifiedEmail() && claims["email_verified"] !== true) {
          return fail("email_not_verified", "oidc_email_not_verified", email);
        }

        const groupsClaim =
          (claims["groups"] as string[] | undefined) ??
          (claims["realm_access"] as { roles?: string[] } | undefined)?.roles ??
          [];
        const groups = Array.isArray(groupsClaim) ? groupsClaim : [];
        const displayName =
          (claims["name"] as string | undefined) ??
          (claims["preferred_username"] as string | undefined) ??
          email.split("@")[0] ??
          email;

        // Compte identifié par le `sub` ; provisionné sans mot de passe local au
        // besoin (les inscriptions fermées bloquent aussi le SSO).
        const { createSession, resolveOidcUser } = await import("@/lib/session.server");
        let userId: string;
        try {
          const resolved = await resolveOidcUser({
            providerId: provider.id,
            subject,
            email,
            displayName,
          });
          userId = resolved.userId;
          if (resolved.linked) {
            await audit({
              userId,
              actorEmail: email,
              action: "auth.oidc_linked",
              targetType: "auth",
              targetLabel: provider.issuer_url,
            });
          }
        } catch (err) {
          const message = (err as Error).message;
          if (message === "signup_disabled") return fail("signup_disabled");
          if (message === "identity_conflict") {
            return fail("identity_conflict", "oidc_identity_conflict", email);
          }
          return fail("user_provisioning_failed");
        }

        // Compte bloqué : refus de la session.
        const userRows = await sql<{ banned_until: Date | string | null }[]>`
          SELECT banned_until FROM users WHERE id = ${userId}
        `;
        const bannedUntil = userRows[0]?.banned_until;
        if (bannedUntil && new Date(bannedUntil).getTime() > Date.now()) {
          return fail("account_banned", "account_banned", email);
        }

        // Synchronise les adhésions issues des groupes du fournisseur. Seules
        // les adhésions gérées par le SSO sont touchées : une adhésion manuelle
        // (y compris propriétaire) n'est ni convertie ni supprimée.
        if (provider.permission_mode !== "local") {
          await sql.begin(async (db) => {
            const mappings = await db<
              { workspace_id: string | null; workspace_role: WorkspaceRole | null }[]
            >`
              SELECT workspace_id, workspace_role
              FROM oidc_group_mappings
              WHERE provider_id = ${provider.id}
                AND oidc_group = ANY(${groups.length ? groups : ["__none__"]})
            `;
            // Plusieurs groupes peuvent viser le même coffre : le rôle le plus
            // élevé est retenu.
            const best = new Map<string, WorkspaceRole>();
            for (const m of mappings) {
              if (!m.workspace_id || !m.workspace_role) continue;
              const current = best.get(m.workspace_id);
              if (!current || !roleAtLeast(current, m.workspace_role)) {
                best.set(m.workspace_id, m.workspace_role);
              }
            }
            const kept = [...best.keys()];
            await db`
              DELETE FROM workspace_members
              WHERE user_id = ${userId} AND managed_by_oidc = true
                AND NOT (workspace_id = ANY(${db.array(kept)}::uuid[]))
            `;
            for (const [workspaceId, role] of best) {
              await db`
                INSERT INTO workspace_members (workspace_id, user_id, role, managed_by_oidc)
                VALUES (${workspaceId}, ${userId}, ${role}::workspace_role, true)
                ON CONFLICT (workspace_id, user_id)
                DO UPDATE SET role = EXCLUDED.role
                WHERE workspace_members.managed_by_oidc = true
              `;
            }
          });
        }

        // Émet une session applicative (cookie httpOnly, empreinte SHA-256 en base).
        const session = await createSession(userId);
        await sql`UPDATE users SET last_sign_in_at = now() WHERE id = ${userId}`;

        await audit({
          userId,
          actorEmail: email,
          action: "auth.oidc_login",
          targetType: "auth",
          targetLabel: provider.issuer_url,
        });

        return new Response(null, {
          status: 302,
          headers: [
            ["Location", `${origin}/`],
            ["Set-Cookie", clearTransactionCookie(secure)],
            [
              "Set-Cookie",
              `${SESSION_COOKIE}=${encodeURIComponent(session.token)}; Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}; Max-Age=${7 * 24 * 3600}`,
            ],
            ["Cache-Control", "no-store"],
          ],
        });
      },
    },
  },
});
