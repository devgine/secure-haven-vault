import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/public/oidc/start")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const { getDb } = await import("@/lib/db.server");
        const { codeChallenge, discover, newTransaction, transactionCookie } = await import(
          "@/lib/oidc.server"
        );
        const { isSecureOrigin, publicOrigin } = await import("@/lib/request.server");

        const rows = await getDb()<
          { id: string; issuer_url: string | null; client_id: string | null; scopes: string }[]
        >`
          SELECT id, issuer_url, client_id, scopes
          FROM oidc_providers
          WHERE enabled = true
          ORDER BY created_at ASC
          LIMIT 1
        `;
        const provider = rows[0];
        if (!provider?.client_id || !provider.issuer_url) {
          return new Response("SSO is not configured", { status: 404 });
        }

        const discovery = await discover(provider.issuer_url);
        if (!discovery) {
          return new Response("Could not resolve the provider configuration", { status: 502 });
        }

        const tx = newTransaction();
        const url = new URL(discovery.authorizationEndpoint);
        url.searchParams.set("client_id", provider.client_id);
        url.searchParams.set("redirect_uri", `${publicOrigin(request)}/api/public/oidc/callback`);
        url.searchParams.set("response_type", "code");
        url.searchParams.set("scope", provider.scopes || "openid email profile groups");
        url.searchParams.set("state", tx.state);
        url.searchParams.set("nonce", tx.nonce);
        url.searchParams.set("code_challenge", await codeChallenge(tx.codeVerifier));
        url.searchParams.set("code_challenge_method", "S256");

        return new Response(null, {
          status: 302,
          headers: {
            Location: url.toString(),
            "Set-Cookie": transactionCookie(tx, isSecureOrigin(request)),
            "Cache-Control": "no-store",
          },
        });
      },
    },
  },
});
