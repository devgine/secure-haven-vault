import { createFileRoute } from "@tanstack/react-router";

function randomState(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export const Route = createFileRoute("/api/public/oidc/start")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const { getDb } = await import("@/lib/db.server");
        const rows = await getDb()<
          {
            id: string;
            issuer_url: string | null;
            client_id: string | null;
            authorization_endpoint: string | null;
            scopes: string;
          }[]
        >`
          SELECT id, issuer_url, client_id, authorization_endpoint, scopes
          FROM oidc_providers
          WHERE enabled = true
          ORDER BY created_at ASC
          LIMIT 1
        `;
        const provider = rows[0];
        if (!provider?.client_id || !provider.issuer_url) {
          return new Response("SSO is not configured", { status: 404 });
        }

        let authorizationEndpoint = provider.authorization_endpoint;
        if (!authorizationEndpoint) {
          const discovery = await fetch(
            `${provider.issuer_url}/.well-known/openid-configuration`,
          ).then((r) => (r.ok ? r.json() : null));
          authorizationEndpoint = discovery?.authorization_endpoint ?? null;
        }
        if (!authorizationEndpoint) {
          return new Response("Could not resolve the provider authorization endpoint", { status: 502 });
        }

        const origin = new URL(request.url).origin;
        const redirectUri = `${origin}/api/public/oidc/callback`;
        const state = randomState();

        const url = new URL(authorizationEndpoint);
        url.searchParams.set("client_id", provider.client_id);
        url.searchParams.set("redirect_uri", redirectUri);
        url.searchParams.set("response_type", "code");
        url.searchParams.set("scope", provider.scopes || "openid email profile groups");
        url.searchParams.set("state", state);

        return new Response(null, {
          status: 302,
          headers: {
            Location: url.toString(),
            "Set-Cookie": `oidc_state=${state}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=600`,
            "Cache-Control": "no-store",
          },
        });
      },
    },
  },
});
