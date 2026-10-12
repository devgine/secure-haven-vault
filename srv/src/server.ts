import "./lib/error-capture";

import { consumeLastCapturedError } from "./lib/error-capture";
import { renderErrorPage } from "./lib/error-page";

type ServerEntry = {
  fetch: (request: Request, env: unknown, ctx: unknown) => Promise<Response> | Response;
};

let serverEntryPromise: Promise<ServerEntry> | undefined;

async function getServerEntry(): Promise<ServerEntry> {
  if (!serverEntryPromise) {
    serverEntryPromise = import("@tanstack/react-start/server-entry").then(
      (m) => (m.default ?? m) as ServerEntry,
    );
  }
  return serverEntryPromise;
}

// h3 swallows in-handler throws into a normal 500 Response with body
// {"unhandled":true,"message":"HTTPError"} — try/catch alone never fires for those.
async function normalizeCatastrophicSsrResponse(response: Response): Promise<Response> {
  if (response.status < 500) return response;
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) return response;

  const body = await response.clone().text();
  if (!isH3SwallowedErrorBody(body)) return response;

  console.error(consumeLastCapturedError() ?? new Error(`h3 swallowed SSR error: ${body}`));
  return new Response(renderErrorPage(), {
    status: 500,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function isH3SwallowedErrorBody(body: string): boolean {
  try {
    const payload = JSON.parse(body) as { unhandled?: unknown; message?: unknown };
    return payload.unhandled === true && payload.message === "HTTPError";
  } catch {
    return false;
  }
}

// ── En-têtes de sécurité ─────────────────────────────────────────────────────
// 'unsafe-inline' reste nécessaire pour les scripts d'hydratation injectés par
// le SSR et pour les styles en ligne des composants ; 'wasm-unsafe-eval' pour
// Argon2 (déchiffrement KeePass dans le navigateur). L'essentiel est ailleurs :
// aucune origine tierce ne peut fournir de script, ni encadrer l'application.
const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' data: https://fonts.gstatic.com",
  "img-src 'self' data: blob:",
  "connect-src 'self'",
  "worker-src 'self' blob:",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

function withSecurityHeaders(request: Request, response: Response, secure: boolean): Response {
  // Les réponses peuvent porter des en-têtes immuables : on les recopie.
  const headers = new Headers(response.headers);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  // Le serveur de développement (HMR) a besoin de scripts que la CSP interdit.
  if (process.env["NODE_ENV"] === "production") {
    headers.set("Content-Security-Policy", CONTENT_SECURITY_POLICY);
  }
  if (secure) {
    headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  // Les réponses d'API et de fonctions serveur peuvent contenir des secrets
  // déchiffrés : jamais de mise en cache intermédiaire.
  const path = new URL(request.url).pathname;
  if ((path.startsWith("/_serverFn") || path.startsWith("/api/")) && !headers.has("Cache-Control")) {
    headers.set("Cache-Control", "no-store");
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

// Corps de requête maximal (MAX_BODY_BYTES, défaut 24 Mo) : le plus gros
// appel légitime est un lot d'import KeePass avec pièces jointes.
function maxBodyBytes(): number {
  const value = Number(process.env["MAX_BODY_BYTES"]);
  return Number.isFinite(value) && value > 0 ? value : 24 * 1024 * 1024;
}

function rejectOversizedBody(request: Request): Response | null {
  const length = Number(request.headers.get("content-length") ?? 0);
  if (length > maxBodyBytes()) {
    return new Response("Payload Too Large", { status: 413 });
  }
  return null;
}

const HEALTH_PATH = "/api/public/health";

export default {
  async fetch(request: Request, env: unknown, ctx: unknown) {
    const { isSecureOrigin } = await import("./lib/request.server");
    const secure = isSecureOrigin(request);
    try {
      const tooLarge = rejectOversizedBody(request);
      if (tooLarge) return withSecurityHeaders(request, tooLarge, secure);

      // Migrations, compte administrateur, rotation de clé : une fois par
      // processus. La sonde de vivacité n'en dépend pas, pour ne pas faire
      // redémarrer le pod en boucle quand la base est momentanément absente.
      if (new URL(request.url).pathname !== HEALTH_PATH) {
        try {
          const { ensureBootstrapped } = await import("./lib/bootstrap.server");
          await ensureBootstrapped();
        } catch (error) {
          console.error(error);
          return withSecurityHeaders(
            request,
            Response.json({ status: "not_ready" }, { status: 503 }),
            secure,
          );
        }
      }

      const handler = await getServerEntry();
      const response = await handler.fetch(request, env, ctx);
      return withSecurityHeaders(request, await normalizeCatastrophicSsrResponse(response), secure);
    } catch (error) {
      console.error(error);
      return withSecurityHeaders(
        request,
        new Response(renderErrorPage(), {
          status: 500,
          headers: { "content-type": "text/html; charset=utf-8" },
        }),
        secure,
      );
    }
  },
};
