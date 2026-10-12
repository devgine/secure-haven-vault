// Contexte de requête derrière un reverse proxy — SERVER ONLY.
//
// L'application tourne en HTTP derrière un ingress qui termine TLS : l'URL vue
// par Node n'est donc pas l'URL publique. Deux réglages la reconstituent :
//   APP_URL      URL publique canonique (ex. https://vault.example.com).
//                Recommandé en production : aucune dépendance aux en-têtes.
//   TRUST_PROXY  "true" pour faire confiance à X-Forwarded-Proto/Host/For.
//                À n'activer que si l'application n'est joignable qu'à travers
//                le proxy (sinon ces en-têtes sont falsifiables).
import { getRequest, getRequestIP } from "@tanstack/react-start/server";

export function trustProxy(): boolean {
  const value = process.env["TRUST_PROXY"];
  return value === "true" || value === "1";
}

function firstToken(header: string | null): string | undefined {
  return header?.split(",")[0]?.trim() || undefined;
}

/** Origine publique (schéma + hôte) à utiliser dans les redirections. */
export function publicOrigin(request: Request): string {
  const configured = process.env["APP_URL"];
  if (configured) return new URL(configured).origin;
  const url = new URL(request.url);
  if (trustProxy()) {
    const proto = firstToken(request.headers.get("x-forwarded-proto")) ?? url.protocol.replace(":", "");
    const host = firstToken(request.headers.get("x-forwarded-host")) ?? url.host;
    return `${proto}://${host}`;
  }
  return url.origin;
}

export function isSecureOrigin(request: Request): boolean {
  return publicOrigin(request).startsWith("https://");
}

/**
 * Adresse du client. Derrière un proxy de confiance, on prend la DERNIÈRE
 * entrée de X-Forwarded-For : c'est celle ajoutée par le proxy lui-même, les
 * précédentes étant fournies par le client.
 */
export function clientIp(request: Request): string | null {
  if (trustProxy()) {
    const entries = request.headers.get("x-forwarded-for")?.split(",") ?? [];
    const last = entries[entries.length - 1]?.trim();
    if (last) return last;
  }
  try {
    return getRequestIP() ?? null;
  } catch {
    return null;
  }
}

/** Requête courante, ou null hors contexte HTTP (tâches de démarrage). */
export function currentRequest(): Request | null {
  try {
    return getRequest() ?? null;
  } catch {
    return null;
  }
}
