// Flux OIDC authorization-code — helpers SERVER ONLY.
//
// Protections : `state` (CSRF), `nonce` (rejeu de jeton) et PKCE S256
// (interception du code). Les trois valeurs voyagent dans un unique cookie
// httpOnly de courte durée, limité aux routes OIDC.
import { createRemoteJWKSet } from "jose";

export const OIDC_CLIENT_SECRET_CONTEXT = "oidc-client-secret";
export const OIDC_TX_COOKIE = "oidc_tx";
const OIDC_COOKIE_PATH = "/api/public/oidc";
const DISCOVERY_TTL_MS = 10 * 60_000;

export interface OidcDiscovery {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
}

const discoveryCache = new Map<string, { at: number; value: OidcDiscovery }>();
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

const stripSlash = (url: string) => url.replace(/\/+$/, "");

/**
 * Lit le document de découverte et vérifie que l'émetteur annoncé est bien
 * celui configuré : un fournisseur ne peut pas se faire passer pour un autre.
 */
export async function discover(issuerUrl: string): Promise<OidcDiscovery | null> {
  const issuer = stripSlash(issuerUrl);
  const cached = discoveryCache.get(issuer);
  if (cached && Date.now() - cached.at < DISCOVERY_TTL_MS) return cached.value;
  try {
    const response = await fetch(`${issuer}/.well-known/openid-configuration`, {
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) return null;
    const doc = (await response.json()) as Record<string, unknown>;
    const value = {
      issuer: String(doc["issuer"] ?? ""),
      authorizationEndpoint: String(doc["authorization_endpoint"] ?? ""),
      tokenEndpoint: String(doc["token_endpoint"] ?? ""),
      jwksUri: String(doc["jwks_uri"] ?? ""),
    };
    if (stripSlash(value.issuer) !== issuer) return null;
    if (!value.authorizationEndpoint || !value.tokenEndpoint || !value.jwksUri) return null;
    discoveryCache.set(issuer, { at: Date.now(), value });
    return value;
  } catch {
    return null;
  }
}

export function jwksFor(jwksUri: string): ReturnType<typeof createRemoteJWKSet> {
  let jwks = jwksCache.get(jwksUri);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(jwksUri));
    jwksCache.set(jwksUri, jwks);
  }
  return jwks;
}

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

export interface OidcTransaction {
  state: string;
  nonce: string;
  codeVerifier: string;
}

export function newTransaction(): OidcTransaction {
  return { state: randomToken(24), nonce: randomToken(24), codeVerifier: randomToken(48) };
}

export async function codeChallenge(codeVerifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
  return Buffer.from(digest).toString("base64url");
}

export function transactionCookie(tx: OidcTransaction, secure: boolean): string {
  const value = Buffer.from(JSON.stringify(tx)).toString("base64url");
  return `${OIDC_TX_COOKIE}=${value}; Path=${OIDC_COOKIE_PATH}; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}; Max-Age=600`;
}

export function clearTransactionCookie(secure: boolean): string {
  return `${OIDC_TX_COOKIE}=; Path=${OIDC_COOKIE_PATH}; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}; Max-Age=0`;
}

export function readTransaction(cookieValue: string | undefined): OidcTransaction | null {
  if (!cookieValue) return null;
  try {
    const parsed = JSON.parse(Buffer.from(cookieValue, "base64url").toString("utf8")) as Partial<OidcTransaction>;
    if (
      typeof parsed.state === "string" &&
      typeof parsed.nonce === "string" &&
      typeof parsed.codeVerifier === "string"
    ) {
      return { state: parsed.state, nonce: parsed.nonce, codeVerifier: parsed.codeVerifier };
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Par défaut, seul un email marqué vérifié par le fournisseur peut ouvrir une
 * session. Certains fournisseurs n'émettent pas ce claim : mettre
 * OIDC_REQUIRE_VERIFIED_EMAIL=false uniquement si le fournisseur garantit
 * lui-même la propriété des adresses.
 */
export function requireVerifiedEmail(): boolean {
  return process.env["OIDC_REQUIRE_VERIFIED_EMAIL"] !== "false";
}
