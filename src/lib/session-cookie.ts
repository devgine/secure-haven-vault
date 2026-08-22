// Nom du cookie de session — module client-safe (importé par le middleware
// d'authentification dont la portée module peut rejoindre le bundle client).
export const SESSION_COOKIE = "vault_session";

export function readCookieHeader(header: string | null, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(`${name}=`)) {
      return decodeURIComponent(trimmed.slice(name.length + 1));
    }
  }
  return undefined;
}
