// Authentification maison — SERVER ONLY.
//
// - Mots de passe : scrypt (node:crypto), sel aléatoire 128 bits par compte.
//   Format stocké : "s1.<salt_b64>.<hash_b64>".
// - Sessions : jeton opaque 256 bits, seul son empreinte SHA-256 est stockée.
//   Durée 7 jours, last_seen glissant. Le jeton vit dans un cookie httpOnly.
import { createHash, randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { getDb } from "./db.server";
import { SESSION_COOKIE } from "./session-cookie";

const scrypt = promisify(scryptCb);

export { SESSION_COOKIE };
export const SESSION_TTL_MS = 7 * 24 * 3600 * 1000;

// ── Mots de passe ────────────────────────────────────────────────────────────

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const derived = (await scrypt(password, salt, 64)) as Buffer;
  return `s1.${salt.toString("base64")}.${derived.toString("base64")}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [version, saltB64, hashB64] = stored.split(".");
  if (version !== "s1" || !saltB64 || !hashB64) return false;
  const salt = Buffer.from(saltB64, "base64");
  const expected = Buffer.from(hashB64, "base64");
  const derived = (await scrypt(password, salt, expected.length)) as Buffer;
  return timingSafeEqual(derived, expected);
}

// ── Sessions ─────────────────────────────────────────────────────────────────

function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export interface SessionUser {
  id: string;
  email: string;
}

export async function createSession(userId: string): Promise<{ token: string; expiresAt: Date }> {
  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
  await getDb()`
    INSERT INTO sessions (user_id, token_hash, expires_at)
    VALUES (${userId}, ${hashToken(token)}, ${expiresAt.toISOString()})
  `;
  return { token, expiresAt };
}

export async function validateSession(token: string | undefined): Promise<SessionUser | null> {
  if (!token) return null;
  const sql = getDb();
  const rows = await sql<
    {
      user_id: string;
      email: string;
      banned_until: Date | null;
      session_id: string;
      expires_at: Date;
    }[]
  >`
    SELECT u.id AS user_id, u.email, u.banned_until, s.id AS session_id, s.expires_at
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ${hashToken(token)}
    LIMIT 1
  `;
  const row = rows[0];
  if (!row) return null;
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    await sql`DELETE FROM sessions WHERE id = ${row.session_id}`;
    return null;
  }
  if (row.banned_until && new Date(row.banned_until).getTime() > Date.now()) {
    return null;
  }
  // Touch glissant (sans prolonger l'expiration absolue).
  await sql`UPDATE sessions SET last_seen_at = now() WHERE id = ${row.session_id}`;
  return { id: row.user_id, email: row.email };
}

export async function destroySession(token: string | undefined): Promise<void> {
  if (!token) return;
  await getDb()`DELETE FROM sessions WHERE token_hash = ${hashToken(token)}`;
}

/** Invalide toutes les sessions du compte sauf celle courante (changement de mot de passe). */
export async function destroyOtherSessions(userId: string, keepToken: string | undefined): Promise<void> {
  if (keepToken) {
    await getDb()`DELETE FROM sessions WHERE user_id = ${userId} AND token_hash <> ${hashToken(keepToken)}`;
  } else {
    await getDb()`DELETE FROM sessions WHERE user_id = ${userId}`;
  }
}

// ── Provisionnement de compte ────────────────────────────────────────────────

export async function isSignupEnabled(): Promise<boolean> {
  const rows = await getDb()<{ value: boolean }[]>`
    SELECT value FROM platform_settings WHERE key = 'signup_enabled'
  `;
  return rows[0]?.value !== false;
}

/**
 * Crée le compte + profil + rôle applicatif + coffre personnel, en transaction.
 * Le tout premier compte de la plateforme devient SUPER_ADMIN.
 * Refuse si les inscriptions sont fermées ou si l'email existe déjà.
 */
export async function provisionUser(
  email: string,
  passwordHash: string | null,
  displayName?: string | null,
): Promise<string> {
  const sql = getDb();
  return sql.begin(async (tx) => {
    const gate = await tx<{ value: boolean }[]>`
      SELECT value FROM platform_settings WHERE key = 'signup_enabled'
    `;
    if (gate.length > 0 && gate[0]!.value === false) throw new Error("signup_disabled");

    const existing = await tx<{ id: string }[]>`
      SELECT id FROM users WHERE lower(email) = lower(${email})
    `;
    if (existing.length > 0) throw new Error("account_exists");

    const inserted = await tx<{ id: string }[]>`
      INSERT INTO users (email, password_hash) VALUES (${email}, ${passwordHash}) RETURNING id
    `;
    const userId = inserted[0]!.id;
    const name = displayName ?? email.split("@")[0] ?? email;
    await tx`
      INSERT INTO profiles (id, email, display_name) VALUES (${userId}, ${email}, ${name})
    `;
    const admins = await tx<{ x: number }[]>`
      SELECT 1 AS x FROM user_roles WHERE role = 'SUPER_ADMIN' LIMIT 1
    `;
    await tx`
      INSERT INTO user_roles (user_id, role)
      VALUES (${userId}, ${admins.length === 0 ? "SUPER_ADMIN" : "USER"}::app_role)
    `;
    const ws = await tx<{ id: string }[]>`
      INSERT INTO workspaces (name, is_personal, owner_id)
      VALUES ('Personal Vault', true, ${userId}) RETURNING id
    `;
    await tx`
      INSERT INTO workspace_members (workspace_id, user_id, role)
      VALUES (${ws[0]!.id}, ${userId}, 'OWNER')
    `;
    return userId;
  });
}

/** Connexion SSO : retrouve le compte par email ou le provisionne (sans mot de passe). */
export async function findOrCreateOidcUser(email: string, displayName: string): Promise<string> {
  const existing = await getDb()<{ id: string }[]>`
    SELECT id FROM users WHERE lower(email) = lower(${email})
  `;
  if (existing[0]) return existing[0].id;
  return provisionUser(email, null, displayName);
}
