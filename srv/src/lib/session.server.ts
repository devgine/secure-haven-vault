// Authentification maison — SERVER ONLY.
//
// - Mots de passe : scrypt (node:crypto), sel aléatoire 128 bits par compte.
//   Format stocké : "s1.<salt_b64>.<hash_b64>".
// - Sessions : jeton opaque 256 bits, seule son empreinte SHA-256 est stockée.
//   Durée 7 jours, last_seen glissant. Le jeton vit dans un cookie httpOnly.
import { createHash, randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import type postgres from "postgres";
import { getDb, type Tx } from "./db.server";
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

let dummyHash: Promise<string> | undefined;

/**
 * Vérifie le mot de passe en temps comparable que le compte existe ou non :
 * sans hash stocké, on calcule quand même un scrypt contre un hash factice.
 */
export async function verifyPasswordOrDummy(
  password: string,
  stored: string | null | undefined,
): Promise<boolean> {
  if (stored) return verifyPassword(password, stored);
  dummyHash ??= hashPassword(randomBytes(16).toString("hex"));
  await verifyPassword(password, await dummyHash);
  return false;
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
  // Touch glissant (sans prolonger l'expiration absolue), au plus une
  // écriture toutes les 5 minutes par session.
  await sql`
    UPDATE sessions SET last_seen_at = now()
    WHERE id = ${row.session_id} AND last_seen_at < now() - interval '5 minutes'
  `;
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

export interface ProvisionOptions {
  displayName?: string | null;
  /** Rôle applicatif du compte (défaut : USER). */
  role?: "SUPER_ADMIN" | "USER";
  /** Ignore la fermeture des inscriptions (amorçage administrateur). */
  bypassSignupGate?: boolean;
}

/**
 * Crée le compte + profil + rôle applicatif + coffre personnel, en transaction.
 * Refuse si les inscriptions sont fermées ou si l'email existe déjà. Aucun
 * compte ne devient administrateur par simple inscription : le SUPER_ADMIN
 * initial est amorcé par ADMIN_EMAIL / ADMIN_PASSWORD (bootstrap.server.ts).
 */
export async function provisionUser(
  email: string,
  passwordHash: string | null,
  options: ProvisionOptions = {},
  transaction?: postgres.TransactionSql,
): Promise<string> {
  const run = async (tx: Tx) => {
    if (!options.bypassSignupGate) {
      const gate = await tx<{ value: boolean }[]>`
        SELECT value FROM platform_settings WHERE key = 'signup_enabled'
      `;
      if (gate.length > 0 && gate[0]!.value === false) throw new Error("signup_disabled");
    }

    const existing = await tx<{ id: string }[]>`
      SELECT id FROM users WHERE lower(email) = lower(${email})
    `;
    if (existing.length > 0) throw new Error("account_exists");

    const inserted = await tx<{ id: string }[]>`
      INSERT INTO users (email, password_hash) VALUES (${email}, ${passwordHash}) RETURNING id
    `;
    const userId = inserted[0]!.id;
    const name = options.displayName ?? email.split("@")[0] ?? email;
    await tx`
      INSERT INTO profiles (id, email, display_name) VALUES (${userId}, ${email}, ${name})
    `;
    await tx`
      INSERT INTO user_roles (user_id, role)
      VALUES (${userId}, ${options.role ?? "USER"}::app_role)
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
  };
  // Réutilise la transaction de l'appelant quand il en fournit une.
  return transaction ? run(transaction) : getDb().begin(run);
}

export interface OidcLogin {
  providerId: string;
  subject: string;
  email: string;
  displayName: string;
}

/**
 * Connexion SSO. Le compte est identifié par le `sub` du fournisseur ; l'email
 * ne sert qu'au tout premier rattachement (l'appelant a déjà exigé un email
 * vérifié). Un compte déjà lié à un autre `sub` n'est jamais réattribué.
 */
export async function resolveOidcUser(
  login: OidcLogin,
): Promise<{ userId: string; linked: boolean }> {
  return getDb().begin(async (tx) => {
    const identities = await tx<{ user_id: string }[]>`
      SELECT user_id FROM oidc_identities
      WHERE provider_id = ${login.providerId} AND subject = ${login.subject}
    `;
    if (identities[0]) return { userId: identities[0].user_id, linked: false };

    const existing = await tx<{ id: string }[]>`
      SELECT id FROM users WHERE lower(email) = lower(${login.email})
    `;
    let userId = existing[0]?.id;
    if (userId) {
      const other = await tx<{ id: string }[]>`
        SELECT id FROM oidc_identities
        WHERE provider_id = ${login.providerId} AND user_id = ${userId}
      `;
      if (other.length > 0) throw new Error("identity_conflict");
    } else {
      userId = await provisionUser(login.email, null, { displayName: login.displayName }, tx);
    }
    await tx`
      INSERT INTO oidc_identities (provider_id, subject, user_id)
      VALUES (${login.providerId}, ${login.subject}, ${userId})
    `;
    return { userId, linked: true };
  });
}
