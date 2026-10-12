// Limitation de débit des opérations d'authentification — SERVER ONLY.
//
// Les compteurs vivent en base (table auth_attempts) : ils sont donc partagés
// entre tous les pods et survivent aux redémarrages.
import { getDb } from "./db.server";

export type AttemptKind = "login" | "signup" | "password";

interface Limit {
  windowMinutes: number;
  /** Échecs tolérés pour un même sujet (email ou compte) sur la fenêtre. */
  perSubject: number;
  /** Tentatives tolérées pour une même adresse IP sur la fenêtre. */
  perIp: number;
  /** Compte aussi les réussites (création de compte). */
  countSuccess: boolean;
}

const LIMITS: Record<AttemptKind, Limit> = {
  login: { windowMinutes: 15, perSubject: 5, perIp: 30, countSuccess: false },
  signup: { windowMinutes: 60, perSubject: 5, perIp: 10, countSuccess: true },
  password: { windowMinutes: 15, perSubject: 5, perIp: 30, countSuccess: false },
};

export class ThrottledError extends Error {
  constructor() {
    super("Trop de tentatives. Réessayez dans quelques minutes.");
  }
}

export interface AttemptKey {
  /** Email (connexion, inscription) ou identifiant de compte (mot de passe). */
  subject: string;
  ip: string | null;
}

export async function assertNotThrottled(kind: AttemptKind, key: AttemptKey): Promise<void> {
  const limit = LIMITS[kind];
  const subject = key.subject.toLowerCase();
  const rows = await getDb()<{ by_subject: number; by_ip: number }[]>`
    SELECT
      count(*) FILTER (WHERE subject = ${subject})::int AS by_subject,
      count(*) FILTER (WHERE ip = ${key.ip})::int AS by_ip
    FROM auth_attempts
    WHERE kind = ${kind}
      AND created_at > now() - make_interval(mins => ${limit.windowMinutes})
      AND (${limit.countSuccess} OR success = false)
      AND (subject = ${subject} OR ip = ${key.ip})
  `;
  const counts = rows[0];
  if (!counts) return;
  if (counts.by_subject >= limit.perSubject || counts.by_ip >= limit.perIp) {
    throw new ThrottledError();
  }
}

export async function recordAttempt(
  kind: AttemptKind,
  key: AttemptKey,
  success: boolean,
): Promise<void> {
  const subject = key.subject.toLowerCase();
  const sql = getDb();
  if (success && !LIMITS[kind].countSuccess) {
    // Une réussite remet le compteur d'échecs du sujet à zéro.
    await sql`DELETE FROM auth_attempts WHERE kind = ${kind} AND subject = ${subject}`;
    return;
  }
  await sql`
    INSERT INTO auth_attempts (kind, subject, ip, success)
    VALUES (${kind}, ${subject}, ${key.ip}, ${success})
  `;
}
