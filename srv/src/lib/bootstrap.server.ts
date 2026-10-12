// Initialisation au démarrage — SERVER ONLY.
//
// Exécutée une fois par processus, avant de servir la première requête :
//   1. vérifie la clé maître ;
//   2. applique les migrations de schéma ;
//   3. amorce le compte SUPER_ADMIN (ADMIN_EMAIL / ADMIN_PASSWORD) ;
//   4. accorde au rôle de métriques l'accès à sa seule vue ;
//   5. ré-enveloppe ce qui est encore chiffré par l'ancienne clé maître ;
//   6. lance la maintenance périodique (purges) et prépare l'arrêt propre.
// Tout est idempotent et sûr avec plusieurs pods démarrant en parallèle.
import { audit } from "./audit.server";
import {
  assertMasterKeyConfigured,
  decryptWithMaster,
  encryptWithMaster,
  getKeyProvider,
  isWrappedWithCurrentKey,
} from "./crypto.server";
import { getDb } from "./db.server";
import { runMigrations } from "./migrate.server";
import { OIDC_CLIENT_SECRET_CONTEXT } from "./oidc.server";
import { hashPassword, provisionUser } from "./session.server";

let ready: Promise<void> | undefined;

/** Idempotent ; un échec (base injoignable…) sera retenté à l'appel suivant. */
export function ensureBootstrapped(): Promise<void> {
  ready ??= bootstrap().catch((err) => {
    ready = undefined;
    throw err;
  });
  return ready;
}

async function bootstrap(): Promise<void> {
  await assertMasterKeyConfigured();
  const applied = await runMigrations();
  if (applied.length > 0) console.log(`migrations_applied ${applied.join(", ")}`);
  await ensureAdminAccount();
  await grantMetricsAccess();
  await rewrapWithCurrentMasterKey();
  startMaintenance();
  closeDatabaseOnShutdown();
}

let shutdownRegistered = false;

/**
 * Le serveur HTTP s'arrête proprement sur SIGTERM, mais les connexions
 * PostgreSQL ouvertes retiendraient le processus jusqu'au SIGKILL de
 * l'orchestrateur : on ferme donc le pool au même signal.
 */
function closeDatabaseOnShutdown(): void {
  if (shutdownRegistered) return;
  shutdownRegistered = true;
  const close = () => void getDb().end({ timeout: 5 }).catch(() => undefined);
  process.once("SIGTERM", close);
  process.once("SIGINT", close);
}

/**
 * Aucun compte ne devient administrateur par inscription. Tant que la
 * plateforme n'a pas de SUPER_ADMIN, il est créé (ou promu, si le compte
 * existe déjà) à partir de ADMIN_EMAIL / ADMIN_PASSWORD.
 */
async function ensureAdminAccount(): Promise<void> {
  const sql = getDb();
  const admins = await sql`SELECT 1 FROM user_roles WHERE role = 'SUPER_ADMIN' LIMIT 1`;
  if (admins.length > 0) return;

  const email = process.env["ADMIN_EMAIL"]?.trim();
  const password = process.env["ADMIN_PASSWORD"];
  if (!email || !password) {
    console.warn(
      "no_super_admin: définissez ADMIN_EMAIL et ADMIN_PASSWORD pour amorcer le compte administrateur",
    );
    return;
  }
  if (password.length < 12) {
    throw new Error("ADMIN_PASSWORD doit contenir au moins 12 caractères");
  }

  const passwordHash = await hashPassword(password);
  const userId = await sql.begin(async (tx) => {
    // Sérialise les pods : un seul amorce le compte.
    await tx`SELECT pg_advisory_xact_lock(7430116::bigint)`;
    const again = await tx`SELECT 1 FROM user_roles WHERE role = 'SUPER_ADMIN' LIMIT 1`;
    if (again.length > 0) return null;
    const existing = await tx<{ id: string }[]>`
      SELECT id FROM users WHERE lower(email) = lower(${email})
    `;
    if (existing[0]) {
      await tx`
        INSERT INTO user_roles (user_id, role) VALUES (${existing[0].id}, 'SUPER_ADMIN')
        ON CONFLICT (user_id, role) DO NOTHING
      `;
      return existing[0].id;
    }
    return provisionUser(
      email,
      passwordHash,
      { role: "SUPER_ADMIN", bypassSignupGate: true },
      tx,
    );
  });
  if (userId) {
    await audit({
      userId,
      actorEmail: email,
      action: "admin.bootstrap",
      targetType: "user",
      targetId: userId,
    });
    console.log(`super_admin_bootstrapped ${email}`);
  }
}

/**
 * Le rôle de métriques (METRICS_DB_ROLE, défaut « exporter ») ne lit que la
 * vue secret_expiry_metrics. Sans effet si le rôle n'existe pas.
 */
async function grantMetricsAccess(): Promise<void> {
  const role = process.env["METRICS_DB_ROLE"] ?? "exporter";
  if (!/^[a-z_][a-z0-9_]*$/i.test(role)) {
    console.warn(`metrics_role_ignored: nom de rôle invalide « ${role} »`);
    return;
  }
  const sql = getDb();
  const exists = await sql`SELECT 1 FROM pg_roles WHERE rolname = ${role}`;
  if (exists.length === 0) return;
  try {
    await sql.unsafe(`GRANT USAGE ON SCHEMA public TO "${role}"`);
    await sql.unsafe(`GRANT SELECT ON public.secret_expiry_metrics TO "${role}"`);
  } catch (err) {
    console.warn("metrics_grant_failed", (err as Error).message);
  }
}

/** Rotation de clé maître : ré-enveloppe DEK et secret OIDC sous la clé courante. */
async function rewrapWithCurrentMasterKey(): Promise<void> {
  const sql = getDb();
  const provider = getKeyProvider();
  let rewrapped = 0;

  const keys = await sql<{ workspace_id: string; wrapped_dek: string }[]>`
    SELECT workspace_id, wrapped_dek FROM encryption_keys
  `;
  for (const row of keys) {
    if (await isWrappedWithCurrentKey(row.wrapped_dek)) continue;
    try {
      const dek = await provider.unwrapKey(row.wrapped_dek, row.workspace_id);
      const wrapped = await provider.wrapKey(dek, row.workspace_id);
      // La condition sur l'ancienne valeur évite d'écraser le travail d'un autre pod.
      const updated = await sql`
        UPDATE encryption_keys
        SET wrapped_dek = ${wrapped}, key_version = key_version + 1
        WHERE workspace_id = ${row.workspace_id} AND wrapped_dek = ${row.wrapped_dek}
      `;
      rewrapped += updated.count;
    } catch {
      console.error(
        `dek_unwrap_failed workspace=${row.workspace_id}: clé maître courante et précédente toutes deux incorrectes`,
      );
    }
  }

  const providers = await sql<{ id: string; client_secret_ciphertext: string }[]>`
    SELECT id, client_secret_ciphertext FROM oidc_providers
    WHERE client_secret_ciphertext IS NOT NULL
  `;
  for (const row of providers) {
    if (await isWrappedWithCurrentKey(row.client_secret_ciphertext)) continue;
    try {
      const secret = await decryptWithMaster(row.client_secret_ciphertext, OIDC_CLIENT_SECRET_CONTEXT);
      const ciphertext = await encryptWithMaster(secret, OIDC_CLIENT_SECRET_CONTEXT);
      await sql`
        UPDATE oidc_providers SET client_secret_ciphertext = ${ciphertext}
        WHERE id = ${row.id} AND client_secret_ciphertext = ${row.client_secret_ciphertext}
      `;
      rewrapped += 1;
    } catch {
      console.error(`oidc_secret_decrypt_failed provider=${row.id}`);
    }
  }

  if (rewrapped > 0) console.log(`master_key_rewrap ${rewrapped} valeur(s) ré-enveloppée(s)`);
}

const MAINTENANCE_INTERVAL_MS = 60 * 60_000;
let maintenanceTimer: ReturnType<typeof setInterval> | undefined;

/** Rétention du journal d'audit en jours (AUDIT_RETENTION_DAYS, 0 = illimitée). */
function auditRetentionDays(): number {
  const days = Number(process.env["AUDIT_RETENTION_DAYS"] ?? 365);
  return Number.isFinite(days) && days > 0 ? Math.floor(days) : 0;
}

export async function runMaintenance(): Promise<void> {
  const sql = getDb();
  await sql`DELETE FROM sessions WHERE expires_at < now()`;
  await sql`DELETE FROM auth_attempts WHERE created_at < now() - interval '1 day'`;
  const retention = auditRetentionDays();
  if (retention > 0) {
    await sql`
      DELETE FROM audit_logs WHERE created_at < now() - make_interval(days => ${retention})
    `;
  }
}

function startMaintenance(): void {
  if (maintenanceTimer) return;
  const tick = () =>
    void runMaintenance().catch((err) => console.error("maintenance_failed", (err as Error).message));
  tick();
  maintenanceTimer = setInterval(tick, MAINTENANCE_INTERVAL_MS);
  // Ne retient pas le processus à l'arrêt.
  maintenanceTimer.unref?.();
}
