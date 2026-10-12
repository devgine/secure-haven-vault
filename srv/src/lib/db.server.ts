// Accès base de données — SERVER ONLY.
// Connexion directe à PostgreSQL via postgres.js : l'autorisation est appliquée
// par les fonctions serveur (vault.server.ts) avant chaque requête.
import postgres from "postgres";

let _sql: postgres.Sql | undefined;

function connect(): postgres.Sql {
  // Les NOTICE PostgreSQL (« existe déjà, ignoré »…) ne sont pas journalisés.
  const options = { max: 10, onnotice: () => undefined };
  const url = process.env["DATABASE_URL"];
  if (url) return postgres(url, options);
  // Variables PG* standards : identifiants passés tels quels au driver, donc
  // aucun encodage d'URL à prévoir pour les mots de passe.
  const host = process.env["PGHOST"];
  if (host) {
    return postgres({
      ...options,
      host,
      port: Number(process.env["PGPORT"] ?? 5432),
      database: process.env["PGDATABASE"] ?? "postgres",
      username: process.env["PGUSER"] ?? "postgres",
      password: process.env["PGPASSWORD"] ?? "",
    });
  }
  throw new Error("DATABASE_URL is not configured");
}

export function getDb(): postgres.Sql {
  if (!_sql) _sql = connect();
  return _sql;
}

export type Tx = postgres.Sql | postgres.TransactionSql;

/** postgres.js renvoie les timestamptz en Date : normalise en ISO string. */
export function iso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

export function isoOrNull(value: unknown): string | null {
  if (value == null) return null;
  return iso(value);
}
