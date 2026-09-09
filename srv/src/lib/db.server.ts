// Accès base de données — SERVER ONLY.
// Connexion directe à PostgreSQL via postgres.js. Plus aucune dépendance à
// Supabase : l'autorisation est appliquée par les fonctions serveur
// (vault.server.ts) avant chaque requête.
import postgres from "postgres";

let _sql: postgres.Sql | undefined;

function connectionUrl(): string {
  const url = process.env["DATABASE_URL"];
  if (url) return url;
  // Repli de développement : variables PG* standards (psql, outils locaux).
  const host = process.env["PGHOST"];
  if (host) {
    const user = process.env["PGUSER"] ?? "postgres";
    const password = process.env["PGPASSWORD"] ?? "";
    const port = process.env["PGPORT"] ?? "5432";
    const database = process.env["PGDATABASE"] ?? "postgres";
    return `postgres://${encodeURIComponent(user)}:${encodeURIComponent(password)}@${host}:${port}/${database}`;
  }
  throw new Error("DATABASE_URL is not configured");
}

export function getDb(): postgres.Sql {
  if (!_sql) {
    _sql = postgres(connectionUrl(), { max: 10 });
  }
  return _sql;
}

/** postgres.js renvoie les timestamptz en Date : normalise en ISO string. */
export function iso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

export function isoOrNull(value: unknown): string | null {
  if (value == null) return null;
  return iso(value);
}
