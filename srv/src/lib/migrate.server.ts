// Migrations de schéma — SERVER ONLY.
//
// Les fichiers src/migrations/*.sql sont embarqués dans le bundle serveur et
// appliqués au démarrage, une seule fois chacun, dans l'ordre de leur nom.
// Un verrou consultatif PostgreSQL sérialise les pods qui démarrent en même
// temps : un seul applique, les autres attendent puis constatent que tout est
// déjà en place.
import { getDb } from "./db.server";

const files = import.meta.glob<string>("../migrations/*.sql", {
  query: "?raw",
  import: "default",
  eager: true,
});

// Identifiant arbitraire mais stable du verrou consultatif.
const MIGRATION_LOCK_ID = 7430115;

export function listMigrations(): { name: string; sql: string }[] {
  return Object.entries(files)
    .map(([path, sql]) => ({ name: path.split("/").pop()!.replace(/\.sql$/, ""), sql }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export async function runMigrations(): Promise<string[]> {
  const applied: string[] = [];
  await getDb().begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(${MIGRATION_LOCK_ID}::bigint)`;
    await tx`
      CREATE TABLE IF NOT EXISTS public.schema_migrations (
        name text PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `;
    const done = new Set(
      (await tx<{ name: string }[]>`SELECT name FROM public.schema_migrations`).map((r) => r.name),
    );
    for (const migration of listMigrations()) {
      if (done.has(migration.name)) continue;
      await tx.unsafe(migration.sql);
      await tx`INSERT INTO public.schema_migrations (name) VALUES (${migration.name})`;
      applied.push(migration.name);
    }
  });
  return applied;
}
