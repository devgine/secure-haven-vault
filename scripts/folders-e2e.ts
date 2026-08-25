// E2E serveur des groupes natifs — exécuté contre un PostgreSQL local.
//   DATABASE_URL=... MASTER_ENCRYPTION_KEY=... bun scripts/folders-e2e.ts
//
// Couvre : création/renommage/déplacement, anti-cycle, profondeur maximale,
// unicité des noms par niveau, suppression récursive vs remontée du contenu,
// et permissions (un lecteur ne peut pas gérer les groupes).
import { getDb } from "../src/lib/db.server";
import { provisionUser } from "../src/lib/session.server";
import { requireWorkspacePermission } from "../src/lib/vault.server";
import {
  descendantIds,
  folderDepth,
  folderPath,
  getFolder,
  nameTaken,
  nextPosition,
  subtreeHeight,
  directSecretCounts,
} from "../src/lib/folders.server";

const sql = getDb();
let passed = 0;
const failures: string[] = [];

function check(name: string, cond: boolean) {
  if (cond) {
    passed += 1;
    console.log(`  ok  ${name}`);
  } else {
    failures.push(name);
    console.log(`FAIL  ${name}`);
  }
}

async function expectThrows(name: string, fn: () => Promise<unknown>) {
  try {
    await fn();
    check(name, false);
  } catch {
    check(name, true);
  }
}

async function mkFolder(workspaceId: string, parentId: string | null, name: string) {
  const position = await nextPosition(sql, workspaceId, parentId);
  const rows = await sql<{ id: string }[]>`
    INSERT INTO secret_folders (workspace_id, parent_id, name, position)
    VALUES (${workspaceId}, ${parentId}, ${name}, ${position})
    RETURNING id
  `;
  return rows[0]!.id;
}

async function mkSecret(workspaceId: string, folderId: string | null, name: string) {
  const rows = await sql<{ id: string }[]>`
    INSERT INTO secrets (workspace_id, folder_id, name) VALUES (${workspaceId}, ${folderId}, ${name})
    RETURNING id
  `;
  return rows[0]!.id;
}

async function main() {
  const owner = await provisionUser({ email: `owner+${crypto.randomUUID()}@test.local`, password: "MotDePasse!123" });
  const viewer = await provisionUser({ email: `viewer+${crypto.randomUUID()}@test.local`, password: "MotDePasse!123" });
  const ws = (
    await sql<{ id: string }[]>`
      INSERT INTO workspaces (name, owner_id) VALUES ('Coffre équipe', ${owner.userId}) RETURNING id
    `
  )[0]!.id;
  await sql`INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (${ws}, ${owner.userId}, 'OWNER')`;
  await sql`INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (${ws}, ${viewer.userId}, 'VIEWER')`;

  // Permissions
  check(
    "un propriétaire peut gérer les groupes",
    (await requireWorkspacePermission(owner.userId, ws, "folder.manage")) === "OWNER",
  );
  await expectThrows("un lecteur ne peut pas créer de groupe", () =>
    requireWorkspacePermission(viewer.userId, ws, "folder.create"),
  );
  await expectThrows("un lecteur ne peut pas gérer les groupes", () =>
    requireWorkspacePermission(viewer.userId, ws, "folder.manage"),
  );

  // Arborescence
  const infra = await mkFolder(ws, null, "Infra");
  const prod = await mkFolder(ws, infra, "Prod");
  const bases = await mkFolder(ws, prod, "Bases");
  const perso = await mkFolder(ws, null, "Perso");

  check("chemin complet lisible", (await folderPath(sql, bases)) === "Infra / Prod / Bases");
  check("profondeur calculée", (await folderDepth(sql, bases)) === 3);
  check("hauteur de sous-arbre", (await subtreeHeight(sql, infra)) === 3);
  check("descendance complète", (await descendantIds(sql, infra)).sort().join() === [infra, prod, bases].sort().join());
  check("un groupe hors sous-arbre est exclu", !(await descendantIds(sql, infra)).includes(perso));

  // Unicité par niveau
  check("nom déjà pris détecté", await nameTaken(sql, ws, infra, "prod"));
  check("même nom autorisé sous un autre parent", !(await nameTaken(sql, ws, perso, "Prod")));
  check("le groupe lui-même est exclu du test d'unicité", !(await nameTaken(sql, ws, infra, "Prod", prod)));

  // Anti-cycle
  check("cycle détecté (parent dans sa descendance)", (await descendantIds(sql, infra)).includes(bases));

  // Compteurs
  await mkSecret(ws, infra, "s1");
  await mkSecret(ws, prod, "s2");
  await mkSecret(ws, prod, "s3");
  await mkSecret(ws, null, "s4");
  const counts = await directSecretCounts(ws);
  check("compte direct par groupe", counts[infra] === 1 && counts[prod] === 2);
  check("les secrets sans groupe ne sont pas comptés", counts["null"] === undefined);

  // Suppression « detach » : contenu remonté d'un cran
  const movedSecrets = await sql<{ id: string }[]>`
    UPDATE secrets SET folder_id = ${infra} WHERE folder_id = ${prod} AND deleted_at IS NULL RETURNING id
  `;
  await sql`UPDATE secret_folders SET parent_id = ${infra} WHERE parent_id = ${prod}`;
  await sql`DELETE FROM secret_folders WHERE id = ${prod}`;
  check("remontée du contenu au parent", movedSecrets.length === 2);
  check("groupe supprimé", (await getFolder(sql, prod)) === null);
  check("sous-groupe rattaché au parent", (await getFolder(sql, bases))!.parent_id === infra);
  check("secrets conservés", (await sql`SELECT id FROM secrets WHERE folder_id = ${infra} AND deleted_at IS NULL`).length === 3);

  // Suppression récursive : secrets en corbeille, jamais détruits
  const ids = await descendantIds(sql, infra);
  const trashed = await sql<{ id: string }[]>`
    UPDATE secrets SET deleted_at = now() WHERE folder_id = ANY(${sql.array(ids)}) AND deleted_at IS NULL RETURNING id
  `;
  await sql`UPDATE secret_folders SET deleted_at = now() WHERE id = ANY(${sql.array(ids)})`;
  check("secrets envoyés à la corbeille", trashed.length === 3);
  check(
    "aucun secret détruit",
    (await sql`SELECT id FROM secrets WHERE workspace_id = ${ws} AND deleted_at IS NOT NULL`).length === 3,
  );
  check("groupes marqués supprimés", (await getFolder(sql, infra)) === null);
  check(
    "les groupes supprimés ne sont plus listés",
    (await sql`SELECT id FROM secret_folders WHERE workspace_id = ${ws} AND deleted_at IS NULL`).length === 1,
  );

  console.log(`\n${passed} tests OK, ${failures.length} échec(s)`);
  if (failures.length) {
    for (const f of failures) console.log(` - ${f}`);
    process.exitCode = 1;
  }
  await sql.end();
}

void main();
