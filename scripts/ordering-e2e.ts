// E2E serveur du glisser-déposer (organisation manuelle) — PostgreSQL local.
//   DATABASE_URL=... MASTER_ENCRYPTION_KEY=... bun scripts/ordering-e2e.ts
//
// Couvre : réordonnancement atomique, déplacement entre groupes, positions
// contiguës, anti-cycle, contrôle de version (édition concurrente),
// permissions, journal d'audit, et non-altération du contenu des secrets.
import { getDb } from "../src/lib/db.server";
import { provisionUser } from "../src/lib/session.server";
import { nextPosition } from "../src/lib/folders.server";
import { moveItems, currentTreeVersion, OrderConflictError } from "../src/lib/ordering.server";
import { requireWorkspacePermission } from "../src/lib/vault.server";
import { audit } from "../src/lib/audit.server";

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

async function mkFolder(ws: string, parentId: string | null, name: string) {
  const position = await nextPosition(sql, ws, parentId);
  const rows = await sql<{ id: string }[]>`
    INSERT INTO secret_folders (workspace_id, parent_id, name, position)
    VALUES (${ws}, ${parentId}, ${name}, ${position}) RETURNING id
  `;
  return rows[0]!.id;
}

async function mkSecret(ws: string, folderId: string | null, name: string) {
  const rows = await sql<{ id: string }[]>`
    INSERT INTO secrets (workspace_id, folder_id, name, position)
    VALUES (${ws}, ${folderId}, ${name},
      (SELECT coalesce(max(position), -1) + 1 FROM secrets
        WHERE workspace_id = ${ws} AND folder_id IS NOT DISTINCT FROM ${folderId} AND deleted_at IS NULL))
    RETURNING id
  `;
  return rows[0]!.id;
}

const folderOrder = async (ws: string, parentId: string | null) =>
  (
    await sql<{ name: string; position: number }[]>`
      SELECT name, position FROM secret_folders
      WHERE workspace_id = ${ws} AND parent_id IS NOT DISTINCT FROM ${parentId} AND deleted_at IS NULL
      ORDER BY position ASC
    `
  ).map((r) => r.name);

const secretOrder = async (ws: string, folderId: string | null) =>
  (
    await sql<{ name: string; position: number }[]>`
      SELECT name, position FROM secrets
      WHERE workspace_id = ${ws} AND folder_id IS NOT DISTINCT FROM ${folderId} AND deleted_at IS NULL
      ORDER BY position ASC
    `
  ).map((r) => r.name);

const positions = async (ws: string, folderId: string | null) =>
  (
    await sql<{ position: number }[]>`
      SELECT position FROM secrets
      WHERE workspace_id = ${ws} AND folder_id IS NOT DISTINCT FROM ${folderId} AND deleted_at IS NULL
      ORDER BY position ASC
    `
  ).map((r) => r.position);

async function main() {
  const ownerId = await provisionUser(`owner+${crypto.randomUUID()}@test.local`, null);
  const viewerId = await provisionUser(`viewer+${crypto.randomUUID()}@test.local`, null);
  const ws = (
    await sql<{ id: string }[]>`
      INSERT INTO workspaces (name, owner_id) VALUES ('Coffre DnD', ${ownerId}) RETURNING id
    `
  )[0]!.id;
  await sql`INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (${ws}, ${ownerId}, 'OWNER')`;
  await sql`INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (${ws}, ${viewerId}, 'VIEWER')`;

  const infra = await mkFolder(ws, null, "Infra");
  const clients = await mkFolder(ws, null, "Clients");
  const prod = await mkFolder(ws, infra, "Prod");
  const staging = await mkFolder(ws, infra, "Staging");

  const s1 = await mkSecret(ws, null, "Racine 1");
  const s2 = await mkSecret(ws, null, "Racine 2");
  const s3 = await mkSecret(ws, null, "Racine 3");
  const p1 = await mkSecret(ws, prod, "Prod 1");

  const base = { workspaceId: ws, userId: ownerId, expectedVersion: -1 as number };

  // 1. Réordonnancement de groupes racine
  await moveItems({ ...base, kind: "folder", ids: [clients], parentId: null, index: 0 });
  check("groupe déplacé en tête", (await folderOrder(ws, null))[0] === "Clients");

  // 2. Déplacement d'un groupe dans un autre
  await moveItems({ ...base, kind: "folder", ids: [staging], parentId: clients, index: 0 });
  check("groupe déplacé de conteneur", (await folderOrder(ws, clients)).join() === "Staging");
  check("ancien conteneur renuméroté", (await folderOrder(ws, infra)).join() === "Prod");
  check(
    "positions contiguës après déplacement",
    (
      await sql<{ position: number }[]>`
        SELECT position FROM secret_folders WHERE parent_id = ${infra} AND deleted_at IS NULL ORDER BY position
      `
    ).every((r, i) => r.position === i),
  );

  // 3. Anti-cycle
  await expectThrows("refus du dépôt dans soi-même", () =>
    moveItems({ ...base, kind: "folder", ids: [clients], parentId: clients, index: 0 }),
  );
  await expectThrows("refus du dépôt dans sa descendance", () =>
    moveItems({ ...base, kind: "folder", ids: [clients], parentId: staging, index: 0 }),
  );

  // 4. Réordonnancement de secrets à la racine
  await moveItems({ ...base, kind: "secret", ids: [s3], parentId: null, index: 0 });
  check("secret remonté en tête", (await secretOrder(ws, null)).join() === "Racine 3,Racine 1,Racine 2");
  // L'index est exprimé dans la liste affichée (élément déplacé inclus).
  await moveItems({ ...base, kind: "secret", ids: [s3], parentId: null, index: 3 });
  check("secret redescendu", (await secretOrder(ws, null)).join() === "Racine 1,Racine 2,Racine 3");
  check("positions 0..n sans trou", (await positions(ws, null)).join() === "0,1,2");

  // 5. Déplacement multiple vers un groupe
  await moveItems({ ...base, kind: "secret", ids: [s1, s2], parentId: prod, index: 0 });
  check("sélection multiple déplacée", (await secretOrder(ws, prod)).join() === "Racine 1,Racine 2,Prod 1");
  check("source renumérotée", (await positions(ws, null)).join() === "0");

  // 6. Le contenu du secret n'est pas modifié
  const row = (
    await sql<{ name: string; type: string; updated_at: Date }[]>`
      SELECT name, type, updated_at FROM secrets WHERE id = ${p1}
    `
  )[0]!;
  check("aucune altération du secret voisin", row.name === "Prod 1" && row.type === "LOGIN");

  // 7. Contrôle de version (édition concurrente)
  const v = await currentTreeVersion(ws);
  check("version incrémentée", v > 0);
  let conflict = false;
  try {
    await moveItems({
      workspaceId: ws,
      userId: ownerId,
      kind: "secret",
      ids: [p1],
      parentId: null,
      index: 0,
      expectedVersion: v - 1,
    });
  } catch (err) {
    conflict = err instanceof OrderConflictError;
  }
  check("conflit détecté sur version périmée", conflict);
  await moveItems({
    workspaceId: ws,
    userId: ownerId,
    kind: "secret",
    ids: [p1],
    parentId: null,
    index: 0,
    expectedVersion: v,
  });
  check("déplacement accepté avec la bonne version", (await secretOrder(ws, null))[0] === "Prod 1");
  check("version à nouveau incrémentée", (await currentTreeVersion(ws)) === v + 1);

  // 8. Permissions
  await expectThrows("lecteur : réordonnancement de groupes refusé", () =>
    requireWorkspacePermission(viewerId, ws, "folder.manage"),
  );
  await expectThrows("lecteur : réordonnancement de secrets refusé", () =>
    requireWorkspacePermission(viewerId, ws, "secret.update"),
  );

  // 9. Coffre inconnu / élément hors coffre
  const otherWs = (
    await sql<{ id: string }[]>`
      INSERT INTO workspaces (name, owner_id) VALUES ('Autre', ${ownerId}) RETURNING id
    `
  )[0]!.id;
  await expectThrows("secret d'un autre coffre refusé", () =>
    moveItems({ ...base, workspaceId: otherWs, kind: "secret", ids: [p1], parentId: null, index: 0 }),
  );

  // 10. Audit : métadonnées seulement
  await audit({
    userId: ownerId,
    workspaceId: ws,
    action: "secret.reordered",
    targetType: "secret",
    targetId: p1,
    targetLabel: "1 élément(s) → Racine du coffre (position 0)",
  });
  const logs = await sql<{ action: string; target_label: string }[]>`
    SELECT action, target_label FROM audit_logs WHERE workspace_id = ${ws} ORDER BY created_at DESC LIMIT 1
  `;
  check("journal d'audit écrit", logs[0]?.action === "secret.reordered");
  check("aucune valeur sensible journalisée", !/password|secret=|=/.test(logs[0]?.target_label ?? ""));

  // 11. Idempotence : rejouer le même déplacement ne change rien
  const before = await secretOrder(ws, null);
  await moveItems({ ...base, kind: "secret", ids: [p1], parentId: null, index: 0 });
  check("déplacement idempotent", (await secretOrder(ws, null)).join() === before.join());

  console.log(`\n${passed} tests OK, ${failures.length} échec(s)`);
  if (failures.length) {
    for (const f of failures) console.log(` - ${f}`);
    process.exitCode = 1;
  }
  await sql.end();
}

void main();
