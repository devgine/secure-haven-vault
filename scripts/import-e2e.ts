// E2E serveur de l'import KeePass — exécuté contre un PostgreSQL local.
//   DATABASE_URL=... MASTER_ENCRYPTION_KEY=... bun scripts/import-e2e.ts
//
// Couvre : permissions serveur (personnel, coffre autorisé, coffre interdit),
// doublons, reprise après interruption, double soumission, limites de taille,
// chiffrement avant stockage et absence de secret dans le journal d'audit.
import { getDb } from "../src/lib/db.server";
import { provisionUser } from "../src/lib/session.server";
import { getOrCreateDek, requireWorkspacePermission } from "../src/lib/vault.server";
import { decryptField } from "../src/lib/crypto.server";
import { ensureRootFolder, runImportBatch, MAX_ATTACHMENT_SIZE } from "../src/lib/import.server";
import type { ImportItemPayload } from "../src/lib/keepass/mapping";

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

function item(over: Partial<ImportItemPayload> = {}): ImportItemPayload {
  return {
    clientKey: crypto.randomUUID(),
    path: ["Travail", "Infra"],
    type: "LOGIN",
    name: "Entrée test",
    username: "alice",
    url: "https://example.test",
    description: "note",
    tags: ["import"],
    icon: null,
    sourceCreatedAt: null,
    sourceModifiedAt: null,
    fields: [
      { label: "Mot de passe", fieldType: "password", isSensitive: true, value: "valeur-fictive-1" },
      { label: "TOTP", fieldType: "totp", isSensitive: true, value: "seed-fictif" },
    ],
    attachments: [],
    ...over,
  };
}

async function newJob(userId: string, workspaceId: string, strategy = "skip") {
  const { folderId } = await ensureRootFolder(sql, workspaceId, `Import KeePass — ${crypto.randomUUID()}`);
  const rows = await sql<{ id: string }[]>`
    INSERT INTO import_jobs (user_id, workspace_id, root_folder_id, duplicate_strategy, planned_entries)
    VALUES (${userId}, ${workspaceId}, ${folderId}, ${strategy}, 10) RETURNING id
  `;
  return rows[0]!.id;
}

async function main() {
  const stamp = Date.now();
  const ownerId = await provisionUser(`owner-${stamp}@test.local`, null, "Owner");
  const viewerId = await provisionUser(`viewer-${stamp}@test.local`, null, "Viewer");
  const outsiderId = await provisionUser(`out-${stamp}@test.local`, null, "Outsider");

  const personal = (
    await sql<{ id: string }[]>`SELECT id FROM workspaces WHERE owner_id = ${ownerId} AND is_personal LIMIT 1`
  )[0]!.id;

  const team = (
    await sql<{ id: string }[]>`
      INSERT INTO workspaces (name, owner_id) VALUES ('Équipe test', ${ownerId}) RETURNING id`
  )[0]!.id;
  await sql`INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (${team}, ${ownerId}, 'OWNER')`;
  await sql`INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (${team}, ${viewerId}, 'VIEWER')`;

  // ── Permissions serveur ────────────────────────────────────────────────
  await requireWorkspacePermission(ownerId, personal, "secret.import");
  check("import autorisé dans l'espace personnel", true);
  await requireWorkspacePermission(ownerId, team, "secret.import");
  check("import autorisé dans un coffre d'équipe habilité", true);
  await expectThrows("import refusé pour un lecteur (VIEWER)", () =>
    requireWorkspacePermission(viewerId, team, "secret.import"),
  );
  await expectThrows("import refusé pour un non-membre (requête forgée)", () =>
    requireWorkspacePermission(outsiderId, team, "secret.import"),
  );

  const forgedJob = await newJob(ownerId, team);
  await expectThrows("lot refusé si le job appartient à un autre utilisateur", () =>
    runImportBatch({ userId: outsiderId, jobId: forgedJob, items: [item()], strategy: "skip", criteria: ["name"] }),
  );

  // ── Import nominal ─────────────────────────────────────────────────────
  const job = await newJob(ownerId, personal);
  const base = item({ clientKey: "kp-1" });
  let res = await runImportBatch({ userId: ownerId, jobId: job, items: [base], strategy: "skip", criteria: ["name", "username", "folder"] });
  check("entrée importée", res.imported === 1);
  check("arborescence de groupes créée", res.folders === 2);

  const stored = (
    await sql<{ id: string; folder_id: string; tags: string[] }[]>`
      SELECT id, folder_id, tags FROM secrets WHERE workspace_id = ${personal} AND name = 'Entrée test' LIMIT 1`
  )[0]!;
  check("secret rattaché à un dossier", Boolean(stored.folder_id));
  check("tags préservés", stored.tags.includes("import"));

  const fields = await sql<{ label: string; ciphertext: string; is_sensitive: boolean }[]>`
    SELECT label, ciphertext, is_sensitive FROM secret_fields WHERE secret_id = ${stored.id}
  `;
  check("aucune valeur en clair en base", fields.every((f) => !f.ciphertext.includes("valeur-fictive-1")));
  check("champ TOTP marqué sensible", fields.find((f) => f.label === "TOTP")?.is_sensitive === true);
  const dek = await getOrCreateDek(personal);
  const clear = await decryptField(dek, fields.find((f) => f.label === "Mot de passe")!.ciphertext);
  check("déchiffrement correct après stockage", clear === "valeur-fictive-1");

  // ── Idempotence / reprise / double soumission ──────────────────────────
  res = await runImportBatch({ userId: ownerId, jobId: job, items: [base], strategy: "copy", criteria: ["name"] });
  check("rejeu de la même clé n'importe rien", res.imported === 0);
  const count = await sql<{ c: string }[]>`SELECT count(*) c FROM secrets WHERE workspace_id = ${personal} AND name = 'Entrée test'`;
  check("aucun doublon créé lors de la reprise", count[0]!.c === "1");

  const resumeJob = await newJob(ownerId, personal);
  const batch = [item({ clientKey: "kp-a", name: "Reprise A" }), item({ clientKey: "kp-b", name: "Reprise B" })];
  await runImportBatch({ userId: ownerId, jobId: resumeJob, items: [batch[0]!], strategy: "skip", criteria: ["name"] });
  const after = await runImportBatch({ userId: ownerId, jobId: resumeJob, items: batch, strategy: "skip", criteria: ["name"] });
  check("reprise après interruption n'importe que le reste", after.imported === 1);

  const concurrentJob = await newJob(ownerId, personal);
  const twice = await Promise.all([
    runImportBatch({ userId: ownerId, jobId: concurrentJob, items: [item({ clientKey: "kp-c", name: "Concurrent" })], strategy: "skip", criteria: ["name"] }),
    runImportBatch({ userId: ownerId, jobId: concurrentJob, items: [item({ clientKey: "kp-c", name: "Concurrent" })], strategy: "skip", criteria: ["name"] }),
  ]);
  check("import lancé deux fois n'écrit qu'une entrée", twice[0]!.imported + twice[1]!.imported === 1);

  // ── Stratégies de doublons ─────────────────────────────────────────────
  const dupSkip = await newJob(ownerId, personal);
  const skipRes = await runImportBatch({ userId: ownerId, jobId: dupSkip, items: [item({ clientKey: "kp-d", name: "Reprise A", path: [] })], strategy: "skip", criteria: ["name"] });
  check("stratégie ignorer détecte le doublon", skipRes.skipped === 1);

  const dupCopy = await newJob(ownerId, personal);
  const copyRes = await runImportBatch({ userId: ownerId, jobId: dupCopy, items: [item({ clientKey: "kp-e", name: "Reprise A", path: [] })], strategy: "copy", criteria: ["name"] });
  check("stratégie copie crée une nouvelle entrée", copyRes.imported === 1);

  const dupMerge = await newJob(ownerId, personal);
  const mergeRes = await runImportBatch({
    userId: ownerId,
    jobId: dupMerge,
    items: [item({ clientKey: "kp-f", name: "Reprise A", path: [], fields: [{ label: "Champ manquant", fieldType: "text", isSensitive: false, value: "x" }] })],
    strategy: "merge",
    criteria: ["name"],
  });
  check("stratégie fusion complète les champs manquants", mergeRes.merged === 1);

  const dupReplace = await newJob(ownerId, personal);
  const replaceRes = await runImportBatch({ userId: ownerId, jobId: dupReplace, items: [item({ clientKey: "kp-g", name: "Reprise B", path: [] })], strategy: "replace", criteria: ["name"] });
  check("stratégie remplacement remplace l'entrée", replaceRes.replaced === 1);
  const recoverable = await sql<{ c: string }[]>`
    SELECT count(*) c FROM secrets WHERE workspace_id = ${personal} AND name = 'Reprise B' AND deleted_at IS NOT NULL`;
  check("version précédente reste récupérable (corbeille)", Number(recoverable[0]!.c) >= 1);

  // ── Limites ────────────────────────────────────────────────────────────
  const limitJob = await newJob(ownerId, personal);
  const big = await runImportBatch({
    userId: ownerId,
    jobId: limitJob,
    items: [
      item({
        clientKey: "kp-h",
        name: "Avec pièce jointe",
        attachments: [
          { filename: "ok.txt", mimeType: "text/plain", size: 4, dataB64: "AQIDBA==" },
          { filename: "trop-gros.bin", mimeType: "application/octet-stream", size: MAX_ATTACHMENT_SIZE + 1, dataB64: "AA==" },
        ],
      }),
    ],
    strategy: "copy",
    criteria: ["name"],
  });
  check("entrée importée malgré une pièce jointe trop volumineuse", big.imported === 1);
  check("pièce jointe conforme stockée", big.attachments === 1);
  check("avertissement de dépassement de taille émis", big.warnings.length === 1);
  const attRow = (
    await sql<{ ciphertext: string }[]>`SELECT ciphertext FROM secret_attachments ORDER BY created_at DESC LIMIT 1`
  )[0]!;
  check("pièce jointe chiffrée avant stockage", !attRow.ciphertext.includes("AQIDBA=="));

  // ── Journal d'audit ────────────────────────────────────────────────────
  const logs = await sql<{ action: string; target_label: string | null }[]>`
    SELECT action, target_label FROM audit_logs WHERE user_id = ${ownerId}
  `;
  const dump = JSON.stringify(logs);
  check("aucun secret dans le journal", !dump.includes("valeur-fictive-1") && !dump.includes("seed-fictif"));

  console.log(`\n${passed} tests réussis, ${failures.length} échecs`);
  if (failures.length) {
    console.log(failures.map((f) => ` - ${f}`).join("\n"));
    process.exitCode = 1;
  }
  await sql.end();
}

await main();
