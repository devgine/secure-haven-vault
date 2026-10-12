// Secours : régénère le mot de passe du compte administrateur (ADMIN_EMAIL)
// quand il a été perdu. À lancer là où tourne l'application, avec le même
// environnement (connexion PostgreSQL) :
//
//   production  kubectl exec deploy/<release> -- node /app/bin/reset-admin-password.mjs
//   compose     task admin:reset-password
//
// Un autre compte peut être visé :  … reset-admin-password.mjs autre@exemple.com
//
// Le nouveau mot de passe est généré ici et affiché UNE fois ; il n'est jamais
// passé en argument (donc absent de l'historique du shell). Le compte est
// aussi débloqué, rétabli SUPER_ADMIN, et toutes ses sessions sont fermées.
// S'il n'existe pas, il est créé. L'opération est tracée au journal d'audit.
import { randomBytes } from "node:crypto";
import { getDb } from "../src/lib/db.server";
import { hashPassword, provisionUser } from "../src/lib/session.server";

async function main(): Promise<number> {
  const email = (process.argv[2] ?? process.env["ADMIN_EMAIL"] ?? "").trim();
  if (!email || !email.includes("@")) {
    console.error(
      "Aucun compte visé : définissez ADMIN_EMAIL ou passez l'adresse en argument.",
    );
    return 1;
  }

  const password = randomBytes(18).toString("base64url");
  const passwordHash = await hashPassword(password);
  const sql = getDb();

  const created = await sql.begin(async (tx) => {
    const users = await tx<{ id: string }[]>`
      SELECT id FROM users WHERE lower(email) = lower(${email}) FOR UPDATE
    `;
    let userId = users[0]?.id;
    const isNew = !userId;
    if (userId) {
      await tx`
        UPDATE users SET password_hash = ${passwordHash}, banned_until = NULL
        WHERE id = ${userId}
      `;
    } else {
      userId = await provisionUser(
        email,
        passwordHash,
        { role: "SUPER_ADMIN", bypassSignupGate: true },
        tx,
      );
    }
    await tx`
      INSERT INTO user_roles (user_id, role) VALUES (${userId}, 'SUPER_ADMIN')
      ON CONFLICT (user_id, role) DO NOTHING
    `;
    // Sessions existantes fermées, compteur d'échecs de connexion remis à zéro.
    await tx`DELETE FROM sessions WHERE user_id = ${userId}`;
    await tx`
      DELETE FROM auth_attempts
      WHERE subject = lower(${email}) OR subject = ${userId}
    `;
    await tx`
      INSERT INTO audit_logs (user_id, actor_email, action, target_type, target_id, target_label)
      VALUES (${userId}, ${email}, 'admin.password_reset_cli', 'user', ${userId},
              ${isNew ? "compte créé" : "mot de passe régénéré"})
    `;
    return isNew;
  });

  console.log(created ? `Compte créé : ${email}` : `Mot de passe régénéré : ${email}`);
  console.log(`Nouveau mot de passe : ${password}`);
  console.log("Connectez-vous puis changez-le dans Paramètres.");
  return 0;
}

let code = 1;
try {
  code = await main();
} catch (err) {
  console.error("Échec :", (err as Error).message);
}
try {
  await getDb().end({ timeout: 5 });
} catch {
  // Connexion jamais établie : rien à fermer.
}
process.exit(code);
