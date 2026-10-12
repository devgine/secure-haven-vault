// E2E HTTP de sécurité — exécuté contre l'application BUILDÉE (image runtime)
// et un PostgreSQL vierge. Appelle les fonctions serveur comme le navigateur,
// et joue un fournisseur OIDC factice pour le parcours SSO.
//
//   BASE_URL=http://app:3000 SELF_URL=http://<ce-conteneur>:9000 \
//   MANIFEST=<résolveur de fonctions serveur extrait de .output/server> \
//   ADMIN_EMAIL=... ADMIN_PASSWORD=... bun scripts/security-e2e.ts
//
// Couvre : amorçage admin, anti-brute-force, hiérarchie des rôles, suppression
// de compte sans perte de coffre, dossier d'un autre coffre, historique
// restaurable, changement de mot de passe, limite de taille, OIDC (PKCE,
// nonce, email vérifié, liaison par `sub`, synchronisation des groupes).
/* eslint-disable @typescript-eslint/no-explicit-any -- résultats RPC non typés */
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fromCrossJSON, toJSONAsync } from "seroval";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

const BASE = process.env["BASE_URL"]!;
const SELF = process.env["SELF_URL"]!;
const ADMIN_EMAIL = process.env["ADMIN_EMAIL"]!;
const ADMIN_PASSWORD = process.env["ADMIN_PASSWORD"]!;

const ids: Record<string, string> = {};
for (const m of readFileSync(process.env["MANIFEST"]!, "utf8").matchAll(
  /"([a-f0-9]{64})": \{\s*functionName: "(\w+)_createServerFn_handler"/g,
)) {
  ids[m[2]!] = m[1]!;
}

let passed = 0;
const failures: string[] = [];
function check(name: string, cond: boolean, detail?: unknown) {
  if (cond) passed += 1;
  else {
    failures.push(name);
    console.error(`✗ ${name}`, detail ?? "");
  }
}

class Client {
  cookies = new Map<string, string>();
  headers(extra: Record<string, string> = {}) {
    return {
      "x-tsr-serverFn": "true",
      accept: "application/json",
      origin: BASE,
      "sec-fetch-site": "same-origin",
      cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "),
      ...extra,
    };
  }
  absorb(res: Response) {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const [name, ...rest] = pair!.split("=");
      const value = rest.join("=");
      if (value === "" || /max-age=0/i.test(line)) this.cookies.delete(name!);
      else this.cookies.set(name!, value);
    }
  }
  /** Appelle une fonction serveur ; renvoie { result } ou { error }. */
  async call(fn: string, method: "GET" | "POST", data?: unknown): Promise<{ result?: any; error?: string; status: number }> {
    if (!ids[fn]) throw new Error(`fonction serveur inconnue : ${fn}`);
    const payload = data === undefined ? undefined : JSON.stringify(await toJSONAsync({ data }));
    let url = `${BASE}/_serverFn/${ids[fn]}`;
    const init: RequestInit = { method, headers: this.headers(), redirect: "manual" };
    if (method === "GET" && payload) url += `?${new URLSearchParams({ payload })}`;
    if (method === "POST" && payload) {
      init.body = payload;
      init.headers = this.headers({ "content-type": "application/json" });
    }
    const res = await fetch(url, init);
    this.absorb(res);
    const text = await res.text();
    try {
      const decoded = fromCrossJSON(JSON.parse(text), {
        refs: new Map(),
        plugins: [
          {
            tag: "$TSR/Error",
            test: () => false,
            parse: {} as never,
            serialize: () => "",
            deserialize: (node: any, ctx: any) => ({ message: ctx.deserialize(node.message) }),
          } as never,
        ],
      }) as { result?: unknown; error?: { message?: string } };
      return decoded.error
        ? { error: decoded.error.message ?? "error", status: res.status }
        : { result: decoded.result, status: res.status };
    } catch {
      return { error: `HTTP ${res.status}: ${text.slice(0, 200)}`, status: res.status };
    }
  }
}

async function signUp(email: string, password = "Password-123456") {
  const c = new Client();
  const r = await c.call("signUp", "POST", { email, password });
  if (r.error) throw new Error(`signUp ${email}: ${r.error}`);
  const info = await c.call("getSessionInfo", "GET");
  return { client: c, userId: info.result.userId as string, info: info.result };
}

// ── Fournisseur OIDC factice ────────────────────────────────────────────────
const { publicKey, privateKey } = await generateKeyPair("RS256");
const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" };
const pending = new Map<string, { claims: Record<string, unknown>; challenge: string }>();
Bun.serve({
  port: 9000,
  hostname: "0.0.0.0",
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/.well-known/openid-configuration") {
      return Response.json({
        issuer: SELF,
        authorization_endpoint: `${SELF}/authorize`,
        token_endpoint: `${SELF}/token`,
        jwks_uri: `${SELF}/jwks`,
      });
    }
    if (url.pathname === "/jwks") return Response.json({ keys: [jwk] });
    if (url.pathname === "/token") {
      const form = new URLSearchParams(await req.text());
      const entry = pending.get(form.get("code") ?? "");
      const verifier = form.get("code_verifier") ?? "";
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      if (!entry || challenge !== entry.challenge || form.get("client_secret") !== "idp-secret") {
        return Response.json({ error: "invalid_grant" }, { status: 400 });
      }
      const idToken = await new SignJWT(entry.claims)
        .setProtectedHeader({ alg: "RS256", kid: "k1" })
        .setIssuer(SELF)
        .setAudience("vault-client")
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(privateKey);
      return Response.json({ id_token: idToken, token_type: "Bearer", access_token: "x" });
    }
    return new Response("not found", { status: 404 });
  },
});

/** Joue un aller-retour SSO complet ; renvoie le client et le paramètre sso_error éventuel. */
async function sso(claims: Record<string, unknown>, opts: { tamperNonce?: boolean; tamperState?: boolean } = {}) {
  const c = new Client();
  const start = await fetch(`${BASE}/api/public/oidc/start`, { redirect: "manual" });
  c.absorb(start);
  const authorize = new URL(start.headers.get("location")!);
  const code = crypto.randomUUID();
  pending.set(code, {
    claims: { ...claims, nonce: opts.tamperNonce ? "autre" : authorize.searchParams.get("nonce") },
    challenge: authorize.searchParams.get("code_challenge")!,
  });
  const state = opts.tamperState ? "autre" : authorize.searchParams.get("state")!;
  const cb = await fetch(`${BASE}/api/public/oidc/callback?code=${code}&state=${state}`, {
    redirect: "manual",
    headers: { cookie: [...c.cookies].map(([k, v]) => `${k}=${v}`).join("; ") },
  });
  c.absorb(cb);
  const location = new URL(cb.headers.get("location")!);
  return { client: c, error: location.searchParams.get("sso_error"), authorize, startCookie: start.headers.getSetCookie()[0] ?? "" };
}

async function main() {
  const stamp = Date.now();
  const mail = (name: string) => `${name}-${stamp}@test.local`;

  // ── Amorçage administrateur ─────────────────────────────────────────────
  const admin = new Client();
  const login = await admin.call("signIn", "POST", { email: ADMIN_EMAIL, password: ADMIN_PASSWORD });
  check("le compte admin amorcé peut se connecter", login.result?.ok === true, login);
  const adminInfo = (await admin.call("getSessionInfo", "GET")).result;
  check("le compte amorcé est SUPER_ADMIN", adminInfo?.isSuperAdmin === true);
  check("recordAuthEvent n'est plus exposée", ids["recordAuthEvent"] === undefined);

  // ── Inscription : jamais d'élévation automatique ────────────────────────
  const alice = await signUp(mail("alice"));
  const bob = await signUp(mail("bob"));
  const carol = await signUp(mail("carol"));
  check("un compte inscrit n'est pas SUPER_ADMIN", alice.info.isSuperAdmin === false);
  check("un compte local a un mot de passe", alice.info.hasPassword === true);
  const anon = new Client();
  check("fonction protégée refusée sans session", Boolean((await anon.call("listWorkspaces", "GET")).error));

  // ── Anti-brute-force ────────────────────────────────────────────────────
  const victim = await signUp(mail("victim"), "Correct-Horse-1234");
  const attacker = new Client();
  for (let i = 0; i < 5; i++) {
    await attacker.call("signIn", "POST", { email: mail("victim"), password: "mauvais" });
  }
  const blocked = await attacker.call("signIn", "POST", { email: mail("victim"), password: "Correct-Horse-1234" });
  check("6e tentative bloquée même avec le bon mot de passe", /Trop de tentatives/.test(blocked.error ?? ""), blocked);
  void victim;

  // ── Hiérarchie des rôles ────────────────────────────────────────────────
  const ws = (await alice.client.call("createWorkspace", "POST", { name: `Équipe ${stamp}` })).result.id as string;
  const addBob = await alice.client.call("addMember", "POST", { workspaceId: ws, email: mail("bob"), role: "ADMIN" });
  check("OWNER ajoute un ADMIN", addBob.result?.ok === true, addBob);
  await alice.client.call("addMember", "POST", { workspaceId: ws, email: mail("carol"), role: "VIEWER" });

  const selfPromote = await bob.client.call("updateMemberRole", "POST", { workspaceId: ws, targetUserId: bob.userId, role: "OWNER" });
  check("ADMIN ne peut pas se promouvoir OWNER", Boolean(selfPromote.error), selfPromote);
  const promoteOther = await bob.client.call("updateMemberRole", "POST", { workspaceId: ws, targetUserId: carol.userId, role: "OWNER" });
  check("ADMIN ne peut pas nommer un OWNER", Boolean(promoteOther.error), promoteOther);
  const demoteOwner = await bob.client.call("updateMemberRole", "POST", { workspaceId: ws, targetUserId: alice.userId, role: "VIEWER" });
  check("ADMIN ne peut pas rétrograder l'OWNER", Boolean(demoteOwner.error), demoteOwner);
  const overwrite = await bob.client.call("addMember", "POST", { workspaceId: ws, email: mail("alice"), role: "VIEWER" });
  check("addMember n'écrase pas un membre existant", Boolean(overwrite.error), overwrite);
  const addOwner = await bob.client.call("addMember", "POST", { workspaceId: ws, email: mail("victim"), role: "OWNER" });
  check("ADMIN ne peut pas ajouter un OWNER", Boolean(addOwner.error), addOwner);
  const editorOk = await bob.client.call("updateMemberRole", "POST", { workspaceId: ws, targetUserId: carol.userId, role: "EDITOR" });
  check("ADMIN peut nommer un EDITOR", editorOk.result?.ok === true, editorOk);
  const lastOwner = await alice.client.call("updateMemberRole", "POST", { workspaceId: ws, targetUserId: alice.userId, role: "ADMIN" });
  check("le dernier OWNER ne peut pas se rétrograder", Boolean(lastOwner.error), lastOwner);
  const members = (await alice.client.call("listMembers", "GET", { workspaceId: ws })).result as { userId: string; role: string }[];
  check("rôles inchangés après les tentatives", members.find((m) => m.userId === alice.userId)?.role === "OWNER" && members.find((m) => m.userId === bob.userId)?.role === "ADMIN");

  // ── Secrets : transaction, dossier étranger, historique restaurable ─────
  const otherWs = (await bob.client.call("createWorkspace", "POST", { name: `Autre ${stamp}` })).result.id as string;
  const foreignFolder = (await bob.client.call("createFolder", "POST", { workspaceId: otherWs, name: "Étranger" })).result.id as string;
  const base = { workspaceId: ws, type: "LOGIN", name: "Compte prod", username: "root", tags: ["prod"] };
  const fields1 = [{ label: "Mot de passe", fieldType: "password", isSensitive: true, value: "valeur-v1" }];
  const foreign = await alice.client.call("createSecret", "POST", { ...base, folderId: foreignFolder, fields: fields1 });
  check("création refusée dans le dossier d'un autre coffre", Boolean(foreign.error), foreign);
  const badDate = await alice.client.call("createSecret", "POST", { ...base, expiresAt: "pas-une-date", fields: fields1 });
  check("date d'expiration invalide refusée", Boolean(badDate.error));
  const secretId = (await alice.client.call("createSecret", "POST", { ...base, expiresAt: "2030-01-01", fields: fields1 })).result.id as string;
  const { workspaceId: _ws, ...updatable } = base;
  const moved = await alice.client.call("updateSecret", "POST", { secretId, ...updatable, folderId: foreignFolder, fields: fields1 });
  check("modification refusée vers le dossier d'un autre coffre", Boolean(moved.error), moved);
  const upd = await alice.client.call("updateSecret", "POST", {
    secretId, ...updatable, name: "Compte prod (v2)",
    fields: [{ label: "Mot de passe", fieldType: "password", isSensitive: true, value: "valeur-v2" }, { label: "Note", fieldType: "text", isSensitive: false, value: "ajout" }],
  });
  check("mise à jour d'un secret", upd.result?.ok === true, upd);
  const reveal2 = (await alice.client.call("revealSecret", "POST", { secretId, action: "reveal" })).result as { label: string; value: string }[];
  check("valeur v2 lisible", reveal2.find((f) => f.label === "Mot de passe")?.value === "valeur-v2" && reveal2.length === 2, reveal2);
  const versions = (await alice.client.call("getSecretVersions", "GET", { secretId })).result as { id: string; version: number; restorable: boolean }[];
  check("deux versions restaurables", versions.length === 2 && versions.every((v) => v.restorable), versions);
  const v1 = versions.find((v) => v.version === 1)!;
  const viewerRestore = await (await (async () => { const d = await signUp(mail("dave")); await alice.client.call("addMember", "POST", { workspaceId: ws, email: mail("dave"), role: "VIEWER" }); return d.client; })()).call("restoreSecretVersion", "POST", { secretId, versionId: v1.id });
  check("un VIEWER ne peut pas restaurer", Boolean(viewerRestore.error), viewerRestore);
  const restored = await alice.client.call("restoreSecretVersion", "POST", { secretId, versionId: v1.id });
  check("restauration de la v1", restored.result?.restoredVersion === 1, restored);
  const reveal3 = (await alice.client.call("revealSecret", "POST", { secretId, action: "reveal" })).result as { label: string; value: string }[];
  check("valeurs v1 de retour", reveal3.length === 1 && reveal3[0]?.value === "valeur-v1", reveal3);
  const detail = (await alice.client.call("getSecret", "GET", { secretId })).result;
  check("métadonnées v1 de retour", detail.name === "Compte prod", detail?.name);
  const versions2 = (await alice.client.call("getSecretVersions", "GET", { secretId })).result as { version: number; action: string }[];
  check("la restauration crée une v3", versions2[0]?.version === 3 && versions2[0]?.action === "restored", versions2);

  // ── Mot de passe ────────────────────────────────────────────────────────
  const wrongCurrent = await carol.client.call("changePassword", "POST", { currentPassword: "faux", newPassword: "Nouveau-Mot-De-Passe-1" });
  check("changement refusé sans le mot de passe actuel", /actuel incorrect/.test(wrongCurrent.error ?? ""), wrongCurrent);
  const okChange = await carol.client.call("changePassword", "POST", { currentPassword: "Password-123456", newPassword: "Nouveau-Mot-De-Passe-1" });
  check("changement accepté avec le mot de passe actuel", okChange.result?.ok === true, okChange);
  const relog = await new Client().call("signIn", "POST", { email: mail("carol"), password: "Nouveau-Mot-De-Passe-1" });
  check("connexion avec le nouveau mot de passe", relog.result?.ok === true, relog);

  // ── Suppression de compte sans perte de coffre ──────────────────────────
  const refuse = await admin.call("deleteUserAccount", "POST", { targetUserId: alice.userId });
  check("suppression refusée pour l'unique propriétaire d'un coffre d'équipe", /unique propriétaire/.test(refuse.error ?? ""), refuse);
  await alice.client.call("updateMemberRole", "POST", { workspaceId: ws, targetUserId: bob.userId, role: "OWNER" });
  const del = await admin.call("deleteUserAccount", "POST", { targetUserId: alice.userId });
  check("suppression acceptée après nomination d'un autre propriétaire", del.result?.ok === true, del);
  const bobWs = (await bob.client.call("listWorkspaces", "GET")).result as { id: string; ownerId: string }[];
  check("le coffre d'équipe survit, propriété transférée", bobWs.find((w) => w.id === ws)?.ownerId === bob.userId, bobWs);
  const survived = (await bob.client.call("revealSecret", "POST", { secretId, action: "reveal" })).result as { value: string }[];
  check("les secrets du coffre restent déchiffrables", survived?.[0]?.value === "valeur-v1", survived);
  check("la session du compte supprimé est invalide", Boolean((await alice.client.call("listWorkspaces", "GET")).error));

  // ── Limite de taille de requête ─────────────────────────────────────────
  const huge = await fetch(`${BASE}/_serverFn/${ids["signIn"]}`, {
    method: "POST",
    headers: { ...new Client().headers(), "content-type": "application/json" },
    body: "x".repeat(25 * 1024 * 1024),
  });
  check("corps de 25 Mo rejeté (413)", huge.status === 413, huge.status);

  // ── OIDC ────────────────────────────────────────────────────────────────
  const save = await admin.call("saveOidcProvider", "POST", {
    name: "Faux IdP", issuerUrl: SELF, clientId: "vault-client", clientSecret: "idp-secret", enabled: true, permissionMode: "hybrid",
  });
  check("configuration OIDC enregistrée", save.result?.ok === true, save);
  await admin.call("saveOidcMapping", "POST", { idpGroup: "equipe", workspaceId: ws, role: "VIEWER" });

  const first = await sso({ sub: "sub-erin", email: mail("erin"), email_verified: true, groups: ["equipe"] });
  check("PKCE S256 + nonce demandés", first.authorize.searchParams.get("code_challenge_method") === "S256" && Boolean(first.authorize.searchParams.get("nonce")));
  check("cookie de transaction httpOnly + Secure", /HttpOnly/.test(first.startCookie) && /Secure/.test(first.startCookie), first.startCookie);
  check("connexion SSO d'un nouvel utilisateur", first.error === null && first.client.cookies.has("vault_session"), first.error);
  const erinInfo = (await first.client.call("getSessionInfo", "GET")).result;
  check("compte SSO sans mot de passe local", erinInfo?.hasPassword === false, erinInfo);
  const ssoPwd = await first.client.call("changePassword", "POST", { currentPassword: "x", newPassword: "Nouveau-Mot-De-Passe-1" });
  check("changement de mot de passe refusé pour un compte SSO", /SSO/.test(ssoPwd.error ?? ""), ssoPwd);
  const erinWs = (await first.client.call("listWorkspaces", "GET")).result as { id: string; role: string }[];
  check("adhésion issue du groupe IdP", erinWs.find((w) => w.id === ws)?.role === "VIEWER", erinWs);

  const unverified = await sso({ sub: "sub-x", email: mail("bob"), email_verified: false });
  check("email non vérifié refusé", unverified.error === "email_not_verified" && !unverified.client.cookies.has("vault_session"), unverified.error);
  const noClaim = await sso({ sub: "sub-x", email: mail("bob") });
  check("email sans claim email_verified refusé", noClaim.error === "email_not_verified", noClaim.error);
  const hijack = await sso({ sub: "sub-pirate", email: mail("erin"), email_verified: true });
  check("même email, autre `sub` : refusé", hijack.error === "identity_conflict" && !hijack.client.cookies.has("vault_session"), hijack.error);
  const badNonce = await sso({ sub: "sub-erin", email: mail("erin"), email_verified: true }, { tamperNonce: true });
  check("nonce incorrect refusé", badNonce.error === "invalid_token", badNonce.error);
  const badState = await sso({ sub: "sub-erin", email: mail("erin"), email_verified: true }, { tamperState: true });
  check("state incorrect refusé", badState.error === "invalid_state", badState.error);

  // Bob (OWNER manuel) se connecte en SSO sans le groupe : son adhésion manuelle reste.
  const bobSso = await sso({ sub: "sub-bob", email: mail("bob"), email_verified: true, groups: [] });
  check("liaison d'un compte local par email vérifié", bobSso.error === null, bobSso.error);
  const bobAfter = (await bobSso.client.call("listWorkspaces", "GET")).result as { id: string; role: string }[];
  check("adhésion manuelle OWNER préservée par la synchronisation", bobAfter.find((w) => w.id === ws)?.role === "OWNER", bobAfter);
  const bobSso2 = await sso({ sub: "sub-bob", email: "autre-adresse@test.local", email_verified: true, groups: ["equipe"] });
  const bobAgain = (await bobSso2.client.call("getSessionInfo", "GET")).result;
  check("identité suivie par `sub`, pas par email", bobAgain?.userId === bob.userId, bobAgain);
  const bobAfter2 = (await bobSso2.client.call("listWorkspaces", "GET")).result as { id: string; role: string }[];
  check("le groupe IdP ne rétrograde pas une adhésion manuelle", bobAfter2.find((w) => w.id === ws)?.role === "OWNER", bobAfter2);
  // Erin perd son groupe : son adhésion gérée par le SSO disparaît.
  const erinGone = await sso({ sub: "sub-erin", email: mail("erin"), email_verified: true, groups: [] });
  const erinWs2 = (await erinGone.client.call("listWorkspaces", "GET")).result as { id: string }[];
  check("adhésion SSO retirée quand le groupe disparaît", !erinWs2.some((w) => w.id === ws), erinWs2);

  // ── Déconnexion ─────────────────────────────────────────────────────────
  const out = await carol.client.call("signOut", "POST", { reason: "logout" });
  check("déconnexion", out.result?.ok === true, out);
  check("session invalide après déconnexion", Boolean((await carol.client.call("listWorkspaces", "GET")).error));

  console.log(`\n${passed} vérifications réussies, ${failures.length} échec(s)`);
  if (failures.length > 0) {
    console.log(failures.map((f) => ` - ${f}`).join("\n"));
    process.exit(1);
  }
  process.exit(0);
}

await main();
