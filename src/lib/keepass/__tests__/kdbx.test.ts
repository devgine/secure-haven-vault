// Tests d'import KeePass — bases générées à la volée, aucun secret réel.
import { describe, expect, it, vi } from "vitest";
import * as kdbxweb from "kdbxweb";
import { argon2d, argon2id } from "hash-wasm";
import { detectFormat, openKeepassDatabase, parseTotp } from "../kdbx";
import { defaultRootFolderName, inferSecretType, mapEntryToPayload } from "../mapping";

kdbxweb.CryptoEngine.setArgon2Impl(
  async (password, salt, memory, iterations, length, parallelism, type) => {
    const common = {
      password: new Uint8Array(password),
      salt: new Uint8Array(salt),
      parallelism,
      iterations,
      memorySize: memory,
      hashLength: length,
      outputType: "binary" as const,
    };
    const out =
      type === kdbxweb.CryptoEngine.Argon2TypeArgon2id
        ? await argon2id(common)
        : await argon2d(common);
    return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength) as ArrayBuffer;
  },
);

interface BuildOptions {
  password?: string | null;
  keyFile?: ArrayBuffer | null;
  kdbx3?: boolean;
  empty?: boolean;
}

async function buildDatabase(opts: BuildOptions = {}): Promise<ArrayBuffer> {
  const credentials = new kdbxweb.Credentials(
    opts.password === null ? null : kdbxweb.ProtectedValue.fromString(opts.password ?? "correct horse"),
    opts.keyFile ?? null,
  );
  await credentials.ready;
  const db = kdbxweb.Kdbx.create(credentials, "Test");
  if (opts.kdbx3) db.setVersion(3);
  if (opts.empty) return db.save();

  const root = db.getDefaultGroup();
  const child = db.createGroup(root, "Travail");
  const nested = db.createGroup(child, "Infra");

  const login = db.createEntry(child);
  login.fields.set("Title", "Serveur de test");
  login.fields.set("UserName", "alice");
  login.fields.set("Password", kdbxweb.ProtectedValue.fromString("fake-password-not-real"));
  login.fields.set("URL", "https://example.test");
  login.fields.set("Notes", "note publique");
  login.fields.set("Champ perso", kdbxweb.ProtectedValue.fromString("valeur-protegee"));
  login.fields.set("otp", "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=8&period=60");
  login.tags = ["prod", "web"];
  login.binaries.set("note.txt", new Uint8Array([1, 2, 3, 4]).buffer);

  const note = db.createEntry(nested);
  note.fields.set("Title", "Note imbriquée");
  note.fields.set("Notes", "contenu");

  const dup = db.createEntry(child);
  dup.fields.set("Title", "Serveur de test");
  dup.fields.set("UserName", "alice");

  return db.save();
}

describe("détection de format", () => {
  it("reconnaît une base KDBX valide", async () => {
    expect(detectFormat(await buildDatabase()).kind).toBe("kdbx");
  });

  it("rejette un fichier qui n'est pas une base KeePass", () => {
    expect(detectFormat(new TextEncoder().encode("pas une base du tout").buffer as ArrayBuffer).kind).toBe(
      "unknown",
    );
  });

  it("identifie une base .kdb historique par sa signature", () => {
    const bytes = new Uint8Array([0x03, 0xd9, 0xa2, 0x9a, 0x65, 0xfb, 0x4b, 0xb5]);
    expect(detectFormat(bytes.buffer).kind).toBe("kdb");
  });
});

describe("ouverture de base", () => {
  it("ouvre une base KDBX 4 protégée par mot de passe", async () => {
    const res = await openKeepassDatabase({ file: await buildDatabase(), password: "correct horse" });
    expect(res.formatVersion).toContain("KDBX 4");
    expect(res.stats.entries).toBe(3);
    expect(res.stats.groups).toBeGreaterThanOrEqual(3);
  });

  it("ouvre une base KDBX 3", async () => {
    const res = await openKeepassDatabase({
      file: await buildDatabase({ kdbx3: true }),
      password: "correct horse",
    });
    expect(res.formatVersion).toContain("KDBX 3");
  });

  it("ouvre une base protégée uniquement par fichier clé", async () => {
    const keyFile = crypto.getRandomValues(new Uint8Array(32)).buffer;
    const file = await buildDatabase({ password: null, keyFile });
    const res = await openKeepassDatabase({ file, password: "", keyFile });
    expect(res.stats.entries).toBe(3);
  });

  it("ouvre une base protégée par mot de passe ET fichier clé", async () => {
    const keyFile = crypto.getRandomValues(new Uint8Array(32)).buffer;
    const file = await buildDatabase({ keyFile });
    const res = await openKeepassDatabase({ file, password: "correct horse", keyFile });
    expect(res.stats.entries).toBe(3);
  });

  it("refuse un mauvais mot de passe sans détail cryptographique", async () => {
    await expect(
      openKeepassDatabase({ file: await buildDatabase(), password: "mauvais" }),
    ).rejects.toMatchObject({ code: "bad_credentials" });
  });

  it("refuse un mauvais fichier clé", async () => {
    const keyFile = crypto.getRandomValues(new Uint8Array(32)).buffer;
    const file = await buildDatabase({ keyFile });
    await expect(
      openKeepassDatabase({
        file,
        password: "correct horse",
        keyFile: crypto.getRandomValues(new Uint8Array(32)).buffer,
      }),
    ).rejects.toMatchObject({ code: "bad_credentials" });
  });

  it("refuse une base corrompue", async () => {
    const file = await buildDatabase();
    new Uint8Array(file).fill(0xff, 200, 400);
    await expect(openKeepassDatabase({ file, password: "correct horse" })).rejects.toBeDefined();
  });

  it("refuse le format .kdb avec un message de conversion", async () => {
    const bytes = new Uint8Array(64);
    bytes.set([0x03, 0xd9, 0xa2, 0x9a, 0x65, 0xfb, 0x4b, 0xb5]);
    await expect(
      openKeepassDatabase({ file: bytes.buffer, password: "x" }),
    ).rejects.toMatchObject({ code: "unsupported_format" });
  });

  it("refuse un format non pris en charge", async () => {
    await expect(
      openKeepassDatabase({ file: new Uint8Array(32).buffer, password: "x" }),
    ).rejects.toMatchObject({ code: "unsupported_format" });
  });

  it("ouvre une base vide", async () => {
    const res = await openKeepassDatabase({ file: await buildDatabase({ empty: true }), password: "correct horse" });
    expect(res.stats.entries).toBe(0);
  });
});

describe("préservation des données", () => {
  it("préserve l'arborescence, les champs personnalisés, TOTP et pièces jointes", async () => {
    const res = await openKeepassDatabase({ file: await buildDatabase(), password: "correct horse" });
    const entry = res.entries.find((e) => e.title === "Serveur de test")!;
    expect(entry.path).toEqual(["Travail"]);
    expect(entry.username).toBe("alice");
    expect(entry.fields.some((f) => f.label === "Champ perso" && f.protectedValue)).toBe(true);
    expect(entry.totp?.digits).toBe(8);
    expect(entry.totp?.period).toBe(60);
    expect(entry.attachments[0]?.name).toBe("note.txt");
    expect(entry.tags).toContain("prod");
    expect(entry.createdAt).toBeTruthy();

    const nested = res.entries.find((e) => e.title === "Note imbriquée")!;
    expect(nested.path).toEqual(["Travail", "Infra"]);
  });

  it("expose les doublons potentiels sans les fusionner à la lecture", async () => {
    const res = await openKeepassDatabase({ file: await buildDatabase(), password: "correct horse" });
    const dups = res.entries.filter((e) => e.title === "Serveur de test");
    expect(dups).toHaveLength(2);
  });
});

describe("mapping", () => {
  it("mappe une entrée sans perdre de champ et garde les valeurs protégées sensibles", async () => {
    const res = await openKeepassDatabase({ file: await buildDatabase(), password: "correct horse" });
    const payload = mapEntryToPayload(res.entries.find((e) => e.title === "Serveur de test")!);
    expect(payload.name).toBe("Serveur de test");
    expect(payload.url).toBe("https://example.test");
    expect(payload.fields.find((f) => f.label === "Champ perso")?.isSensitive).toBe(true);
    expect(payload.fields.find((f) => f.fieldType === "totp")?.isSensitive).toBe(true);
    expect(payload.clientKey).toBeTruthy();
  });

  it("produit une clé d'idempotence stable entre deux lectures", async () => {
    const file = await buildDatabase();
    const a = await openKeepassDatabase({ file: file.slice(0), password: "correct horse" });
    const b = await openKeepassDatabase({ file: file.slice(0), password: "correct horse" });
    expect(a.entries.map((e) => e.uuid).sort()).toEqual(b.entries.map((e) => e.uuid).sort());
  });

  it("déduit un type de secret plausible", () => {
    expect(
      inferSecretType({
        title: "Base postgres",
        url: "",
        username: "u",
        password: "p",
        notes: "",
        fields: [],
      } as never),
    ).toBe("DATABASE");
  });

  it("nomme le dossier racine avec la date", () => {
    expect(defaultRootFolderName(new Date("2026-01-02T00:00:00Z"))).toBe("Import KeePass — 2026-01-02");
  });

  it("lit les TOTP au format KeeOtp", () => {
    const totp = parseTotp(new Map([["TOTP Seed", "ABCD"], ["TOTP Settings", "45;7"]]));
    expect(totp).toMatchObject({ secret: "ABCD", period: 45, digits: 7 });
  });
});

describe("garanties de confidentialité", () => {
  it("n'émet aucune requête réseau pendant l'ouverture locale", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    await openKeepassDatabase({ file: await buildDatabase(), password: "correct horse" });
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it("ne journalise jamais le mot de passe maître ni un secret", async () => {
    const logs: string[] = [];
    const spies = (["log", "warn", "error", "info", "debug"] as const).map((level) =>
      vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
        logs.push(args.map(String).join(" "));
      }),
    );
    await openKeepassDatabase({ file: await buildDatabase(), password: "correct horse" });
    spies.forEach((s) => s.mockRestore());
    const joined = logs.join("\n");
    expect(joined).not.toContain("correct horse");
    expect(joined).not.toContain("fake-password-not-real");
    expect(joined).not.toContain("JBSWY3DPEHPK3PXP");
  });

  it("ne place aucun secret dans le rapport d'import", async () => {
    const res = await openKeepassDatabase({ file: await buildDatabase(), password: "correct horse" });
    const report = {
      counters: { imported: res.stats.entries, failed: 0 },
      warnings: res.warnings,
    };
    const json = JSON.stringify(report);
    expect(json).not.toContain("fake-password-not-real");
    expect(json).not.toContain("JBSWY3DPEHPK3PXP");
    expect(json).not.toContain("correct horse");
  });
});
