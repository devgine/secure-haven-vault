// Lecture d'une base KeePass — EXÉCUTÉ UNIQUEMENT DANS LE NAVIGATEUR.
//
// Aucune primitive cryptographique KeePass n'est réimplémentée ici :
// - kdbxweb (MIT) réalise le déchiffrement KDBX 3.1 / 4.x
// - hash-wasm (MIT) fournit Argon2d / Argon2id requis par KDBX 4
//
// Ni le fichier .kdbx, ni le mot de passe maître, ni le fichier clé, ni les
// clés dérivées ne quittent cette frontière : tout reste en mémoire.

import * as kdbxweb from "kdbxweb";
import type {
  KeepassAttachment,
  KeepassEntry,
  KeepassField,
  KeepassGroupNode,
  KeepassParseResult,
  KeepassTotp,
} from "./types";
import { MAX_KEEPASS_ATTACHMENT_SIZE, MAX_KEEPASS_ENTRY_COUNT } from "./types";

let argon2Ready = false;

async function installArgon2(): Promise<void> {
  if (argon2Ready) return;
  const { argon2d, argon2id } = await import("hash-wasm");
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
  argon2Ready = true;
}

export class KeepassError extends Error {
  code: "unsupported_format" | "bad_credentials" | "corrupted" | "too_large";
  constructor(code: KeepassError["code"], message: string) {
    super(message);
    this.code = code;
    this.name = "KeepassError";
  }
}

const KDBX_SIGNATURE = [0x03, 0xd9, 0xa2, 0x9a];
const KDBX2_SIG2 = [0x67, 0xfb, 0x4b, 0xb5];
const KDB1_SIG2 = [0x65, 0xfb, 0x4b, 0xb5];

export interface FileFormatInfo {
  kind: "kdbx" | "kdb" | "unknown";
  label: string;
}

/** Détection sur le contenu réel du fichier, jamais sur l'extension ou le MIME. */
export function detectFormat(buffer: ArrayBuffer): FileFormatInfo {
  const head = new Uint8Array(buffer.slice(0, 8));
  const match = (offset: number, sig: number[]) => sig.every((b, i) => head[offset + i] === b);
  if (!match(0, KDBX_SIGNATURE)) return { kind: "unknown", label: "Format inconnu" };
  if (match(4, KDBX2_SIG2)) return { kind: "kdbx", label: "KeePass 2.x (.kdbx)" };
  if (match(4, KDB1_SIG2)) return { kind: "kdb", label: "KeePass 1.x (.kdb)" };
  return { kind: "unknown", label: "Format inconnu" };
}

function toB64(bytes: Uint8Array): string {
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

function valueToString(value: unknown): { text: string; protectedValue: boolean } {
  if (value == null) return { text: "", protectedValue: false };
  if (value instanceof kdbxweb.ProtectedValue) {
    return { text: value.getText(), protectedValue: true };
  }
  return { text: String(value), protectedValue: false };
}

const KNOWN_FIELDS = new Set(["Title", "UserName", "Password", "URL", "Notes"]);

/** otpauth:// ou champs KeeOtp / KeePass 2.47+ (TimeOtp-*). */
export function parseTotp(fields: Map<string, string>): KeepassTotp | null {
  const otp = fields.get("otp") ?? fields.get("TOTP Seed") ?? fields.get("TimeOtp-Secret-Base32");
  if (!otp) return null;
  if (otp.startsWith("otpauth://")) {
    try {
      const url = new URL(otp);
      const secret = url.searchParams.get("secret");
      if (!secret) return null;
      const label = decodeURIComponent(url.pathname.replace(/^\//, ""));
      const [labelIssuer, account] = label.includes(":") ? label.split(":") : [null, label];
      return {
        secret,
        issuer: url.searchParams.get("issuer") ?? labelIssuer ?? null,
        account: account ?? null,
        algorithm: (url.searchParams.get("algorithm") ?? "SHA1").toUpperCase(),
        digits: Number(url.searchParams.get("digits") ?? 6) || 6,
        period: Number(url.searchParams.get("period") ?? 30) || 30,
      };
    } catch {
      return null;
    }
  }
  // KeeOtp : "TOTP Settings" = "30;6"
  const settings = fields.get("TOTP Settings") ?? "";
  const [period, digits] = settings.split(";");
  return {
    secret: otp,
    issuer: null,
    account: null,
    algorithm: (fields.get("TimeOtp-Algorithm") ?? "SHA1").toUpperCase(),
    digits: Number(fields.get("TimeOtp-Length") ?? digits ?? 6) || 6,
    period: Number(fields.get("TimeOtp-Period") ?? period ?? 30) || 30,
  };
}

const TOTP_FIELD_NAMES = new Set([
  "otp",
  "TOTP Seed",
  "TOTP Settings",
  "TimeOtp-Secret-Base32",
  "TimeOtp-Algorithm",
  "TimeOtp-Length",
  "TimeOtp-Period",
]);

export interface OpenOptions {
  file: ArrayBuffer;
  password: string;
  keyFile?: ArrayBuffer | undefined;
}

/**
 * Ouvre et analyse la base. La valeur retournée ne contient aucune référence
 * au fichier chiffré, au mot de passe ni aux clés dérivées.
 */
export async function openKeepassDatabase(opts: OpenOptions): Promise<KeepassParseResult> {
  const format = detectFormat(opts.file);
  if (format.kind === "kdb") {
    throw new KeepassError(
      "unsupported_format",
      "Les bases KeePass 1.x (.kdb) ne sont pas prises en charge. Convertissez la base en .kdbx depuis KeePass (Fichier → Enregistrer sous).",
    );
  }
  if (format.kind !== "kdbx") {
    throw new KeepassError("unsupported_format", "Ce fichier n'est pas une base KeePass .kdbx valide.");
  }

  await installArgon2();

  const credentials = new kdbxweb.Credentials(
    opts.password ? kdbxweb.ProtectedValue.fromString(opts.password) : null,
    // kdbxweb efface le tampon du fichier clé après usage : on lui passe une
    // copie pour qu'une nouvelle tentative reste possible.
    opts.keyFile ? opts.keyFile.slice(0) : null,
  );
  await credentials.ready;

  let db: kdbxweb.Kdbx;
  try {
    db = await kdbxweb.Kdbx.load(opts.file, credentials);
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === "InvalidKey") {
      throw new KeepassError("bad_credentials", "Impossible d'ouvrir cette base.");
    }
    if (code === "InvalidVersion" || code === "Unsupported") {
      throw new KeepassError("unsupported_format", "Version ou méthode de déverrouillage non prise en charge.");
    }
    throw new KeepassError("corrupted", "Fichier illisible ou corrompu.");
  }

  const warnings: string[] = [];
  const entries: KeepassEntry[] = [];
  let groups = 0;
  let attachments = 0;
  let customFields = 0;
  let totpEntries = 0;
  let skipped = 0;

  const recycleBinId = db.meta.recycleBinUuid?.id ?? null;

  function walk(group: kdbxweb.KdbxGroup, path: string[]): KeepassGroupNode {
    groups += 1;
    const node: KeepassGroupNode = {
      id: group.uuid.id,
      name: group.name ?? "Groupe",
      path,
      children: [],
      entryIds: [],
    };

    for (const entry of group.entries) {
      if (entries.length >= MAX_KEEPASS_ENTRY_COUNT) {
        skipped += 1;
        continue;
      }
      const raw = new Map<string, string>();
      const custom: KeepassField[] = [];
      let notesProtected = false;
      for (const [key, value] of entry.fields) {
        const { text, protectedValue } = valueToString(value);
        raw.set(key, text);
        if (key === "Notes") notesProtected = protectedValue;
        if (!KNOWN_FIELDS.has(key) && !TOTP_FIELD_NAMES.has(key) && text !== "") {
          custom.push({ label: key, value: text, protectedValue });
        }
      }
      customFields += custom.length;

      const totp = parseTotp(raw);
      if (totp) totpEntries += 1;

      const atts: KeepassAttachment[] = [];
      for (const [name, binary] of entry.binaries) {
        const bytes =
          binary instanceof kdbxweb.ProtectedValue
            ? binary.getBinary()
            : new Uint8Array(
                (binary as { value?: ArrayBuffer })?.value ?? (binary as unknown as ArrayBuffer),
              );
        if (bytes.length > MAX_KEEPASS_ATTACHMENT_SIZE) {
          warnings.push(
            `Pièce jointe « ${name} » ignorée (taille supérieure à la limite autorisée).`,
          );
          continue;
        }
        atts.push({ name, size: bytes.length, dataB64: toB64(bytes) });
      }
      attachments += atts.length;

      entries.push({
        uuid: entry.uuid.id,
        path,
        title: raw.get("Title") ?? "Sans titre",
        username: raw.get("UserName") ?? "",
        password: raw.get("Password") ?? "",
        url: raw.get("URL") ?? "",
        notes: raw.get("Notes") ?? "",
        notesProtected,
        tags: entry.tags ?? [],
        createdAt: entry.times.creationTime?.toISOString() ?? null,
        modifiedAt: entry.times.lastModTime?.toISOString() ?? null,
        icon: entry.icon ?? null,
        fields: custom,
        totp,
        attachments: atts,
      });
      node.entryIds.push(entry.uuid.id);
    }

    for (const child of group.groups) {
      if (recycleBinId && child.uuid.id === recycleBinId) {
        warnings.push("La corbeille KeePass a été ignorée.");
        continue;
      }
      node.children.push(walk(child, [...path, child.name ?? "Groupe"]));
    }
    return node;
  }

  const rootGroup = db.getDefaultGroup();
  const root = walk(rootGroup, []);

  if (entries.length >= MAX_KEEPASS_ENTRY_COUNT) {
    warnings.push(`Limite de ${MAX_KEEPASS_ENTRY_COUNT} entrées atteinte : les suivantes sont ignorées.`);
  }
  if (db.meta.historyMaxItems !== 0) {
    warnings.push("L'historique des versions KeePass n'est pas importé.");
  }

  const version = `${db.header.versionMajor}.${db.header.versionMinor}`;
  const kdf = db.header.versionMajor >= 4 ? "Argon2" : "AES-KDF";

  // Efface les références internes de kdbxweb dès l'analyse terminée.
  db.credentials = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(""));

  return {
    formatVersion: `KDBX ${version}`,
    kdfName: kdf,
    root,
    entries,
    stats: {
      groups,
      entries: entries.length,
      attachments,
      customFields,
      totpEntries,
      skipped,
    },
    warnings,
  };
}
