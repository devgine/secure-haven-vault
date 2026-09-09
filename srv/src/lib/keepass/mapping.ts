// Mapping KeePass → modèle Sentinel Vault. Fonctions pures (testables sans DOM).
// Aucun champ n'est supprimé silencieusement : tout ce qui n'a pas d'équivalent
// direct devient un champ personnalisé.

import type { SecretType, FieldType } from "../types";
import type { KeepassEntry } from "./types";

export interface ImportFieldPayload {
  label: string;
  fieldType: FieldType;
  isSensitive: boolean;
  value: string;
}

export interface ImportAttachmentPayload {
  filename: string;
  mimeType: string;
  size: number;
  dataB64: string;
}

export interface ImportItemPayload {
  /** Clé d'idempotence déterministe (UUID KeePass). */
  clientKey: string;
  path: string[];
  type: SecretType;
  name: string;
  username: string | null;
  url: string | null;
  description: string | null;
  tags: string[];
  icon: string | null;
  sourceCreatedAt: string | null;
  sourceModifiedAt: string | null;
  fields: ImportFieldPayload[];
  attachments: ImportAttachmentPayload[];
}

const ICON_MAP: Record<number, string> = {
  0: "key-round",
  1: "globe",
  3: "network",
  9: "mail",
  12: "database",
  19: "mail",
  27: "terminal",
  29: "shield",
  36: "file-text",
};

export function inferSecretType(entry: KeepassEntry): SecretType {
  const hay = `${entry.title} ${entry.url} ${entry.fields.map((f) => f.label).join(" ")}`.toLowerCase();
  if (entry.fields.some((f) => /private key|clé privée|passphrase/i.test(f.label))) return "SSH_KEY";
  if (/ssh|sftp/.test(hay)) return "SSH_KEY";
  if (/postgres|mysql|mariadb|mongodb|jdbc|database|base de données/.test(hay)) return "DATABASE";
  if (/api[ _-]?key|clé api/.test(hay)) return "API_KEY";
  if (/token|bearer/.test(hay)) return "TOKEN";
  if (!entry.password && !entry.username && entry.notes) return "SECURE_NOTE";
  if (entry.username || entry.password) return "LOGIN";
  return "CUSTOM";
}

/** Un champ protégé KeePass reste sensible côté application, sans exception. */
function fieldTypeFor(label: string, protectedValue: boolean): FieldType {
  const l = label.toLowerCase();
  if (/url|endpoint|lien/.test(l)) return "url";
  if (/user|login|utilisateur/.test(l)) return "username";
  if (/pass|mot de passe|passphrase/.test(l)) return "password";
  if (/date|expir/.test(l)) return "date";
  if (protectedValue) return "secret";
  return "text";
}

export function mapEntryToPayload(entry: KeepassEntry): ImportItemPayload {
  const fields: ImportFieldPayload[] = [];

  if (entry.password) {
    fields.push({
      label: "Mot de passe",
      fieldType: "password",
      isSensitive: true,
      value: entry.password,
    });
  }

  if (entry.totp) {
    fields.push({
      label: "TOTP",
      fieldType: "totp",
      isSensitive: true,
      value: JSON.stringify({
        secret: entry.totp.secret,
        issuer: entry.totp.issuer,
        account: entry.totp.account,
        algorithm: entry.totp.algorithm,
        digits: entry.totp.digits,
        period: entry.totp.period,
      }),
    });
  }

  // Notes protégées : conservées comme champ sensible plutôt qu'en description.
  const description = entry.notesProtected ? null : entry.notes || null;
  if (entry.notesProtected && entry.notes) {
    fields.push({
      label: "Notes",
      fieldType: "textarea",
      isSensitive: true,
      value: entry.notes,
    });
  }

  for (const custom of entry.fields) {
    fields.push({
      label: custom.label,
      fieldType: fieldTypeFor(custom.label, custom.protectedValue),
      isSensitive: custom.protectedValue,
      value: custom.value,
    });
  }

  return {
    clientKey: entry.uuid,
    path: entry.path,
    type: inferSecretType(entry),
    name: entry.title || "Sans titre",
    username: entry.username || null,
    url: entry.url || null,
    description,
    tags: entry.tags.slice(0, 30),
    icon: entry.icon != null ? (ICON_MAP[entry.icon] ?? null) : null,
    sourceCreatedAt: entry.createdAt,
    sourceModifiedAt: entry.modifiedAt,
    fields: fields.slice(0, 100),
    attachments: entry.attachments.map((a) => ({
      filename: a.name,
      mimeType: "application/octet-stream",
      size: a.size,
      dataB64: a.dataB64,
    })),
  };
}

/** Nom par défaut du dossier racine d'import. */
export function defaultRootFolderName(date = new Date()): string {
  const d = date.toISOString().slice(0, 10);
  return `Import KeePass — ${d}`;
}
