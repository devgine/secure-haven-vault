// Types et limites de l'import KeePass — client-safe.
// Aucun secret n'est stocké ici : ce sont des structures en mémoire uniquement.

export interface KeepassTotp {
  secret: string;
  issuer: string | null;
  account: string | null;
  algorithm: string;
  digits: number;
  period: number;
}

export interface KeepassAttachment {
  name: string;
  size: number;
  /** Contenu base64 — uniquement en mémoire navigateur jusqu'à confirmation. */
  dataB64: string;
}

export interface KeepassField {
  label: string;
  value: string;
  protectedValue: boolean;
}

export interface KeepassEntry {
  /** Identifiant local stable (UUID KeePass) — sert de clé d'idempotence. */
  uuid: string;
  /** Chemin de groupes, racine exclue. */
  path: string[];
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  notesProtected: boolean;
  tags: string[];
  createdAt: string | null;
  modifiedAt: string | null;
  icon: number | null;
  fields: KeepassField[];
  totp: KeepassTotp | null;
  attachments: KeepassAttachment[];
}

export interface KeepassGroupNode {
  id: string;
  name: string;
  path: string[];
  children: KeepassGroupNode[];
  entryIds: string[];
}

export interface KeepassParseResult {
  formatVersion: string;
  kdfName: string;
  root: KeepassGroupNode;
  entries: KeepassEntry[];
  stats: {
    groups: number;
    entries: number;
    attachments: number;
    customFields: number;
    totpEntries: number;
    skipped: number;
  };
  warnings: string[];
}

// Limites configurables (surchargables via variables VITE_* au build).
function num(value: string | undefined, fallback: number): number {
  const n = value ? Number(value) : NaN;
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const env = (import.meta as unknown as { env?: Record<string, string | undefined> }).env ?? {};

export const MAX_KEEPASS_ATTACHMENT_SIZE = num(env["VITE_MAX_KEEPASS_ATTACHMENT_SIZE"], 10 * 1024 * 1024);
export const MAX_KEEPASS_TOTAL_IMPORT_SIZE = num(env["VITE_MAX_KEEPASS_TOTAL_IMPORT_SIZE"], 100 * 1024 * 1024);
export const MAX_KEEPASS_ENTRY_COUNT = num(env["VITE_MAX_KEEPASS_ENTRY_COUNT"], 5000);
export const LARGE_FILE_WARNING_SIZE = 20 * 1024 * 1024;
export const MAX_UNLOCK_ATTEMPTS = 5;

export type DuplicateStrategy = "skip" | "copy" | "replace" | "merge";

export const DUPLICATE_STRATEGY_LABELS: Record<DuplicateStrategy, string> = {
  skip: "Ignorer les doublons",
  copy: "Importer une nouvelle copie",
  replace: "Remplacer l'entrée existante",
  merge: "Fusionner les champs manquants",
};

export type DuplicateCriterion = "name" | "username" | "url" | "folder";

export const DUPLICATE_CRITERION_LABELS: Record<DuplicateCriterion, string> = {
  name: "Nom",
  username: "Nom d'utilisateur",
  url: "URL",
  folder: "Dossier de destination",
};

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / 1024 / 1024).toFixed(1)} Mo`;
}
