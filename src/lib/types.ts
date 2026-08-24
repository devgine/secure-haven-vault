// Shared DTOs and secret templates (client-safe).

import type { WorkspaceRole } from "./permissions";

export type SecretType =
  | "LOGIN"
  | "API_KEY"
  | "TOKEN"
  | "SSH_KEY"
  | "DATABASE"
  | "SECURE_NOTE"
  | "CUSTOM";

export type FieldType =
  | "text"
  | "secret"
  | "password"
  | "url"
  | "username"
  | "date"
  | "totp"
  | "textarea";

export interface WorkspaceDto {
  id: string;
  name: string;
  description: string | null;
  isPersonal: boolean;
  ownerId: string;
  disabled: boolean;
  allowViewerReveal: boolean;
  role: WorkspaceRole | null;
  memberCount?: number | undefined;
  secretCount?: number | undefined;
  createdAt: string;
}

export interface SecretListItem {
  id: string;
  workspaceId: string;
  workspaceName?: string | undefined;
  type: SecretType;
  name: string;
  username: string | null;
  url: string | null;
  description: string | null;
  tags: string[];
  favorite: boolean;
  expiresAt: string | null;
  notifyBeforeDays: number | null;
  updatedAt: string;
  updatedByEmail?: string | null | undefined;
}

export interface SecretFieldMeta {
  id: string;
  label: string;
  fieldType: FieldType;
  isSensitive: boolean;
  position: number;
}

export interface SecretDetail extends SecretListItem {
  createdAt: string;
  createdByEmail?: string | null | undefined;
  fields: SecretFieldMeta[];
}

export interface RevealedField {
  id: string;
  label: string;
  fieldType: FieldType;
  isSensitive: boolean;
  value: string;
}

export interface SecretFieldInput {
  label: string;
  fieldType: FieldType;
  isSensitive: boolean;
  value: string;
}

export interface SecretInput {
  workspaceId: string;
  type: SecretType;
  name: string;
  username?: string;
  url?: string;
  description?: string;
  tags?: string[];
  expiresAt?: string | null;
  notifyBeforeDays?: number | null;
  fields: SecretFieldInput[];
}

export interface MemberDto {
  userId: string;
  email: string | null;
  displayName: string | null;
  role: WorkspaceRole;
  managedByOidc: boolean;
  createdAt: string;
}

export interface SecretVersionDto {
  id: string;
  version: number;
  action: string;
  changedByEmail: string | null;
  changedFields: string[];
  changedAt: string;
}

export interface AuditLogDto {
  id: string;
  actorEmail: string | null;
  workspaceName: string | null;
  action: string;
  targetType: string | null;
  targetLabel: string | null;
  result: string;
  createdAt: string;
}

export interface SecretFieldTemplate {
  label: string;
  fieldType: FieldType;
  sensitive: boolean;
}

// Field templates per secret type. Only `name` is required at creation.
export const SECRET_TEMPLATES: Record<
  SecretType,
  { label: string; fields: SecretFieldTemplate[] }
> = {
  LOGIN: {
    label: "Identifiant",
    fields: [
      { label: "Nom d'utilisateur", fieldType: "username", sensitive: false },
      { label: "Mot de passe", fieldType: "password", sensitive: true },
      { label: "URL", fieldType: "url", sensitive: false },
    ],
  },
  API_KEY: {
    label: "Clé API",
    fields: [
      { label: "Clé API", fieldType: "secret", sensitive: true },
      { label: "Secret API", fieldType: "secret", sensitive: true },
      { label: "Endpoint", fieldType: "url", sensitive: false },
    ],
  },
  TOKEN: {
    label: "Token",
    fields: [
      { label: "Token", fieldType: "secret", sensitive: true },
      { label: "Endpoint", fieldType: "url", sensitive: false },
    ],
  },
  SSH_KEY: {
    label: "Clé SSH",
    fields: [
      { label: "Nom d'utilisateur", fieldType: "username", sensitive: false },
      { label: "Hôte", fieldType: "text", sensitive: false },
      { label: "Port", fieldType: "text", sensitive: false },
      { label: "Clé privée", fieldType: "textarea", sensitive: true },
      { label: "Clé publique", fieldType: "textarea", sensitive: false },
      { label: "Passphrase", fieldType: "password", sensitive: true },
    ],
  },
  DATABASE: {
    label: "Base de données",
    fields: [
      { label: "Hôte", fieldType: "text", sensitive: false },
      { label: "Port", fieldType: "text", sensitive: false },
      { label: "Base", fieldType: "text", sensitive: false },
      { label: "Nom d'utilisateur", fieldType: "username", sensitive: false },
      { label: "Mot de passe", fieldType: "password", sensitive: true },
      { label: "Chaîne de connexion", fieldType: "secret", sensitive: true },
    ],
  },
  SECURE_NOTE: {
    label: "Note sécurisée",
    fields: [{ label: "Contenu", fieldType: "textarea", sensitive: true }],
  },
  CUSTOM: { label: "Personnalisé", fields: [] },
};

export const SECRET_TYPE_LABELS: Record<SecretType, string> = {
  LOGIN: "Identifiant",
  API_KEY: "Clé API",
  TOKEN: "Token",
  SSH_KEY: "Clé SSH",
  DATABASE: "Base de données",
  SECURE_NOTE: "Note",
  CUSTOM: "Personnalisé",
};

export const FIELD_TYPE_LABELS: Record<FieldType, string> = {
  text: "Texte",
  secret: "Secret",
  password: "Mot de passe",
  url: "URL",
  username: "Nom d'utilisateur",
  date: "Date",
  totp: "TOTP",
  textarea: "Texte long",
};
