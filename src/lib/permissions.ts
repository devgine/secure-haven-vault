// RBAC — client-safe permission matrix. Roles only group permissions;
// every server function re-checks the exact permission server-side.

export type WorkspaceRole = "OWNER" | "ADMIN" | "EDITOR" | "VIEWER";
export type AppRole = "SUPER_ADMIN" | "USER";

export type Permission =
  | "workspace.read"
  | "workspace.update"
  | "workspace.delete"
  | "member.read"
  | "member.invite"
  | "member.update"
  | "member.delete"
  | "secret.create"
  | "secret.import"
  | "folder.create"
  | "secret.read"
  | "secret.reveal"
  | "secret.copy"
  | "secret.update"
  | "secret.delete"
  | "audit.read"
  | "oidc.manage"
  | "users.manage"
  | "admin.access";

const OWNER_PERMS: Permission[] = [
  "workspace.read",
  "secret.import",
  "folder.create",
  "workspace.update",
  "workspace.delete",
  "member.read",
  "member.invite",
  "member.update",
  "member.delete",
  "secret.create",
  "secret.read",
  "secret.reveal",
  "secret.copy",
  "secret.update",
  "secret.delete",
];

const ADMIN_PERMS: Permission[] = [
  "workspace.read",
  "secret.import",
  "folder.create",
  "workspace.update",
  "member.read",
  "member.invite",
  "member.update",
  "member.delete",
  "secret.create",
  "secret.read",
  "secret.reveal",
  "secret.copy",
  "secret.update",
  "secret.delete",
];

const EDITOR_PERMS: Permission[] = [
  "workspace.read",
  "secret.import",
  "folder.create",
  "member.read",
  "secret.create",
  "secret.read",
  "secret.reveal",
  "secret.copy",
  "secret.update",
];

const VIEWER_PERMS: Permission[] = ["workspace.read", "member.read", "secret.read"];

export const ROLE_PERMISSIONS: Record<WorkspaceRole, Permission[]> = {
  OWNER: OWNER_PERMS,
  ADMIN: ADMIN_PERMS,
  EDITOR: EDITOR_PERMS,
  VIEWER: VIEWER_PERMS,
};

export function roleHasPermission(
  role: WorkspaceRole | null | undefined,
  permission: Permission,
  opts?: { allowViewerReveal?: boolean },
): boolean {
  if (!role) return false;
  if (
    role === "VIEWER" &&
    (permission === "secret.reveal" || permission === "secret.copy")
  ) {
    return opts?.allowViewerReveal === true;
  }
  return ROLE_PERMISSIONS[role].includes(permission);
}

export const ROLE_LABELS: Record<WorkspaceRole, string> = {
  OWNER: "Propriétaire",
  ADMIN: "Admin",
  EDITOR: "Éditeur",
  VIEWER: "Lecteur",
};
