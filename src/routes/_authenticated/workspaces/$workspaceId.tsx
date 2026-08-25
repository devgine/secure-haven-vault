import { useMemo, useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import {
  ArchiveRestore,
  KeyRound,
  Plus,
  Search,
  Trash2,
  UserPlus,
  FileKey2,
} from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { KeepassImportDialog } from "@/components/vault/keepass-import-dialog";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { SecretDetailDialog } from "@/components/vault/secret-detail-dialog";
import { SecretFormDialog } from "@/components/vault/secret-form-dialog";
import { SecretRow } from "@/components/vault/secret-row";
import { FolderTree, type FolderSelection } from "@/components/vault/folder-tree";
import { FolderPicker } from "@/components/vault/folder-picker";
import { listFolders, moveSecrets } from "@/lib/folders.functions";
import { folderAncestry, subtreeIds } from "@/lib/folders";
import { Checkbox } from "@/components/ui/checkbox";
import {
  addMember,
  listMembers,
  removeMember,
  updateMemberRole,
} from "@/lib/members.functions";
import {
  deleteSecret,
  deleteWorkspace,
  getSecret,
  listSecrets,
  listWorkspaces,
  updateWorkspace,
} from "@/lib/vault.functions";
import { ROLE_LABELS, type WorkspaceRole } from "@/lib/permissions";
import type { SecretDetail } from "@/lib/types";

interface WorkspaceSearch {
  secret?: string | undefined;
  tab?: string | undefined;
}

export const Route = createFileRoute("/_authenticated/workspaces/$workspaceId")({
  validateSearch: (search: Record<string, unknown>): WorkspaceSearch => ({
    secret: typeof search["secret"] === "string" ? search["secret"] : undefined,
    tab: typeof search["tab"] === "string" ? search["tab"] : undefined,
  }),
  head: () => ({
    meta: [
      { title: "Coffre — Sentinel Vault" },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: WorkspacePage,
});

function AddMemberDialog({
  open,
  onOpenChange,
  workspaceId,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  workspaceId: string;
}) {
  const queryClient = useQueryClient();
  const addFn = useServerFn(addMember);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<WorkspaceRole>("VIEWER");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    try {
      await addFn({ data: { workspaceId, email: email.trim(), role } });
      toast.success("Membre ajouté");
      await queryClient.invalidateQueries({ queryKey: ["members", workspaceId] });
      setEmail("");
      onOpenChange(false);
    } catch (err) {
      toast.error((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Ajouter un membre</DialogTitle>
          <DialogDescription>
            La personne doit déjà posséder un compte. Son rôle détermine précisément
            ce qu'elle peut voir et faire.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="member-email">Email du compte</Label>
            <Input id="member-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label>Rôle</Label>
            <Select value={role} onValueChange={(v) => setRole(v as WorkspaceRole)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {(Object.keys(ROLE_LABELS) as WorkspaceRole[]).map((r) => (
                  <SelectItem key={r} value={r}>{ROLE_LABELS[r]}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Annuler</Button>
          <Button onClick={() => void submit()} disabled={busy || !email.includes("@")}>
            {busy ? "Ajout…" : "Ajouter"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function WorkspacePage() {
  const { workspaceId } = Route.useParams();
  const { secret: secretParam, tab } = Route.useSearch();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [filter, setFilter] = useState("");
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<SecretDetail | null>(null);
  const [addMemberOpen, setAddMemberOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [selection, setSelection] = useState<FolderSelection>({ kind: "all" });
  const [includeSub, setIncludeSub] = useState(true);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [moveOpen, setMoveOpen] = useState(false);
  const [moveTargetFolder, setMoveTargetFolder] = useState<string | null>(null);

  const [confirmDelete, setConfirmDelete] = useState(false);

  const updateFn = useServerFn(updateWorkspace);
  const deleteWsFn = useServerFn(deleteWorkspace);
  const deleteSecretFn = useServerFn(deleteSecret);
  const removeMemberFn = useServerFn(removeMember);
  const updateRoleFn = useServerFn(updateMemberRole);
  const moveSecretsFn = useServerFn(moveSecrets);

  const { data: workspaces } = useQuery({ queryKey: ["workspaces"], queryFn: () => listWorkspaces() });
  const workspace = useMemo(
    () => (workspaces ?? []).find((w) => w.id === workspaceId) ?? null,
    [workspaces, workspaceId],
  );
  const role = workspace?.role ?? null;
  const canCreate = role === "OWNER" || role === "ADMIN" || role === "EDITOR";
  const canManageMembers = role === "OWNER" || role === "ADMIN";
  const canUpdateWorkspace = role === "OWNER" || role === "ADMIN";
  const canDeleteWorkspace = role === "OWNER";

  const { data: secrets, isLoading } = useQuery({
    queryKey: ["secrets", workspaceId],
    queryFn: () => listSecrets({ data: { workspaceId } }),
  });
  const { data: trashed } = useQuery({
    queryKey: ["secrets", workspaceId, "trash"],
    queryFn: () => listSecrets({ data: { workspaceId, trashed: true } }),
    enabled: canDeleteWorkspace || canCreate,
  });
  const { data: folders } = useQuery({
    queryKey: ["folders", workspaceId],
    queryFn: () => listFolders({ data: { workspaceId } }),
  });
  const { data: members } = useQuery({
    queryKey: ["members", workspaceId],
    queryFn: () => listMembers({ data: { workspaceId } }),
  });

  const folderList = folders ?? [];

  // Périmètre courant : tout le coffre, les secrets sans groupe, ou un groupe
  // (avec ou sans ses sous-groupes).
  const scoped = useMemo(() => {
    const list = secrets ?? [];
    if (selection.kind === "all") return list;
    if (selection.kind === "unfiled") return list.filter((s) => !s.folderId);
    const ids = includeSub
      ? subtreeIds(folderList, selection.id)
      : new Set([selection.id]);
    return list.filter((s) => s.folderId && ids.has(s.folderId));
  }, [secrets, selection, includeSub, folderList]);

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return scoped;
    return scoped.filter(
      (s) =>
        s.name.toLowerCase().includes(q) ||
        (s.username ?? "").toLowerCase().includes(q) ||
        (s.url ?? "").toLowerCase().includes(q) ||
        s.tags.some((t) => t.toLowerCase().includes(q)),
    );
  }, [scoped, filter]);

  const breadcrumb =
    selection.kind === "folder" ? folderAncestry(folderList, selection.id) : [];
  const unfiledCount = (secrets ?? []).filter((s) => !s.folderId).length;

  const toggleChecked = (id: string) =>
    setChecked((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const submitMoveSecrets = async () => {
    try {
      const res = await moveSecretsFn({
        data: { workspaceId, secretIds: [...checked], folderId: moveTargetFolder },
      });
      toast.success(`${res.moved} secret(s) déplacé(s)`);
      setChecked(new Set());
      setMoveOpen(false);
      await queryClient.invalidateQueries({ queryKey: ["secrets"] });
      await queryClient.invalidateQueries({ queryKey: ["folders", workspaceId] });
    } catch (err) {
      toast.error((err as Error).message);
    }
  };

  const openSecret = (id: string | undefined) =>
    navigate({
      to: "/workspaces/$workspaceId",
      params: { workspaceId },
      search: (prev) => ({ ...prev, secret: id }),
      replace: true,
    });

  const openEdit = async () => {
    if (!secretParam) return;
    const detail = await getSecret({ data: { secretId: secretParam } });
    setEditing(detail);
    setFormOpen(true);
  };

  const saveWorkspaceSettings = async (form: HTMLFormElement) => {
    const fd = new FormData(form);
    try {
      await updateFn({
        data: {
          workspaceId,
          name: String(fd.get("name") ?? ""),
          description: String(fd.get("description") ?? "") || null,
          allowViewerReveal: fd.get("allowViewerReveal") === "on",
        },
      });
      toast.success("Coffre mis à jour");
      await queryClient.invalidateQueries({ queryKey: ["workspaces"] });
    } catch (err) {
      toast.error((err as Error).message);
    }
  };

  if (workspaces && !workspace) {
    return (
      <div className="mx-auto max-w-lg py-20 text-center">
        <h1 className="text-lg font-semibold">Coffre introuvable</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Ce coffre n'existe pas, a été désactivé, ou vous n'y avez pas accès.
        </p>
        <Button className="mt-4" variant="outline" onClick={() => navigate({ to: "/" })}>
          Retour au tableau de bord
        </Button>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            {workspace?.name ?? "…"}
            {workspace?.isPersonal && <Badge variant="secondary">Personnel</Badge>}
            {role && <Badge variant="outline">{ROLE_LABELS[role]}</Badge>}
          </h1>
          <p className="text-sm text-muted-foreground">{workspace?.description}</p>
        </div>
        {canCreate && (
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => setImportOpen(true)}>
              <FileKey2 className="mr-2 h-4 w-4" /> Importer KeePass
            </Button>
            <Button onClick={() => { setEditing(null); setFormOpen(true); }}>
              <Plus className="mr-2 h-4 w-4" /> Nouveau secret
            </Button>
          </div>
        )}
        <KeepassImportDialog
          open={importOpen}
          onOpenChange={setImportOpen}
          workspaceId={workspaceId}
          onImported={() => void queryClient.invalidateQueries({ queryKey: ["secrets"] })}
        />
      </div>

      <Tabs defaultValue={tab ?? "secrets"}>
        <TabsList>
          <TabsTrigger value="secrets">
            <KeyRound className="mr-1.5 h-3.5 w-3.5" /> Secrets ({secrets?.length ?? 0})
          </TabsTrigger>
          {!workspace?.isPersonal && <TabsTrigger value="members">Membres ({members?.length ?? 0})</TabsTrigger>}
          {(canDeleteWorkspace || canCreate) && <TabsTrigger value="trash">Corbeille ({trashed?.length ?? 0})</TabsTrigger>}
          {canUpdateWorkspace && <TabsTrigger value="settings">Paramètres</TabsTrigger>}
        </TabsList>

        <TabsContent value="secrets" className="pt-4">
          <div className="grid gap-6 md:grid-cols-[240px_1fr]">
            <aside className="md:sticky md:top-4 md:self-start">
              <FolderTree
                workspaceId={workspaceId}
                folders={folderList}
                selection={selection}
                onSelect={(next) => {
                  setSelection(next);
                  setChecked(new Set());
                }}
                canManage={canCreate}
                totalCount={secrets?.length ?? 0}
                unfiledCount={unfiledCount}
              />
            </aside>

            <div className="space-y-4">
              <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
                <button type="button" className="hover:text-foreground" onClick={() => setSelection({ kind: "all" })}>
                  {workspace?.name ?? "Coffre"}
                </button>
                {selection.kind === "unfiled" && <><span>/</span><span className="text-foreground">Sans groupe</span></>}
                {breadcrumb.map((f, i) => (
                  <span key={f.id} className="flex items-center gap-2">
                    <span>/</span>
                    <button
                      type="button"
                      className={i === breadcrumb.length - 1 ? "font-medium text-foreground" : "hover:text-foreground"}
                      onClick={() => setSelection({ kind: "folder", id: f.id })}
                    >
                      {f.name}
                    </button>
                  </span>
                ))}
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <div className="relative min-w-[220px] flex-1">
                  <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                    placeholder="Filtrer dans ce périmètre…"
                    className="pl-9"
                  />
                </div>
                {selection.kind === "folder" && (
                  <label className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Switch checked={includeSub} onCheckedChange={setIncludeSub} />
                    Inclure les sous-groupes
                  </label>
                )}
                {canCreate && checked.size > 0 && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setMoveTargetFolder(selection.kind === "folder" ? selection.id : null);
                      setMoveOpen(true);
                    }}
                  >
                    Déplacer ({checked.size})
                  </Button>
                )}
              </div>

              {isLoading ? (
                <p className="py-10 text-center text-sm text-muted-foreground">Chargement…</p>
              ) : filtered.length === 0 ? (
                <div className="rounded-xl border border-dashed py-14 text-center">
                  <KeyRound className="mx-auto h-8 w-8 text-muted-foreground/50" />
                  <p className="mt-3 text-sm text-muted-foreground">
                    {filter ? "Aucun secret ne correspond au filtre." : "Aucun secret dans ce périmètre."}
                  </p>
                </div>
              ) : (
                <div className="space-y-2">
                  {filtered.map((s) => (
                    <div key={s.id} className="flex items-center gap-2">
                      {canCreate && (
                        <Checkbox
                          checked={checked.has(s.id)}
                          onCheckedChange={() => toggleChecked(s.id)}
                          aria-label={`Sélectionner ${s.name}`}
                        />
                      )}
                      <button onClick={() => openSecret(s.id)} className="block min-w-0 flex-1 text-left">
                        <div className="pointer-events-none">
                          <SecretRow secret={s} />
                        </div>
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <Dialog open={moveOpen} onOpenChange={setMoveOpen}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Déplacer {checked.size} secret(s)</DialogTitle>
                <DialogDescription>
                  Choisissez le groupe de destination dans ce coffre.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-2">
                <Label>Destination</Label>
                <FolderPicker folders={folderList} value={moveTargetFolder} onChange={setMoveTargetFolder} />
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setMoveOpen(false)}>Annuler</Button>
                <Button onClick={() => void submitMoveSecrets()}>Déplacer</Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </TabsContent>

        {!workspace?.isPersonal && (
          <TabsContent value="members" className="space-y-4 pt-4">
            {canManageMembers && (
              <div className="flex justify-end">
                <Button variant="outline" size="sm" onClick={() => setAddMemberOpen(true)}>
                  <UserPlus className="mr-2 h-4 w-4" /> Ajouter un membre
                </Button>
              </div>
            )}
            <div className="space-y-2">
              {(members ?? []).map((m) => (
                <div key={m.userId} className="flex items-center gap-3 rounded-lg border bg-card px-4 py-3">
                  <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary">
                    {(m.email ?? "?").slice(0, 2).toUpperCase()}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium">{m.displayName || m.email}</div>
                    <div className="truncate text-xs text-muted-foreground">{m.email}</div>
                  </div>
                  {m.managedByOidc && <Badge variant="outline" className="text-[10px]">via SSO</Badge>}
                  {canManageMembers && !m.managedByOidc ? (
                    <>
                      <Select
                        value={m.role}
                        onValueChange={async (v) => {
                          try {
                            await updateRoleFn({ data: { workspaceId, targetUserId: m.userId, role: v as WorkspaceRole } });
                            await queryClient.invalidateQueries({ queryKey: ["members", workspaceId] });
                            toast.success("Rôle mis à jour");
                          } catch (err) {
                            toast.error((err as Error).message);
                          }
                        }}
                      >
                        <SelectTrigger className="h-8 w-36"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          {(Object.keys(ROLE_LABELS) as WorkspaceRole[]).map((r) => (
                            <SelectItem key={r} value={r}>{ROLE_LABELS[r]}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="text-muted-foreground hover:text-destructive"
                        onClick={async () => {
                          try {
                            await removeMemberFn({ data: { workspaceId, targetUserId: m.userId } });
                            await queryClient.invalidateQueries({ queryKey: ["members", workspaceId] });
                            toast.success("Membre retiré");
                          } catch (err) {
                            toast.error((err as Error).message);
                          }
                        }}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </>
                  ) : (
                    <Badge variant="secondary">{ROLE_LABELS[m.role]}</Badge>
                  )}
                </div>
              ))}
            </div>
          </TabsContent>
        )}

        <TabsContent value="trash" className="space-y-2 pt-4">
          {(trashed ?? []).length === 0 ? (
            <p className="py-10 text-center text-sm text-muted-foreground">La corbeille est vide.</p>
          ) : (
            (trashed ?? []).map((s) => (
              <div key={s.id} className="flex items-center gap-3 rounded-lg border bg-card px-4 py-3">
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium text-muted-foreground line-through">{s.name}</div>
                  <div className="text-xs text-muted-foreground">
                    Supprimé le {new Date(s.updatedAt).toLocaleDateString("fr-FR")}
                  </div>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={async () => {
                    await deleteSecretFn({ data: { secretId: s.id, mode: "restore" } });
                    await queryClient.invalidateQueries({ queryKey: ["secrets"] });
                    toast.success("Secret restauré");
                  }}
                >
                  <ArchiveRestore className="mr-1.5 h-3.5 w-3.5" /> Restaurer
                </Button>
                {canDeleteWorkspace !== false && (role === "OWNER" || role === "ADMIN") && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-destructive hover:text-destructive"
                    onClick={async () => {
                      if (!window.confirm(`Détruire définitivement « ${s.name} » ? Cette action est irréversible.`)) return;
                      await deleteSecretFn({ data: { secretId: s.id, mode: "purge" } });
                      await queryClient.invalidateQueries({ queryKey: ["secrets"] });
                      toast.success("Secret détruit");
                    }}
                  >
                    <Trash2 className="mr-1.5 h-3.5 w-3.5" /> Détruire
                  </Button>
                )}
              </div>
            ))
          )}
        </TabsContent>

        {canUpdateWorkspace && workspace && (
          <TabsContent value="settings" className="max-w-lg space-y-6 pt-4">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void saveWorkspaceSettings(e.currentTarget);
              }}
              className="space-y-4 rounded-xl border bg-card p-5"
            >
              <div className="space-y-2">
                <Label htmlFor="ws-edit-name">Nom</Label>
                <Input id="ws-edit-name" name="name" defaultValue={workspace.name} required />
              </div>
              <div className="space-y-2">
                <Label htmlFor="ws-edit-desc">Description</Label>
                <Input id="ws-edit-desc" name="description" defaultValue={workspace.description ?? ""} />
              </div>
              <label className="flex items-center justify-between gap-4 text-sm">
                <span>
                  Autoriser les lecteurs à révéler les valeurs
                  <span className="block text-xs text-muted-foreground">
                    Sinon, un lecteur voit les métadonnées mais jamais les valeurs.
                  </span>
                </span>
                <Switch name="allowViewerReveal" defaultChecked={workspace.allowViewerReveal} />
              </label>
              <Button type="submit">Enregistrer</Button>
            </form>

            {canDeleteWorkspace && !workspace.isPersonal && (
              <div className="rounded-xl border border-destructive/40 p-5">
                <h3 className="text-sm font-semibold text-destructive">Zone dangereuse</h3>
                <p className="mt-1 text-xs text-muted-foreground">
                  La suppression est logique : les données chiffrées restent inaccessibles à tous.
                </p>
                <Button variant="destructive" size="sm" className="mt-3" onClick={() => setConfirmDelete(true)}>
                  Supprimer ce coffre
                </Button>
              </div>
            )}
          </TabsContent>
        )}
      </Tabs>

      <SecretDetailDialog
        secretId={secretParam ?? null}
        workspaceId={workspaceId}
        role={role}
        allowViewerReveal={workspace?.allowViewerReveal ?? false}
        onClose={() => openSecret(undefined)}
        onEdit={() => void openEdit()}
      />
      <SecretFormDialog
        open={formOpen}
        onOpenChange={(o) => { setFormOpen(o); if (!o) setEditing(null); }}
        workspaceId={workspaceId}
        existing={editing}
        defaultFolderId={selection.kind === "folder" ? selection.id : null}
      />
      <AddMemberDialog open={addMemberOpen} onOpenChange={setAddMemberOpen} workspaceId={workspaceId} />

      <Dialog open={confirmDelete} onOpenChange={setConfirmDelete}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Supprimer « {workspace?.name} » ?</DialogTitle>
            <DialogDescription>
              Le coffre et tous ses secrets deviendront inaccessibles à tous les membres.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmDelete(false)}>Annuler</Button>
            <Button
              variant="destructive"
              onClick={async () => {
                try {
                  await deleteWsFn({ data: { workspaceId } });
                  await queryClient.invalidateQueries({ queryKey: ["workspaces"] });
                  navigate({ to: "/" });
                } catch (err) {
                  toast.error((err as Error).message);
                }
              }}
            >
              Supprimer
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
