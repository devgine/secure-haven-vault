import { useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import {
  ChevronDown,
  ChevronRight,
  FolderPlus,
  Folder,
  FolderOpen,
  Inbox,
  Layers,
  MoreHorizontal,
  MoveRight,
  Pencil,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { FolderPicker } from "@/components/vault/folder-picker";
import { buildFolderTree, folderPathLabel } from "@/lib/folders";
import {
  createFolder,
  deleteFolder,
  moveFolder,
  updateFolder,
} from "@/lib/folders.functions";
import { cn } from "@/lib/utils";
import type { FolderDto, FolderNode } from "@/lib/types";

export type FolderSelection = { kind: "all" } | { kind: "unfiled" } | { kind: "folder"; id: string };

export function FolderTree({
  workspaceId,
  folders,
  selection,
  onSelect,
  canManage,
  totalCount,
  unfiledCount,
}: {
  workspaceId: string;
  folders: FolderDto[];
  selection: FolderSelection;
  onSelect: (selection: FolderSelection) => void;
  canManage: boolean;
  totalCount: number;
  unfiledCount: number;
}) {
  const queryClient = useQueryClient();
  const createFn = useServerFn(createFolder);
  const updateFn = useServerFn(updateFolder);
  const moveFn = useServerFn(moveFolder);
  const deleteFn = useServerFn(deleteFolder);

  const tree = useMemo(() => buildFolderTree(folders), [folders]);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);

  const [createOpen, setCreateOpen] = useState(false);
  const [createParent, setCreateParent] = useState<string | null>(null);
  const [createName, setCreateName] = useState("");
  const [createDesc, setCreateDesc] = useState("");

  const [editTarget, setEditTarget] = useState<FolderDto | null>(null);
  const [editName, setEditName] = useState("");
  const [editDesc, setEditDesc] = useState("");

  const [moveTarget, setMoveTarget] = useState<FolderDto | null>(null);
  const [moveParent, setMoveParent] = useState<string | null>(null);

  const [deleteTarget, setDeleteTarget] = useState<FolderDto | null>(null);
  const [deleteMode, setDeleteMode] = useState<"detach" | "trash">("detach");

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ["folders", workspaceId] });
    await queryClient.invalidateQueries({ queryKey: ["secrets"] });
  };

  const toggle = (id: string) =>
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const openCreate = (parentId: string | null) => {
    setCreateParent(parentId);
    setCreateName("");
    setCreateDesc("");
    setCreateOpen(true);
  };

  const submitCreate = async () => {
    setBusy(true);
    try {
      const res = await createFn({
        data: {
          workspaceId,
          parentId: createParent,
          name: createName.trim(),
          description: createDesc.trim() || null,
        },
      });
      toast.success("Groupe créé");
      setCreateOpen(false);
      await refresh();
      onSelect({ kind: "folder", id: res.id });
    } catch (err) {
      toast.error((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const submitEdit = async () => {
    if (!editTarget) return;
    setBusy(true);
    try {
      await updateFn({
        data: {
          folderId: editTarget.id,
          name: editName.trim(),
          description: editDesc.trim() || null,
        },
      });
      toast.success("Groupe renommé");
      setEditTarget(null);
      await refresh();
    } catch (err) {
      toast.error((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const submitMove = async () => {
    if (!moveTarget) return;
    setBusy(true);
    try {
      await moveFn({ data: { folderId: moveTarget.id, parentId: moveParent } });
      toast.success("Groupe déplacé");
      setMoveTarget(null);
      await refresh();
    } catch (err) {
      toast.error((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const submitDelete = async () => {
    if (!deleteTarget) return;
    setBusy(true);
    try {
      const res = await deleteFn({ data: { folderId: deleteTarget.id, mode: deleteMode } });
      toast.success(
        deleteMode === "trash"
          ? `${res.folders} groupe(s) supprimé(s), ${res.secrets} secret(s) à la corbeille`
          : `Groupe supprimé, ${res.secrets} secret(s) remonté(s)`,
      );
      if (selection.kind === "folder" && selection.id === deleteTarget.id) onSelect({ kind: "all" });
      setDeleteTarget(null);
      await refresh();
    } catch (err) {
      toast.error((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const renderNode = (node: FolderNode) => {
    const isSelected = selection.kind === "folder" && selection.id === node.id;
    const isCollapsed = collapsed.has(node.id);
    const hasChildren = node.children.length > 0;
    return (
      <div key={node.id}>
        <div
          className={cn(
            "group flex items-center gap-1 rounded-md pr-1 text-sm",
            isSelected ? "bg-primary/10 text-primary" : "hover:bg-muted",
          )}
          style={{ paddingLeft: `${node.depth * 14}px` }}
        >
          <button
            type="button"
            aria-label={isCollapsed ? "Déplier" : "Replier"}
            className="flex h-6 w-5 shrink-0 items-center justify-center text-muted-foreground"
            onClick={() => hasChildren && toggle(node.id)}
          >
            {hasChildren ? (
              isCollapsed ? <ChevronRight className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />
            ) : null}
          </button>
          <button
            type="button"
            onClick={() => onSelect({ kind: "folder", id: node.id })}
            className="flex min-w-0 flex-1 items-center gap-2 py-1.5 text-left"
          >
            {isSelected ? (
              <FolderOpen className="h-4 w-4 shrink-0" />
            ) : (
              <Folder className="h-4 w-4 shrink-0 text-muted-foreground" />
            )}
            <span className="truncate">{node.name}</span>
            <span className="ml-auto shrink-0 text-xs text-muted-foreground">{node.totalCount}</span>
          </button>
          {canManage && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" className="h-6 w-6 opacity-0 group-hover:opacity-100 data-[state=open]:opacity-100">
                  <MoreHorizontal className="h-3.5 w-3.5" />
                  <span className="sr-only">Actions du groupe</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => openCreate(node.id)}>
                  <FolderPlus className="mr-2 h-3.5 w-3.5" /> Nouveau sous-groupe
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={() => {
                    setEditTarget(node);
                    setEditName(node.name);
                    setEditDesc(node.description ?? "");
                  }}
                >
                  <Pencil className="mr-2 h-3.5 w-3.5" /> Renommer
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={() => {
                    setMoveTarget(node);
                    setMoveParent(node.parentId);
                  }}
                >
                  <MoveRight className="mr-2 h-3.5 w-3.5" /> Déplacer
                </DropdownMenuItem>
                <DropdownMenuItem
                  className="text-destructive focus:text-destructive"
                  onClick={() => {
                    setDeleteTarget(node);
                    setDeleteMode("detach");
                  }}
                >
                  <Trash2 className="mr-2 h-3.5 w-3.5" /> Supprimer
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
        {!isCollapsed && node.children.map(renderNode)}
      </div>
    );
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h2 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Groupes</h2>
        {canManage && (
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => openCreate(null)}>
            <FolderPlus className="h-4 w-4" />
            <span className="sr-only">Nouveau groupe</span>
          </Button>
        )}
      </div>

      <button
        type="button"
        onClick={() => onSelect({ kind: "all" })}
        className={cn(
          "flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-sm",
          selection.kind === "all" ? "bg-primary/10 text-primary" : "hover:bg-muted",
        )}
      >
        <Layers className="h-4 w-4" />
        <span>Tous les secrets</span>
        <span className="ml-auto text-xs text-muted-foreground">{totalCount}</span>
      </button>
      <button
        type="button"
        onClick={() => onSelect({ kind: "unfiled" })}
        className={cn(
          "flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-sm",
          selection.kind === "unfiled" ? "bg-primary/10 text-primary" : "hover:bg-muted",
        )}
      >
        <Inbox className="h-4 w-4" />
        <span>Sans groupe</span>
        <span className="ml-auto text-xs text-muted-foreground">{unfiledCount}</span>
      </button>

      <div className="space-y-0.5 pt-1">
        {tree.length === 0 ? (
          <p className="px-2 py-3 text-xs text-muted-foreground">
            Aucun groupe. {canManage ? "Créez-en un pour organiser ce coffre." : ""}
          </p>
        ) : (
          tree.map(renderNode)
        )}
      </div>

      {/* Création */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Nouveau groupe</DialogTitle>
            <DialogDescription>
              Emplacement : {folderPathLabel(folders, createParent)}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="folder-name">Nom</Label>
              <Input
                id="folder-name"
                value={createName}
                onChange={(e) => setCreateName(e.target.value)}
                placeholder="ex. Infrastructure"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="folder-desc">Description</Label>
              <Textarea id="folder-desc" rows={2} value={createDesc} onChange={(e) => setCreateDesc(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label>Groupe parent</Label>
              <FolderPicker folders={folders} value={createParent} onChange={setCreateParent} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Annuler</Button>
            <Button onClick={() => void submitCreate()} disabled={busy || !createName.trim()}>
              {busy ? "Création…" : "Créer"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Renommage */}
      <Dialog open={Boolean(editTarget)} onOpenChange={(o) => !o && setEditTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Renommer le groupe</DialogTitle>
            <DialogDescription>{folderPathLabel(folders, editTarget?.id ?? null)}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="folder-edit-name">Nom</Label>
              <Input id="folder-edit-name" value={editName} onChange={(e) => setEditName(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="folder-edit-desc">Description</Label>
              <Textarea id="folder-edit-desc" rows={2} value={editDesc} onChange={(e) => setEditDesc(e.target.value)} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditTarget(null)}>Annuler</Button>
            <Button onClick={() => void submitEdit()} disabled={busy || !editName.trim()}>Enregistrer</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Déplacement */}
      <Dialog open={Boolean(moveTarget)} onOpenChange={(o) => !o && setMoveTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Déplacer « {moveTarget?.name} »</DialogTitle>
            <DialogDescription>
              Le groupe et tout son contenu suivent le déplacement. Un groupe ne peut pas
              être déplacé dans lui-même.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label>Nouvel emplacement</Label>
            <FolderPicker
              folders={folders}
              value={moveParent}
              onChange={setMoveParent}
              excludeId={moveTarget?.id}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setMoveTarget(null)}>Annuler</Button>
            <Button onClick={() => void submitMove()} disabled={busy}>Déplacer</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Suppression */}
      <Dialog open={Boolean(deleteTarget)} onOpenChange={(o) => !o && setDeleteTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Supprimer « {deleteTarget?.name} »</DialogTitle>
            <DialogDescription>
              Aucun secret n'est détruit : ils sont soit remontés d'un niveau, soit envoyés
              à la corbeille du coffre.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label>Que faire du contenu ?</Label>
            <Select value={deleteMode} onValueChange={(v) => setDeleteMode(v as "detach" | "trash")}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="detach">Remonter le contenu au niveau supérieur</SelectItem>
                <SelectItem value="trash">Supprimer le groupe et son contenu (corbeille)</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>Annuler</Button>
            <Button variant="destructive" onClick={() => void submitDelete()} disabled={busy}>
              Supprimer
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
