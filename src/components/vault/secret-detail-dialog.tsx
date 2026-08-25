import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import {
  CalendarClock,
  Copy,
  Eye,
  EyeOff,
  History,
  Pencil,
  Star,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Folder } from "lucide-react";
import { listFolders } from "@/lib/folders.functions";
import { folderPathLabel } from "@/lib/folders";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  deleteSecret,
  getSecret,
  getSecretVersions,
  revealSecret,
  toggleFavorite,
} from "@/lib/vault.functions";
import { SECRET_TYPE_LABELS, type RevealedField } from "@/lib/types";
import type { WorkspaceRole } from "@/lib/permissions";
import { cn } from "@/lib/utils";

const MASK = "••••••••••";

function ExpiryBanner({ expiresAt }: { expiresAt: string }) {
  const days = Math.ceil((new Date(expiresAt).getTime() - Date.now()) / 86_400_000);
  if (days > 30) return null;
  const expired = days < 0;
  return (
    <div
      className={cn(
        "flex items-center gap-2 rounded-lg border px-3 py-2 text-sm",
        expired
          ? "border-destructive/40 bg-destructive/10 text-destructive"
          : "border-warning/40 bg-warning/10 text-warning",
      )}
    >
      <CalendarClock className="h-4 w-4 shrink-0" />
      {expired
        ? `Ce secret a expiré il y a ${Math.abs(days)} jour(s).`
        : `Expire dans ${days} jour(s) — pensez à le faire tourner.`}
    </div>
  );
}

export function SecretDetailDialog({
  secretId,
  workspaceId,
  role,
  allowViewerReveal,
  onClose,
  onEdit,
}: {
  secretId: string | null;
  workspaceId: string;
  role: WorkspaceRole | null;
  allowViewerReveal: boolean;
  onClose: () => void;
  onEdit: () => void;
}) {
  const queryClient = useQueryClient();
  const revealFn = useServerFn(revealSecret);
  const favoriteFn = useServerFn(toggleFavorite);
  const deleteFn = useServerFn(deleteSecret);

  const { data: folderData } = useQuery({
    queryKey: ["folders", workspaceId],
    queryFn: () => listFolders({ data: { workspaceId } }),
    enabled: Boolean(secretId),
  });
  const detailFolders = folderData ?? [];

  const [revealed, setRevealed] = useState<Map<string, string>>(new Map());
  const [busyField, setBusyField] = useState<string | null>(null);

  const { data: secret } = useQuery({
    queryKey: ["secret", secretId],
    queryFn: () => getSecret({ data: { secretId: secretId! } }),
    enabled: Boolean(secretId),
  });
  const { data: versions } = useQuery({
    queryKey: ["secret-versions", secretId],
    queryFn: () => getSecretVersions({ data: { secretId: secretId! } }),
    enabled: Boolean(secretId),
  });

  const canReveal =
    role === "OWNER" || role === "ADMIN" || role === "EDITOR" ||
    (role === "VIEWER" && allowViewerReveal);
  const canUpdate = role === "OWNER" || role === "ADMIN" || role === "EDITOR";
  const canDelete = role === "OWNER" || role === "ADMIN";

  const close = () => {
    setRevealed(new Map());
    onClose();
  };

  const revealField = async (fieldId: string) => {
    if (!secretId) return;
    setBusyField(fieldId);
    try {
      const result = await revealFn({ data: { secretId, action: "reveal", fieldId } });
      setRevealed((prev) => {
        const next = new Map(prev);
        for (const f of result) next.set(f.id, f.value);
        return next;
      });
    } catch (err) {
      toast.error((err as Error).message || "Révélation refusée");
    } finally {
      setBusyField(null);
    }
  };

  const copyField = async (fieldId: string, label: string) => {
    if (!secretId) return;
    setBusyField(fieldId);
    try {
      let value = revealed.get(fieldId);
      if (value === undefined) {
        const result: RevealedField[] = await revealFn({ data: { secretId, action: "copy", fieldId } });
        value = result[0]?.value ?? "";
      }
      await navigator.clipboard.writeText(value);
      toast.success(`${label} copié — presse-papiers vidé dans 20 s`);
      setTimeout(() => {
        void navigator.clipboard.writeText("").catch(() => undefined);
      }, 20_000);
    } catch (err) {
      toast.error((err as Error).message || "Copie refusée");
    } finally {
      setBusyField(null);
    }
  };

  const onToggleFavorite = async () => {
    if (!secret) return;
    await favoriteFn({ data: { secretId: secret.id, favorite: !secret.favorite } });
    await queryClient.invalidateQueries({ queryKey: ["secret", secret.id] });
    await queryClient.invalidateQueries({ queryKey: ["secrets"] });
  };

  const onTrash = async () => {
    if (!secret) return;
    await deleteFn({ data: { secretId: secret.id, mode: "trash" } });
    toast.success("Secret déplacé dans la corbeille");
    await queryClient.invalidateQueries({ queryKey: ["secrets"] });
    close();
  };

  return (
    <Dialog open={Boolean(secretId)} onOpenChange={(o) => !o && close()}>
      <DialogContent className="max-h-[90vh] overflow-y-auto scrollbar-thin sm:max-w-2xl">
        {!secret ? (
          <div className="py-10 text-center text-sm text-muted-foreground">Chargement…</div>
        ) : (
          <>
            <DialogHeader>
              <div className="flex items-start justify-between gap-4 pr-6">
                <div>
                  <DialogTitle className="flex items-center gap-2">
                    {secret.name}
                    <Badge variant="secondary">{SECRET_TYPE_LABELS[secret.type]}</Badge>
                  </DialogTitle>
                  <DialogDescription className="mt-1">
                    {secret.description || "Aucune description"}
                  </DialogDescription>
                  <p className="mt-1 flex items-center gap-1.5 text-xs text-muted-foreground">
                    <Folder className="h-3.5 w-3.5" />
                    {folderPathLabel(detailFolders, secret.folderId)}
                  </p>
                </div>
                <Button variant="ghost" size="icon" onClick={() => void onToggleFavorite()} title="Favori">
                  <Star className={cn("h-4 w-4", secret.favorite && "fill-warning text-warning")} />
                </Button>
              </div>
            </DialogHeader>

            {secret.expiresAt && <ExpiryBanner expiresAt={secret.expiresAt} />}

            <Tabs defaultValue="fields">
              <TabsList>
                <TabsTrigger value="fields">Champs</TabsTrigger>
                <TabsTrigger value="history">
                  <History className="mr-1.5 h-3.5 w-3.5" /> Historique
                </TabsTrigger>
              </TabsList>

              <TabsContent value="fields" className="space-y-4 pt-2">
                {(secret.username || secret.url) && (
                  <div className="grid gap-2 text-sm sm:grid-cols-2">
                    {secret.username && (
                      <div>
                        <div className="text-xs text-muted-foreground">Identifiant</div>
                        <div className="secret-value">{secret.username}</div>
                      </div>
                    )}
                    {secret.url && (
                      <div>
                        <div className="text-xs text-muted-foreground">URL</div>
                        <a href={secret.url} target="_blank" rel="noreferrer" className="secret-value text-primary hover:underline">
                          {secret.url}
                        </a>
                      </div>
                    )}
                  </div>
                )}

                <div className="space-y-2">
                  {secret.fields.length === 0 && (
                    <p className="text-sm text-muted-foreground">Aucun champ chiffré.</p>
                  )}
                  {secret.fields.map((f) => {
                    const value = revealed.get(f.id);
                    const isVisible = value !== undefined;
                    return (
                      <div
                        key={f.id}
                        className="flex items-center gap-2 rounded-lg border bg-muted/30 px-3 py-2.5"
                      >
                        <div className="min-w-0 flex-1">
                          <div className="text-xs text-muted-foreground">{f.label}</div>
                          <div className={cn("secret-value truncate text-sm", !isVisible && "text-muted-foreground")}>
                            {f.isSensitive ? (isVisible ? value : MASK) : "Chiffré au repos"}
                          </div>
                        </div>
                        {canReveal && f.isSensitive && (
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8"
                            disabled={busyField === f.id}
                            onClick={() =>
                              isVisible
                                ? setRevealed((prev) => {
                                    const next = new Map(prev);
                                    next.delete(f.id);
                                    return next;
                                  })
                                : void revealField(f.id)
                            }
                            title={isVisible ? "Masquer" : "Révéler (tracé au journal)"}
                          >
                            {isVisible ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                          </Button>
                        )}
                        {canReveal && (
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8"
                            disabled={busyField === f.id}
                            onClick={() => void copyField(f.id, f.label)}
                            title="Copier (tracé au journal)"
                          >
                            <Copy className="h-4 w-4" />
                          </Button>
                        )}
                      </div>
                    );
                  })}
                  {!canReveal && (
                    <p className="text-xs text-muted-foreground">
                      Votre rôle ne permet pas de révéler les valeurs de ce coffre.
                    </p>
                  )}
                </div>

                {secret.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {secret.tags.map((t) => (
                      <Badge key={t} variant="outline">{t}</Badge>
                    ))}
                  </div>
                )}

                <Separator />
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span>
                    Modifié le {new Date(secret.updatedAt).toLocaleString("fr-FR")}
                  </span>
                  <div className="flex gap-2">
                    {canUpdate && (
                      <Button variant="outline" size="sm" onClick={onEdit}>
                        <Pencil className="mr-1.5 h-3.5 w-3.5" /> Modifier
                      </Button>
                    )}
                    {canDelete && (
                      <Button variant="outline" size="sm" className="text-destructive hover:text-destructive" onClick={() => void onTrash()}>
                        <Trash2 className="mr-1.5 h-3.5 w-3.5" /> Corbeille
                      </Button>
                    )}
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="history" className="pt-2">
                {!versions?.length ? (
                  <p className="text-sm text-muted-foreground">Aucun historique.</p>
                ) : (
                  <div className="space-y-2">
                    {versions.map((v) => (
                      <div key={v.id} className="flex items-center justify-between rounded-lg border px-3 py-2 text-sm">
                        <div className="flex items-center gap-2">
                          <Badge variant="secondary">v{v.version}</Badge>
                          <span className="capitalize">{v.action === "created" ? "Création" : "Modification"}</span>
                          {v.changedFields.length > 0 && (
                            <span className="text-xs text-muted-foreground">
                              ({v.changedFields.join(", ")})
                            </span>
                          )}
                        </div>
                        <div className="text-right text-xs text-muted-foreground">
                          <div>{v.changedByEmail ?? "—"}</div>
                          <div>{new Date(v.changedAt).toLocaleString("fr-FR")}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </TabsContent>
            </Tabs>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
