import { useEffect, useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { Plus, Sparkles, Trash2 } from "lucide-react";
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
import { Textarea } from "@/components/ui/textarea";
import { createSecret, revealSecret, updateSecret } from "@/lib/vault.functions";
import { listFolders } from "@/lib/folders.functions";
import { useQuery } from "@tanstack/react-query";
import { FolderPicker } from "@/components/vault/folder-picker";
import {
  FIELD_TYPE_LABELS,
  SECRET_TEMPLATES,
  SECRET_TYPE_LABELS,
  type FieldType,
  type SecretDetail,
  type SecretType,
} from "@/lib/types";
import { generatePassword } from "@/lib/generators";

interface FieldDraft {
  label: string;
  fieldType: FieldType;
  isSensitive: boolean;
  value: string;
}

export function SecretFormDialog({
  open,
  onOpenChange,
  workspaceId,
  existing,
  defaultFolderId = null,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  workspaceId: string;
  existing?: SecretDetail | null;
  defaultFolderId?: string | null;
}) {
  const queryClient = useQueryClient();
  const createFn = useServerFn(createSecret);
  const updateFn = useServerFn(updateSecret);
  const revealFn = useServerFn(revealSecret);

  const { data: folders } = useQuery({
    queryKey: ["folders", workspaceId],
    queryFn: () => listFolders({ data: { workspaceId } }),
    enabled: open,
  });

  const [folderId, setFolderId] = useState<string | null>(null);
  const [type, setType] = useState<SecretType>("LOGIN");
  const [name, setName] = useState("");
  const [username, setUsername] = useState("");
  const [url, setUrl] = useState("");
  const [description, setDescription] = useState("");
  const [tags, setTags] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [notifyDays, setNotifyDays] = useState("");
  const [fields, setFields] = useState<FieldDraft[]>([]);
  const [saving, setSaving] = useState(false);
  const [loadingValues, setLoadingValues] = useState(false);

  const isEdit = Boolean(existing);

  useEffect(() => {
    if (!open) return;
    setFolderId(existing ? existing.folderId : defaultFolderId);
    setType(existing?.type ?? "LOGIN");
    setName(existing?.name ?? "");
    setUsername(existing?.username ?? "");
    setUrl(existing?.url ?? "");
    setDescription(existing?.description ?? "");
    setTags((existing?.tags ?? []).join(", "));
    setExpiresAt(existing?.expiresAt ? existing.expiresAt.slice(0, 10) : "");
    setNotifyDays(existing?.notifyBeforeDays ? String(existing.notifyBeforeDays) : "");

    if (existing) {
      setLoadingValues(true);
      setFields(
        existing.fields.map((f) => ({
          label: f.label,
          fieldType: f.fieldType,
          isSensitive: f.isSensitive,
          value: "",
        })),
      );
      // Prefill values through the audited reveal path.
      revealFn({ data: { secretId: existing.id, action: "reveal" } })
        .then((revealed) => {
          const byId = new Map(revealed.map((r) => [r.id, r.value]));
          setFields(
            existing.fields.map((f) => ({
              label: f.label,
              fieldType: f.fieldType,
              isSensitive: f.isSensitive,
              value: byId.get(f.id) ?? "",
            })),
          );
        })
        .catch(() => toast.error("Impossible de charger les valeurs"))
        .finally(() => setLoadingValues(false));
    } else {
      setFields(
        SECRET_TEMPLATES.LOGIN.fields.map((f) => ({
          label: f.label,
          fieldType: f.fieldType,
          isSensitive: f.sensitive,
          value: "",
        })),
      );
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, existing?.id]);

  const applyTemplate = (next: SecretType) => {
    setType(next);
    if (!isEdit) {
      setFields(
        SECRET_TEMPLATES[next].fields.map((f) => ({
          label: f.label,
          fieldType: f.fieldType,
          isSensitive: f.sensitive,
          value: "",
        })),
      );
    }
  };

  const setField = (index: number, patch: Partial<FieldDraft>) => {
    setFields((prev) => prev.map((f, i) => (i === index ? { ...f, ...patch } : f)));
  };

  const parsedTags = useMemo(
    () => tags.split(",").map((t) => t.trim()).filter(Boolean).slice(0, 30),
    [tags],
  );

  const onSubmit = async () => {
    if (!name.trim()) {
      toast.error("Le nom est requis");
      return;
    }
    setSaving(true);
    try {
      const payload = {
        folderId,
        type,
        name: name.trim(),
        username: username || undefined,
        url: url || undefined,
        description: description || undefined,
        tags: parsedTags,
        expiresAt: expiresAt ? new Date(`${expiresAt}T00:00:00Z`).toISOString() : null,
        notifyBeforeDays: notifyDays ? Number.parseInt(notifyDays, 10) : null,
        fields: fields.filter((f) => f.label.trim()).map((f) => ({
          label: f.label.trim(),
          fieldType: f.fieldType,
          isSensitive: f.isSensitive,
          value: f.value,
        })),
      };
      if (isEdit && existing) {
        await updateFn({ data: { secretId: existing.id, ...payload } });
        toast.success("Secret mis à jour");
      } else {
        await createFn({ data: { workspaceId, ...payload } });
        toast.success("Secret créé et chiffré");
      }
      await queryClient.invalidateQueries({ queryKey: ["secrets"] });
      await queryClient.invalidateQueries({ queryKey: ["secret", existing?.id] });
      onOpenChange(false);
    } catch (err) {
      toast.error((err as Error).message || "Échec de l'enregistrement");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto scrollbar-thin sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Modifier le secret" : "Nouveau secret"}</DialogTitle>
          <DialogDescription>
            Les valeurs sensibles sont chiffrées côté serveur (AES-256-GCM) avant stockage.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label>Type</Label>
            <Select value={type} onValueChange={(v) => applyTemplate(v as SecretType)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {(Object.keys(SECRET_TYPE_LABELS) as SecretType[]).map((t) => (
                  <SelectItem key={t} value={t}>{SECRET_TYPE_LABELS[t]}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Groupe</Label>
            <FolderPicker folders={folders ?? []} value={folderId} onChange={setFolderId} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="sf-name">Nom *</Label>
            <Input id="sf-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="ex. GitHub — équipe infra" />
          </div>
          <div className="space-y-2">
            <Label htmlFor="sf-username">Identifiant</Label>
            <Input id="sf-username" value={username} onChange={(e) => setUsername(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="sf-url">URL</Label>
            <Input id="sf-url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://…" />
          </div>
          <div className="space-y-2 sm:col-span-2">
            <Label htmlFor="sf-tags">Tags (séparés par des virgules)</Label>
            <Input id="sf-tags" value={tags} onChange={(e) => setTags(e.target.value)} placeholder="prod, infra, rotation-90j" />
          </div>
          <div className="space-y-2 sm:col-span-2">
            <Label htmlFor="sf-desc">Description</Label>
            <Textarea id="sf-desc" value={description} onChange={(e) => setDescription(e.target.value)} rows={2} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="sf-exp">Date d'expiration</Label>
            <Input id="sf-exp" type="date" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="sf-notify">Rappel (jours avant expiration)</Label>
            <Input id="sf-notify" type="number" min={1} max={365} value={notifyDays} onChange={(e) => setNotifyDays(e.target.value)} placeholder="ex. 30" />
          </div>
        </div>

        <div className="mt-2 space-y-3">
          <div className="flex items-center justify-between">
            <Label className="text-sm font-semibold">Champs</Label>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setFields((prev) => [...prev, { label: "", fieldType: "secret", isSensitive: true, value: "" }])}
            >
              <Plus className="mr-1 h-3.5 w-3.5" /> Champ
            </Button>
          </div>
          {fields.length === 0 && (
            <p className="text-sm text-muted-foreground">Aucun champ — ajoutez-en un pour stocker une valeur chiffrée.</p>
          )}
          {fields.map((f, i) => (
            <div key={i} className="space-y-2 rounded-lg border bg-muted/30 p-3">
              <div className="flex items-center gap-2">
                <Input
                  value={f.label}
                  onChange={(e) => setField(i, { label: e.target.value })}
                  placeholder="Nom du champ"
                  className="h-8 flex-1"
                />
                <Select value={f.fieldType} onValueChange={(v) => setField(i, { fieldType: v as FieldType })}>
                  <SelectTrigger className="h-8 w-40"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {(Object.keys(FIELD_TYPE_LABELS) as FieldType[]).map((t) => (
                      <SelectItem key={t} value={t}>{FIELD_TYPE_LABELS[t]}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  <Switch checked={f.isSensitive} onCheckedChange={(v) => setField(i, { isSensitive: v })} />
                  Sensible
                </label>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 text-muted-foreground hover:text-destructive"
                  onClick={() => setFields((prev) => prev.filter((_, j) => j !== i))}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
              <div className="flex items-center gap-2">
                {f.fieldType === "textarea" ? (
                  <Textarea
                    value={f.value}
                    onChange={(e) => setField(i, { value: e.target.value })}
                    rows={4}
                    disabled={loadingValues}
                    className="secret-value flex-1 text-xs"
                  />
                ) : (
                  <Input
                    value={f.value}
                    onChange={(e) => setField(i, { value: e.target.value })}
                    disabled={loadingValues}
                    type={f.isSensitive ? "password" : "text"}
                    autoComplete="off"
                    className="secret-value flex-1"
                  />
                )}
                {(f.fieldType === "password" || f.fieldType === "secret") && (
                  <Button
                    type="button"
                    variant="outline"
                    size="icon"
                    title="Générer une valeur aléatoire"
                    onClick={() =>
                      setField(i, {
                        value: generatePassword({
                          length: 24,
                          lowercase: true,
                          uppercase: true,
                          digits: true,
                          symbols: f.fieldType === "password",
                          excludeAmbiguous: true,
                          customChars: "",
                        }),
                      })
                    }
                  >
                    <Sparkles className="h-4 w-4" />
                  </Button>
                )}
              </div>
            </div>
          ))}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            Annuler
          </Button>
          <Button onClick={() => void onSubmit()} disabled={saving || loadingValues}>
            {saving ? "Chiffrement…" : isEdit ? "Enregistrer" : "Créer"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
