// Assistant d'import KeePass.
//
// SÉCURITÉ : tout le déchiffrement a lieu dans ce composant, côté navigateur.
// Le fichier .kdbx, le mot de passe maître, le fichier clé et les clés dérivées
// ne sont jamais envoyés au serveur, ni écrits dans localStorage / sessionStorage,
// ni journalisés. Seules les entrées sélectionnées partent, après confirmation.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  ChevronRight,
  Download,
  Eye,
  EyeOff,
  FileKey2,
  Loader2,
  Lock,
  Search,
  ShieldCheck,
  Trash2,
  Upload,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { FolderPicker } from "@/components/vault/folder-picker";
import { listFolders } from "@/lib/folders.functions";
import { folderPathLabel } from "@/lib/folders";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  DUPLICATE_CRITERION_LABELS,
  DUPLICATE_STRATEGY_LABELS,
  LARGE_FILE_WARNING_SIZE,
  MAX_KEEPASS_TOTAL_IMPORT_SIZE,
  MAX_UNLOCK_ATTEMPTS,
  formatBytes,
  type DuplicateCriterion,
  type DuplicateStrategy,
  type KeepassParseResult,
} from "@/lib/keepass/types";
import { defaultRootFolderName, mapEntryToPayload } from "@/lib/keepass/mapping";
import {
  finishImportJob,
  importBatch,
  listImportTargets,
  startImportJob,
} from "@/lib/import.functions";

type Step = "destination" | "file" | "unlock" | "preview" | "options" | "confirm" | "running" | "report";

interface Report {
  imported: number;
  skipped: number;
  replaced: number;
  merged: number;
  failed: number;
  attachments: number;
  folders: number;
  warnings: string[];
}

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  workspaceId?: string;
  onImported?: () => void;
}

export function KeepassImportDialog({ open, onOpenChange, workspaceId, onImported }: Props) {
  const [step, setStep] = useState<Step>("destination");
  const [target, setTarget] = useState<string>(workspaceId ?? "");
  const [rootFolderName, setRootFolderName] = useState(defaultRootFolderName());
  const [rootMode, setRootMode] = useState<"new" | "existing" | "root">("new");
  const [rootFolderId, setRootFolderId] = useState<string | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [fileBuffer, setFileBuffer] = useState<ArrayBuffer | null>(null);
  const [formatLabel, setFormatLabel] = useState<string>("");
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const keyBufferRef = useRef<ArrayBuffer | null>(null);
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [capsLock, setCapsLock] = useState(false);
  const [attempts, setAttempts] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [parsed, setParsed] = useState<KeepassParseResult | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [strategy, setStrategy] = useState<DuplicateStrategy>("skip");
  const [criteria, setCriteria] = useState<DuplicateCriterion[]>(["name", "username"]);
  const [progress, setProgress] = useState(0);
  const [report, setReport] = useState<Report | null>(null);
  const submittingRef = useRef(false);

  const { data: targets } = useQuery({
    queryKey: ["import-targets"],
    queryFn: () => listImportTargets(),
    enabled: open,
  });

  // Groupes du coffre de destination (pour importer sous un groupe existant).
  const { data: folderData } = useQuery({
    queryKey: ["folders", target],
    queryFn: () => listFolders({ data: { workspaceId: target } }),
    enabled: open && Boolean(target),
  });
  const importFolders = folderData ?? [];

  useEffect(() => {
    if (workspaceId) setTarget(workspaceId);
  }, [workspaceId]);

  /** Purge mémoire — voir la documentation pour les limites réelles en JS. */
  const wipe = useCallback(() => {
    if (fileBuffer) new Uint8Array(fileBuffer).fill(0);
    if (keyBufferRef.current) new Uint8Array(keyBufferRef.current).fill(0);
    keyBufferRef.current = null;
    setFileBuffer(null);
    setFile(null);
    setKeyFile(null);
    setPassword("");
    setParsed(null);
    setSelected(new Set());
    setError(null);
    setAttempts(0);
    setProgress(0);
  }, [fileBuffer]);

  const close = useCallback(
    (next: boolean) => {
      if (!next) {
        wipe();
        setStep("destination");
        setReport(null);
      }
      onOpenChange(next);
    },
    [onOpenChange, wipe],
  );

  const entriesById = useMemo(() => {
    const map = new Map<string, KeepassParseResult["entries"][number]>();
    for (const e of parsed?.entries ?? []) map.set(e.uuid, e);
    return map;
  }, [parsed]);

  const visibleEntries = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = parsed?.entries ?? [];
    if (!q) return list;
    return list.filter(
      (e) =>
        e.title.toLowerCase().includes(q) ||
        e.username.toLowerCase().includes(q) ||
        e.path.join("/").toLowerCase().includes(q),
    );
  }, [parsed, query]);

  const grouped = useMemo(() => {
    const map = new Map<string, typeof visibleEntries>();
    for (const e of visibleEntries) {
      const key = e.path.length ? e.path.join(" / ") : "Racine";
      const arr = map.get(key) ?? [];
      arr.push(e);
      map.set(key, arr);
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [visibleEntries]);

  async function onPickFile(picked: File | null) {
    setError(null);
    if (!picked) return;
    if (picked.size > MAX_KEEPASS_TOTAL_IMPORT_SIZE) {
      setError(`Fichier trop volumineux (limite ${formatBytes(MAX_KEEPASS_TOTAL_IMPORT_SIZE)}).`);
      return;
    }
    const buffer = await picked.arrayBuffer();
    const { detectFormat } = await import("@/lib/keepass/kdbx");
    const format = detectFormat(buffer);
    if (format.kind === "kdb") {
      setError(
        "Base KeePass 1.x (.kdb) détectée : convertissez-la en .kdbx depuis KeePass (Fichier → Enregistrer sous), puis réessayez.",
      );
      return;
    }
    if (format.kind !== "kdbx") {
      setError("Ce fichier n'est pas une base KeePass .kdbx valide.");
      return;
    }
    setFile(picked);
    setFileBuffer(buffer);
    setFormatLabel(format.label);
  }

  async function unlock() {
    if (!fileBuffer) return;
    if (attempts >= MAX_UNLOCK_ATTEMPTS) {
      setError("Trop de tentatives. Fermez et rouvrez l'assistant.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const { openKeepassDatabase } = await import("@/lib/keepass/kdbx");
      const result = await openKeepassDatabase({
        file: fileBuffer,
        password,
        keyFile: keyBufferRef.current ?? undefined,
      });
      setParsed(result);
      setSelected(new Set(result.entries.map((e) => e.uuid)));
      setPassword(""); // le mot de passe maître ne survit pas au déverrouillage
      setStep("preview");
    } catch (err) {
      setAttempts((a) => a + 1);
      const code = (err as { code?: string }).code;
      setError(
        code === "unsupported_format"
          ? (err as Error).message
          : "Impossible d'ouvrir cette base. Vérifiez le mot de passe, le fichier clé et la compatibilité du format.",
      );
    } finally {
      setBusy(false);
    }
  }

  const selectedEntries = useMemo(
    () => [...selected].map((id) => entriesById.get(id)).filter(Boolean) as KeepassParseResult["entries"],
    [selected, entriesById],
  );

  const selectedAttachments = selectedEntries.reduce((n, e) => n + e.attachments.length, 0);

  async function runImport() {
    if (submittingRef.current) return; // protection anti-double soumission
    submittingRef.current = true;
    setStep("running");
    setProgress(0);
    const warnings = [...(parsed?.warnings ?? [])];
    try {
      const job = await startImportJob({
        data: {
          workspaceId: target,
          rootMode,
          rootFolderName: rootMode === "new" ? rootFolderName : undefined,
          rootFolderId: rootMode === "existing" ? rootFolderId : null,
          strategy,
          criteria,
          plannedEntries: selectedEntries.length,
        },
      });
      const payloads = selectedEntries.map(mapEntryToPayload);
      const totals: Report = {
        imported: 0,
        skipped: 0,
        replaced: 0,
        merged: 0,
        failed: 0,
        attachments: 0,
        folders: 0,
        warnings,
      };
      const size = 25;
      for (let i = 0; i < payloads.length; i += size) {
        const chunk = payloads.slice(i, i + size);
        const res = await importBatch({
          data: { jobId: job.jobId, strategy, criteria, items: chunk },
        });
        totals.imported += res.imported;
        totals.skipped += res.skipped;
        totals.replaced += res.replaced;
        totals.merged += res.merged;
        totals.failed += res.failed;
        totals.attachments += res.attachments;
        totals.folders += res.folders;
        totals.warnings.push(...res.warnings);
        setProgress(Math.round(((i + chunk.length) / payloads.length) * 100));
      }
      await finishImportJob({ data: { jobId: job.jobId, status: "completed" } });
      setReport(totals);
      setStep("report");
      wipe();
      onImported?.();
    } catch {
      toast.error("L'import a échoué. Vous pouvez relancer : les entrées déjà importées ne seront pas dupliquées.");
      setStep("confirm");
    } finally {
      submittingRef.current = false;
    }
  }

  function downloadReport() {
    if (!report) return;
    // Rapport strictement non sensible : compteurs et avertissements seulement.
    const body = {
      generatedAt: new Date().toISOString(),
      destination: targets?.find((t) => t.id === target)?.name ?? "",
      rootFolder:
        rootMode === "new"
          ? rootFolderName
          : rootMode === "existing"
            ? folderPathLabel(importFolders, rootFolderId)
            : "Racine du coffre",
      duplicateStrategy: strategy,
      counters: {
        imported: report.imported,
        replaced: report.replaced,
        merged: report.merged,
        skipped: report.skipped,
        failed: report.failed,
        attachments: report.attachments,
        folders: report.folders,
      },
      warnings: report.warnings,
    };
    const blob = new Blob([JSON.stringify(body, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "rapport-import-keepass.json";
    a.click();
    URL.revokeObjectURL(url); // révocation immédiate de l'URL temporaire
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FileKey2 className="h-5 w-5 text-primary" /> Importer une base KeePass
          </DialogTitle>
          <DialogDescription>
            Le fichier est déchiffré dans votre navigateur. Le mot de passe maître et le fichier
            clé ne sont jamais envoyés au serveur.
          </DialogDescription>
        </DialogHeader>

        {step === "destination" && (
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Coffre de destination</Label>
              <Select value={target} onValueChange={setTarget}>
                <SelectTrigger>
                  <SelectValue placeholder="Choisir un coffre autorisé" />
                </SelectTrigger>
                <SelectContent>
                  {(targets ?? []).map((t) => (
                    <SelectItem key={t.id} value={t.id}>
                      {t.isPersonal ? "Coffre personnel" : t.name} · {t.role}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Seuls les coffres où vous avez le droit de créer des secrets sont proposés. La
                permission est revérifiée côté serveur à chaque lot.
              </p>
            </div>
            <div className="space-y-2">
              <Label>Emplacement de l'import</Label>
              <Select value={rootMode} onValueChange={(v) => setRootMode(v as typeof rootMode)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="new">Créer un nouveau groupe racine</SelectItem>
                  <SelectItem value="existing">Importer dans un groupe existant</SelectItem>
                  <SelectItem value="root">Recréer l'arborescence à la racine du coffre</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                La hiérarchie des groupes KeePass est recréée à l'identique sous cet emplacement.
              </p>
            </div>
            {rootMode === "new" && (
              <div className="space-y-2">
                <Label htmlFor="root-folder">Nom du groupe racine</Label>
                <Input
                  id="root-folder"
                  value={rootFolderName}
                  onChange={(e) => setRootFolderName(e.target.value)}
                />
              </div>
            )}
            {rootMode === "existing" && (
              <div className="space-y-2">
                <Label>Groupe de destination</Label>
                <FolderPicker
                  folders={importFolders}
                  value={rootFolderId}
                  onChange={setRootFolderId}
                  rootLabel="— choisir un groupe —"
                />
              </div>
            )}
            <div className="flex justify-end">
              <Button
                disabled={
                  !target ||
                  (rootMode === "new" && !rootFolderName) ||
                  (rootMode === "existing" && !rootFolderId)
                }
                onClick={() => setStep("file")}
              >
                Continuer <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}

        {step === "file" && (
          <div className="space-y-4">
            <label
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                void onPickFile(e.dataTransfer.files?.[0] ?? null);
              }}
              className="flex cursor-pointer flex-col items-center gap-2 rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground hover:bg-muted/40"
            >
              <Upload className="h-6 w-6" />
              Glissez votre fichier .kdbx ici, ou cliquez pour le sélectionner
              <input
                type="file"
                accept=".kdbx,.kdb"
                className="hidden"
                onChange={(e) => void onPickFile(e.target.files?.[0] ?? null)}
              />
            </label>

            {file && (
              <div className="rounded-md border p-3 text-sm">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium">{file.name}</p>
                    <p className="text-xs text-muted-foreground">
                      {formatBytes(file.size)} · {formatLabel}
                    </p>
                  </div>
                  <Button variant="ghost" size="sm" onClick={wipe}>
                    <Trash2 className="h-4 w-4" /> Retirer
                  </Button>
                </div>
                {file.size > LARGE_FILE_WARNING_SIZE && (
                  <p className="mt-2 flex items-center gap-1 text-xs text-amber-600">
                    <AlertTriangle className="h-3 w-3" /> Fichier volumineux : l'analyse peut être
                    lente et consommer beaucoup de mémoire.
                  </p>
                )}
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="keyfile">Fichier clé (facultatif)</Label>
              <Input
                id="keyfile"
                type="file"
                onChange={async (e) => {
                  const f = e.target.files?.[0] ?? null;
                  setKeyFile(f);
                  keyBufferRef.current = f ? await f.arrayBuffer() : null;
                }}
              />
              {keyFile && <p className="text-xs text-muted-foreground">{keyFile.name}</p>}
            </div>

            {error && <p className="text-sm text-destructive">{error}</p>}

            <div className="flex justify-between">
              <Button variant="ghost" onClick={() => setStep("destination")}>
                Retour
              </Button>
              <Button disabled={!fileBuffer} onClick={() => setStep("unlock")}>
                Continuer <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}

        {step === "unlock" && (
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="master">Mot de passe maître KeePass</Label>
              <div className="relative">
                <Input
                  id="master"
                  type={showPassword ? "text" : "password"}
                  autoComplete="off"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyUp={(e) => setCapsLock(e.getModifierState?.("CapsLock") ?? false)}
                  onKeyDown={(e) => {
                    setCapsLock(e.getModifierState?.("CapsLock") ?? false);
                    if (e.key === "Enter") void unlock();
                  }}
                />
                <button
                  type="button"
                  className="absolute right-2 top-2 text-muted-foreground"
                  onClick={() => setShowPassword((v) => !v)}
                  aria-label={showPassword ? "Masquer" : "Afficher"}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {capsLock && (
                <p className="text-xs text-amber-600">Verrouillage majuscules activé.</p>
              )}
              <p className="text-xs text-muted-foreground">
                Tentatives restantes : {Math.max(0, MAX_UNLOCK_ATTEMPTS - attempts)}
              </p>
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
            <div className="flex justify-between">
              <Button variant="ghost" onClick={() => setStep("file")}>
                Retour
              </Button>
              <Button disabled={busy} onClick={() => void unlock()}>
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lock className="h-4 w-4" />}
                Déverrouiller localement
              </Button>
            </div>
          </div>
        )}

        {step === "preview" && parsed && (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2 text-xs">
              <Badge variant="secondary">{parsed.formatVersion}</Badge>
              <Badge variant="secondary">KDF {parsed.kdfName}</Badge>
              <Badge variant="secondary">{parsed.stats.groups} groupes</Badge>
              <Badge variant="secondary">{parsed.stats.entries} entrées</Badge>
              <Badge variant="secondary">{parsed.stats.attachments} pièces jointes</Badge>
              <Badge variant="secondary">{parsed.stats.customFields} champs personnalisés</Badge>
              <Badge variant="secondary">{parsed.stats.totpEntries} TOTP</Badge>
              <Badge variant="secondary">{parsed.stats.skipped} ignorées</Badge>
            </div>
            {parsed.warnings.length > 0 && (
              <ul className="rounded-md border border-amber-500/40 bg-amber-500/10 p-2 text-xs">
                {[...new Set(parsed.warnings)].map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            )}
            <div className="flex items-center gap-2">
              <Search className="h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Rechercher une entrée"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSelected(new Set(parsed.entries.map((e) => e.uuid)))}
              >
                Tout
              </Button>
              <Button variant="outline" size="sm" onClick={() => setSelected(new Set())}>
                Aucun
              </Button>
            </div>
            <ScrollArea className="h-72 rounded-md border p-2">
              {grouped.map(([path, items]) => (
                <div key={path} className="mb-3">
                  <div className="mb-1 flex items-center gap-2">
                    <Checkbox
                      checked={items.every((e) => selected.has(e.uuid))}
                      onCheckedChange={(v) => {
                        const next = new Set(selected);
                        for (const e of items) v ? next.add(e.uuid) : next.delete(e.uuid);
                        setSelected(next);
                      }}
                    />
                    <span className="text-xs font-medium text-muted-foreground">{path}</span>
                  </div>
                  {items.map((e) => (
                    <div key={e.uuid} className="ml-6 flex items-center gap-2 py-1 text-sm">
                      <Checkbox
                        checked={selected.has(e.uuid)}
                        onCheckedChange={(v) => {
                          const next = new Set(selected);
                          v ? next.add(e.uuid) : next.delete(e.uuid);
                          setSelected(next);
                        }}
                      />
                      <span className="truncate">{e.title}</span>
                      {e.username && (
                        <span className="truncate text-xs text-muted-foreground">{e.username}</span>
                      )}
                      {/* Valeurs sensibles toujours masquées en prévisualisation */}
                      {e.password && <span className="text-xs text-muted-foreground">••••••••</span>}
                      {e.totp && <Badge variant="outline">TOTP</Badge>}
                      {e.attachments.length > 0 && (
                        <Badge variant="outline">{e.attachments.length} PJ</Badge>
                      )}
                    </div>
                  ))}
                </div>
              ))}
            </ScrollArea>
            <div className="flex justify-between">
              <Button variant="ghost" onClick={() => close(false)}>
                Annuler
              </Button>
              <Button disabled={selected.size === 0} onClick={() => setStep("options")}>
                {selected.size} sélectionnée(s) — continuer
              </Button>
            </div>
          </div>
        )}

        {step === "options" && (
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Stratégie en cas de doublon</Label>
              <Select value={strategy} onValueChange={(v) => setStrategy(v as DuplicateStrategy)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(DUPLICATE_STRATEGY_LABELS).map(([value, label]) => (
                    <SelectItem key={value} value={value}>
                      {label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Critères de détection d'un doublon</Label>
              <div className="flex flex-wrap gap-4">
                {(Object.keys(DUPLICATE_CRITERION_LABELS) as DuplicateCriterion[]).map((c) => (
                  <label key={c} className="flex items-center gap-2 text-sm">
                    <Checkbox
                      checked={criteria.includes(c)}
                      onCheckedChange={(v) =>
                        setCriteria((prev) =>
                          v ? [...new Set([...prev, c])] : prev.filter((x) => x !== c),
                        )
                      }
                    />
                    {DUPLICATE_CRITERION_LABELS[c]}
                  </label>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">
                Les mots de passe ne sont jamais comparés : la détection porte uniquement sur des
                métadonnées.
              </p>
            </div>
            <div className="flex justify-between">
              <Button variant="ghost" onClick={() => setStep("preview")}>
                Retour
              </Button>
              <Button disabled={criteria.length === 0} onClick={() => setStep("confirm")}>
                Continuer
              </Button>
            </div>
          </div>
        )}

        {step === "confirm" && parsed && (
          <div className="space-y-4 text-sm">
            <div className="rounded-md border p-3">
              <dl className="grid grid-cols-2 gap-2">
                <dt className="text-muted-foreground">Coffre de destination</dt>
                <dd>{targets?.find((t) => t.id === target)?.name}</dd>
                <dt className="text-muted-foreground">Emplacement</dt>
                <dd>
                  {rootMode === "new"
                    ? rootFolderName
                    : rootMode === "existing"
                      ? folderPathLabel(importFolders, rootFolderId)
                      : "Racine du coffre"}
                </dd>
                <dt className="text-muted-foreground">Groupes</dt>
                <dd>{parsed.stats.groups}</dd>
                <dt className="text-muted-foreground">Entrées à importer</dt>
                <dd>{selectedEntries.length}</dd>
                <dt className="text-muted-foreground">Pièces jointes</dt>
                <dd>{selectedAttachments}</dd>
                <dt className="text-muted-foreground">Entrées non sélectionnées</dt>
                <dd>{parsed.stats.entries - selectedEntries.length}</dd>
                <dt className="text-muted-foreground">Stratégie doublons</dt>
                <dd>{DUPLICATE_STRATEGY_LABELS[strategy]}</dd>
              </dl>
            </div>
            <p className="flex items-center gap-2 text-xs text-muted-foreground">
              <ShieldCheck className="h-4 w-4 text-primary" /> Les valeurs seront rechiffrées
              (AES-256-GCM, clé du coffre) avant d'être stockées.
            </p>
            <div className="flex justify-between">
              <Button variant="ghost" onClick={() => setStep("options")}>
                Retour
              </Button>
              <Button onClick={() => void runImport()}>Confirmer et importer</Button>
            </div>
          </div>
        )}

        {step === "running" && (
          <div className="space-y-3 py-6 text-center">
            <Loader2 className="mx-auto h-6 w-6 animate-spin text-primary" />
            <Progress value={progress} />
            <p className="text-sm text-muted-foreground">Import en cours — {progress} %</p>
          </div>
        )}

        {step === "report" && report && (
          <div className="space-y-4 text-sm">
            <div className="grid grid-cols-2 gap-2 rounded-md border p-3">
              <span className="text-muted-foreground">Entrées importées</span>
              <span>{report.imported}</span>
              <span className="text-muted-foreground">Entrées remplacées</span>
              <span>{report.replaced}</span>
              <span className="text-muted-foreground">Entrées fusionnées</span>
              <span>{report.merged}</span>
              <span className="text-muted-foreground">Doublons ignorés</span>
              <span>{report.skipped}</span>
              <span className="text-muted-foreground">Dossiers créés</span>
              <span>{report.folders}</span>
              <span className="text-muted-foreground">Pièces jointes importées</span>
              <span>{report.attachments}</span>
              <span className="text-muted-foreground">Échecs</span>
              <span>{report.failed}</span>
            </div>
            {report.warnings.length > 0 && (
              <ul className="rounded-md border p-2 text-xs text-muted-foreground">
                {[...new Set(report.warnings)].map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            )}
            <Separator />
            <div className="flex justify-between">
              <Button variant="outline" onClick={downloadReport}>
                <Download className="h-4 w-4" /> Télécharger le rapport
              </Button>
              <Button onClick={() => close(false)}>Terminer</Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
