import { useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { Ban, ShieldCheck, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
import {
  deleteUserAccount,
  deleteWorkspaceAdmin,
  getAdminOverview,
  listAllWorkspaces,
  listAuditLogs,
  listUsers,
  setUserAppRole,
  setUserBanned,
  setWorkspaceDisabled,
} from "@/lib/admin.functions";
import {
  deleteOidcMapping,
  getOidcProvider,
  listOidcMappings,
  saveOidcMapping,
  saveOidcProvider,
} from "@/lib/oidc.functions";
import { getSessionInfo, listWorkspaces } from "@/lib/vault.functions";
import { ROLE_LABELS, type WorkspaceRole } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/admin")({
  head: () => ({
    meta: [
      { title: "Administration — Sentinel Vault" },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: AdminPage,
});

function OverviewTab() {
  const { data } = useQuery({ queryKey: ["admin-overview"], queryFn: () => getAdminOverview() });
  const stats = [
    { label: "Utilisateurs", value: data?.userCount ?? "—" },
    { label: "Coffres actifs", value: data?.workspaceCount ?? "—" },
    { label: "Secrets chiffrés", value: data?.secretCount ?? "—" },
    { label: "Connexions (24 h)", value: data?.loginsLast24h ?? "—" },
    { label: "Échecs de connexion (24 h)", value: data?.failedLoginsLast24h ?? "—" },
  ];
  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
      {stats.map((s) => (
        <Card key={s.label}>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">{s.label}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tabular-nums">{s.value}</div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function UsersTab() {
  const queryClient = useQueryClient();
  const banFn = useServerFn(setUserBanned);
  const roleFn = useServerFn(setUserAppRole);
  const deleteFn = useServerFn(deleteUserAccount);
  const { data: users } = useQuery({ queryKey: ["admin-users"], queryFn: () => listUsers() });

  const run = async (fn: () => Promise<unknown>, message: string) => {
    try {
      await fn();
      toast.success(message);
      await queryClient.invalidateQueries({ queryKey: ["admin-users"] });
    } catch (err) {
      toast.error((err as Error).message);
    }
  };

  return (
    <div className="space-y-2">
      {(users ?? []).map((u) => (
        <div key={u.id} className="flex flex-wrap items-center gap-3 rounded-lg border bg-card px-4 py-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary">
            {(u.email ?? "?").slice(0, 2).toUpperCase()}
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="truncate text-sm font-medium">{u.displayName || u.email}</span>
              {u.appRole === "SUPER_ADMIN" && (
                <Badge variant="secondary" className="gap-1 text-[10px]">
                  <ShieldCheck className="h-3 w-3" /> Super admin
                </Badge>
              )}
              {u.banned && <Badge variant="destructive" className="text-[10px]">Désactivé</Badge>}
            </div>
            <div className="truncate text-xs text-muted-foreground">
              {u.email} · dernière connexion {u.lastSignInAt ? new Date(u.lastSignInAt).toLocaleString("fr-FR") : "jamais"}
            </div>
          </div>
          <Select
            value={u.appRole}
            onValueChange={(v) =>
              void run(() => roleFn({ data: { targetUserId: u.id, role: v as "SUPER_ADMIN" | "USER" } }), "Rôle mis à jour")
            }
          >
            <SelectTrigger className="h-8 w-36"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="USER">Utilisateur</SelectItem>
              <SelectItem value="SUPER_ADMIN">Super admin</SelectItem>
            </SelectContent>
          </Select>
          <Button
            variant="outline"
            size="sm"
            onClick={() => void run(() => banFn({ data: { targetUserId: u.id, banned: !u.banned } }), u.banned ? "Compte réactivé" : "Compte désactivé")}
          >
            <Ban className="mr-1.5 h-3.5 w-3.5" /> {u.banned ? "Réactiver" : "Désactiver"}
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="text-muted-foreground hover:text-destructive"
            onClick={() => {
              if (!window.confirm(`Supprimer définitivement le compte ${u.email} ? Ses coffres personnels seront supprimés.`)) return;
              void run(() => deleteFn({ data: { targetUserId: u.id } }), "Compte supprimé");
            }}
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      ))}
    </div>
  );
}

function WorkspacesTab() {
  const queryClient = useQueryClient();
  const disableFn = useServerFn(setWorkspaceDisabled);
  const deleteFn = useServerFn(deleteWorkspaceAdmin);
  const { data: workspaces } = useQuery({ queryKey: ["admin-workspaces"], queryFn: () => listAllWorkspaces() });

  return (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground">
        L'administration plateforme ne donne jamais accès aux valeurs : les clés de chiffrement
        sont gérées séparément. La désactivation coupe l'accès de tous les membres.
      </p>
      {(workspaces ?? []).map((w) => (
        <div key={w.id} className="flex flex-wrap items-center gap-3 rounded-lg border bg-card px-4 py-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="truncate text-sm font-medium">{w.name}</span>
              {w.isPersonal && <Badge variant="secondary" className="text-[10px]">Personnel</Badge>}
              {w.disabled && <Badge variant="destructive" className="text-[10px]">Désactivé</Badge>}
            </div>
            <div className="text-xs text-muted-foreground">
              {w.ownerEmail} · {w.memberCount} membre(s) · {w.secretCount} secret(s)
            </div>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={async () => {
              try {
                await disableFn({ data: { workspaceId: w.id, disabled: !w.disabled } });
                await queryClient.invalidateQueries({ queryKey: ["admin-workspaces"] });
                toast.success(w.disabled ? "Coffre réactivé" : "Coffre désactivé");
              } catch (err) {
                toast.error((err as Error).message);
              }
            }}
          >
            {w.disabled ? "Réactiver" : "Désactiver"}
          </Button>
          {!w.isPersonal && (
            <Button
              variant="ghost"
              size="icon"
              className="text-muted-foreground hover:text-destructive"
              onClick={() => {
                if (!window.confirm(`Supprimer le coffre « ${w.name} » ?`)) return;
                void (async () => {
                  try {
                    await deleteFn({ data: { workspaceId: w.id } });
                    await queryClient.invalidateQueries({ queryKey: ["admin-workspaces"] });
                    toast.success("Coffre supprimé");
                  } catch (err) {
                    toast.error((err as Error).message);
                  }
                })();
              }}
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          )}
        </div>
      ))}
    </div>
  );
}

function OidcTab() {
  const queryClient = useQueryClient();
  const saveProviderFn = useServerFn(saveOidcProvider);
  const saveMappingFn = useServerFn(saveOidcMapping);
  const deleteMappingFn = useServerFn(deleteOidcMapping);

  const { data: provider } = useQuery({ queryKey: ["oidc-provider"], queryFn: () => getOidcProvider() });
  const { data: mappings } = useQuery({ queryKey: ["oidc-mappings"], queryFn: () => listOidcMappings() });
  const { data: workspaces } = useQuery({ queryKey: ["workspaces"], queryFn: () => listWorkspaces() });

  const [name, setName] = useState<string | null>(null);
  const [issuer, setIssuer] = useState<string | null>(null);
  const [clientId, setClientId] = useState<string | null>(null);
  const [clientSecret, setClientSecret] = useState("");
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [mode, setMode] = useState<string | null>(null);
  const [mapGroup, setMapGroup] = useState("");
  const [mapWorkspace, setMapWorkspace] = useState("");
  const [mapRole, setMapRole] = useState<WorkspaceRole>("VIEWER");
  const [busy, setBusy] = useState(false);

  const callbackUrl = `${window.location.origin}/api/public/oidc/callback`;

  const save = async () => {
    setBusy(true);
    try {
      await saveProviderFn({
        data: {
          name: name ?? provider?.name ?? "Keycloak",
          issuerUrl: issuer ?? provider?.issuerUrl ?? "",
          clientId: clientId ?? provider?.clientId ?? "",
          clientSecret: clientSecret || undefined,
          enabled: enabled ?? provider?.enabled ?? false,
          permissionMode: (mode ?? provider?.permissionMode ?? "local") as "oidc" | "local" | "hybrid",
        },
      });
      setClientSecret("");
      toast.success("Fournisseur OIDC enregistré");
      await queryClient.invalidateQueries({ queryKey: ["oidc-provider"] });
    } catch (err) {
      toast.error((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Fournisseur OIDC</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-lg bg-muted/50 p-3 text-xs text-muted-foreground">
            URL de rappel à déclarer chez le fournisseur :{" "}
            <code className="secret-value text-foreground">{callbackUrl}</code>
          </div>
          <div className="space-y-2">
            <Label>Nom affiché</Label>
            <Input value={name ?? provider?.name ?? "Keycloak"} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label>Issuer URL</Label>
            <Input
              value={issuer ?? provider?.issuerUrl ?? ""}
              onChange={(e) => setIssuer(e.target.value)}
              placeholder="https://sso.example.com/realms/entreprise"
              className="font-mono text-xs"
            />
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>Client ID</Label>
              <Input value={clientId ?? provider?.clientId ?? ""} onChange={(e) => setClientId(e.target.value)} className="font-mono text-xs" />
            </div>
            <div className="space-y-2">
              <Label>Client secret {provider?.clientSecretSet && "(déjà défini)"}</Label>
              <Input
                type="password"
                value={clientSecret}
                onChange={(e) => setClientSecret(e.target.value)}
                placeholder={provider?.clientSecretSet ? "••••••••" : "Requis"}
                autoComplete="off"
              />
              <p className="text-[11px] text-muted-foreground">Chiffré avant stockage — jamais lisible en clair.</p>
            </div>
          </div>
          <div className="space-y-2">
            <Label>Mode de gestion des permissions</Label>
            <Select value={mode ?? provider?.permissionMode ?? "local"} onValueChange={setMode}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="local">Local — membres gérés dans l'application</SelectItem>
                <SelectItem value="oidc">OIDC — appartenances synchronisées depuis l'IdP</SelectItem>
                <SelectItem value="hybrid">Hybride — synchronisation IdP + ajouts locaux</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <label className="flex items-center gap-2 text-sm">
            <Switch checked={enabled ?? provider?.enabled ?? false} onCheckedChange={setEnabled} />
            Activer la connexion SSO
          </label>
          <Button onClick={() => void save()} disabled={busy}>
            {busy ? "Enregistrement…" : "Enregistrer"}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Mapping groupes → coffres</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-xs text-muted-foreground">
            À chaque connexion SSO, les groupes de l'utilisateur (claim <code>groups</code>) sont
            synchronisés avec les coffres ci-dessous.
          </p>
          <div className="space-y-2">
            {(mappings ?? []).map((m) => (
              <div key={m.id} className="flex items-center gap-2 rounded-lg border px-3 py-2 text-sm">
                <code className="secret-value rounded bg-muted px-1.5 py-0.5 text-xs">{m.idpGroup}</code>
                <span className="text-muted-foreground">→</span>
                <span className="flex-1 truncate">{m.workspaceName}</span>
                <Badge variant="secondary">{ROLE_LABELS[m.role]}</Badge>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 text-muted-foreground hover:text-destructive"
                  onClick={async () => {
                    await deleteMappingFn({ data: { mappingId: m.id } });
                    await queryClient.invalidateQueries({ queryKey: ["oidc-mappings"] });
                  }}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
            ))}
            {(mappings ?? []).length === 0 && (
              <p className="text-sm text-muted-foreground">Aucun mapping configuré.</p>
            )}
          </div>
          <div className="grid gap-2 sm:grid-cols-[1fr_1fr_auto_auto]">
            <Input value={mapGroup} onChange={(e) => setMapGroup(e.target.value)} placeholder="groupe IdP" className="font-mono text-xs" />
            <Select value={mapWorkspace} onValueChange={setMapWorkspace}>
              <SelectTrigger><SelectValue placeholder="Coffre" /></SelectTrigger>
              <SelectContent>
                {(workspaces ?? []).filter((w) => !w.isPersonal).map((w) => (
                  <SelectItem key={w.id} value={w.id}>{w.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={mapRole} onValueChange={(v) => setMapRole(v as WorkspaceRole)}>
              <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
              <SelectContent>
                {(Object.keys(ROLE_LABELS) as WorkspaceRole[]).map((r) => (
                  <SelectItem key={r} value={r}>{ROLE_LABELS[r]}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button
              variant="outline"
              disabled={!mapGroup || !mapWorkspace}
              onClick={async () => {
                try {
                  await saveMappingFn({ data: { idpGroup: mapGroup.trim(), workspaceId: mapWorkspace, role: mapRole } });
                  setMapGroup("");
                  await queryClient.invalidateQueries({ queryKey: ["oidc-mappings"] });
                  toast.success("Mapping ajouté");
                } catch (err) {
                  toast.error((err as Error).message);
                }
              }}
            >
              Ajouter
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

const AUDIT_ACTIONS = [
  ["", "Toutes les actions"],
  ["auth.login", "Connexions"],
  ["auth.login_failed", "Échecs de connexion"],
  ["auth.oidc_login", "Connexions SSO"],
  ["secret.created", "Créations de secrets"],
  ["secret.updated", "Modifications"],
  ["secret.revealed", "Révélations"],
  ["secret.copied", "Copies"],
  ["secret.deleted", "Suppressions"],
  ["member.added", "Ajouts de membres"],
] as const;

function AuditTab() {
  const [action, setAction] = useState("");
  const { data: logs, isLoading } = useQuery({
    queryKey: ["audit-logs", action],
    queryFn: () => listAuditLogs({ data: { ...(action ? { action } : {}), limit: 200 } }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs text-muted-foreground">
          Journal en écriture seule : aucune valeur de secret n'y figure jamais, uniquement des métadonnées.
        </p>
        <Select value={action} onValueChange={setAction}>
          <SelectTrigger className="h-8 w-56"><SelectValue /></SelectTrigger>
          <SelectContent>
            {AUDIT_ACTIONS.map(([value, label]) => (
              <SelectItem key={value || "all"} value={value}>{label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      {isLoading ? (
        <p className="py-10 text-center text-sm text-muted-foreground">Chargement…</p>
      ) : (
        <div className="overflow-hidden rounded-lg border">
          <table className="w-full text-sm">
            <thead className="bg-muted/50 text-left text-xs text-muted-foreground">
              <tr>
                <th className="px-3 py-2 font-medium">Date</th>
                <th className="px-3 py-2 font-medium">Acteur</th>
                <th className="px-3 py-2 font-medium">Action</th>
                <th className="px-3 py-2 font-medium">Cible</th>
                <th className="px-3 py-2 font-medium">Coffre</th>
                <th className="px-3 py-2 font-medium">Résultat</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {(logs ?? []).map((l) => (
                <tr key={l.id} className="bg-card">
                  <td className="whitespace-nowrap px-3 py-2 text-xs text-muted-foreground">
                    {new Date(l.createdAt).toLocaleString("fr-FR")}
                  </td>
                  <td className="max-w-40 truncate px-3 py-2 text-xs">{l.actorEmail ?? "—"}</td>
                  <td className="px-3 py-2">
                    <code className="rounded bg-muted px-1.5 py-0.5 text-[11px]">{l.action}</code>
                  </td>
                  <td className="max-w-48 truncate px-3 py-2 text-xs">{l.targetLabel ?? "—"}</td>
                  <td className="max-w-32 truncate px-3 py-2 text-xs text-muted-foreground">{l.workspaceName ?? "—"}</td>
                  <td className="px-3 py-2">
                    <Badge variant={l.result === "success" ? "secondary" : "destructive"} className="text-[10px]">
                      {l.result}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function AdminPage() {
  const navigate = useNavigate();
  const { data: session, isLoading } = useQuery({
    queryKey: ["session-info"],
    queryFn: () => getSessionInfo(),
  });

  // Gate strict : les onglets admin (et leurs requêtes privilégiées) ne sont
  // montés qu'une fois le rôle SUPER_ADMIN confirmé — jamais pendant le
  // chargement de la session ni pour un utilisateur non administrateur.
  if (isLoading) {
    return (
      <div className="mx-auto max-w-lg py-20 text-center text-sm text-muted-foreground">
        Vérification des droits…
      </div>
    );
  }

  if (!session?.isSuperAdmin) {
    return (
      <div className="mx-auto max-w-lg py-20 text-center">
        <ShieldCheck className="mx-auto h-8 w-8 text-muted-foreground/50" />
        <h1 className="mt-3 text-lg font-semibold">Accès réservé</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          La console d'administration est réservée au rôle SUPER_ADMIN. Votre compte
          n'a pas ce rôle — seul le premier utilisateur inscrit l'obtient
          automatiquement (un administrateur peut ensuite l'accorder à d'autres).
        </p>
        <Button variant="outline" className="mt-4" onClick={() => navigate({ to: "/" })}>
          Retour au tableau de bord
        </Button>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Administration</h1>
        <p className="text-sm text-muted-foreground">
          Gouvernance plateforme — sans jamais accéder aux valeurs chiffrées des coffres.
        </p>
      </div>
      <Tabs defaultValue="overview">
        <TabsList className="flex-wrap">
          <TabsTrigger value="overview">Vue d'ensemble</TabsTrigger>
          <TabsTrigger value="users">Utilisateurs</TabsTrigger>
          <TabsTrigger value="workspaces">Coffres</TabsTrigger>
          <TabsTrigger value="oidc">SSO / OIDC</TabsTrigger>
          <TabsTrigger value="audit">Journal d'audit</TabsTrigger>
        </TabsList>
        <div className="pt-5">
          <TabsContent value="overview"><OverviewTab /></TabsContent>
          <TabsContent value="users"><UsersTab /></TabsContent>
          <TabsContent value="workspaces"><WorkspacesTab /></TabsContent>
          <TabsContent value="oidc"><OidcTab /></TabsContent>
          <TabsContent value="audit"><AuditTab /></TabsContent>
        </div>
      </Tabs>
    </div>
  );
}
