import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { CalendarClock, KeyRound, Plus, ShieldCheck, Star, Vault } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SecretRow } from "@/components/vault/secret-row";
import { listWorkspaces, searchSecrets } from "@/lib/vault.functions";

export const Route = createFileRoute("/_authenticated/")({
  head: () => ({
    meta: [
      { title: "Tableau de bord — Sentinel Vault" },
      { name: "description", content: "Vue d'ensemble de vos coffres et secrets chiffrés." },
      { property: "og:title", content: "Sentinel Vault — Tableau de bord" },
      { property: "og:type", content: "website" },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: DashboardPage,
});

function DashboardPage() {
  const { data: workspaces } = useQuery({
    queryKey: ["workspaces"],
    queryFn: () => listWorkspaces(),
  });
  const { data: allSecrets } = useQuery({
    queryKey: ["secrets", "all"],
    queryFn: () => searchSecrets({ data: {} }),
  });
  const { data: recent } = useQuery({
    queryKey: ["secrets", "recent"],
    queryFn: () => searchSecrets({ data: { recentOnly: true } }),
  });
  const { data: favorites } = useQuery({
    queryKey: ["secrets", "favorites"],
    queryFn: () => searchSecrets({ data: { favoritesOnly: true } }),
  });

  const soon = Date.now() + 30 * 86_400_000;
  const expiring = (allSecrets ?? []).filter(
    (s) => s.expiresAt && new Date(s.expiresAt).getTime() < soon,
  );

  const stats = [
    { label: "Coffres", value: workspaces?.length ?? 0, icon: Vault },
    { label: "Secrets", value: allSecrets?.length ?? 0, icon: KeyRound },
    { label: "Favoris", value: favorites?.length ?? 0, icon: Star },
    { label: "Expirent < 30 j", value: expiring.length, icon: CalendarClock },
  ];

  return (
    <div className="mx-auto max-w-6xl space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Tableau de bord</h1>
        <p className="text-sm text-muted-foreground">
          Vos secrets sont chiffrés au repos (AES-256-GCM, clé par coffre).
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {stats.map((s) => (
          <Card key={s.label}>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">{s.label}</CardTitle>
              <s.icon className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-semibold tabular-nums">{s.value}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {expiring.length > 0 && (
        <Card className="border-warning/40">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <CalendarClock className="h-4 w-4 text-warning" />
              Expirations proches
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {expiring.slice(0, 5).map((s) => (
              <div key={s.id} className="flex items-center justify-between text-sm">
                <span className="truncate">{s.name}</span>
                <Badge variant="outline" className="border-warning/50 text-warning">
                  {s.expiresAt ? new Date(s.expiresAt).toLocaleDateString("fr-FR") : ""}
                </Badge>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-3">
            <CardTitle className="text-base">Récemment modifiés</CardTitle>
            <Button variant="ghost" size="sm" asChild>
              <Link to="/search">Tout voir</Link>
            </Button>
          </CardHeader>
          <CardContent className="space-y-2">
            {(recent ?? []).slice(0, 5).map((s) => <SecretRow key={s.id} secret={s} />)}
            {(recent ?? []).length === 0 && (
              <p className="py-6 text-center text-sm text-muted-foreground">
                Aucun secret pour le moment. Créez votre premier secret dans un coffre.
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-3">
            <CardTitle className="text-base">Vos coffres</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {(workspaces ?? []).map((ws) => (
              <Link
                key={ws.id}
                to="/workspaces/$workspaceId"
                params={{ workspaceId: ws.id }}
                search={{}}
                className="flex items-center gap-3 rounded-lg border bg-card px-4 py-3 transition-colors hover:border-primary/40 hover:bg-accent/40"
              >
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <ShieldCheck className="h-4 w-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-sm font-medium">{ws.name}</span>
                    {ws.isPersonal && <Badge variant="secondary" className="text-[10px]">Personnel</Badge>}
                  </div>
                  <div className="truncate text-xs text-muted-foreground">
                    {ws.description || (ws.isPersonal ? "Votre coffre privé" : "Coffre d'équipe")}
                  </div>
                </div>
              </Link>
            ))}
          </CardContent>
        </Card>
      </div>

      {(workspaces ?? []).length > 0 && (
        <div className="flex justify-center">
          <Button variant="outline" asChild>
            <Link to="/workspaces/$workspaceId" params={{ workspaceId: workspaces![0]!.id }} search={{}}>
              <Plus className="mr-2 h-4 w-4" /> Ajouter un secret
            </Link>
          </Button>
        </div>
      )}
    </div>
  );
}
