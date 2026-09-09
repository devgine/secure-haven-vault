import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { getSessionInfo } from "@/lib/vault.functions";
import { changePassword as changePasswordFn, updateProfile } from "@/lib/auth.functions";

export const Route = createFileRoute("/_authenticated/settings")({
  head: () => ({
    meta: [
      { title: "Paramètres — Sentinel Vault" },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: SettingsPage,
});

function applyTheme(theme: string) {
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const dark = theme === "dark" || (theme === "system" && prefersDark);
  document.documentElement.classList.toggle("dark", dark);
  localStorage.setItem("vault-theme", theme);
}

function SettingsPage() {
  const queryClient = useQueryClient();
  const saveProfileFn = useServerFn(updateProfile);
  const changePasswordServerFn = useServerFn(changePasswordFn);
  const { data: session } = useQuery({
    queryKey: ["session-info"],
    queryFn: () => getSessionInfo(),
  });

  const [displayName, setDisplayName] = useState<string | null>(null);
  const [lockTimeout, setLockTimeout] = useState<string | null>(null);
  const [newPassword, setNewPassword] = useState("");
  const [busy, setBusy] = useState(false);

  const saveProfile = async () => {
    setBusy(true);
    try {
      await saveProfileFn({
        data: {
          displayName: (displayName ?? session?.displayName ?? "") || null,
          lockTimeoutMinutes: Number.parseInt(lockTimeout ?? String(session?.lockTimeoutMinutes ?? 15), 10),
        },
      });
      toast.success("Profil mis à jour");
      await queryClient.invalidateQueries({ queryKey: ["session-info"] });
    } catch (err) {
      toast.error((err as Error).message || "Échec de l'enregistrement");
    } finally {
      setBusy(false);
    }
  };

  const changePassword = async () => {
    if (newPassword.length < 12) {
      toast.error("Le mot de passe doit contenir au moins 12 caractères");
      return;
    }
    try {
      await changePasswordServerFn({ data: { newPassword } });
      setNewPassword("");
      toast.success("Mot de passe mis à jour — vos autres sessions ont été fermées");
    } catch (err) {
      toast.error((err as Error).message);
    }
  };

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Paramètres</h1>
        <p className="text-sm text-muted-foreground">Profil, verrouillage automatique et apparence.</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Profil</CardTitle>
          <CardDescription>{session?.email}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="display-name">Nom d'affichage</Label>
            <Input
              id="display-name"
              value={displayName ?? session?.displayName ?? ""}
              onChange={(e) => setDisplayName(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label>Verrouillage automatique</Label>
            <Select
              value={lockTimeout ?? String(session?.lockTimeoutMinutes ?? 15)}
              onValueChange={setLockTimeout}
            >
              <SelectTrigger className="w-56"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="5">Après 5 minutes</SelectItem>
                <SelectItem value="15">Après 15 minutes</SelectItem>
                <SelectItem value="30">Après 30 minutes</SelectItem>
                <SelectItem value="60">Après 1 heure</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              En cas d'inactivité, la session est fermée et toutes les données déchiffrées sont purgées de la mémoire.
            </p>
          </div>
          <Button onClick={() => void saveProfile()} disabled={busy}>
            {busy ? "Enregistrement…" : "Enregistrer"}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Apparence</CardTitle>
        </CardHeader>
        <CardContent>
          <Select
            defaultValue={localStorage.getItem("vault-theme") ?? "dark"}
            onValueChange={applyTheme}
          >
            <SelectTrigger className="w-56"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="dark">Sombre</SelectItem>
              <SelectItem value="light">Clair</SelectItem>
              <SelectItem value="system">Système</SelectItem>
            </SelectContent>
          </Select>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Changer de mot de passe</CardTitle>
          <CardDescription>12 caractères minimum. Les autres sessions resteront actives jusqu'à expiration.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="new-password">Nouveau mot de passe</Label>
            <Input
              id="new-password"
              type="password"
              autoComplete="new-password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
          </div>
          <Button variant="outline" onClick={() => void changePassword()} disabled={!newPassword}>
            Mettre à jour
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
