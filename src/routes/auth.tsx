import { useState } from "react";
import { createFileRoute, redirect, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { KeyRound, Lock } from "lucide-react";
import { toast } from "sonner";
import { VaultLogo } from "@/components/vault/logo";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { getPublicOidcProviders } from "@/lib/oidc.functions";
import { getCurrentUser, getSignupEnabled, signIn, signUp } from "@/lib/auth.functions";

interface AuthSearch {
  sso_error?: string | undefined;
  locked?: string | undefined;
}

export const Route = createFileRoute("/auth")({
  ssr: false,
  validateSearch: (search: Record<string, unknown>): AuthSearch => ({
    sso_error: typeof search["sso_error"] === "string" ? search["sso_error"] : undefined,
    locked: typeof search["locked"] === "string" ? search["locked"] : undefined,
  }),
  beforeLoad: async () => {
    const user = await getCurrentUser();
    if (user) throw redirect({ to: "/" });
  },
  head: () => ({
    meta: [
      { title: "Connexion — Sentinel Vault" },
      { name: "description", content: "Connectez-vous à votre coffre-fort de secrets chiffré." },
      { property: "og:title", content: "Sentinel Vault" },
      { property: "og:type", content: "website" },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: AuthPage,
});

function AuthPage() {
  const navigate = useNavigate();
  const { sso_error: ssoError, locked } = Route.useSearch();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);

  const { data: oidcProviders } = useQuery({
    queryKey: ["oidc-providers"],
    queryFn: () => getPublicOidcProviders(),
    staleTime: 60_000,
  });

  // Quand les inscriptions sont fermées par l'administrateur, on masque
  // l'onglet de création de compte. Le SSO d'entreprise reste visible.
  const { data: signup } = useQuery({
    queryKey: ["signup-enabled"],
    queryFn: () => getSignupEnabled(),
    staleTime: 30_000,
  });
  const signupEnabled = signup?.signupEnabled !== false;
  const ssoProviders = oidcProviders ?? [];

  const onSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await signIn({ data: { email, password } });
      navigate({ to: "/" });
    } catch (err) {
      toast.error((err as Error).message || "Identifiants invalides");
      setBusy(false);
    }
  };

  const onSignUp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password.length < 12) {
      toast.error("Le mot de passe doit contenir au moins 12 caractères");
      return;
    }
    if (password !== confirm) {
      toast.error("Les mots de passe ne correspondent pas");
      return;
    }
    setBusy(true);
    try {
      await signUp({ data: { email, password } });
      navigate({ to: "/" });
    } catch (err) {
      toast.error((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="w-full max-w-md space-y-8">
        <div className="flex flex-col items-center gap-4 text-center">
          <VaultLogo />
          <p className="max-w-sm text-sm text-muted-foreground">
            Coffre-fort de secrets chiffré pour les équipes — enveloppe AES-256-GCM,
            audit complet, partage par rôles.
          </p>
        </div>

        {locked && (
          <div className="flex items-center gap-2 rounded-lg border border-warning/40 bg-warning/10 px-3 py-2 text-sm text-warning">
            <Lock className="h-4 w-4 shrink-0" />
            Session verrouillée après une période d'inactivité. Reconnectez-vous.
          </div>
        )}
        {ssoError && (
          <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            Échec de la connexion SSO ({ssoError}).
          </div>
        )}

        <div className="rounded-xl border bg-card p-6 shadow-sm">
          <Tabs defaultValue="signin">
            {signupEnabled && (
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="signin">Connexion</TabsTrigger>
                <TabsTrigger value="signup">Créer un compte</TabsTrigger>
              </TabsList>
            )}

            <TabsContent value="signin" className="pt-4">
              <form onSubmit={(e) => void onSignIn(e)} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <Input id="email" type="email" required autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password">Mot de passe</Label>
                  <Input id="password" type="password" required autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
                </div>
                <Button type="submit" className="w-full" disabled={busy}>
                  {busy ? "Connexion…" : "Se connecter"}
                </Button>
              </form>
            </TabsContent>

            {signupEnabled && (
              <TabsContent value="signup" className="pt-4">
                <form onSubmit={(e) => void onSignUp(e)} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="su-email">Email</Label>
                    <Input id="su-email" type="email" required autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="su-password">Mot de passe (12 caractères min.)</Label>
                    <Input id="su-password" type="password" required minLength={12} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="su-confirm">Confirmation</Label>
                    <Input id="su-confirm" type="password" required autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
                  </div>
                  <Button type="submit" className="w-full" disabled={busy}>
                    {busy ? "Création…" : "Créer mon coffre"}
                  </Button>
                </form>
              </TabsContent>
            )}
          </Tabs>

          {ssoProviders.length > 0 && (
            <>
              <div className="my-5 flex items-center gap-3">
                <Separator className="flex-1" />
                <span className="text-xs text-muted-foreground">ou</span>
                <Separator className="flex-1" />
              </div>
              <div className="space-y-2">
                {ssoProviders.map((name) => (
                  <Button key={name} variant="outline" className="w-full" asChild>
                    <a href="/api/public/oidc/start">
                      <KeyRound className="mr-2 h-4 w-4" />
                      SSO — {name}
                    </a>
                  </Button>
                ))}
              </div>
            </>
          )}
        </div>

        <p className="text-center text-xs text-muted-foreground">
          Chaque connexion est tracée dans le journal d'audit.
        </p>
      </div>
    </div>
  );
}
