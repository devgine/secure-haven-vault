import { useState } from "react";
import { createFileRoute, redirect, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { KeyRound, Lock } from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { lovable } from "@/integrations/lovable";
import { VaultLogo } from "@/components/vault/logo";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { getPublicOidcProviders } from "@/lib/oidc.functions";
import { recordAuthEvent } from "@/lib/auth.functions";

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
    const { data } = await supabase.auth.getSession();
    if (data.session) throw redirect({ to: "/" });
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
  const logAuth = useServerFn(recordAuthEvent);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [signupDone, setSignupDone] = useState(false);

  const { data: oidcProviders } = useQuery({
    queryKey: ["oidc-providers"],
    queryFn: () => getPublicOidcProviders(),
    staleTime: 60_000,
  });

  const onSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) {
      await logAuth({ data: { action: "auth.login_failed", email } });
      toast.error("Identifiants invalides");
      setBusy(false);
      return;
    }
    await logAuth({ data: { action: "auth.login", email } });
    navigate({ to: "/" });
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
    const { error } = await supabase.auth.signUp({
      email,
      password,
      options: { emailRedirectTo: window.location.origin },
    });
    setBusy(false);
    if (error) {
      toast.error(error.message);
      return;
    }
    await logAuth({ data: { action: "auth.signup", email } });
    setSignupDone(true);
  };

  const onGoogle = async () => {
    const result = await lovable.auth.signInWithOAuth("google", {
      redirect_uri: window.location.origin,
    });
    if (result.error) toast.error("La connexion Google a échoué");
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

        {signupDone ? (
          <div className="rounded-xl border bg-card p-6 text-center shadow-sm">
            <h2 className="text-lg font-semibold">Vérifiez votre boîte mail</h2>
            <p className="mt-2 text-sm text-muted-foreground">
              Un lien de confirmation a été envoyé à <span className="font-medium text-foreground">{email}</span>.
              Cliquez dessus pour activer votre compte.
            </p>
            <Button variant="outline" className="mt-4" onClick={() => setSignupDone(false)}>
              Retour à la connexion
            </Button>
          </div>
        ) : (
          <div className="rounded-xl border bg-card p-6 shadow-sm">
            <Tabs defaultValue="signin">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="signin">Connexion</TabsTrigger>
                <TabsTrigger value="signup">Créer un compte</TabsTrigger>
              </TabsList>

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
            </Tabs>

            <div className="my-5 flex items-center gap-3">
              <Separator className="flex-1" />
              <span className="text-xs text-muted-foreground">ou</span>
              <Separator className="flex-1" />
            </div>

            <div className="space-y-2">
              <Button variant="outline" className="w-full" onClick={() => void onGoogle()}>
                Continuer avec Google
              </Button>
              {(oidcProviders ?? []).map((name) => (
                <Button key={name} variant="outline" className="w-full" asChild>
                  <a href="/api/public/oidc/start">
                    <KeyRound className="mr-2 h-4 w-4" />
                    SSO — {name}
                  </a>
                </Button>
              ))}
            </div>
          </div>
        )}

        <p className="text-center text-xs text-muted-foreground">
          Chaque connexion est tracée dans le journal d'audit.
        </p>
      </div>
    </div>
  );
}
