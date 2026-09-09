import { createFileRoute } from "@tanstack/react-router";
import { Sparkles } from "lucide-react";
import { GeneratorPanel } from "@/components/vault/generator-panel";

export const Route = createFileRoute("/_authenticated/generator")({
  head: () => ({
    meta: [
      { title: "Générateur — Sentinel Vault" },
      { name: "description", content: "Générateur cryptographique de mots de passe, clés et tokens." },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: GeneratorPage,
});

function GeneratorPage() {
  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
          <Sparkles className="h-5 w-5 text-primary" /> Générateur
        </h1>
        <p className="text-sm text-muted-foreground">
          Valeurs générées localement via le CSPRNG du navigateur — rien n'est transmis ni journalisé.
        </p>
      </div>
      <div className="rounded-xl border bg-card p-6">
        <GeneratorPanel />
      </div>
    </div>
  );
}
