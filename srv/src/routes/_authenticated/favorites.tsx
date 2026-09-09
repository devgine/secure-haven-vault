import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Star } from "lucide-react";
import { SecretRow } from "@/components/vault/secret-row";
import { searchSecrets } from "@/lib/vault.functions";

export const Route = createFileRoute("/_authenticated/favorites")({
  head: () => ({
    meta: [
      { title: "Favoris — Sentinel Vault" },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: FavoritesPage,
});

function FavoritesPage() {
  const { data: favorites, isLoading } = useQuery({
    queryKey: ["secrets", "favorites"],
    queryFn: () => searchSecrets({ data: { favoritesOnly: true } }),
  });

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
          <Star className="h-5 w-5 text-warning" /> Favoris
        </h1>
        <p className="text-sm text-muted-foreground">Vos secrets épinglés, tous coffres confondus.</p>
      </div>
      {isLoading ? (
        <p className="py-10 text-center text-sm text-muted-foreground">Chargement…</p>
      ) : (favorites ?? []).length === 0 ? (
        <div className="rounded-xl border border-dashed py-14 text-center text-sm text-muted-foreground">
          Aucun favori. Épinglez un secret depuis sa fiche détaillée.
        </div>
      ) : (
        <div className="space-y-2">
          {(favorites ?? []).map((s) => <SecretRow key={s.id} secret={s} />)}
        </div>
      )}
    </div>
  );
}
