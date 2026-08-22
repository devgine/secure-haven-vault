import { useEffect, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Search, Star } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { SecretRow } from "@/components/vault/secret-row";
import { searchSecrets } from "@/lib/vault.functions";

interface SearchParams {
  q?: string | undefined;
}

export const Route = createFileRoute("/_authenticated/search")({
  validateSearch: (search: Record<string, unknown>): SearchParams => ({
    q: typeof search["q"] === "string" ? search["q"] : undefined,
  }),
  head: () => ({
    meta: [
      { title: "Recherche — Sentinel Vault" },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: SearchPage,
});

function SearchPage() {
  const initial = Route.useSearch().q ?? "";
  const [query, setQuery] = useState(initial);
  const [debounced, setDebounced] = useState(initial);
  const [favoritesOnly, setFavoritesOnly] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setDebounced(query), 250);
    return () => clearTimeout(t);
  }, [query]);

  const { data: results, isFetching } = useQuery({
    queryKey: ["secrets", "search", debounced, favoritesOnly],
    queryFn: () => searchSecrets({ data: { query: debounced, favoritesOnly } }),
  });

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Recherche</h1>
        <p className="text-sm text-muted-foreground">
          Nom, identifiant, URL, description et tags — tous vos coffres accessibles.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-60 flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Rechercher un secret…"
            className="pl-9"
          />
        </div>
        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          <Switch checked={favoritesOnly} onCheckedChange={setFavoritesOnly} />
          <Star className="h-3.5 w-3.5" /> Favoris uniquement
        </label>
      </div>

      {isFetching && (results ?? []).length === 0 ? (
        <p className="py-10 text-center text-sm text-muted-foreground">Recherche…</p>
      ) : (results ?? []).length === 0 ? (
        <div className="rounded-xl border border-dashed py-14 text-center text-sm text-muted-foreground">
          {debounced ? "Aucun résultat." : "Saisissez un terme pour rechercher dans vos secrets."}
        </div>
      ) : (
        <div className="space-y-2">
          {(results ?? []).map((s) => <SecretRow key={s.id} secret={s} />)}
        </div>
      )}
    </div>
  );
}
