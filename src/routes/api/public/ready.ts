import { createFileRoute } from "@tanstack/react-router";

// Sonde de disponibilité (readiness) : l'application répond ET le backend
# de données est joignable (lecture anonyme d'une table publique).
export const Route = createFileRoute("/api/public/ready")({
  server: {
    handlers: {
      GET: async () => {
        try {
          const url = process.env["SUPABASE_URL"];
          const key = process.env["SUPABASE_PUBLISHABLE_KEY"];
          if (!url || !key) throw new Error("Configuration backend manquante");

          const { createClient } = await import("@supabase/supabase-js");
          const supabase = createClient(url, key, {
            auth: { persistSession: false, autoRefreshToken: false },
          });
          const { error } = await supabase.from("platform_settings").select("key").limit(1);
          if (error) throw error;

          return Response.json({ status: "ready", timestamp: new Date().toISOString() });
        } catch {
          return Response.json(
            { status: "not_ready", timestamp: new Date().toISOString() },
            { status: 503 },
          );
        }
      },
    },
  },
});
