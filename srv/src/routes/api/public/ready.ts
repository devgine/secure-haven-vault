import { createFileRoute } from "@tanstack/react-router";

// Sonde de disponibilité (readiness) : l'application répond, les migrations
// sont appliquées (voir server.ts, qui renvoie 503 tant que l'initialisation
// n'a pas abouti) ET la base PostgreSQL est joignable.
export const Route = createFileRoute("/api/public/ready")({
  server: {
    handlers: {
      GET: async () => {
        try {
          const { getDb } = await import("@/lib/db.server");
          await getDb()`SELECT 1`;
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
