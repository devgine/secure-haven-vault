import { createFileRoute } from "@tanstack/react-router";

// Sonde de disponibilité (readiness) : l'application répond ET la base
// PostgreSQL est joignable (utile pour un orchestrateur).
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
