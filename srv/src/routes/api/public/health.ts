import { createFileRoute } from "@tanstack/react-router";

// Sonde de vivacité (liveness) : l'application répond. Utilisée par le
// HEALTHCHECK du Dockerfile et docker compose. Aucune dépendance externe.
export const Route = createFileRoute("/api/public/health")({
  server: {
    handlers: {
      GET: () =>
        Response.json({
          status: "ok",
          timestamp: new Date().toISOString(),
        }),
    },
  },
});
