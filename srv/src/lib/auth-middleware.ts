// Middleware d'authentification des fonctions serveur.
// Remplace l'ancien middleware Supabase : la session est un cookie httpOnly
// validé contre la table `sessions` (empreinte SHA-256 du jeton).
import { createMiddleware } from "@tanstack/react-start";
import { getRequest } from "@tanstack/react-start/server";
import { SESSION_COOKIE, readCookieHeader } from "./session-cookie";

export const requireAuth = createMiddleware({ type: "function" }).server(async ({ next }) => {
  const request = getRequest();
  const token = readCookieHeader(request?.headers.get("cookie") ?? null, SESSION_COOKIE);
  // Import dynamique : session.server.ts est server-only, la portée module de
  // ce fichier peut rejoindre le bundle client.
  const { validateSession } = await import("./session.server");
  const user = await validateSession(token);
  if (!user) {
    throw new Error("Unauthorized");
  }
  return next({
    context: {
      userId: user.id,
      userEmail: user.email,
    },
  });
});
