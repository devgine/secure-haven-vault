import { createServerFn } from "@tanstack/react-start";
import { deleteCookie, getRequest, setCookie } from "@tanstack/react-start/server";
import { z } from "zod";
import { audit } from "./audit.server";
import { getDb } from "./db.server";
import { requireAuth } from "./auth-middleware";
import { SESSION_COOKIE, readCookieHeader } from "./session-cookie";
import {
  createSession,
  destroyOtherSessions,
  destroySession,
  hashPassword,
  isSignupEnabled,
  provisionUser,
  validateSession,
  verifyPassword,
} from "./session.server";

const emailSchema = z.string().email().max(320);
const passwordSchema = z.string().min(12).max(256);

function sessionCookieOptions(request: Request) {
  return {
    path: "/",
    httpOnly: true,
    sameSite: "lax" as const,
    secure: new URL(request.url).protocol === "https:",
    maxAge: 7 * 24 * 3600,
  };
}

/**
 * Connexion email + mot de passe. Vérifie le hash scrypt, le blocage éventuel
 * du compte, puis dépose le cookie de session httpOnly.
 */
export const signIn = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) =>
    z.object({ email: emailSchema, password: z.string().min(1).max(256) }).parse(input),
  )
  .handler(async ({ data }) => {
    const email = data.email.trim();
    const rows = await getDb()<
      { id: string; password_hash: string | null; banned_until: Date | null }[]
    >`
      SELECT id, password_hash, banned_until FROM users WHERE lower(email) = lower(${email})
    `;
    const user = rows[0];
    const passwordOk = user?.password_hash
      ? await verifyPassword(data.password, user.password_hash)
      : false;
    const banned =
      user?.banned_until != null && new Date(user.banned_until).getTime() > Date.now();

    if (!user || !passwordOk || banned) {
      await audit({
        action: "auth.login_failed",
        actorEmail: email,
        targetType: "auth",
        targetLabel: banned ? "account_banned" : "invalid_credentials",
        result: "failure",
      });
      throw new Error("Identifiants invalides");
    }

    const session = await createSession(user.id);
    setCookie(SESSION_COOKIE, session.token, sessionCookieOptions(getRequest()));
    await getDb()`UPDATE users SET last_sign_in_at = now() WHERE id = ${user.id}`;
    await audit({ userId: user.id, actorEmail: email, action: "auth.login", targetType: "auth" });
    return { ok: true };
  });

/**
 * Création de compte : hash scrypt, provisionnement transactionnel (profil,
 * rôle — SUPER_ADMIN pour le tout premier compte — et coffre personnel),
 * puis session immédiate (pas de vérification d'email en auto-hébergé).
 */
export const signUp = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) =>
    z.object({ email: emailSchema, password: passwordSchema }).parse(input),
  )
  .handler(async ({ data }) => {
    const email = data.email.trim();
    const passwordHash = await hashPassword(data.password);
    let userId: string;
    try {
      userId = await provisionUser(email, passwordHash);
    } catch (err) {
      const message = (err as Error).message;
      if (message === "signup_disabled") {
        throw new Error("La création de comptes est désactivée par l'administrateur");
      }
      if (message === "account_exists") {
        throw new Error("Un compte existe déjà pour cette adresse email");
      }
      throw err;
    }
    const session = await createSession(userId);
    setCookie(SESSION_COOKIE, session.token, sessionCookieOptions(getRequest()));
    await getDb()`UPDATE users SET last_sign_in_at = now() WHERE id = ${userId}`;
    await audit({ userId, actorEmail: email, action: "auth.signup", targetType: "auth" });
    return { ok: true };
  });

export const signOut = createServerFn({ method: "POST" }).handler(async () => {
  const request = getRequest();
  const token = readCookieHeader(request.headers.get("cookie"), SESSION_COOKIE);
  await destroySession(token);
  deleteCookie(SESSION_COOKIE, { path: "/" });
  return { ok: true };
});

/** Session courante (ou null) — utilisé par les gardes de routes côté client. */
export const getCurrentUser = createServerFn({ method: "GET" }).handler(async () => {
  const request = getRequest();
  const token = readCookieHeader(request.headers.get("cookie"), SESSION_COOKIE);
  const user = await validateSession(token);
  return user ? { userId: user.id, email: user.email } : null;
});

/** Public : indique à la page de connexion si la création de compte est ouverte. */
export const getSignupEnabled = createServerFn({ method: "GET" }).handler(async () => {
  return { signupEnabled: await isSignupEnabled() };
});

/**
 * Records authentication events (success and failure) for the audit trail.
 * Never receives passwords — only the email and the outcome.
 */
export const recordAuthEvent = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) =>
    z.object({
      action: z.enum(["auth.login", "auth.login_failed", "auth.oidc_login", "auth.signup", "auth.logout"]),
      email: z.string().max(320).optional(),
    }).parse(input),
  )
  .handler(async ({ data }) => {
    await audit({
      action: data.action,
      actorEmail: data.email ?? null,
      targetType: "auth",
      result: data.action === "auth.login_failed" ? "failure" : "success",
    });
    return { ok: true };
  });

export const updateProfile = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({
      displayName: z.string().max(100).nullable(),
      lockTimeoutMinutes: z.number().int().min(1).max(240),
    }).parse(input),
  )
  .handler(async ({ data, context }) => {
    await getDb()`
      UPDATE profiles
      SET display_name = ${data.displayName}, lock_timeout_minutes = ${data.lockTimeoutMinutes}
      WHERE id = ${context.userId}
    `;
    return { ok: true };
  });

/**
 * Change le mot de passe du compte courant et invalide toutes les autres
 * sessions (la session courante est conservée).
 */
export const changePassword = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z.object({ newPassword: passwordSchema }).parse(input),
  )
  .handler(async ({ data, context }) => {
    const newHash = await hashPassword(data.newPassword);
    await getDb()`UPDATE users SET password_hash = ${newHash} WHERE id = ${context.userId}`;
    const request = getRequest();
    const token = readCookieHeader(request.headers.get("cookie"), SESSION_COOKIE);
    await destroyOtherSessions(context.userId, token);
    await audit({
      userId: context.userId,
      actorEmail: context.userEmail,
      action: "auth.password_changed",
      targetType: "auth",
    });
    return { ok: true };
  });
