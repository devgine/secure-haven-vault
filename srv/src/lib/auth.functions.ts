import { createServerFn } from "@tanstack/react-start";
import { deleteCookie, getRequest, setCookie } from "@tanstack/react-start/server";
import { z } from "zod";
import { audit } from "./audit.server";
import { getDb } from "./db.server";
import { requireAuth } from "./auth-middleware";
import { assertNotThrottled, recordAttempt, ThrottledError } from "./rate-limit.server";
import { clientIp, isSecureOrigin } from "./request.server";
import { SESSION_COOKIE, readCookieHeader } from "./session-cookie";
import {
  createSession,
  destroyOtherSessions,
  destroySession,
  hashPassword,
  isSignupEnabled,
  provisionUser,
  validateSession,
  verifyPasswordOrDummy,
} from "./session.server";

const emailSchema = z.string().email().max(320);
const passwordSchema = z.string().min(12).max(256);

function sessionCookieOptions(request: Request) {
  return {
    path: "/",
    httpOnly: true,
    sameSite: "lax" as const,
    secure: isSecureOrigin(request),
    maxAge: 7 * 24 * 3600,
  };
}

/**
 * Connexion email + mot de passe. Vérifie le hash scrypt, le blocage éventuel
 * du compte, puis dépose le cookie de session httpOnly. Les échecs répétés
 * (par email ou par adresse IP) sont temporairement bloqués.
 */
export const signIn = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) =>
    z.object({ email: emailSchema, password: z.string().min(1).max(256) }).parse(input),
  )
  .handler(async ({ data }) => {
    const request = getRequest();
    const email = data.email.trim();
    const key = { subject: email, ip: clientIp(request) };
    try {
      await assertNotThrottled("login", key);
    } catch (err) {
      if (err instanceof ThrottledError) {
        await audit({
          action: "auth.login_failed",
          actorEmail: email,
          targetType: "auth",
          targetLabel: "throttled",
          result: "failure",
        });
      }
      throw err;
    }

    const rows = await getDb()<
      { id: string; password_hash: string | null; banned_until: Date | null }[]
    >`
      SELECT id, password_hash, banned_until FROM users WHERE lower(email) = lower(${email})
    `;
    const user = rows[0];
    // Même coût de calcul que le compte existe ou non (pas d'énumération par le temps).
    const passwordOk = await verifyPasswordOrDummy(data.password, user?.password_hash);
    const banned =
      user?.banned_until != null && new Date(user.banned_until).getTime() > Date.now();

    if (!user || !passwordOk || banned) {
      await recordAttempt("login", key, false);
      await audit({
        action: "auth.login_failed",
        actorEmail: email,
        targetType: "auth",
        targetLabel: banned ? "account_banned" : "invalid_credentials",
        result: "failure",
      });
      throw new Error("Identifiants invalides");
    }

    await recordAttempt("login", key, true);
    const session = await createSession(user.id);
    setCookie(SESSION_COOKIE, session.token, sessionCookieOptions(request));
    await getDb()`UPDATE users SET last_sign_in_at = now() WHERE id = ${user.id}`;
    await audit({ userId: user.id, actorEmail: email, action: "auth.login", targetType: "auth" });
    return { ok: true };
  });

/**
 * Création de compte : hash scrypt, provisionnement transactionnel (profil,
 * rôle USER et coffre personnel), puis session immédiate (pas de vérification
 * d'email en auto-hébergé). Limitée en débit par adresse IP.
 */
export const signUp = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) =>
    z.object({ email: emailSchema, password: passwordSchema }).parse(input),
  )
  .handler(async ({ data }) => {
    const request = getRequest();
    const email = data.email.trim();
    const key = { subject: email, ip: clientIp(request) };
    await assertNotThrottled("signup", key);
    await recordAttempt("signup", key, true);

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
    setCookie(SESSION_COOKIE, session.token, sessionCookieOptions(request));
    await getDb()`UPDATE users SET last_sign_in_at = now() WHERE id = ${userId}`;
    await audit({ userId, actorEmail: email, action: "auth.signup", targetType: "auth" });
    return { ok: true };
  });

export const signOut = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) =>
    z.object({ reason: z.enum(["logout", "lock"]).optional() }).optional().parse(input),
  )
  .handler(async ({ data }) => {
    const request = getRequest();
    const token = readCookieHeader(request.headers.get("cookie"), SESSION_COOKIE);
    // L'événement est rattaché à la session réellement présentée, jamais à
    // une identité déclarée par le client.
    const user = await validateSession(token);
    await destroySession(token);
    deleteCookie(SESSION_COOKIE, { path: "/" });
    if (user) {
      await audit({
        userId: user.id,
        actorEmail: user.email,
        action: data?.reason === "lock" ? "auth.locked" : "auth.logout",
        targetType: "auth",
      });
    }
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
 * Change le mot de passe du compte courant après vérification de l'ancien, et
 * invalide toutes les autres sessions (la session courante est conservée).
 * Refusé pour un compte provisionné par le SSO : son authentification
 * appartient au fournisseur d'identité.
 */
export const changePassword = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) =>
    z
      .object({ currentPassword: z.string().min(1).max(256), newPassword: passwordSchema })
      .parse(input),
  )
  .handler(async ({ data, context }) => {
    const request = getRequest();
    const sql = getDb();
    const rows = await sql<{ password_hash: string | null }[]>`
      SELECT password_hash FROM users WHERE id = ${context.userId}
    `;
    const currentHash = rows[0]?.password_hash;
    if (!currentHash) {
      throw new Error(
        "Ce compte est géré par le SSO : son mot de passe se modifie chez le fournisseur d'identité",
      );
    }

    const key = { subject: context.userId, ip: clientIp(request) };
    await assertNotThrottled("password", key);
    if (!(await verifyPasswordOrDummy(data.currentPassword, currentHash))) {
      await recordAttempt("password", key, false);
      await audit({
        userId: context.userId,
        actorEmail: context.userEmail,
        action: "auth.password_change_failed",
        targetType: "auth",
        result: "failure",
      });
      throw new Error("Mot de passe actuel incorrect");
    }
    await recordAttempt("password", key, true);

    const newHash = await hashPassword(data.newPassword);
    await sql`UPDATE users SET password_hash = ${newHash} WHERE id = ${context.userId}`;
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
