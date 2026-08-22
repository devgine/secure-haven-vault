import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { audit } from "./audit.server";

/**
 * Records authentication events (success and failure) for the audit trail.
 * Write-only into audit_logs; readable exclusively by SUPER_ADMIN.
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
