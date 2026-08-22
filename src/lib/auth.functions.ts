import { createServerFn } from "@tanstack/react-start";
import { createClient } from "@supabase/supabase-js";
import { z } from "zod";
import { audit } from "./audit.server";
import type { Database } from "@/integrations/supabase/types";

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

/**
 * Public, unauthenticated: tells the auth page whether account creation is
 * open. Reads only the non-sensitive `signup_enabled` flag through the
 * publishable key (narrow anon SELECT policy on platform_settings).
 */
export const getSignupEnabled = createServerFn({ method: "GET" }).handler(async () => {
  const key = process.env["SUPABASE_PUBLISHABLE_KEY"]!;
  const supabasePublic = createClient<Database>(process.env["SUPABASE_URL"]!, key, {
    auth: { persistSession: false },
    global: {
      fetch: (input, init) => {
        const h = new Headers(init?.headers);
        if (key.startsWith("sb_") && h.get("Authorization") === `Bearer ${key}`) h.delete("Authorization");
        h.set("apikey", key);
        return fetch(input, { ...init, headers: h });
      },
    },
  });
  const { data } = await supabasePublic
    .from("platform_settings")
    .select("value")
    .eq("key", "signup_enabled")
    .maybeSingle();
  return { signupEnabled: data?.value !== false };
});
