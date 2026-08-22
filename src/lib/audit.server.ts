// Audit logging — server only. NEVER pass secret values here: metadata only.

export interface AuditEvent {
  userId?: string | null;
  actorEmail?: string | null;
  workspaceId?: string | null;
  action: string;
  targetType?: string | null;
  targetId?: string | null;
  targetLabel?: string | null;
  result?: "success" | "failure";
}

export async function audit(event: AuditEvent): Promise<void> {
  try {
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    await supabaseAdmin.from("audit_logs").insert({
      user_id: event.userId ?? null,
      actor_email: event.actorEmail ?? null,
      workspace_id: event.workspaceId ?? null,
      action: event.action,
      target_type: event.targetType ?? null,
      target_id: event.targetId ?? null,
      target_label: event.targetLabel ?? null,
      result: event.result ?? "success",
    });
  } catch (err) {
    // Auditing must never break the main flow, but we surface the failure
    // server-side for operators.
    console.error("audit_log_insert_failed", (err as Error).message);
  }
}
