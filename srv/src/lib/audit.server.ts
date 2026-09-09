// Audit logging — server only. NEVER pass secret values here: metadata only.
import { getDb } from "./db.server";

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
    await getDb()`
      INSERT INTO audit_logs (user_id, actor_email, workspace_id, action, target_type, target_id, target_label, result)
      VALUES (
        ${event.userId ?? null},
        ${event.actorEmail ?? null},
        ${event.workspaceId ?? null},
        ${event.action},
        ${event.targetType ?? null},
        ${event.targetId ?? null},
        ${event.targetLabel ?? null},
        ${event.result ?? "success"}
      )
    `;
  } catch (err) {
    // Auditing must never break the main flow, but we surface the failure
    // server-side for operators.
    console.error("audit_log_insert_failed", (err as Error).message);
  }
}
