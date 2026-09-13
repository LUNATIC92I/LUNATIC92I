export interface AuditLogEntry {
  id: string;
  actor_id: string | null;
  actor_ip: string | null;
  user_agent: string | null;
  action: string;
  object_type: string;
  object_id: string | null;
  before_state: Record<string, unknown> | null;
  after_state: Record<string, unknown> | null;
  result: string;
  occurred_at: string;
}
