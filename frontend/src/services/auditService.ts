import { api } from "./apiClient";
import type { AuditLogEntry } from "@/types/audit";

export function listAuditLog(params: { action?: string; object_type?: string } = {}): Promise<AuditLogEntry[]> {
  return api.get<AuditLogEntry[]>("/audit", { action: params.action, object_type: params.object_type, limit: 200 });
}
