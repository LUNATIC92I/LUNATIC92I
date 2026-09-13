export const INCIDENT_STATUSES = [
  "NEW",
  "TRIAGE",
  "INVESTIGATION",
  "CONTAINMENT",
  "ERADICATION",
  "RECOVERY",
  "CLOSED",
] as const;

export const INCIDENT_TRANSITIONS: Record<string, string[]> = {
  NEW: ["TRIAGE", "INVESTIGATION", "CLOSED"],
  TRIAGE: ["INVESTIGATION", "CONTAINMENT", "CLOSED", "NEW"],
  INVESTIGATION: ["CONTAINMENT", "ERADICATION", "TRIAGE", "CLOSED"],
  CONTAINMENT: ["ERADICATION", "INVESTIGATION", "CLOSED"],
  ERADICATION: ["RECOVERY", "CONTAINMENT", "INVESTIGATION", "CLOSED"],
  RECOVERY: ["CLOSED", "ERADICATION", "INVESTIGATION"],
  CLOSED: ["INVESTIGATION", "TRIAGE"],
};

export const TASK_STATUSES = ["open", "in_progress", "done"] as const;
export const INCIDENT_SEVERITIES = ["low", "medium", "high", "critical"] as const;
export const INCIDENT_PRIORITIES = ["P1", "P2", "P3", "P4"] as const;

export interface IncidentPublic {
  id: string;
  display_id: string;
  title: string;
  description: string | null;
  severity: string;
  priority: string;
  status: string;
  analyst_id: string | null;
  resolution: string | null;
  lessons_learned: string | null;
  detected_at: string | null;
  contained_at: string | null;
  closed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface LinkedAlert {
  id: string;
  display_id: string;
  title: string;
  severity: string;
  risk_score: number;
  status: string;
}

export interface LinkedEntities {
  assets: Record<string, unknown>[];
  iocs: Record<string, unknown>[];
  users: Record<string, unknown>[];
}

export interface IncidentDetail extends IncidentPublic {
  alerts: LinkedAlert[];
  linked: LinkedEntities;
}

export interface IncidentCounts {
  by_status: Record<string, number>;
  open_total: number;
}

export interface IncidentNote {
  id: string;
  author_id: string | null;
  body: string;
  created_at: string;
}

export interface IncidentTask {
  id: string;
  title: string;
  description: string | null;
  assignee_id: string | null;
  status: string;
  due_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface TimelineEntry {
  kind: string;
  summary: string;
  detail: Record<string, unknown>;
  actor_id: string | null;
  occurred_at: string;
}

export interface IncidentEvidenceDocument {
  event_id: string;
  found: boolean;
  document: Record<string, unknown> | null;
}

export interface IncidentEvidenceResponse {
  incident_id: string;
  display_id: string;
  total_event_ids: number;
  resolved: number;
  missing_event_ids: string[];
  documents: IncidentEvidenceDocument[];
}
