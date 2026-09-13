export const ALERT_STATUSES = [
  "NEW",
  "IN_PROGRESS",
  "ESCALATED",
  "FALSE_POSITIVE",
  "RESOLVED",
  "CLOSED",
] as const;

export const ALERT_TRANSITIONS: Record<string, string[]> = {
  NEW: ["IN_PROGRESS", "ESCALATED", "FALSE_POSITIVE", "RESOLVED", "CLOSED"],
  IN_PROGRESS: ["ESCALATED", "FALSE_POSITIVE", "RESOLVED", "CLOSED", "NEW"],
  ESCALATED: ["IN_PROGRESS", "FALSE_POSITIVE", "RESOLVED", "CLOSED"],
  FALSE_POSITIVE: ["IN_PROGRESS", "CLOSED"],
  RESOLVED: ["IN_PROGRESS", "CLOSED"],
  CLOSED: ["IN_PROGRESS"],
};

export interface AlertPublic {
  id: string;
  display_id: string;
  title: string;
  description: string;
  source: string;
  rule_key: string | null;
  correlation_id: string | null;
  severity: string;
  confidence: number;
  risk_score: number;
  risk_bucket: string | null;
  status: string;
  analyst_id: string | null;
  affected_user: string | null;
  affected_host: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  mitre_techniques: string[];
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
  acknowledged_at: string | null;
  closed_at: string | null;
  created_at: string;
}

export interface AlertDetail extends AlertPublic {
  event_ids: string[];
  detection_ids: string[];
  evidence: Record<string, unknown>;
  risk_explanation: Record<string, unknown>;
  resolution_note: string | null;
}

export interface AlertNote {
  id: string;
  author_id: string | null;
  body: string;
  created_at: string;
}

export interface AlertTransition {
  from_status: string | null;
  to_status: string;
  actor_id: string | null;
  note: string | null;
  occurred_at: string;
}

export interface EvidenceDocument {
  event_id: string;
  found: boolean;
  document: Record<string, unknown> | null;
}

export interface EvidenceResponse {
  alert_id: string;
  display_id: string;
  total_event_ids: number;
  resolved: number;
  missing_event_ids: string[];
  documents: EvidenceDocument[];
}

export interface AlertCounts {
  by_status: Record<string, number>;
  open_total: number;
}
