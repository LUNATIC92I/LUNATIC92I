export const RULE_STATUSES = ["enabled", "disabled", "testing"] as const;

export interface Rule {
  id: string;
  rule_key: string;
  name: string;
  description: string | null;
  severity: string;
  confidence: number;
  risk_score: number;
  status: string;
  rule_type: string;
  mitre_techniques: string[];
  references_urls: string[];
  false_positive_notes: string | null;
  investigation_steps: string | null;
  author: string | null;
  current_version: number;
  definition_yaml: string;
}

export interface RuleVersion {
  version: number;
  change_summary: string | null;
  changed_by: string | null;
  created_at: string;
  definition_yaml: string;
}

export interface RuleTestResult {
  matched: boolean;
  rule_id: string;
  rule_type: string;
  excepted_by: string | null;
  entity: Record<string, unknown>;
  note: string | null;
}
