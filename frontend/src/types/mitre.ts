export interface TacticCoverage {
  tactic_id: string;
  name: string;
  shortname: string;
  total: number;
  covered: number;
  partial: number;
  coverage_rate: number;
}

export interface TechniqueCoverage {
  technique_id: string;
  name: string;
  is_subtechnique: boolean;
  parent_id: string | null;
  tactics: string[];
  status: "covered" | "partial" | "uncovered";
  rule_keys: string[];
  detection_count: number;
}

export interface Coverage {
  attack_version: string | null;
  imported_at: string | null;
  catalog_is_stale: boolean;
  total_techniques: number;
  covered_techniques: number;
  partially_covered_techniques: number;
  coverage_rate: number;
  detection_window_days: number;
  tactics: TacticCoverage[];
  techniques: TechniqueCoverage[];
  unknown_technique_claims: Record<string, string[]>;
}
