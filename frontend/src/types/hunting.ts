export interface Condition {
  field: string;
  operator: string;
  value: unknown;
  case_sensitive?: boolean;
}

export interface HuntQuery {
  free_text?: string | null;
  filters?: Condition | null;
  since?: string | null;
  until?: string | null;
}

export interface HuntSearchResponse {
  total: number;
  events: Record<string, unknown>[];
}

export interface SavedHunt {
  id: string;
  name: string;
  description: string | null;
  query: HuntQuery;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export const PIVOT_NAMES = [
  "ip_to_events",
  "ip_to_users",
  "user_to_hosts",
  "host_to_processes",
  "hash_to_events",
  "domain_to_events",
  "user_to_timeline",
] as const;

export interface PivotResponse {
  pivot: string;
  result_type: "events" | "values";
  total: number;
  events: Record<string, unknown>[];
  values: { value: string; count: number }[];
}

export const HUNT_OPERATORS = [
  "equals",
  "not_equals",
  "contains",
  "not_contains",
  "starts_with",
  "ends_with",
  "in",
  "not_in",
  "gt",
  "gte",
  "lt",
  "lte",
  "exists",
  "cidr",
] as const;
