export const IOC_TYPES = [
  "ipv4",
  "ipv6",
  "domain",
  "url",
  "md5",
  "sha1",
  "sha256",
  "email",
  "asn",
  "certificate",
] as const;

export const CLASSIFICATIONS = ["malicious", "suspicious", "benign", "unknown"] as const;

export interface Ioc {
  id: string;
  ioc_type: string;
  value: string;
  classification: string;
  confidence: number;
  source: string;
  description: string | null;
  tags: string[];
  first_seen: string;
  last_seen: string;
  expires_at: string | null;
  is_expired: boolean;
  shared: boolean;
}

export interface IocHistoryEntry {
  changed_field: string;
  old_value: string | null;
  new_value: string | null;
  changed_by: string | null;
  changed_at: string;
}
