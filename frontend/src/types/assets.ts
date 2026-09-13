export const ASSET_TYPES = ["server", "endpoint", "laptop", "network_device", "cloud_resource", "application"] as const;
export const CRITICALITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;

export interface Asset {
  id: string;
  asset_type: string;
  hostname: string | null;
  ip_address: string | null;
  mac_address: string | null;
  os: string | null;
  owner: string | null;
  department: string | null;
  criticality: string;
  environment: string | null;
  tags: string[];
  is_active: boolean;
  last_seen_at: string | null;
  created_at: string;
  updated_at: string;
}
