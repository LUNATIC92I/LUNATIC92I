import { api } from "./apiClient";
import type { Asset } from "@/types/assets";

export function listAssets(): Promise<Asset[]> {
  return api.get<Asset[]>("/assets");
}

export function createAsset(payload: {
  asset_type: string;
  hostname?: string;
  ip_address?: string;
  criticality: string;
}): Promise<Asset> {
  return api.post<Asset>("/assets", payload);
}

export function updateAsset(id: string, payload: Record<string, unknown>): Promise<Asset> {
  return api.patch<Asset>(`/assets/${id}`, payload);
}

export function deleteAsset(id: string): Promise<void> {
  return api.delete<void>(`/assets/${id}`);
}
