import { api } from "./apiClient";
import type { Ioc, IocHistoryEntry } from "@/types/threatIntel";

export function listIocs(params: { ioc_type?: string; include_expired?: boolean } = {}): Promise<Ioc[]> {
  return api.get<Ioc[]>("/iocs", { ioc_type: params.ioc_type, include_expired: params.include_expired, limit: 500 });
}

export function createIoc(payload: {
  value: string;
  ioc_type?: string;
  classification: string;
  confidence: number;
  source: string;
  description?: string;
  tags?: string[];
}): Promise<Ioc> {
  return api.post<Ioc>("/iocs", payload);
}

export function updateIoc(id: string, payload: Record<string, unknown>): Promise<Ioc> {
  return api.patch<Ioc>(`/iocs/${id}`, payload);
}

export function deleteIoc(id: string): Promise<void> {
  return api.delete<void>(`/iocs/${id}`);
}

export function getIocHistory(id: string): Promise<IocHistoryEntry[]> {
  return api.get<IocHistoryEntry[]>(`/iocs/${id}/history`);
}
