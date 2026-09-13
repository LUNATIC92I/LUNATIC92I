import { api } from "./apiClient";
import type {
  AlertCounts,
  AlertDetail,
  AlertNote,
  AlertPublic,
  AlertTransition,
  EvidenceResponse,
} from "@/types/alerts";

export interface ListAlertsParams {
  status?: string;
  severity?: string;
  mine?: boolean;
  limit?: number;
  offset?: number;
}

export function listAlerts(params: ListAlertsParams = {}): Promise<AlertPublic[]> {
  return api.get<AlertPublic[]>("/alerts", {
    status: params.status,
    severity: params.severity,
    mine: params.mine,
    limit: params.limit,
    offset: params.offset,
  });
}

export function getAlertCounts(): Promise<AlertCounts> {
  return api.get<AlertCounts>("/alerts/counts");
}

export function getAlert(alertId: string): Promise<AlertDetail> {
  return api.get<AlertDetail>(`/alerts/${alertId}`);
}

export function transitionAlert(alertId: string, status: string, note?: string): Promise<AlertDetail> {
  return api.post<AlertDetail>(`/alerts/${alertId}/status`, { status, note });
}

export function assignAlert(alertId: string, analystId: string | null): Promise<AlertDetail> {
  return api.post<AlertDetail>(`/alerts/${alertId}/assign`, { analyst_id: analystId });
}

export function listAlertNotes(alertId: string): Promise<AlertNote[]> {
  return api.get<AlertNote[]>(`/alerts/${alertId}/notes`);
}

export function addAlertNote(alertId: string, body: string): Promise<AlertNote> {
  return api.post<AlertNote>(`/alerts/${alertId}/notes`, { body });
}

export function listAlertHistory(alertId: string): Promise<AlertTransition[]> {
  return api.get<AlertTransition[]>(`/alerts/${alertId}/history`);
}

export function getAlertEvidence(alertId: string): Promise<EvidenceResponse> {
  return api.get<EvidenceResponse>(`/alerts/${alertId}/evidence`);
}
