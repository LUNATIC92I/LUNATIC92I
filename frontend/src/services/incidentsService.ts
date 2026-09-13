import { api } from "./apiClient";
import type {
  IncidentCounts,
  IncidentDetail,
  IncidentEvidenceResponse,
  IncidentNote,
  IncidentPublic,
  IncidentTask,
  TimelineEntry,
} from "@/types/incidents";

export interface ListIncidentsParams {
  status?: string;
  severity?: string;
  limit?: number;
  offset?: number;
}

export function listIncidents(params: ListIncidentsParams = {}): Promise<IncidentPublic[]> {
  return api.get<IncidentPublic[]>("/incidents", {
    status: params.status,
    severity: params.severity,
    limit: params.limit,
    offset: params.offset,
  });
}

export function getIncidentCounts(): Promise<IncidentCounts> {
  return api.get<IncidentCounts>("/incidents/counts");
}

export function getIncident(id: string): Promise<IncidentDetail> {
  return api.get<IncidentDetail>(`/incidents/${id}`);
}

export function createIncident(payload: { title: string; description?: string; severity: string; alert_ids?: string[] }): Promise<IncidentDetail> {
  return api.post<IncidentDetail>("/incidents", payload);
}

export function updateIncident(id: string, payload: Record<string, unknown>): Promise<IncidentDetail> {
  return api.patch<IncidentDetail>(`/incidents/${id}`, payload);
}

export function transitionIncident(id: string, status: string, note?: string): Promise<IncidentDetail> {
  return api.post<IncidentDetail>(`/incidents/${id}/status`, { status, note });
}

export function linkAlert(id: string, alertId: string): Promise<IncidentDetail> {
  return api.post<IncidentDetail>(`/incidents/${id}/alerts`, { alert_id: alertId });
}

export function listIncidentNotes(id: string): Promise<IncidentNote[]> {
  return api.get<IncidentNote[]>(`/incidents/${id}/notes`);
}

export function addIncidentNote(id: string, body: string): Promise<IncidentNote> {
  return api.post<IncidentNote>(`/incidents/${id}/notes`, { body });
}

export function listIncidentTasks(id: string): Promise<IncidentTask[]> {
  return api.get<IncidentTask[]>(`/incidents/${id}/tasks`);
}

export function createIncidentTask(id: string, payload: { title: string; description?: string }): Promise<IncidentTask> {
  return api.post<IncidentTask>(`/incidents/${id}/tasks`, payload);
}

export function updateIncidentTask(id: string, taskId: string, payload: { status: string }): Promise<IncidentTask> {
  return api.patch<IncidentTask>(`/incidents/${id}/tasks/${taskId}`, payload);
}

export function listIncidentTimeline(id: string): Promise<TimelineEntry[]> {
  return api.get<TimelineEntry[]>(`/incidents/${id}/timeline`);
}

export function getIncidentEvidence(id: string): Promise<IncidentEvidenceResponse> {
  return api.get<IncidentEvidenceResponse>(`/incidents/${id}/evidence`);
}
