import { api, API_BASE_URL, apiRequest } from "./apiClient";
import { getAccessToken } from "./tokenStore";
import type { HuntQuery, HuntSearchResponse, PivotResponse, SavedHunt } from "@/types/hunting";

export function fetchHuntingFields(): Promise<{ fields: string[] }> {
  return api.get<{ fields: string[] }>("/hunting/fields");
}

export function searchHunt(query: HuntQuery, limit = 100): Promise<HuntSearchResponse> {
  return api.post<HuntSearchResponse>("/hunting/search", { ...query, limit });
}

export function listSavedHunts(): Promise<SavedHunt[]> {
  return api.get<SavedHunt[]>("/hunting/saved");
}

export function createSavedHunt(payload: { name: string; description?: string; query: HuntQuery }): Promise<SavedHunt> {
  return api.post<SavedHunt>("/hunting/saved", payload);
}

export function deleteSavedHunt(id: string): Promise<void> {
  return api.delete<void>(`/hunting/saved/${id}`);
}

export function runSavedHunt(id: string): Promise<HuntSearchResponse> {
  return api.post<HuntSearchResponse>(`/hunting/saved/${id}/run`);
}

export function runPivot(pivot: string, value: string, limit?: number): Promise<PivotResponse> {
  return api.post<PivotResponse>("/hunting/pivot", { pivot, value, limit });
}

/**
 * Export streams back a file body (CSV or JSON), not a JSON envelope, so it
 * bypasses the shared `api.post` helper — but still goes through the same
 * `apiRequest` 401-refresh-and-retry path other calls do. Returns a
 * download-ready Blob and the filename extension to save it as.
 */
export async function exportHunt(
  query: HuntQuery,
  format: "csv" | "json",
): Promise<{ blob: Blob; extension: string }> {
  const token = getAccessToken();
  const doFetch = () =>
    fetch(`${API_BASE_URL}/hunting/export`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ ...query, format }),
    });

  let response = await doFetch();
  if (response.status === 401) {
    // Reuse the shared refresh cycle rather than duplicating it here.
    await apiRequest("/hunting/fields", {}).catch(() => undefined);
    response = await doFetch();
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(typeof body.detail === "string" ? body.detail : "export failed");
  }
  return { blob: await response.blob(), extension: format };
}
