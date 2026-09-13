import { getAccessToken, setAccessToken } from "./tokenStore";

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(status: number, detail: unknown) {
    super(extractMessage(detail, status));
    this.status = status;
    this.detail = detail;
  }
}

function extractMessage(detail: unknown, status: number): string {
  // FastAPI's HTTPException detail is usually a string, but pydantic's own
  // 422s carry a list of {loc, msg, ...} objects, and a couple of endpoints
  // (MFA-required) return a small object. All three are real shapes seen
  // from this API, so all three are handled rather than assumed away.
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item) => (typeof item === "object" && item && "msg" in item ? String(item.msg) : String(item)))
      .join("; ");
  }
  if (detail && typeof detail === "object" && "message" in detail) {
    return String((detail as { message: unknown }).message);
  }
  return `request failed with status ${status}`;
}

let refreshInFlight: Promise<boolean> | null = null;

export async function refreshAccessToken(): Promise<boolean> {
  // Concurrent 401s (a page firing several requests at once) must not each
  // spend their own refresh call — the httpOnly cookie is rotated by the
  // backend on every use, so a second concurrent refresh would invalidate
  // the first one's new cookie before it is ever read.
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
          method: "POST",
          credentials: "include",
        });
        if (!response.ok) return false;
        const body = (await response.json()) as { access_token: string };
        setAccessToken(body.access_token);
        return true;
      } catch {
        return false;
      } finally {
        refreshInFlight = null;
      }
    })();
  }
  return refreshInFlight;
}

export interface RequestOptions {
  method?: string;
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined | null>;
  signal?: AbortSignal;
  /** Skip the automatic 401-refresh-and-retry cycle (used by auth endpoints themselves). */
  skipAuthRetry?: boolean;
}

function buildUrl(path: string, query?: RequestOptions["query"]): string {
  const url = new URL(`${API_BASE_URL}${path}`);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    }
  }
  return url.toString();
}

async function rawRequest<T>(path: string, options: RequestOptions): Promise<T> {
  const headers: Record<string, string> = {};
  const token = getAccessToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  let body: string | undefined;
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.body);
  }

  const response = await fetch(buildUrl(path, options.query), {
    method: options.method ?? "GET",
    headers,
    body,
    credentials: "include",
    signal: options.signal,
  });

  if (response.status === 204) return undefined as T;

  const isJson = response.headers.get("content-type")?.includes("application/json");
  const payload = isJson ? await response.json().catch(() => undefined) : await response.text();

  if (!response.ok) {
    throw new ApiError(response.status, isJson ? (payload as { detail?: unknown })?.detail ?? payload : payload);
  }
  return payload as T;
}

/**
 * The shared request function every service module goes through. A 401 from
 * anything other than the auth endpoints themselves triggers exactly one
 * silent refresh-and-retry — the access token is short-lived by design
 * (15 minutes, JWT_ACCESS_TOKEN_TTL_SECONDS) so this is the normal path
 * through a long analyst session, not an edge case.
 */
export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  try {
    return await rawRequest<T>(path, options);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401 && !options.skipAuthRetry) {
      const refreshed = await refreshAccessToken();
      if (refreshed) {
        return rawRequest<T>(path, options);
      }
      setAccessToken(null);
    }
    throw error;
  }
}

export const api = {
  get: <T>(path: string, query?: RequestOptions["query"], signal?: AbortSignal) =>
    apiRequest<T>(path, { method: "GET", query, signal }),
  post: <T>(path: string, body?: unknown, options: RequestOptions = {}) =>
    apiRequest<T>(path, { ...options, method: "POST", body }),
  patch: <T>(path: string, body?: unknown, options: RequestOptions = {}) =>
    apiRequest<T>(path, { ...options, method: "PATCH", body }),
  delete: <T>(path: string, options: RequestOptions = {}) =>
    apiRequest<T>(path, { ...options, method: "DELETE" }),
};
