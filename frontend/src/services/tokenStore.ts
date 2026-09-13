/**
 * The access token lives in memory only — never localStorage/sessionStorage.
 * The refresh token is an httpOnly cookie the browser holds and the backend
 * sets (app/api/auth.py); a token this module could read is a token an XSS
 * payload could read too, so it never touches storage APIs a script can
 * reach. A page reload loses the in-memory token and re-derives it from the
 * refresh cookie via `POST /auth/refresh` (see apiClient.ts).
 */

type Listener = (token: string | null) => void;

let accessToken: string | null = null;
const listeners = new Set<Listener>();

export function getAccessToken(): string | null {
  return accessToken;
}

export function setAccessToken(token: string | null): void {
  accessToken = token;
  for (const listener of listeners) listener(token);
}

export function subscribeToAccessToken(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
