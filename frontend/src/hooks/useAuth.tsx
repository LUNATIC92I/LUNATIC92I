import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { refreshAccessToken } from "@/services/apiClient";
import { fetchCurrentUser, login as loginRequest, logout as logoutRequest } from "@/services/authService";
import type { CurrentUser } from "@/types/auth";
import type { LoginParams } from "@/services/authService";

interface AuthContextValue {
  user: CurrentUser | null;
  status: "loading" | "authenticated" | "unauthenticated";
  login: (params: LoginParams) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [status, setStatus] = useState<AuthContextValue["status"]>("loading");

  const refreshUser = useCallback(async () => {
    const me = await fetchCurrentUser();
    setUser(me);
    setStatus("authenticated");
  }, []);

  useEffect(() => {
    // On first load there is no in-memory access token — only the httpOnly
    // refresh cookie might still be valid from a previous session. One
    // silent refresh attempt tells us which.
    let cancelled = false;
    (async () => {
      const refreshed = await refreshAccessToken();
      if (cancelled) return;
      if (!refreshed) {
        setStatus("unauthenticated");
        return;
      }
      try {
        await refreshUser();
      } catch {
        if (!cancelled) setStatus("unauthenticated");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [refreshUser]);

  const login = useCallback(
    async (params: LoginParams) => {
      await loginRequest(params);
      await refreshUser();
    },
    [refreshUser],
  );

  const logout = useCallback(async () => {
    await logoutRequest();
    setUser(null);
    setStatus("unauthenticated");
  }, []);

  return (
    <AuthContext.Provider value={{ user, status, login, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components -- the hook belongs beside its provider, not split into a second file for one export
export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
