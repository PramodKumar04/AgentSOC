// The signed-in user. The session itself is an HttpOnly cookie the page cannot read; the
// CSRF token is kept in memory and fetched again after a reload.
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, type ReactNode } from "react";

import { api, ApiError, setCsrfToken, UNAUTHORIZED_EVENT, type SessionInfo } from "@/lib/api";

interface AuthState {
  session: SessionInfo | null;
  isLoading: boolean;
  error: unknown;
  retry: () => void;
  signIn: (username: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
  replaceSession: (session: SessionInfo) => void;
}

const AuthContext = createContext<AuthState | null>(null);
const KEY = ["auth", "session"];

export function AuthProvider({ children }: { children: ReactNode }) {
  const client = useQueryClient();
  const query = useQuery({
    queryKey: KEY,
    queryFn: async () => {
      try { return await api.session(); }
      catch (err) { if (err instanceof ApiError && err.status === 401) return null; throw err; }
    },
    retry: false, staleTime: Infinity,
  });
  const session = query.data ?? null;
  useEffect(() => setCsrfToken(session?.csrf_token ?? null), [session]);

  const replaceSession = useCallback((next: SessionInfo | null) => {
    setCsrfToken(next?.csrf_token ?? null);
    if (next === null) client.removeQueries({ predicate: (q) => q.queryKey[0] !== "auth" });
    client.setQueryData(KEY, next);
  }, [client]);

  useEffect(() => {
    const expired = () => replaceSession(null);
    window.addEventListener(UNAUTHORIZED_EVENT, expired);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, expired);
  }, [replaceSession]);

  const value = useMemo<AuthState>(() => ({
    session, isLoading: query.isLoading, error: query.error, retry: () => void query.refetch(),
    signIn: async (username, password) => replaceSession(await api.login(username, password)),
    signOut: async () => {
      try { await api.logout(); } finally { replaceSession(null); }
    },
    replaceSession,
  }), [session, query, replaceSession]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth outside AuthProvider");
  return value;
}
