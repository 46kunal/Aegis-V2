import { createContext, useCallback, useEffect, useMemo, useState } from "react";

import { api, tokenStore } from "../api/client";

export const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [devMode, setDevMode] = useState(false);

  const logout = useCallback(() => {
    tokenStore.clear();
    setUser(null);
  }, []);

  const loadProfile = useCallback(async () => {
    // ── Check DEV_MODE from backend ─────────────────────────────────────
    try {
      const devRes = await api.get("/api/auth/dev-status");
      if (devRes.data?.dev_mode) {
        setDevMode(true);
        // In DEV_MODE the backend accepts requests without tokens.
        // Fetch the profile (deps.py returns the seeded user automatically).
        try {
          const meRes = await api.get("/api/auth/me");
          setUser(meRes.data);
        } catch {
          // Even if /me fails, still allow dashboard access in dev mode
          setUser({ id: "dev", email: "admin@aegis.local", full_name: "Aegis Admin", role: "admin", is_active: true });
        }
        setIsLoading(false);
        return;
      }
    } catch {
      // dev-status endpoint unavailable — proceed normally
    }

    // ── Normal auth flow ────────────────────────────────────────────────
    const accessToken = tokenStore.getAccessToken();
    if (!accessToken) {
      setIsLoading(false);
      return;
    }

    try {
      const response = await api.get("/api/auth/me");
      setUser(response.data);
    } catch {
      logout();
    } finally {
      setIsLoading(false);
    }
  }, [logout]);

  const login = useCallback(async ({ email, password }) => {
    const response = await api.post("/api/auth/login", { email, password });
    tokenStore.setTokens({
      accessToken: response.data.tokens.access_token,
      refreshToken: response.data.tokens.refresh_token,
    });
    setUser(response.data.user);
    return response.data.user;
  }, []);

  const register = useCallback(async ({ email, fullName, password, role }) => {
    const response = await api.post("/api/auth/register", {
      email,
      full_name: fullName,
      password,
      role,
    });

    tokenStore.setTokens({
      accessToken: response.data.tokens.access_token,
      refreshToken: response.data.tokens.refresh_token,
    });
    setUser(response.data.user);
    return response.data.user;
  }, []);

  useEffect(() => {
    loadProfile();
  }, [loadProfile]);

  const value = useMemo(
    () => ({
      user,
      isLoading,
      isAuthenticated: Boolean(user),
      devMode,
      login,
      logout,
      register,
      reloadProfile: loadProfile,
    }),
    [devMode, isLoading, loadProfile, login, logout, register, user],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
