import axios from "axios";

const API_BASE_URL = localStorage.getItem("aegis_api_base_url_override") || import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const ACCESS_TOKEN_KEY = "aegis_access_token";
const REFRESH_TOKEN_KEY = "aegis_refresh_token";

let tokenRefresher = null;

export const tokenStore = {
  getAccessToken: () => localStorage.getItem(ACCESS_TOKEN_KEY),
  getRefreshToken: () => localStorage.getItem(REFRESH_TOKEN_KEY),
  setTokens: ({ accessToken, refreshToken }) => {
    localStorage.setItem(ACCESS_TOKEN_KEY, accessToken);
    localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
  },
  clear: () => {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
  },
};

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 20000,
});

api.interceptors.request.use((config) => {
  const token = tokenStore.getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

const refreshToken = async () => {
  const currentRefreshToken = tokenStore.getRefreshToken();
  if (!currentRefreshToken) {
    throw new Error("No refresh token available");
  }

  const response = await axios.post(`${API_BASE_URL}/api/auth/refresh`, {
    refresh_token: currentRefreshToken,
  });

  const accessToken = response.data.tokens.access_token;
  const refreshTokenValue = response.data.tokens.refresh_token;
  tokenStore.setTokens({ accessToken, refreshToken: refreshTokenValue });

  return accessToken;
};

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    const statusCode = error.response?.status;

    if (statusCode !== 401 || originalRequest?._retry) {
      return Promise.reject(error);
    }

    originalRequest._retry = true;

    try {
      if (!tokenRefresher) {
        tokenRefresher = refreshToken().finally(() => {
          tokenRefresher = null;
        });
      }

      const nextAccessToken = await tokenRefresher;
      originalRequest.headers.Authorization = `Bearer ${nextAccessToken}`;

      return api(originalRequest);
    } catch (refreshError) {
      tokenStore.clear();
      return Promise.reject(refreshError);
    }
  },
);
