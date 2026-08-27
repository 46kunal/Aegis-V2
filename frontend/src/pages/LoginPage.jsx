import { useState } from "react";
import { Navigate } from "react-router-dom";

import { useAuth } from "../hooks/useAuth";

export default function LoginPage() {
  const { isAuthenticated, login, register } = useAuth();

  const [mode, setMode] = useState("login");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [form, setForm] = useState({
    email: "",
    password: "",
    fullName: "",
    role: "user",
  });

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  const updateField = (field, value) => {
    setForm((previous) => ({ ...previous, [field]: value }));
  };

  const onSubmit = async (event) => {
    event.preventDefault();
    setError("");
    setIsSubmitting(true);

    try {
      if (mode === "login") {
        await login({ email: form.email, password: form.password });
      } else {
        await register({
          email: form.email,
          password: form.password,
          fullName: form.fullName,
          role: form.role,
        });
      }
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Authentication failed");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="text-grid flex min-h-screen items-center justify-center px-5 py-10">
      <div className="glass-panel w-full max-w-md rounded-2xl p-6">
        <p className="font-display text-3xl font-bold tracking-[0.15em] text-cyber-100">AEGIS V2</p>
        <p className="mt-2 text-cyber-300">Secure your attack surface with continuous scanning intelligence.</p>

        <div className="mt-5 grid grid-cols-2 gap-2 rounded-md bg-cyber-900 p-1">
          <button
            type="button"
            className={`rounded-md py-2 text-sm font-semibold transition ${
              mode === "login" ? "bg-cyber-500 text-cyber-100" : "text-cyber-300"
            }`}
            onClick={() => setMode("login")}
          >
            Login
          </button>
          <button
            type="button"
            className={`rounded-md py-2 text-sm font-semibold transition ${
              mode === "register" ? "bg-cyber-500 text-cyber-100" : "text-cyber-300"
            }`}
            onClick={() => setMode("register")}
          >
            Register
          </button>
        </div>

        <form className="mt-6 space-y-4" onSubmit={onSubmit}>
          {mode === "register" && (
            <div>
              <label className="mb-1 block text-sm text-cyber-300" htmlFor="full-name">
                Full name
              </label>
              <input
                id="full-name"
                className="input-base"
                value={form.fullName}
                onChange={(event) => updateField("fullName", event.target.value)}
                required
                minLength={2}
              />
            </div>
          )}

          <div>
            <label className="mb-1 block text-sm text-cyber-300" htmlFor="email">
              Email
            </label>
            <input
              id="email"
              className="input-base"
              type="email"
              value={form.email}
              onChange={(event) => updateField("email", event.target.value)}
              required
            />
          </div>

          <div>
            <label className="mb-1 block text-sm text-cyber-300" htmlFor="password">
              Password
            </label>
            <input
              id="password"
              className="input-base"
              type="password"
              value={form.password}
              onChange={(event) => updateField("password", event.target.value)}
              minLength={8}
              required
            />
          </div>

          {mode === "register" && (
            <div>
              <label className="mb-1 block text-sm text-cyber-300" htmlFor="role">
                Role
              </label>
              <select
                id="role"
                className="input-base"
                value={form.role}
                onChange={(event) => updateField("role", event.target.value)}
              >
                <option value="user">User</option>
                <option value="admin">Admin</option>
              </select>
            </div>
          )}

          {error && <p className="rounded-md border border-signal-critical/40 bg-signal-critical/20 p-2 text-sm text-red-200">{error}</p>}

          <button className="btn-primary w-full" type="submit" disabled={isSubmitting}>
            {isSubmitting ? "Authenticating..." : mode === "login" ? "Sign in" : "Create account"}
          </button>
        </form>
      </div>
    </div>
  );
}
