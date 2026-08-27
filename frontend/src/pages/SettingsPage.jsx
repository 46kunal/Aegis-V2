import { useState } from "react";

import { useAuth } from "../hooks/useAuth";

const API_KEY = "aegis_api_base_url_override";

export default function SettingsPage() {
  const { user, reloadProfile } = useAuth();
  const [apiBaseUrl, setApiBaseUrl] = useState(localStorage.getItem(API_KEY) || "");
  const [message, setMessage] = useState("");

  const saveApiUrl = (event) => {
    event.preventDefault();
    if (!apiBaseUrl.trim()) {
      localStorage.removeItem(API_KEY);
      setMessage("Cleared API override. App will use VITE_API_BASE_URL.");
      return;
    }

    localStorage.setItem(API_KEY, apiBaseUrl.trim());
    setMessage("Saved API override. Reload browser to apply.");
  };

  return (
    <section className="space-y-6">
      <div>
        <h1 className="font-display text-3xl font-bold tracking-[0.1em] text-cyber-100">Settings</h1>
        <p className="panel-subtitle mt-1">Manage profile and client runtime settings.</p>
      </div>

      <div className="glass-panel rounded-xl p-5">
        <div className="flex items-center justify-between">
          <h2 className="font-display text-xl font-semibold tracking-[0.08em] text-cyber-100">Profile</h2>
          <button className="btn-secondary" type="button" onClick={reloadProfile}>
            Refresh Profile
          </button>
        </div>
        <dl className="mt-4 grid gap-2 text-sm md:grid-cols-2">
          <div>
            <dt className="text-cyber-400">Full name</dt>
            <dd className="text-cyber-100">{user?.full_name || "unknown"}</dd>
          </div>
          <div>
            <dt className="text-cyber-400">Email</dt>
            <dd className="text-cyber-100">{user?.email || "unknown"}</dd>
          </div>
          <div>
            <dt className="text-cyber-400">Role</dt>
            <dd className="text-cyber-100 uppercase">{user?.role || "unknown"}</dd>
          </div>
          <div>
            <dt className="text-cyber-400">Status</dt>
            <dd className="text-cyber-100">{user?.is_active ? "Active" : "Disabled"}</dd>
          </div>
        </dl>
      </div>

      <div className="glass-panel rounded-xl p-5">
        <h2 className="font-display text-xl font-semibold tracking-[0.08em] text-cyber-100">Client API Endpoint</h2>
        <p className="mt-2 text-sm text-cyber-300">Set a browser-local API base URL override for this environment.</p>
        <form className="mt-4 flex flex-col gap-3 md:flex-row" onSubmit={saveApiUrl}>
          <input
            className="input-base"
            placeholder="https://api.yourdomain.com"
            value={apiBaseUrl}
            onChange={(event) => setApiBaseUrl(event.target.value)}
          />
          <button type="submit" className="btn-primary">
            Save
          </button>
        </form>
        {message && <p className="mt-3 text-sm text-cyber-300">{message}</p>}
      </div>
    </section>
  );
}
