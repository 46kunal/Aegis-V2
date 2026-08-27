import { useEffect, useMemo, useState } from "react";

import { api } from "../api/client";

function severityClass(criticalCount, findingCount) {
  if (criticalCount > 0) {
    return "text-signal-critical";
  }
  if (findingCount > 10) {
    return "text-signal-high";
  }
  if (findingCount > 0) {
    return "text-signal-medium";
  }
  return "text-signal-low";
}

export default function FindingsPage() {
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError("");
      try {
        const response = await api.get("/api/dashboard/summary");
        setSummary(response.data);
      } catch (requestError) {
        setError(requestError.response?.data?.detail || "Failed to load findings overview");
      } finally {
        setLoading(false);
      }
    };

    load();
  }, []);

  const totals = useMemo(() => {
    if (!summary) {
      return { critical: 0, total: 0, riskyAssets: 0 };
    }
    return {
      critical: summary.critical_findings,
      total: summary.total_findings,
      riskyAssets: summary.top_risky_assets.length,
    };
  }, [summary]);

  return (
    <section className="space-y-6">
      <div>
        <h1 className="font-display text-3xl font-bold tracking-[0.1em] text-cyber-100">Findings</h1>
        <p className="panel-subtitle mt-1">Consolidated risk posture based on scanned assets.</p>
      </div>

      {error && <p className="rounded-md border border-signal-critical/40 bg-signal-critical/20 p-3 text-sm text-red-200">{error}</p>}

      <div className="grid gap-4 md:grid-cols-3">
        <div className="glass-panel rounded-xl p-4">
          <p className="panel-title">Total Findings</p>
          <p className="mt-2 font-display text-3xl font-bold">{loading ? "..." : totals.total}</p>
        </div>
        <div className="glass-panel rounded-xl p-4">
          <p className="panel-title">Critical Findings</p>
          <p className="mt-2 font-display text-3xl font-bold text-signal-critical">{loading ? "..." : totals.critical}</p>
        </div>
        <div className="glass-panel rounded-xl p-4">
          <p className="panel-title">Risky Assets</p>
          <p className="mt-2 font-display text-3xl font-bold">{loading ? "..." : totals.riskyAssets}</p>
        </div>
      </div>

      <div className="glass-panel rounded-xl p-5">
        <h2 className="font-display text-xl font-semibold tracking-[0.08em] text-cyber-100">Asset Risk Breakdown</h2>
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-cyber-400">
              <tr>
                <th className="pb-2">Asset</th>
                <th className="pb-2">Target</th>
                <th className="pb-2">Findings</th>
                <th className="pb-2">Critical</th>
                <th className="pb-2">Risk Score</th>
              </tr>
            </thead>
            <tbody>
              {(summary?.top_risky_assets || []).map((asset) => (
                <tr key={asset.asset_id} className="border-t border-cyber-700/60">
                  <td className="py-2 pr-2">{asset.asset_name}</td>
                  <td className="py-2 pr-2 text-cyber-300">{asset.target}</td>
                  <td className={`py-2 pr-2 font-semibold ${severityClass(asset.critical_findings, asset.findings)}`}>{asset.findings}</td>
                  <td className="py-2 pr-2 text-signal-critical">{asset.critical_findings}</td>
                  <td className="py-2 pr-2">{asset.risk_score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!summary?.top_risky_assets?.length && !loading && (
          <p className="mt-3 text-cyber-400">No findings are available yet. Run scans to populate this section.</p>
        )}
      </div>
    </section>
  );
}
