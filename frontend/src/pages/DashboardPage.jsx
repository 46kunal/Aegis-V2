import { useEffect, useMemo, useState } from "react";

import { api } from "../api/client";
import StatCard from "../components/StatCard";

export default function DashboardPage() {
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const loadSummary = async () => {
    setLoading(true);
    setError("");
    try {
      const response = await api.get("/api/dashboard/summary");
      setSummary(response.data);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Failed to load dashboard summary");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSummary();
  }, []);

  const severityColors = {
    critical: "bg-signal-critical",
    high: "bg-signal-high",
    medium: "bg-signal-medium",
    low: "bg-signal-low",
    info: "bg-cyber-300",
  };

  const severityData = summary?.findings_by_severity || [];
  const maxSeverityCount = useMemo(() => {
    const values = severityData.map((entry) => entry.count);
    return Math.max(...values, 1);
  }, [severityData]);

  const trendData = summary?.scan_trends || [];
  const maxTrendValue = useMemo(() => {
    const values = trendData.map((entry) => entry.total);
    return Math.max(...values, 1);
  }, [trendData]);

  const trendPath = useMemo(() => {
    if (!trendData.length) {
      return "";
    }

    return trendData
      .map((point, index) => {
        const x = (index / Math.max(trendData.length - 1, 1)) * 100;
        const y = 100 - (point.total / maxTrendValue) * 100;
        return `${x},${y}`;
      })
      .join(" ");
  }, [maxTrendValue, trendData]);

  return (
    <section className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-3xl font-bold tracking-[0.1em] text-cyber-100">Threat Dashboard</h1>
          <p className="panel-subtitle mt-1">Operational awareness for your protected assets.</p>
        </div>
        <button type="button" className="btn-secondary" onClick={loadSummary}>
          Refresh
        </button>
      </div>

      {error && <p className="rounded-md border border-signal-critical/40 bg-signal-critical/20 p-3 text-sm text-red-200">{error}</p>}

      {loading ? (
        <div className="glass-panel rounded-xl p-5">Loading summary...</div>
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
            <StatCard label="Total Assets" value={summary?.total_assets ?? 0} highlight />
            <StatCard label="Active Assets" value={summary?.active_assets ?? 0} />
            <StatCard label="Total Scans" value={summary?.total_scans ?? 0} />
            <StatCard label="Total Findings" value={summary?.total_findings ?? 0} />
            <StatCard label="KEV Findings" value={summary?.kev_findings ?? 0} />
          </div>

          <div className="grid gap-5 xl:grid-cols-2">
            <div className="glass-panel rounded-xl p-5">
              <h2 className="font-display text-xl font-semibold tracking-[0.08em] text-cyber-100">Findings by Severity</h2>
              <div className="mt-4 space-y-3">
                {severityData.map((item) => (
                  <div key={item.severity}>
                    <div className="mb-1 flex items-center justify-between text-sm text-cyber-300">
                      <span className="uppercase tracking-wide">{item.severity}</span>
                      <span>{item.count}</span>
                    </div>
                    <div className="h-2 rounded-full bg-cyber-800">
                      <div
                        className={`h-2 rounded-full ${severityColors[item.severity] || "bg-cyber-300"}`}
                        style={{ width: `${(item.count / maxSeverityCount) * 100}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="glass-panel rounded-xl p-5">
              <h2 className="font-display text-xl font-semibold tracking-[0.08em] text-cyber-100">Scan Trends (14 Days)</h2>
              <p className="mt-1 text-sm text-cyber-400">Daily scan volume with completed and failed context.</p>
              <div className="mt-4 rounded-lg border border-cyber-700 bg-cyber-900/60 p-3">
                <svg viewBox="0 0 100 100" className="h-44 w-full">
                  <polyline
                    fill="none"
                    stroke="#59b3f5"
                    strokeWidth="2"
                    points={trendPath}
                    vectorEffect="non-scaling-stroke"
                  />
                </svg>
                <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-cyber-300">
                  {trendData.slice(-4).map((point) => (
                    <span key={point.date}>
                      {point.date.slice(5)}: {point.total} scans ({point.completed} ok / {point.failed} fail)
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="grid gap-5 xl:grid-cols-2">
            <div className="glass-panel rounded-xl p-5">
              <h2 className="font-display text-xl font-semibold tracking-[0.08em] text-cyber-100">Exposure Breakdown</h2>
              <div className="mt-4 grid grid-cols-2 gap-3">
                {(summary?.exposure_breakdown || []).map((item) => (
                  <div key={item.exposure} className="rounded-md border border-cyber-700 bg-cyber-900/60 p-3 text-center">
                    <p className="text-xs uppercase tracking-wide text-cyber-400">{item.exposure}</p>
                    <p className="mt-1 font-display text-2xl font-bold text-cyber-100">{item.count}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="glass-panel rounded-xl p-5">
              <h2 className="font-display text-xl font-semibold tracking-[0.08em] text-cyber-100">Recent Scans</h2>
              <div className="mt-4 overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="text-left text-cyber-400">
                    <tr>
                      <th className="pb-2">Asset</th>
                      <th className="pb-2">Mode</th>
                      <th className="pb-2">Status</th>
                      <th className="pb-2">Progress</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(summary?.recent_scans || []).map((scan) => (
                      <tr key={scan.scan_id} className="border-t border-cyber-700/60">
                        <td className="py-2 pr-2">{scan.asset_name}</td>
                        <td className="py-2 pr-2 capitalize">{scan.mode}</td>
                        <td className="py-2 pr-2 uppercase tracking-wide text-cyber-200">{scan.status}</td>
                        <td className="py-2 pr-2">{scan.progress}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {!summary?.recent_scans?.length && <p className="mt-3 text-cyber-400">No scans recorded yet.</p>}
            </div>

            <div className="glass-panel rounded-xl p-5">
              <h2 className="font-display text-xl font-semibold tracking-[0.08em] text-cyber-100">Top Exposed Ports</h2>
              <div className="mt-4 overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="text-left text-cyber-400">
                    <tr>
                      <th className="pb-2">Port</th>
                      <th className="pb-2">Protocol</th>
                      <th className="pb-2">Service</th>
                      <th className="pb-2">Occurrences</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(summary?.top_exposed_ports || []).map((portRow) => (
                      <tr key={`${portRow.port}-${portRow.protocol}-${portRow.service}`} className="border-t border-cyber-700/60">
                        <td className="py-2 pr-2">{portRow.port}</td>
                        <td className="py-2 pr-2 uppercase">{portRow.protocol}</td>
                        <td className="py-2 pr-2">{portRow.service}</td>
                        <td className="py-2 pr-2 font-semibold text-cyber-100">{portRow.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {!summary?.top_exposed_ports?.length && <p className="mt-3 text-cyber-400">No exposed ports available yet.</p>}
            </div>
          </div>

          <div className="glass-panel rounded-xl p-5">
            <h2 className="font-display text-xl font-semibold tracking-[0.08em] text-cyber-100">Top Risk Paths</h2>
            <p className="mt-1 text-sm text-cyber-400">Contextual risk: CVSS × EPSS × KEV × criticality × exposure</p>
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-left text-cyber-400">
                  <tr>
                    <th className="pb-2">Asset</th>
                    <th className="pb-2">Criticality</th>
                    <th className="pb-2">Exposure</th>
                    <th className="pb-2">Findings</th>
                    <th className="pb-2">Critical</th>
                    <th className="pb-2">KEV</th>
                    <th className="pb-2 text-right">Risk Score</th>
                  </tr>
                </thead>
                <tbody>
                  {(summary?.top_risky_assets || []).map((asset) => (
                    <tr key={asset.asset_id} className="border-t border-cyber-700/60">
                      <td className="py-2 pr-2">
                        <p className="font-semibold text-cyber-100">{asset.asset_name}</p>
                        <p className="text-xs text-cyber-400">{asset.target}</p>
                      </td>
                      <td className="py-2 pr-2 uppercase text-cyber-300">{asset.criticality}</td>
                      <td className="py-2 pr-2 uppercase text-cyber-300">{asset.exposure}</td>
                      <td className="py-2 pr-2">{asset.findings}</td>
                      <td className="py-2 pr-2 text-signal-critical">{asset.critical_findings}</td>
                      <td className="py-2 pr-2">
                        {asset.kev_findings > 0 ? (
                          <span className="rounded bg-signal-critical/20 px-1.5 py-0.5 text-xs font-bold text-signal-critical">
                            {asset.kev_findings} KEV
                          </span>
                        ) : (
                          <span className="text-cyber-600">—</span>
                        )}
                      </td>
                      <td className="py-2 pl-2 text-right font-mono font-bold">
                        <span className={
                          asset.risk_score >= 70 ? "text-signal-critical" :
                          asset.risk_score >= 40 ? "text-signal-high" :
                          asset.risk_score >= 20 ? "text-signal-medium" : "text-signal-low"
                        }>
                          {asset.risk_score.toFixed(1)}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {!summary?.top_risky_assets?.length && <p className="mt-3 text-cyber-400">No findings yet. Run scans to populate risk scores.</p>}
          </div>
        </>
      )}
    </section>
  );
}
