import { useEffect, useState } from "react";

import { api } from "../api/client";

const defaultState = {
  assetId: "",
  mode: "fast",
};

export default function ScansPage() {
  const [assets, setAssets] = useState([]);
  const [scans, setScans] = useState([]);
  const [form, setForm] = useState(defaultState);
  const [loadingScans, setLoadingScans] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [actionMessage, setActionMessage] = useState("");
  const [error, setError] = useState("");
  const [selectedScanId, setSelectedScanId] = useState("");
  const [scanDetail, setScanDetail] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [busyScanIds, setBusyScanIds] = useState({});

  const loadAssets = async () => {
    try {
      const response = await api.get("/api/assets", { params: { limit: 200, offset: 0 } });
      setAssets(response.data.items || []);
      if (!form.assetId && response.data.items?.length) {
        setForm((previous) => ({ ...previous, assetId: response.data.items[0].id }));
      }
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Failed to load assets");
    }
  };

  const loadScans = async ({ silent = false } = {}) => {
    if (!silent) {
      setLoadingScans(true);
    }

    try {
      const response = await api.get("/api/scans", { params: { limit: 100, offset: 0 } });
      setScans(response.data.items || []);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Failed to load scans");
    } finally {
      if (!silent) {
        setLoadingScans(false);
      }
    }
  };

  useEffect(() => {
    loadAssets();
    loadScans();
  }, []);

  useEffect(() => {
    const intervalId = window.setInterval(() => {
      loadScans({ silent: true });
    }, 5000);

    return () => window.clearInterval(intervalId);
  }, []);

  const startScan = async (event) => {
    event.preventDefault();
    setError("");
    setActionMessage("");
    setSubmitting(true);

    try {
      const response = await api.post("/api/scans/start", {
        asset_id: form.assetId,
        mode: form.mode,
      });
      setActionMessage(`Scan queued: ${response.data.scan_id}`);
      await loadScans({ silent: true });
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Failed to queue scan");
    } finally {
      setSubmitting(false);
    }
  };

  const openDetails = async (scanId) => {
    setSelectedScanId(scanId);
    setScanDetail(null);
    setLoadingDetail(true);
    setError("");
    try {
      const response = await api.get(`/api/scans/${scanId}`);
      setScanDetail(response.data);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Failed to load scan details");
    } finally {
      setLoadingDetail(false);
    }
  };

  const closeDetails = () => {
    setSelectedScanId("");
    setScanDetail(null);
  };

  const retryFailedScan = async (scanId) => {
    setBusyScanIds((previous) => ({ ...previous, [scanId]: true }));
    setActionMessage("");
    setError("");
    try {
      const response = await api.post(`/api/scans/${scanId}/retry`);
      setActionMessage(`Retry queued: ${response.data.scan_id}`);
      await loadScans({ silent: true });
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Failed to retry scan");
    } finally {
      setBusyScanIds((previous) => ({ ...previous, [scanId]: false }));
    }
  };

  const cancelScan = async (scanId) => {
    setBusyScanIds((previous) => ({ ...previous, [scanId]: true }));
    setActionMessage("");
    setError("");
    try {
      await api.post(`/api/scans/${scanId}/cancel`);
      setActionMessage(`Scan cancelled: ${scanId}`);
      await loadScans({ silent: true });
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Failed to cancel scan");
    } finally {
      setBusyScanIds((previous) => ({ ...previous, [scanId]: false }));
    }
  };

  const downloadReport = async (scanItem) => {
    setBusyScanIds((previous) => ({ ...previous, [scanItem.scan_id]: true }));
    setActionMessage("");
    setError("");
    try {
      let reportId = scanItem.latest_report_id;
      if (!reportId) {
        const generated = await api.post(`/api/reports/scan/${scanItem.scan_id}`);
        reportId = generated.data.report_id;
      }

      const response = await api.get(`/api/reports/download/${reportId}`, { responseType: "blob" });
      const blobUrl = window.URL.createObjectURL(new Blob([response.data], { type: "application/pdf" }));
      const link = document.createElement("a");
      link.href = blobUrl;
      link.download = `scan-report-${scanItem.scan_id}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(blobUrl);
      setActionMessage(`Report ready for scan ${scanItem.scan_id}`);
      await loadScans({ silent: true });
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Failed to download report");
    } finally {
      setBusyScanIds((previous) => ({ ...previous, [scanItem.scan_id]: false }));
    }
  };

  const runningScans = scans.filter((scan) => scan.status === "queued" || scan.status === "running");
  const completedScans = scans.filter((scan) => scan.status === "completed" || scan.status === "failed" || scan.status === "cancelled");

  return (
    <section className="space-y-6">
      <div>
        <h1 className="font-display text-3xl font-bold tracking-[0.1em] text-cyber-100">Scans</h1>
        <p className="panel-subtitle mt-1">Continuous scan orchestration with live progress polling every 5 seconds.</p>
      </div>

      <div className="glass-panel rounded-xl p-5">
        <h2 className="font-display text-xl font-semibold tracking-[0.08em] text-cyber-100">Start New Scan</h2>
        <form className="mt-4 grid gap-4 md:grid-cols-3" onSubmit={startScan}>
          <select
            className="input-base"
            value={form.assetId}
            onChange={(event) => setForm((previous) => ({ ...previous, assetId: event.target.value }))}
            required
            disabled={loadingScans}
          >
            <option value="">Select asset</option>
            {assets.map((asset) => (
              <option key={asset.id} value={asset.id}>
                {asset.name} ({asset.target})
              </option>
            ))}
          </select>

          <select
            className="input-base"
            value={form.mode}
            onChange={(event) => setForm((previous) => ({ ...previous, mode: event.target.value }))}
          >
            <option value="fast">Fast</option>
            <option value="smart_fast">Smart Fast</option>
            <option value="medium">Medium</option>
            <option value="full">Full</option>
            <option value="super_full">Super Full</option>
          </select>

          <button type="submit" className="btn-primary" disabled={submitting || !form.assetId}>
            {submitting ? "Queueing..." : "Start Scan"}
          </button>
        </form>

        <div className="mt-3 rounded-md border border-cyber-700 bg-cyber-900/50 p-3 text-xs text-cyber-300 space-y-1">
          <p><span className="font-semibold text-cyber-100">Fast</span> — Quick top-port scan (~100 ports, no service detection). Fastest results.</p>
          <p><span className="font-semibold text-cyber-100">Smart Fast</span> — Top ports with lightweight service detection for CPE/CVE enrichment. Faster than Medium.</p>
          <p><span className="font-semibold text-cyber-100">Medium</span> — Top 200 ports with service/version detection. Balanced speed and depth.</p>
          <p><span className="font-semibold text-cyber-100">Full</span> — All 65535 TCP ports + NSE scripts + OS detection. Thorough but slow.</p>
          <p><span className="font-semibold text-cyber-100">Super Full</span> — Maximum depth scan with full port coverage. Use for exhaustive assessments.</p>
        </div>

        {error && <p className="mt-3 rounded-md border border-signal-critical/40 bg-signal-critical/20 p-2 text-sm text-red-200">{error}</p>}
        {actionMessage && <div className="mt-4 rounded-md border border-cyber-500 bg-cyber-900/60 p-3 text-sm text-cyber-200">{actionMessage}</div>}
      </div>

      <div className="glass-panel rounded-xl p-5">
        <h2 className="font-display text-xl font-semibold tracking-[0.08em] text-cyber-100">Running Scans</h2>
        {loadingScans ? (
          <p className="mt-3 text-cyber-300">Loading scan streams...</p>
        ) : (
          <div className="mt-4 space-y-3">
            {runningScans.map((scan) => (
              <div key={scan.scan_id} className="rounded-lg border border-cyber-700 bg-cyber-900/60 p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="font-semibold text-cyber-100">{scan.asset_name}</p>
                    <p className="text-sm text-cyber-400">
                      {scan.mode} | {scan.status} | {scan.summary || "processing"}
                    </p>
                    {scan.celery_task_id && (
                      <p className="text-xs text-cyber-500 mt-1">Task ID: {scan.celery_task_id}</p>
                    )}
                  </div>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => cancelScan(scan.scan_id)}
                      disabled={busyScanIds[scan.scan_id]}
                    >
                      Cancel
                    </button>
                    <button type="button" className="btn-secondary" onClick={() => openDetails(scan.scan_id)}>
                      Details
                    </button>
                  </div>
                </div>
                <div className="mt-3 h-2 w-full rounded-full bg-cyber-800">
                  <div className="h-2 rounded-full bg-cyber-300" style={{ width: `${scan.progress}%` }} />
                </div>
                <p className="mt-2 text-xs text-cyber-300">{scan.progress}% complete</p>
              </div>
            ))}
            {!runningScans.length && <p className="text-cyber-400">No running or queued scans.</p>}
          </div>
        )}
      </div>

      <div className="glass-panel rounded-xl p-5">
        <h2 className="font-display text-xl font-semibold tracking-[0.08em] text-cyber-100">Completed Scans</h2>
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-cyber-400">
              <tr>
                <th className="pb-2">Asset</th>
                <th className="pb-2">Mode</th>
                <th className="pb-2">Status</th>
                <th className="pb-2">Progress</th>
                <th className="pb-2">Findings</th>
                <th className="pb-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {completedScans.map((scan) => (
                <tr key={scan.scan_id} className="border-t border-cyber-700/60">
                  <td className="py-2 pr-2">{scan.asset_name}</td>
                  <td className="py-2 pr-2 capitalize">{scan.mode}</td>
                  <td className="py-2 pr-2 uppercase tracking-wide text-cyber-200">{scan.status}</td>
                  <td className="py-2 pr-2">{scan.progress}%</td>
                  <td className="py-2 pr-2">
                    {scan.finding_count} ({scan.critical_finding_count} critical)
                  </td>
                  <td className="py-2 pr-2">
                    <div className="flex flex-wrap gap-2">
                      <button type="button" className="btn-secondary" onClick={() => openDetails(scan.scan_id)}>
                        Details
                      </button>
                      {scan.status === "failed" && (
                        <button
                          type="button"
                          className="btn-secondary"
                          onClick={() => retryFailedScan(scan.scan_id)}
                          disabled={busyScanIds[scan.scan_id]}
                        >
                          Retry
                        </button>
                      )}
                      {scan.status === "completed" && (
                        <button
                          type="button"
                          className="btn-primary"
                          onClick={() => downloadReport(scan)}
                          disabled={busyScanIds[scan.scan_id]}
                        >
                          Report
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!completedScans.length && <p className="mt-3 text-cyber-400">No completed, failed, or cancelled scans yet.</p>}
      </div>

      {selectedScanId && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-cyber-950/80 p-4">
          <div className="glass-panel w-full max-w-4xl rounded-2xl p-5">
            <div className="flex items-center justify-between">
              <h3 className="font-display text-xl font-semibold tracking-[0.08em] text-cyber-100">Scan Details</h3>
              <button type="button" className="btn-secondary" onClick={closeDetails}>
                Close
              </button>
            </div>

            {loadingDetail ? (
              <p className="mt-4 text-cyber-300">Loading details...</p>
            ) : scanDetail ? (
              <div className="mt-4 space-y-4">
                <div className="grid gap-3 md:grid-cols-3">
                  <div className="rounded-md border border-cyber-700 bg-cyber-900/60 p-3">
                    <p className="panel-title">Asset</p>
                    <p className="mt-1 text-cyber-100">{scanDetail.asset_name}</p>
                    <p className="text-xs text-cyber-400">{scanDetail.asset_target}</p>
                  </div>
                  <div className="rounded-md border border-cyber-700 bg-cyber-900/60 p-3">
                    <p className="panel-title">Status</p>
                    <p className="mt-1 uppercase text-cyber-100">{scanDetail.status}</p>
                    <p className="text-xs text-cyber-400">{scanDetail.progress}% complete</p>
                  </div>
                  <div className="rounded-md border border-cyber-700 bg-cyber-900/60 p-3">
                    <p className="panel-title">Findings</p>
                    <p className="mt-1 text-cyber-100">{scanDetail.finding_count}</p>
                    <p className="text-xs text-signal-critical">Critical: {scanDetail.critical_finding_count}</p>
                  </div>
                </div>

                <div className="rounded-md border border-cyber-700 bg-cyber-900/60 p-3">
                  <p className="panel-title">Summary</p>
                  <p className="mt-1 text-cyber-100">{scanDetail.summary || "No summary available"}</p>
                  {scanDetail.error_message && <p className="mt-2 text-sm text-red-300">Error: {scanDetail.error_message}</p>}
                  {scanDetail.celery_task_id && <p className="mt-2 text-xs text-cyber-400">Task ID: {scanDetail.celery_task_id}</p>}
                </div>

                <div className="rounded-md border border-cyber-700 bg-cyber-900/60 p-3">
                  <p className="panel-title">Service Intelligence</p>
                  <div className="mt-2 max-h-80 overflow-y-auto">
                    <table className="w-full text-sm">
                      <thead className="text-left text-cyber-400">
                        <tr>
                          <th className="pb-2">Port</th>
                          <th className="pb-2">Service</th>
                          <th className="pb-2">Product / Version</th>
                          <th className="pb-2">CVE / Intelligence</th>
                          <th className="pb-2">CWE</th>
                          <th className="pb-2">Severity</th>
                          <th className="pb-2">CVSS</th>
                        </tr>
                      </thead>
                      <tbody>
                        {scanDetail.findings.map((finding) => (
                          <tr key={finding.id} className="border-t border-cyber-700/60 align-top">
                            <td className="py-2 pr-2 font-mono text-cyber-100">
                              {finding.port ?? "—"}/{finding.protocol ?? "tcp"}
                            </td>
                            <td className="py-2 pr-2">{finding.title.replace(/^Open port \d+\/\w+ \(/, "").replace(/\)$/, "") || "unknown"}</td>
                            <td className="py-2 pr-2">
                              {finding.detected_product || finding.detected_version ? (
                                <span className="text-cyber-100">
                                  {finding.detected_product || ""}{finding.detected_version ? ` ${finding.detected_version}` : ""}
                                </span>
                              ) : (
                                <span className="text-cyber-500">—</span>
                              )}
                            </td>
                            <td className="py-2 pr-2">
                              {finding.cve_id ? (
                                <div className="space-y-1">
                                  <span className="font-mono text-xs font-semibold text-cyber-200">{finding.cve_id}</span>
                                  {finding.epss_score != null && (
                                    <div className="text-[10px] text-cyber-400">
                                      EPSS: {(finding.epss_score * 100).toFixed(2)}% exploit probability
                                    </div>
                                  )}
                                  {finding.cvss_vector && (
                                    <div className="text-[10px] text-cyber-500 font-mono truncate max-w-[150px]" title={finding.cvss_vector}>
                                      {finding.cvss_vector}
                                    </div>
                                  )}
                                  {finding.references && finding.references.length > 0 && (
                                    <div className="text-[10px]">
                                      <a href={finding.references[0]} target="_blank" rel="noreferrer" className="text-cyber-400 hover:text-cyber-300 underline">
                                        NVD Reference
                                      </a>
                                    </div>
                                  )}
                                </div>
                              ) : finding.cpe ? (
                                <span className="font-mono text-[10px] text-cyber-500 break-all">{finding.cpe}</span>
                              ) : (
                                <span className="text-cyber-500">—</span>
                              )}
                            </td>
                            <td className="py-2 pr-2">
                              {finding.cwe_id ? (
                                <span className="font-mono text-xs text-signal-medium">{finding.cwe_id}</span>
                              ) : (
                                <span className="text-cyber-500">—</span>
                              )}
                            </td>
                            <td className="py-2 pr-2 uppercase">{finding.severity}</td>
                            <td className="py-2 pr-2">{finding.cvss_score ?? "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {!scanDetail.findings.length && <p className="text-cyber-400">No findings recorded.</p>}
                  </div>
                </div>
              </div>
            ) : (
              <p className="mt-4 text-cyber-400">No detail payload available.</p>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
