import { useState } from "react";

import { api } from "../api/client";

export default function ReportsPage() {
  const [scanId, setScanId] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState("");
  const [report, setReport] = useState(null);

  const downloadReport = async () => {
    if (!report?.report_id) {
      return;
    }

    setError("");
    try {
      const response = await api.get(`/api/reports/download/${report.report_id}`, {
        responseType: "blob",
      });

      const blobUrl = window.URL.createObjectURL(new Blob([response.data], { type: "application/pdf" }));
      const tempLink = document.createElement("a");
      tempLink.href = blobUrl;
      tempLink.download = `scan-report-${report.scan_id}.pdf`;
      document.body.appendChild(tempLink);
      tempLink.click();
      tempLink.remove();
      window.URL.revokeObjectURL(blobUrl);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Failed to download report");
    }
  };

  const generateReport = async (event) => {
    event.preventDefault();
    setError("");
    setIsGenerating(true);

    try {
      const response = await api.post(`/api/reports/scan/${scanId}`);
      setReport(response.data);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Failed to generate report");
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <section className="space-y-6">
      <div>
        <h1 className="font-display text-3xl font-bold tracking-[0.1em] text-cyber-100">Reports</h1>
        <p className="panel-subtitle mt-1">Generate and retrieve PDF intelligence reports for completed scans.</p>
      </div>

      <div className="glass-panel rounded-xl p-5">
        <h2 className="font-display text-xl font-semibold tracking-[0.08em] text-cyber-100">Generate Scan Report</h2>
        <form className="mt-4 grid gap-3 md:grid-cols-[1fr_auto]" onSubmit={generateReport}>
          <input
            className="input-base"
            value={scanId}
            onChange={(event) => setScanId(event.target.value)}
            placeholder="Paste completed scan UUID"
            required
          />
          <button type="submit" className="btn-primary" disabled={isGenerating}>
            {isGenerating ? "Generating..." : "Generate PDF"}
          </button>
        </form>

        {error && <p className="mt-3 rounded-md border border-signal-critical/40 bg-signal-critical/20 p-2 text-sm text-red-200">{error}</p>}

        {report && (
          <div className="mt-4 rounded-md border border-cyber-600 bg-cyber-900/70 p-4 text-sm text-cyber-200">
            <p>
              <span className="text-cyber-300">Report ID:</span> {report.report_id}
            </p>
            <p>
              <span className="text-cyber-300">Scan ID:</span> {report.scan_id}
            </p>
            <p>
              <span className="text-cyber-300">Status:</span> {report.status}
            </p>
            <p>
              <span className="text-cyber-300">Generated At:</span> {new Date(report.generated_at).toLocaleString()}
            </p>
            <button type="button" className="btn-secondary mt-3" onClick={downloadReport}>
              Download PDF
            </button>
          </div>
        )}
      </div>
    </section>
  );
}
