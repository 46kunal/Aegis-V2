import { useEffect, useMemo, useState } from "react";

import { api } from "../api/client";

const SCAN_MODES = ["fast", "smart_fast", "medium", "full", "super_full"];
const SCAN_MODE_LABELS = {
  fast: "Fast",
  smart_fast: "Smart Fast",
  medium: "Medium",
  full: "Full",
  super_full: "Super Full",
};
const CRITICALITY_OPTIONS = ["low", "medium", "high", "critical"];
const EXPOSURE_OPTIONS = ["internal", "external", "segmented", "isolated"];
const ASSET_ZONES = ["lab", "internal", "external", "dmz", "infrastructure", "unknown"];
const ZONE_LABELS = {
  lab: "LAB",
  internal: "INTERNAL",
  external: "EXTERNAL",
  dmz: "DMZ",
  infrastructure: "INFRA",
  unknown: "UNKNOWN",
};

const EXPOSURE_COLOR = {
  external:  "text-signal-critical",
  internal:  "text-signal-low",
  segmented: "text-signal-medium",
  isolated:  "text-cyber-400",
};

const RISK_COLOR = (score) => {
  if (score >= 70) return "text-signal-critical font-bold";
  if (score >= 40) return "text-signal-high font-semibold";
  if (score >= 20) return "text-signal-medium";
  return "text-signal-low";
};

function statusClass(status) {
  if (status === "active" || status === "up" || status === "completed") {
    return "text-signal-low";
  }
  if (status === "running" || status === "queued") {
    return "text-signal-medium";
  }
  if (status === "failed" || status === "critical") {
    return "text-signal-critical";
  }
  if (status === "high") {
    return "text-signal-high";
  }
  return "text-cyber-300";
}

export default function AssetsPage() {
  const [assets, setAssets] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [isDiscoveryOpen, setIsDiscoveryOpen] = useState(false);
  const [cidr, setCidr] = useState("192.168.11.0/24");
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [discoveryResult, setDiscoveryResult] = useState(null);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [filters, setFilters] = useState({
    asset_status: "",
    criticality: "",
    asset_type: "",
    discovery_status: "",
    last_scan_status: "",
    managed: "",
    asset_zone: "",
  });
  const [scanModesByAsset, setScanModesByAsset] = useState({});
  const [scanActionMessage, setScanActionMessage] = useState("");
  const [patchingAsset, setPatchingAsset] = useState({});
  const [selectedAssets, setSelectedAssets] = useState(() => new Set());
  const [bulkZone, setBulkZone] = useState("lab");
  const [bulkUpdating, setBulkUpdating] = useState(false);
  const [bulkUpdateMessage, setBulkUpdateMessage] = useState("");

  const loadAssets = async ({ silent = false } = {}) => {
    if (!silent) {
      setLoading(true);
    }
    setError("");

    const params = {
      limit: 100,
      offset: 0,
      search: search || undefined,
      ...Object.fromEntries(Object.entries(filters).filter(([, value]) => Boolean(value))),
    };

    try {
      const response = await api.get("/api/assets", { params });
      setAssets(response.data.items || []);
      setTotal(response.data.total || 0);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Failed to load assets");
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    loadAssets();
  }, [search, filters]);

  useEffect(() => {
    const intervalId = window.setInterval(() => {
      loadAssets({ silent: true });
    }, 15000);

    return () => window.clearInterval(intervalId);
  }, [search, filters]);

  const liveStatusTotals = useMemo(() => {
    let up = 0;
    let down = 0;
    let unknown = 0;

    for (const item of assets) {
      const value = (item.discovery_status || "unknown").toLowerCase();
      if (value === "up") {
        up += 1;
      } else if (value === "down") {
        down += 1;
      } else {
        unknown += 1;
      }
    }

    return { up, down, unknown };
  }, [assets]);

  const discoverAssets = async (event) => {
    event.preventDefault();
    setIsDiscovering(true);
    setError("");

    try {
      const response = await api.post("/api/assets/discover", { cidr });
      setDiscoveryResult(response.data);
      await loadAssets({ silent: true });
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Asset discovery failed");
    } finally {
      setIsDiscovering(false);
    }
  };

  const triggerScan = async (assetId) => {
    setScanActionMessage("");
    setError("");

    try {
      const mode = scanModesByAsset[assetId] || "fast";
      const response = await api.post("/api/scans/start", { asset_id: assetId, mode });
      setScanActionMessage(`Queued ${mode} scan for asset ${assetId}. Task: ${response.data.task_id}`);
      await loadAssets({ silent: true });
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Failed to trigger scan");
    }
  };

  const updateFilter = (key, value) => {
    setFilters((previous) => ({ ...previous, [key]: value }));
  };

  const patchAsset = async (assetId, field, value) => {
    setPatchingAsset((prev) => ({ ...prev, [assetId]: true }));
    try {
      await api.patch(`/api/assets/${assetId}`, { [field]: value });
      await loadAssets({ silent: true });
    } catch (requestError) {
      setError(requestError.response?.data?.detail || `Failed to update ${field}`);
    } finally {
      setPatchingAsset((prev) => ({ ...prev, [assetId]: false }));
    }
  };

  const toggleSelected = (assetId) => {
    setSelectedAssets((prev) => {
      const next = new Set(prev);
      if (next.has(assetId)) {
        next.delete(assetId);
      } else {
        next.add(assetId);
      }
      return next;
    });
  };

  const toggleSelectAll = () => {
    setSelectedAssets((prev) => {
      if (prev.size === assets.length) {
        return new Set();
      }
      return new Set(assets.map((asset) => asset.id));
    });
  };

  const bulkUpdate = async (updates) => {
    if (!selectedAssets.size) {
      setError("Select at least one asset to update.");
      return;
    }
    setBulkUpdating(true);
    setError("");
    setBulkUpdateMessage("");
    try {
      const response = await api.patch("/api/assets/bulk", {
        asset_ids: Array.from(selectedAssets),
        ...updates,
      });
      const updatedCount = response.data?.updated ?? selectedAssets.size;
      setBulkUpdateMessage(`Updated ${updatedCount} asset${updatedCount === 1 ? "" : "s"}.`);
      await loadAssets({ silent: true });
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Bulk update failed");
    } finally {
      setBulkUpdating(false);
    }
  };

  const applyQuickScope = (zone, managedOnly) => {
    setFilters((previous) => ({
      ...previous,
      asset_zone: zone,
      managed: managedOnly ? "true" : "",
    }));
  };

  const clearAllAssets = async () => {
    if (!window.confirm("This will delete ALL discovered assets, scans, and findings. Continue?")) {
      return;
    }
    setError("");
    setScanActionMessage("");
    try {
      const response = await api.delete("/api/assets/clear");
      setScanActionMessage(response.data.message || "Assets cleared");
      await loadAssets();
    } catch (requestError) {
      setError(requestError.response?.data?.detail || "Failed to clear assets");
    }
  };

  return (
    <section className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="font-display text-3xl font-bold tracking-[0.1em] text-cyber-100">Assets</h1>
          <p className="panel-subtitle mt-1">Search and operate on discovered infrastructure with live scan state.</p>
        </div>
        <div className="flex gap-2">
          <button type="button" className="btn-secondary" onClick={() => loadAssets()}>
            Refresh Live
          </button>
          <button type="button" className="btn-secondary" onClick={clearAllAssets}>
            Clear All Assets
          </button>
          <button type="button" className="btn-primary" onClick={() => setIsDiscoveryOpen(true)}>
            Discover Network
          </button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <div className="glass-panel rounded-xl p-4">
          <p className="panel-title">Total Assets</p>
          <p className="mt-2 font-display text-3xl font-bold text-cyber-100">{total}</p>
        </div>
        <div className="glass-panel rounded-xl p-4">
          <p className="panel-title">Live Up</p>
          <p className="mt-2 font-display text-3xl font-bold text-signal-low">{liveStatusTotals.up}</p>
        </div>
        <div className="glass-panel rounded-xl p-4">
          <p className="panel-title">Live Down</p>
          <p className="mt-2 font-display text-3xl font-bold text-signal-critical">{liveStatusTotals.down}</p>
        </div>
        <div className="glass-panel rounded-xl p-4">
          <p className="panel-title">Unknown</p>
          <p className="mt-2 font-display text-3xl font-bold text-cyber-300">{liveStatusTotals.unknown}</p>
        </div>
      </div>

      <div className="glass-panel rounded-xl p-5">
        <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-7">
          <input
            className="input-base xl:col-span-2"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search name, IP, hostname, target"
          />

          <select className="input-base" value={filters.asset_status} onChange={(event) => updateFilter("asset_status", event.target.value)}>
            <option value="">All asset statuses</option>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
            <option value="retired">Retired</option>
          </select>

          <select className="input-base" value={filters.criticality} onChange={(event) => updateFilter("criticality", event.target.value)}>
            <option value="">All criticality</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select className="input-base" value={filters.asset_type} onChange={(event) => updateFilter("asset_type", event.target.value)}>
            <option value="">All types</option>
            <option value="ip">IP</option>
            <option value="host">Host</option>
            <option value="domain">Domain</option>
            <option value="webapp">Web App</option>
            <option value="cloud">Cloud</option>
            <option value="api">API</option>
          </select>

          <select className="input-base" value={filters.discovery_status} onChange={(event) => updateFilter("discovery_status", event.target.value)}>
            <option value="">Any live status</option>
            <option value="up">Up</option>
            <option value="down">Down</option>
            <option value="unknown">Unknown</option>
          </select>

          <select className="input-base" value={filters.last_scan_status} onChange={(event) => updateFilter("last_scan_status", event.target.value)}>
            <option value="">Any scan state</option>
            <option value="queued">Queued</option>
            <option value="running">Running</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
          </select>

          <select className="input-base" value={filters.managed} onChange={(event) => updateFilter("managed", event.target.value)}>
            <option value="">All scopes</option>
            <option value="true">Managed</option>
            <option value="false">Discovered</option>
          </select>

          <select className="input-base" value={filters.asset_zone} onChange={(event) => updateFilter("asset_zone", event.target.value)}>
            <option value="">All zones</option>
            {ASSET_ZONES.map((zone) => (
              <option key={zone} value={zone}>{ZONE_LABELS[zone]}</option>
            ))}
          </select>
        </div>
      </div>

      {scanActionMessage && <p className="rounded-md border border-cyber-400/40 bg-cyber-500/20 p-2 text-sm text-cyber-100">{scanActionMessage}</p>}
      {bulkUpdateMessage && <p className="rounded-md border border-emerald-400/30 bg-emerald-500/10 p-2 text-sm text-emerald-200">{bulkUpdateMessage}</p>}
      {error && <p className="rounded-md border border-signal-critical/40 bg-signal-critical/20 p-2 text-sm text-red-200">{error}</p>}

      <div className="glass-panel rounded-xl p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="panel-title">Asset Scope Management</p>
            <p className="text-xs text-cyber-400">Selected: {selectedAssets.size} asset{selectedAssets.size !== 1 ? "s" : ""}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              className="btn-secondary text-xs"
              onClick={() => applyQuickScope("lab", true)}
            >
              View LAB Only
            </button>
            <button
              type="button"
              className="btn-secondary text-xs"
              onClick={() => applyQuickScope("infrastructure", false)}
            >
              View Infrastructure
            </button>
            <button
              type="button"
              className="btn-secondary text-xs"
              onClick={() => applyQuickScope("", false)}
            >
              View All
            </button>
            <button
              type="button"
              className="btn-secondary text-xs"
              onClick={() => bulkUpdate({ managed: true, topology_visible: true, attack_surface_enabled: true })}
              disabled={bulkUpdating}
            >
              Mark Managed
            </button>
            <button
              type="button"
              className="btn-secondary text-xs"
              onClick={() => bulkUpdate({ managed: false, topology_visible: false, attack_surface_enabled: false })}
              disabled={bulkUpdating}
            >
              Mark Discovered
            </button>
            <div className="flex items-center gap-2 rounded border border-cyber-700 px-2 py-1">
              <select
                className="input-base py-1 text-xs"
                value={bulkZone}
                onChange={(event) => setBulkZone(event.target.value)}
              >
                {ASSET_ZONES.map((zone) => (
                  <option key={zone} value={zone}>{ZONE_LABELS[zone]}</option>
                ))}
              </select>
              <button
                type="button"
                className="btn-secondary text-xs"
                onClick={() => bulkUpdate({ asset_zone: bulkZone })}
                disabled={bulkUpdating}
              >
                Assign Zone
              </button>
            </div>
            <button
              type="button"
              className="btn-secondary text-xs"
              onClick={() => bulkUpdate({
                managed: false,
                asset_zone: "infrastructure",
                topology_visible: false,
                attack_surface_enabled: false,
              })}
              disabled={bulkUpdating}
            >
              Exclude Infrastructure
            </button>
            <button type="button" className="btn-secondary text-xs" onClick={() => setSelectedAssets(new Set())}>
              Deselect All
            </button>
          </div>
        </div>
      </div>

      <div className="glass-panel rounded-xl p-5">
        <h2 className="font-display text-xl font-semibold tracking-[0.08em] text-cyber-100">Asset Inventory</h2>
        {loading ? (
          <p className="mt-3 text-cyber-300">Loading assets...</p>
        ) : (
          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-cyber-400">
                <tr>
                  <th className="pb-2">
                    <input
                      type="checkbox"
                      checked={assets.length > 0 && selectedAssets.size === assets.length}
                      onChange={toggleSelectAll}
                    />
                  </th>
                  <th className="pb-2">Name / Target</th>
                  <th className="pb-2">Scope</th>
                  <th className="pb-2">Type</th>
                  <th className="pb-2">Criticality</th>
                  <th className="pb-2">Exposure</th>
                  <th className="pb-2">Zone</th>
                  <th className="pb-2">Risk</th>
                  <th className="pb-2">Managed</th>
                  <th className="pb-2">Topology</th>
                  <th className="pb-2">Attack</th>
                  <th className="pb-2">Asset Status</th>
                  <th className="pb-2">Live Status</th>
                  <th className="pb-2">Last Scan</th>
                  <th className="pb-2">Trigger Scan</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((asset) => (
                  <tr key={asset.id} className="border-t border-cyber-700/60 align-top">
                    <td className="py-2 pr-3">
                      <input
                        type="checkbox"
                        checked={selectedAssets.has(asset.id)}
                        onChange={() => toggleSelected(asset.id)}
                      />
                    </td>
                    <td className="py-2 pr-3">
                      <p className="font-semibold text-cyber-100">{asset.name}</p>
                      <p className="text-cyber-400">{asset.target}</p>
                      <p className="text-xs text-cyber-500">{asset.hostname || asset.ip_address || "unknown endpoint"}</p>
                      {asset.os_fingerprint && (
                        <p className="mt-0.5 text-xs text-cyber-300">OS: {asset.os_fingerprint}</p>
                      )}
                    </td>
                    <td className="py-2 pr-3">
                      <div className="flex flex-wrap gap-1">
                        {asset.managed ? (
                          <span className="rounded bg-emerald-500/20 px-2 py-0.5 text-[10px] font-semibold text-emerald-300">MANAGED</span>
                        ) : (
                          <span className="rounded bg-cyber-700/60 px-2 py-0.5 text-[10px] font-semibold text-cyber-300">DISCOVERED</span>
                        )}
                        {(asset.asset_zone === "infrastructure" || !asset.topology_visible) && (
                          <span className="rounded bg-slate-600/40 px-2 py-0.5 text-[10px] font-semibold text-slate-200">EXCLUDED</span>
                        )}
                        {asset.asset_zone && (
                          <span className="rounded bg-cyber-800 px-2 py-0.5 text-[10px] font-semibold text-cyber-200">
                            {ZONE_LABELS[asset.asset_zone] || asset.asset_zone.toUpperCase()}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-2 pr-3 uppercase text-cyber-200">{asset.asset_type}</td>
                    <td className="py-2 pr-3">
                      <select
                        className="input-base py-0.5 text-xs uppercase"
                        value={asset.criticality}
                        disabled={patchingAsset[asset.id]}
                        onChange={(e) => patchAsset(asset.id, "criticality", e.target.value)}
                      >
                        {CRITICALITY_OPTIONS.map((c) => (
                          <option key={c} value={c}>{c}</option>
                        ))}
                      </select>
                    </td>
                    <td className="py-2 pr-3">
                      <select
                        className="input-base py-0.5 text-xs uppercase"
                        value={asset.exposure || "internal"}
                        disabled={patchingAsset[asset.id]}
                        onChange={(e) => patchAsset(asset.id, "exposure", e.target.value)}
                      >
                        {EXPOSURE_OPTIONS.map((ex) => (
                          <option key={ex} value={ex}>{ex}</option>
                        ))}
                      </select>
                    </td>
                    <td className="py-2 pr-3">
                      <select
                        className="input-base py-0.5 text-xs uppercase"
                        value={asset.asset_zone || "unknown"}
                        disabled={patchingAsset[asset.id]}
                        onChange={(e) => patchAsset(asset.id, "asset_zone", e.target.value)}
                      >
                        {ASSET_ZONES.map((zone) => (
                          <option key={zone} value={zone}>{ZONE_LABELS[zone]}</option>
                        ))}
                      </select>
                    </td>
                    <td className="py-2 pr-3 text-right font-mono text-sm">
                      {asset.risk_score != null ? (
                        <span className={RISK_COLOR(asset.risk_score)}>{asset.risk_score.toFixed(1)}</span>
                      ) : (
                        <span className="text-cyber-600">—</span>
                      )}
                    </td>
                    <td className="py-2 pr-3">
                      <input
                        type="checkbox"
                        checked={asset.managed}
                        disabled={patchingAsset[asset.id]}
                        onChange={(e) => patchAsset(asset.id, "managed", e.target.checked)}
                      />
                    </td>
                    <td className="py-2 pr-3">
                      <input
                        type="checkbox"
                        checked={asset.topology_visible}
                        disabled={patchingAsset[asset.id]}
                        onChange={(e) => patchAsset(asset.id, "topology_visible", e.target.checked)}
                      />
                    </td>
                    <td className="py-2 pr-3">
                      <input
                        type="checkbox"
                        checked={asset.attack_surface_enabled}
                        disabled={patchingAsset[asset.id]}
                        onChange={(e) => patchAsset(asset.id, "attack_surface_enabled", e.target.checked)}
                      />
                    </td>
                    <td className={`py-2 pr-3 uppercase ${statusClass(asset.status)}`}>{asset.status}</td>
                    <td className={`py-2 pr-3 uppercase ${statusClass(asset.discovery_status)}`}>{asset.discovery_status || "unknown"}</td>
                    <td className="py-2 pr-3">
                      <p className={`uppercase ${statusClass(asset.last_scan_status)}`}>{asset.last_scan_status || "never"}</p>
                      <p className="text-xs text-cyber-400">{asset.last_scan_progress ?? 0}%</p>
                    </td>
                    <td className="py-2 pr-3">
                      <div className="flex min-w-44 gap-2">
                        <select
                          className="input-base py-1"
                          value={scanModesByAsset[asset.id] || "fast"}
                          onChange={(event) =>
                            setScanModesByAsset((previous) => ({
                              ...previous,
                              [asset.id]: event.target.value,
                            }))
                          }
                        >
                          {SCAN_MODES.map((mode) => (
                            <option key={mode} value={mode}>
                              {SCAN_MODE_LABELS[mode] || mode}
                            </option>
                          ))}
                        </select>
                        <button type="button" className="btn-secondary py-1" onClick={() => triggerScan(asset.id)}>
                          Start
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {!loading && assets.length === 0 && <p className="mt-3 text-cyber-400">No assets match current search and filters.</p>}
      </div>

      {isDiscoveryOpen && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-cyber-950/80 p-4">
          <div className="glass-panel w-full max-w-3xl rounded-2xl p-5">
            <div className="flex items-center justify-between gap-3">
              <h2 className="font-display text-xl font-semibold tracking-[0.08em] text-cyber-100">Network Discovery</h2>
              <button type="button" className="btn-secondary" onClick={() => setIsDiscoveryOpen(false)}>
                Close
              </button>
            </div>

            <form className="mt-4 grid gap-3 md:grid-cols-[1fr_auto]" onSubmit={discoverAssets}>
              <input
                className="input-base"
                value={cidr}
                onChange={(event) => setCidr(event.target.value)}
                placeholder="CIDR range, e.g., 10.0.0.0/24"
                required
              />
              <button type="submit" className="btn-primary" disabled={isDiscovering}>
                {isDiscovering ? "Discovering..." : "Run Discovery"}
              </button>
            </form>

            {discoveryResult && (
              <div className="mt-4 space-y-3">
                <div className="rounded-lg border border-cyber-500/40 bg-cyber-900/70 p-4">
                  <div className="grid gap-3 md:grid-cols-3">
                    <div>
                      <p className="text-xs uppercase tracking-wide text-cyber-400">Subnet Scanned</p>
                      <p className="mt-1 font-display text-lg font-bold text-cyber-100">{discoveryResult.cidr}</p>
                    </div>
                    <div>
                      <p className="text-xs uppercase tracking-wide text-cyber-400">Live Hosts Found</p>
                      <p className="mt-1 font-display text-lg font-bold text-signal-low">{discoveryResult.discovered_count}</p>
                    </div>
                    <div>
                      <p className="text-xs uppercase tracking-wide text-cyber-400">Status</p>
                      <p className="mt-1 font-display text-lg font-bold text-cyber-100">
                        {discoveryResult.discovered_count > 0 ? "Discovery Complete" : "No Hosts Found"}
                      </p>
                    </div>
                  </div>
                </div>

                {discoveryResult.devices.length > 0 && (
                  <div className="max-h-72 overflow-y-auto rounded-md border border-cyber-700 p-2">
                    <table className="w-full text-sm">
                      <thead className="text-left text-cyber-400">
                        <tr>
                          <th className="pb-2">IP</th>
                          <th className="pb-2">Hostname</th>
                          <th className="pb-2">MAC</th>
                          <th className="pb-2">Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {discoveryResult.devices.map((device) => (
                          <tr key={`${device.ip}-${device.mac || "unknown"}`} className="border-t border-cyber-700/60">
                            <td className="py-2 pr-2">{device.ip}</td>
                            <td className="py-2 pr-2">{device.hostname || "unknown"}</td>
                            <td className="py-2 pr-2">{device.mac || "unknown"}</td>
                            <td className={`py-2 pr-2 uppercase ${statusClass(device.status)}`}>{device.status}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
