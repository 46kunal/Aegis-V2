import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ReactFlow, {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  useEdgesState,
  useNodesState,
} from "reactflow";
import "reactflow/dist/style.css";

import { api } from "../api/client";

// ---------------------------------------------------------------------------
// Colour helpers
// ---------------------------------------------------------------------------
const riskBucket = (score) => {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  if (score > 0) return "low";
  return "none";
};

const RISK_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  none: "#475569",
};

const riskBorder = (score) => RISK_COLORS[riskBucket(score)];

const isKaliOperator = (data) => {
  const role = (data.role || "").toLowerCase();
  if (data.is_attacker || data.central_node || role === "attacker") return true;
  const fingerprint = [
    data.name,
    data.hostname,
    data.label,
    data.ip,
    data.os_fingerprint,
  ].filter(Boolean).join(" ").toLowerCase();
  return fingerprint.includes("kali");
};

const exposureWeight = {
  external: 1.3,
  segmented: 1.15,
  internal: 1.0,
  isolated: 0.85,
};

const nodeSize = (data) => {
  const ports = data.port_count || 0;
  const vulns = data.finding_count || 0;
  const base = 150;
  const raw = base + ports * 4 + vulns * 6;
  const weighted = raw * (exposureWeight[data.exposure] || 1.0);
  return Math.min(240, Math.max(140, Math.round(weighted)));
};

const RELATIONSHIP_COLORS = {
  trusts:            "#ef4444",
  exposes_database:  "#f97316",
  shares_files:      "#eab308",
  exposes_remote:    "#a855f7",
  exposes_web:       "#3b82f6",
  resolves_names:    "#06b6d4",
  routes_through:    "#6366f1",
  connects_to:       "#475569",
};

// All 8 attack states including Critical Impact
const ATTACK_STATE_COLORS = {
  Untouched:           "#475569",
  Reconnaissance:      "#06b6d4",
  Vulnerable:          "#eab308",
  Exploitable:         "#f97316",
  Compromised:         "#ef4444",
  "Privilege Escalated": "#dc2626",
  Pivoted:             "#a855f7",
  "Critical Impact":   "#ff0055",
};

const ATTACK_STATE_ICONS = {
  Untouched:           "○",
  Reconnaissance:      "◎",
  Vulnerable:          "◈",
  Exploitable:         "◉",
  Compromised:         "✖",
  "Privilege Escalated": "⬆",
  Pivoted:             "⟳",
  "Critical Impact":   "☠",
};

const CONFIDENCE_COLORS = {
  LOW:      "#475569",
  MEDIUM:   "#eab308",
  HIGH:     "#f97316",
  VERIFIED: "#ef4444",
};

const LAYOUT_STORAGE_KEY = "aegis.topology.layout.v2";

const readStoredLayout = () => {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(LAYOUT_STORAGE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
};

const writeStoredLayout = (layout) => {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(LAYOUT_STORAGE_KEY, JSON.stringify(layout));
  } catch {
    // ignore
  }
};

const mergeLayout = (nodes, layout) => (
  nodes.map((node) => (
    layout?.[node.id]
      ? { ...node, position: layout[node.id] }
      : node
  ))
);

// ---------------------------------------------------------------------------
// Custom node
// ---------------------------------------------------------------------------
function AssetNode({ data, selected }) {
  const riskLevel = riskBucket(data.risk_score);
  const operatorNode = isKaliOperator(data);
  const attackState = data.attack_state || "Untouched";
  const stateColor = ATTACK_STATE_COLORS[attackState] || "#475569";
  const isCriticalImpact = attackState === "Critical Impact";
  const isPrivEsc = attackState === "Privilege Escalated";
  const isPivot = attackState === "Pivoted" || data.is_lateral_pivot;
  const borderColor = operatorNode
    ? "#22d3ee"
    : data.is_active_attack
      ? stateColor
      : riskBorder(data.risk_score);
  const size = nodeSize(data);
  const riskLabel = operatorNode ? "OPERATOR" : riskLevel === "none" ? "NO DATA" : riskLevel.toUpperCase();
  const stateIcon = ATTACK_STATE_ICONS[attackState] || "○";

  const glowStyle = isCriticalImpact
    ? `0 0 20px #ff005588, 0 0 40px #ff005533`
    : isPrivEsc
      ? `0 0 16px ${stateColor}88`
      : isPivot && !operatorNode
        ? `0 0 12px ${stateColor}66`
        : operatorNode
          ? `0 0 12px ${borderColor}66`
          : data.is_active_attack
            ? `0 0 10px ${borderColor}55`
            : `0 0 4px ${borderColor}33`;

  return (
    <div
      style={{
        border: `${isCriticalImpact ? 3 : 2}px solid ${borderColor}`,
        boxShadow: selected ? `0 0 18px ${borderColor}99, ${glowStyle}` : glowStyle,
        minWidth: size,
        minHeight: Math.round(size * 0.62),
        outline: isCriticalImpact ? "1px dashed #ff005566" : undefined,
        outlineOffset: "3px",
      }}
      className={`rounded-lg px-3 py-2 text-xs ${
        operatorNode
          ? "bg-cyan-950/60"
          : isCriticalImpact
            ? "bg-red-950/70"
            : isPrivEsc
              ? "bg-red-950/50"
              : data.is_active_attack
                ? "bg-cyber-800"
                : "bg-cyber-900"
      }`}
    >
      <Handle type="target" position={Position.Top}    style={{ background: borderColor }} />

      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate font-semibold text-cyber-100">
            {data.hostname || data.alias || data.name || data.ip || "unknown"}
          </p>
          {data.alias && data.alias !== (data.hostname || data.name) && (
            <p className="truncate text-[10px] text-cyber-300">Alias: {data.alias}</p>
          )}
          <p className="truncate font-mono text-[10px] text-cyber-400">{data.ip || "—"}</p>
        </div>
        <div className="flex gap-1 shrink-0 flex-wrap justify-end">
          {operatorNode && (
            <span className="rounded bg-cyan-400/20 px-1 text-[9px] font-semibold uppercase text-cyan-200">KALI</span>
          )}
          {isCriticalImpact && (
            <span className="rounded bg-red-500/30 px-1 text-[9px] font-bold text-red-200 animate-pulse">IMPACT</span>
          )}
          {isPrivEsc && !isCriticalImpact && (
            <span className="rounded bg-red-900/40 px-1 text-[9px] font-semibold text-red-200">PRIV ESC</span>
          )}
          {isPivot && !operatorNode && !isCriticalImpact && !isPrivEsc && (
            <span className="rounded bg-violet-900/40 px-1 text-[9px] text-violet-200">PIVOT</span>
          )}
          {data.is_gateway && (
            <span className="rounded bg-cyber-600 px-1 text-[9px] uppercase text-cyber-200">GW</span>
          )}
          <span className={`rounded px-1 text-[9px] font-semibold ${operatorNode ? "bg-cyan-400/20 text-cyan-100" : "bg-cyber-800 text-cyber-200"}`}>
            {riskLabel}
          </span>
        </div>
      </div>

      <div className="mt-1 flex flex-wrap gap-1">
        <span
          style={{ backgroundColor: `${stateColor}22`, color: stateColor, borderColor: `${stateColor}44` }}
          className="rounded border px-1 text-[9px] font-semibold uppercase flex items-center gap-0.5"
        >
          <span>{stateIcon}</span>
          <span>{attackState}</span>
        </span>
        {data.confidence && data.confidence !== "LOW" && (
          <span
            style={{ backgroundColor: `${CONFIDENCE_COLORS[data.confidence]}22`, color: CONFIDENCE_COLORS[data.confidence] }}
            className="rounded px-1 text-[9px] font-semibold"
          >
            {data.confidence}
          </span>
        )}
        <span className={`rounded px-1 text-[9px] uppercase ${
          { critical:"bg-red-900/40 text-red-300", high:"bg-orange-900/40 text-orange-300",
            medium:"bg-yellow-900/40 text-yellow-300", low:"bg-cyber-700 text-cyber-400" }[data.criticality] || ""}`}>
          {data.criticality}
        </span>
        <span className={`rounded px-1 text-[9px] uppercase ${
          { external:"bg-red-900/40 text-red-300", internal:"bg-green-900/40 text-green-300",
            segmented:"bg-yellow-900/40 text-yellow-300", isolated:"bg-cyber-800 text-cyber-400" }[data.exposure] || ""}`}>
          {data.exposure}
        </span>
        <span className="rounded bg-cyber-800 px-1 text-[9px] text-cyber-200">Vuln {data.finding_count}</span>
        {data.critical_cve_count > 0 && (
          <span className="rounded bg-red-900/40 px-1 text-[9px] text-red-300">Crit {data.critical_cve_count}</span>
        )}
      </div>

      <div className="mt-1.5 flex items-center justify-between text-[10px]">
        <span className="text-cyber-400">{data.port_count} port{data.port_count !== 1 ? "s" : ""}</span>
        <span style={{ color: borderColor }} className="font-bold">
          {data.risk_score > 0 ? `Risk ${data.risk_score}` : "No scan"}
        </span>
      </div>

      <p className="mt-0.5 truncate text-[9px] text-cyber-500">OS: {data.os_fingerprint || "unknown"}</p>
      <Handle type="source" position={Position.Bottom} style={{ background: borderColor }} />
    </div>
  );
}

function ClusterNode({ data }) {
  return (
    <div className="rounded-lg border border-cyber-600 bg-cyber-900/80 px-3 py-2 text-xs">
      <p className="font-semibold text-cyber-100">{data.label}</p>
      <p className="text-cyber-400">{data.count} assets collapsed</p>
    </div>
  );
}

const nodeTypesExtended = { assetNode: AssetNode, clusterNode: ClusterNode };

// ---------------------------------------------------------------------------
// Node sidebar
// ---------------------------------------------------------------------------
function NodeSidebar({ node, onClose }) {
  if (!node) return null;
  const d = node.data;
  const stateColor = ATTACK_STATE_COLORS[d.attack_state] || "#475569";

  return (
    <div className="absolute right-0 top-0 z-10 h-full w-72 overflow-y-auto border-l border-cyber-700 bg-cyber-950/95 p-4 text-sm">
      <div className="flex items-center justify-between">
        <h3 className="font-display text-base font-bold text-cyber-100">{d.hostname || d.name || d.ip}</h3>
        <button type="button" className="text-cyber-400 hover:text-cyber-100" onClick={onClose}>✕</button>
      </div>

      {d.attack_state && d.attack_state !== "Untouched" && (
        <div
          style={{ backgroundColor: `${stateColor}22`, borderColor: `${stateColor}55`, color: stateColor }}
          className="mt-3 rounded-lg border p-2 text-xs"
        >
          <p className="font-bold uppercase tracking-wide">
            {ATTACK_STATE_ICONS[d.attack_state]} {d.attack_state}
          </p>
          {d.attack_reason && (
            <p className="mt-1 text-[10px] opacity-80">{d.attack_reason}</p>
          )}
          {d.confidence && (
            <p className="mt-1 text-[10px]">
              Confidence: <span style={{ color: CONFIDENCE_COLORS[d.confidence] }}>{d.confidence}</span>
            </p>
          )}
        </div>
      )}

      <dl className="mt-4 space-y-1.5 text-xs">
        {[
          ["Hostname",    d.hostname || "—"],
          ["IP",          d.ip || "—"],
          ["Criticality", d.criticality?.toUpperCase()],
          ["Exposure",    d.exposure?.toUpperCase()],
          ["Risk Score",  d.risk_score > 0 ? d.risk_score : "—"],
          ["Vulnerabilities", d.finding_count],
          ["Critical CVEs", d.critical_cve_count],
          ["KEV",         d.kev_count],
          ["Centrality",  d.centrality],
          ["OS",          d.os_fingerprint || "—"],
          ["Zone",        d.asset_zone?.toUpperCase() || "—"],
          ["Type",        d.is_gateway ? "Gateway" : "Host"],
          ["Lateral Pivot", d.is_lateral_pivot ? "Yes" : "No"],
          ["Chains Hitting", d.affected_by_chains || 0],
          ["Pivot Depth",  d.pivot_depth || 0],
        ].map(([k, v]) => (
          <div key={k} className="flex justify-between gap-2">
            <dt className="text-cyber-400">{k}</dt>
            <dd className="text-right font-mono text-cyber-100 break-all">{String(v ?? "—")}</dd>
          </div>
        ))}
      </dl>

      {d.open_ports?.length > 0 && (
        <div className="mt-3">
          <p className="text-[10px] font-semibold uppercase text-cyber-400">Open Ports</p>
          <div className="mt-1.5 flex flex-wrap gap-1">
            {d.open_ports.map((p) => (
              <span key={p} className="rounded bg-cyber-800 px-1.5 py-0.5 font-mono text-[10px] text-cyber-200">{p}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Attack state legend
// ---------------------------------------------------------------------------
function AttackStateLegend() {
  const [open, setOpen] = useState(false);

  return (
    <div className="relative">
      <button
        type="button"
        className="btn-secondary py-1 text-xs"
        onClick={() => setOpen((v) => !v)}
      >
        Legend {open ? "▲" : "▼"}
      </button>
      {open && (
        <div className="absolute right-0 top-full z-30 mt-1 w-72 rounded-xl border border-cyber-700 bg-cyber-950/98 p-4 shadow-scanner">
          <p className="text-[10px] font-semibold uppercase tracking-wide text-cyber-400 mb-2">Attack States</p>
          <div className="grid grid-cols-1 gap-1.5">
            {Object.entries(ATTACK_STATE_COLORS).map(([state, color]) => (
              <div key={state} className="flex items-center gap-2 text-xs">
                <span
                  style={{ backgroundColor: `${color}33`, borderColor: `${color}77`, color }}
                  className="rounded border px-1.5 py-0.5 font-mono text-[10px] min-w-[22px] text-center font-bold"
                >
                  {ATTACK_STATE_ICONS[state]}
                </span>
                <span className="font-semibold text-cyber-100">{state}</span>
                <span className="ml-auto text-[9px] text-cyber-400">
                  {{
                    Untouched: "Not reached",
                    Reconnaissance: "Scanned/observed",
                    Vulnerable: "CVE detected",
                    Exploitable: "CVE-backed exploit path",
                    Compromised: "Shell/app access",
                    "Privilege Escalated": "Admin/root gained",
                    Pivoted: "Used as jump point",
                    "Critical Impact": "Critical system owned",
                  }[state]}
                </span>
              </div>
            ))}
          </div>
          <p className="mt-3 text-[10px] font-semibold uppercase tracking-wide text-cyber-400 mb-1">Confidence</p>
          <div className="flex flex-wrap gap-2">
            {Object.entries(CONFIDENCE_COLORS).map(([tier, color]) => (
              <span key={tier} style={{ backgroundColor: `${color}22`, color, borderColor: `${color}55` }}
                className="rounded border px-2 py-0.5 text-[10px] font-bold">
                {tier}
              </span>
            ))}
          </div>
          <p className="mt-3 text-[10px] font-semibold uppercase tracking-wide text-cyber-400 mb-1">Edge Relationships</p>
          <div className="grid grid-cols-2 gap-1">
            {Object.entries(RELATIONSHIP_COLORS).map(([rel, color]) => (
              <span key={rel} className="flex items-center gap-1 text-[10px]">
                <span style={{ background: color }} className="inline-block h-2 w-4 rounded shrink-0" />
                <span className="text-cyber-400 truncate">{rel}</span>
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Explainable attack simulation helpers
// ---------------------------------------------------------------------------
const STAGE_CLASSES = {
  Reconnaissance:       "border-cyan-500/40 bg-cyan-500/10 text-cyan-200",
  "Initial Access":     "border-blue-500/40 bg-blue-500/10 text-blue-200",
  Exploitation:         "border-orange-500/40 bg-orange-500/10 text-orange-200",
  "Privilege Escalation": "border-red-500/40 bg-red-500/10 text-red-200",
  "Lateral Movement":   "border-violet-500/40 bg-violet-500/10 text-violet-200",
  Persistence:          "border-amber-500/40 bg-amber-500/10 text-amber-200",
  Impact:               "border-rose-500/40 bg-rose-500/10 text-rose-200",
};

const feasibilityClass = (level) => ({
  EASY: "bg-red-500/20 text-red-200",
  MEDIUM: "bg-yellow-500/20 text-yellow-100",
  HARD: "bg-emerald-500/20 text-emerald-200",
}[level] || "bg-cyber-700 text-cyber-200");

const confidenceClass = (tier) => ({
  VERIFIED: "bg-red-500/20 text-red-200 border-red-500/40",
  HIGH:     "bg-orange-500/20 text-orange-200 border-orange-500/40",
  MEDIUM:   "bg-yellow-500/20 text-yellow-100 border-yellow-500/40",
  LOW:      "bg-cyber-800 text-cyber-400 border-cyber-700",
}[tier] || "bg-cyber-800 text-cyber-400 border-cyber-700");

// ---------------------------------------------------------------------------
// Attack chain components
// ---------------------------------------------------------------------------
function AttackProgression({ chain }) {
  const progression = chain.progression || [];
  if (progression.length === 0) return null;

  return (
    <div className="mt-3 overflow-x-auto pb-1">
      <div className="flex min-w-max items-center gap-2">
        {progression.map((node, index) => (
          <div key={node.id} className="flex items-center gap-2">
            <div className={`max-w-40 rounded-md border px-2 py-1.5 ${STAGE_CLASSES[node.stage] || "border-cyber-700 bg-cyber-900 text-cyber-200"}`}>
              <p className="truncate text-[10px] font-semibold uppercase">{node.stage}</p>
              <p className="truncate text-xs font-semibold text-cyber-100">{node.label}</p>
              {node.technique_id && (
                <p className="mt-0.5 truncate font-mono text-[10px] opacity-80">{node.technique_id}</p>
              )}
            </div>
            {index < progression.length - 1 && (
              <span className="text-cyber-500">→</span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function AttackChainCard({ chain, index, isActive, onSelect }) {
  const cves = chain.exploited_cves || [];
  const stages = chain.stage_details || [];
  const confidence = chain.confidence || "LOW";
  const priority = chain.priority_score || 0;

  return (
    <div
      className={`rounded-lg border p-3 cursor-pointer transition-colors ${
        isActive
          ? "border-cyan-500/60 bg-cyber-800/80"
          : "border-cyber-700 bg-cyber-900/70 hover:border-cyber-500/50"
      }`}
      onClick={onSelect}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="text-[10px] uppercase tracking-wide text-cyber-400">Path {index + 1}</p>
          <p className="text-sm font-semibold text-cyber-100">
            {chain.source_name || chain.source_ip} → {chain.target_name || chain.target_ip}
          </p>
          <p className="mt-0.5 font-mono text-[10px] text-cyber-400">
            {chain.hops} hop{chain.hops === 1 ? "" : "s"} · {chain.target_exposure || "unknown"} · {chain.target_criticality || "unknown"}
          </p>
        </div>
        <div className="flex flex-wrap justify-end gap-1 text-[10px]">
          <span className="rounded bg-cyber-800 px-2 py-1 font-semibold text-cyber-100">
            Risk {Number(chain.risk_score || chain.score || 0).toFixed(1)}
          </span>
          <span className="rounded bg-indigo-500/20 px-2 py-1 font-semibold text-indigo-200">
            P {Number(priority).toFixed(1)}
          </span>
          <span className={`rounded border px-2 py-1 font-semibold text-[10px] ${confidenceClass(confidence)}`}>
            {confidence}
          </span>
          <span className={`rounded px-2 py-1 font-semibold ${feasibilityClass(chain.feasibility)}`}>
            {chain.feasibility}
          </span>
          {chain.kev_count > 0 && (
            <span className="rounded bg-red-500/20 px-2 py-1 font-semibold text-red-200">KEV {chain.kev_count}</span>
          )}
          {chain.has_priv_esc && (
            <span className="rounded bg-red-900/40 px-2 py-1 text-red-300">PRIV ESC</span>
          )}
        </div>
      </div>

      <AttackProgression chain={chain} />

      <div className="mt-3 flex flex-wrap gap-1.5">
        {stages.map((stage) => (
          <span key={stage.stage} className={`rounded border px-2 py-1 text-[10px] ${STAGE_CLASSES[stage.stage] || "border-cyber-700 bg-cyber-900 text-cyber-300"}`}>
            {stage.stage} · {stage.technique_id}
          </span>
        ))}
      </div>

      {cves.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {cves.map((cve) => (
            <span key={cve.cve_id} className="rounded bg-orange-500/15 px-2 py-1 font-mono text-[10px] text-orange-100">
              {cve.cve_id}
              {cve.cvss_score != null ? ` CVSS ${Number(cve.cvss_score).toFixed(1)}` : ""}
              {cve.is_kev ? " KEV" : ""}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function AttackTimeline({ timeline }) {
  if (!timeline?.length) return null;

  return (
    <div className="rounded-lg border border-cyber-700 bg-cyber-900/70 p-3">
      <p className="text-[10px] font-semibold uppercase tracking-wide text-cyber-400">Safe Emulation Timeline</p>
      <div className="mt-2 max-h-48 space-y-2 overflow-y-auto pr-1">
        {timeline.map((event) => (
          <div key={`${event.index}-${event.label}`} className="grid grid-cols-[32px_1fr] gap-2 text-xs">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-cyber-700 font-mono text-[10px] text-cyber-100">
              {event.index}
            </span>
            <div>
              <p className="font-semibold text-cyber-100">{event.label}</p>
              <p className="font-mono text-[10px] text-cyber-400">
                {event.stage} · {event.technique_id || "MITRE"} · SAFE
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Blast radius panel
// ---------------------------------------------------------------------------
function BlastRadiusPanel({ attackResult }) {
  const [expanded, setExpanded] = useState(false);
  if (!attackResult) return null;

  const assets = attackResult.blast_radius_assets || [];
  const services = attackResult.blast_radius_services || [];
  const displayAssets = expanded ? assets : assets.slice(0, 5);

  return (
    <div className="rounded-lg border border-cyber-700 bg-cyber-900/70 p-3">
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-cyber-400">
          Blast Radius — {attackResult.blast_radius_count} assets reachable
        </p>
        <div className="flex gap-2 text-[10px]">
          <span className="rounded bg-red-900/30 px-2 py-0.5 text-red-300">
            {attackResult.blast_radius_critical_count} critical/high
          </span>
          <span className="rounded bg-orange-900/30 px-2 py-0.5 text-orange-300">
            {attackResult.blast_radius_exposed_count} external
          </span>
          <span className="rounded bg-cyber-800 px-2 py-0.5 text-cyber-200">
            Risk Σ {Number(attackResult.blast_radius_risk || 0).toFixed(1)}
          </span>
        </div>
      </div>

      {displayAssets.length > 0 && (
        <div className="mt-2 space-y-1">
          {displayAssets.map((asset) => (
            <div key={asset.asset_id}
              className="flex items-center justify-between rounded border border-cyber-800 bg-cyber-950/50 px-2 py-1 text-[10px]">
              <div className="flex items-center gap-2 min-w-0">
                <span className="font-mono text-cyber-300 truncate">{asset.asset_name || asset.asset_ip}</span>
                <span className="text-cyber-500 shrink-0">{asset.asset_ip}</span>
              </div>
              <div className="flex gap-1 shrink-0">
                <span className={`rounded px-1 ${
                  { critical:"text-red-300", high:"text-orange-300", medium:"text-yellow-300", low:"text-green-300" }[asset.criticality] || "text-cyber-400"
                }`}>{asset.criticality}</span>
                <span className="rounded bg-cyber-800 px-1 text-cyber-200">
                  Risk {Number(asset.risk_score || 0).toFixed(1)}
                </span>
              </div>
            </div>
          ))}
          {assets.length > 5 && (
            <button
              type="button"
              className="mt-1 text-[10px] text-cyber-400 hover:text-cyber-200 w-full text-center"
              onClick={() => setExpanded((v) => !v)}
            >
              {expanded ? "Show less ▲" : `Show all ${assets.length} ▼`}
            </button>
          )}
        </div>
      )}

      {services.length > 0 && (
        <div className="mt-3">
          <p className="text-[10px] font-semibold uppercase tracking-wide text-cyber-400 mb-1">
            Exposed Services After Compromise
          </p>
          <div className="max-h-32 space-y-1 overflow-y-auto">
            {services.slice(0, 12).map((svc, i) => (
              <div key={i}
                className="flex items-center gap-2 rounded border border-cyber-800 bg-cyber-950/50 px-2 py-1 text-[10px]">
                <span className={`shrink-0 font-semibold ${svc.is_kev ? "text-red-300" : "text-cyber-300"}`}>
                  {svc.service || "?"}:{svc.port}
                </span>
                <span className="text-cyber-500 truncate">{svc.asset_name}</span>
                {svc.cve_id && (
                  <span className="ml-auto shrink-0 font-mono text-orange-300">{svc.cve_id}</span>
                )}
                {svc.is_kev && (
                  <span className="shrink-0 rounded bg-red-500/20 px-1 text-red-200">KEV</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Attack progression log
// ---------------------------------------------------------------------------
function ProgressionLogPanel({ log }) {
  if (!log?.length) return null;

  return (
    <div className="rounded-lg border border-cyber-700 bg-cyber-900/70 p-3">
      <p className="text-[10px] font-semibold uppercase tracking-wide text-cyber-400 mb-2">
        Attack Progression Log
      </p>
      <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
        {log.map((entry) => (
          <div key={entry.hop} className="rounded border border-cyber-800 bg-cyber-950/50 p-2 text-[10px]">
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="flex h-5 w-5 items-center justify-center rounded-full bg-cyber-700 font-mono font-bold text-cyber-100 shrink-0">
                  {entry.hop}
                </span>
                <span className="font-semibold text-cyber-100">
                  {entry.from_name} → {entry.to_name}
                </span>
              </div>
              <div className="flex gap-1 shrink-0">
                <span className={`rounded px-1 font-semibold ${
                  { ROOT_ADMIN: "bg-red-500/20 text-red-200", SHELL: "bg-orange-500/20 text-orange-200" }[entry.privilege_level?.replace("/", "_")] || "bg-cyber-800 text-cyber-400"
                }`}>{entry.privilege_level}</span>
                <span className={`rounded px-1 ${feasibilityClass(entry.feasibility)}`}>{entry.feasibility}</span>
              </div>
            </div>
            <div className="mt-1 flex flex-wrap gap-2 text-[10px]">
              {entry.exploited_service && (
                <span className="text-cyber-300">
                  Service: <span className="font-mono text-cyan-300">{entry.exploited_service}{entry.port ? `:${entry.port}` : ""}</span>
                </span>
              )}
              {entry.cve_id && (
                <span className="text-orange-300 font-mono">
                  {entry.cve_id}
                  {entry.cvss_score != null ? ` CVSS${Number(entry.cvss_score).toFixed(1)}` : ""}
                  {entry.is_kev ? " KEV" : ""}
                </span>
              )}
              <span className={`rounded border px-1 text-[9px] ${STAGE_CLASSES[entry.stage] || ""}`}>
                {entry.stage}
              </span>
            </div>
            {entry.pivot_source && entry.hop > 1 && (
              <p className="mt-0.5 text-cyber-500">Pivot from: {entry.pivot_source}</p>
            )}
            {entry.affected_downstream?.length > 0 && (
              <p className="mt-0.5 text-cyber-500">
                Downstream: {entry.affected_downstream.map((a) => a.state).join(", ")} ({entry.affected_downstream.length} assets)
              </p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Attack impact panel
// ---------------------------------------------------------------------------
function AttackImpactPanel({ impact }) {
  if (!impact) return null;

  return (
    <div className="rounded-lg border border-cyber-700 bg-cyber-900/70 p-3">
      <p className="text-[10px] font-semibold uppercase tracking-wide text-cyber-400 mb-2">
        Attack Impact Estimation
      </p>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        {[
          ["Affected Assets",    impact.affected_asset_count,          "text-cyber-100"],
          ["Critical Impact",    impact.critical_impact_count,         "text-red-300"],
          ["Priv Esc Targets",   impact.privilege_escalation_count,    "text-orange-300"],
          ["Critical Systems",   impact.critical_system_exposure,      "text-red-300"],
          ["External Exposed",   impact.externally_exposed_in_blast_radius, "text-orange-300"],
          ["Cumulative Risk Σ",  Number(impact.cumulative_risk_increase || 0).toFixed(1), "text-yellow-300"],
          ["Max Chain Risk",     Number(impact.max_single_chain_risk || 0).toFixed(1), "text-cyber-100"],
          ["KEV Chains",         impact.kev_backed_chains,             "text-red-300"],
          ["High-Conf Chains",   impact.high_confidence_chains,        "text-orange-300"],
        ].map(([label, value, cls]) => (
          <div key={label} className="rounded border border-cyber-800 bg-cyber-950/50 px-2 py-1.5 text-center">
            <p className="text-[9px] uppercase tracking-wide text-cyber-400">{label}</p>
            <p className={`mt-0.5 font-display text-lg font-bold ${cls}`}>{value}</p>
          </div>
        ))}
      </div>
      {impact.exposed_service_categories?.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          <span className="text-[10px] text-cyber-400 mr-1">Exposed categories:</span>
          {impact.exposed_service_categories.map((cat) => (
            <span key={cat} className="rounded bg-orange-500/15 px-2 py-0.5 text-[10px] text-orange-200">{cat}</span>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Replay mode
// ---------------------------------------------------------------------------
function AttackReplayMode({ replaySteps, attackStates, onStepChange }) {
  const [currentStep, setCurrentStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const intervalRef = useRef(null);

  const totalSteps = replaySteps.length;

  useEffect(() => {
    setCurrentStep(0);
    setPlaying(false);
  }, [replaySteps]);

  useEffect(() => {
    onStepChange?.(currentStep);
  }, [currentStep, onStepChange]);

  useEffect(() => {
    if (!playing) {
      clearInterval(intervalRef.current);
      return undefined;
    }
    intervalRef.current = setInterval(() => {
      setCurrentStep((prev) => {
        if (prev >= totalSteps - 1) {
          setPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, 1200);
    return () => clearInterval(intervalRef.current);
  }, [playing, totalSteps]);

  if (!replaySteps.length) return null;

  const step = replaySteps[currentStep] || {};
  const stateColor = ATTACK_STATE_COLORS[step.state_transition?.to] || "#475569";
  const prevColor = ATTACK_STATE_COLORS[step.state_transition?.from] || "#475569";

  return (
    <div className="rounded-lg border border-violet-500/30 bg-violet-500/5 p-3">
      <div className="flex items-center justify-between mb-2">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-violet-300">
          Attack Replay Mode
        </p>
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-cyber-400">
            Step {currentStep + 1} / {totalSteps}
          </span>
          <button
            type="button"
            className="rounded border border-cyber-700 bg-cyber-800 px-2 py-0.5 text-[10px] text-cyber-200 hover:bg-cyber-700"
            onClick={() => setCurrentStep((v) => Math.max(0, v - 1))}
            disabled={currentStep === 0}
          >◄</button>
          <button
            type="button"
            className={`rounded border px-2 py-0.5 text-[10px] font-semibold ${
              playing
                ? "border-violet-500/50 bg-violet-500/20 text-violet-200"
                : "border-cyber-700 bg-cyber-800 text-cyber-200"
            }`}
            onClick={() => setPlaying((v) => !v)}
          >{playing ? "⏸ Pause" : "▶ Play"}</button>
          <button
            type="button"
            className="rounded border border-cyber-700 bg-cyber-800 px-2 py-0.5 text-[10px] text-cyber-200 hover:bg-cyber-700"
            onClick={() => setCurrentStep((v) => Math.min(totalSteps - 1, v + 1))}
            disabled={currentStep >= totalSteps - 1}
          >►</button>
          <button
            type="button"
            className="rounded border border-cyber-700 bg-cyber-800 px-2 py-0.5 text-[10px] text-cyber-400 hover:bg-cyber-700"
            onClick={() => { setCurrentStep(0); setPlaying(false); }}
          >↺</button>
        </div>
      </div>

      {/* Progress bar */}
      <div className="mb-3 h-1.5 w-full rounded-full bg-cyber-800">
        <div
          className="h-1.5 rounded-full bg-violet-500 transition-all"
          style={{ width: `${((currentStep) / Math.max(totalSteps - 1, 1)) * 100}%` }}
        />
      </div>

      {/* Current step detail */}
      <div className="rounded border border-cyber-800 bg-cyber-950/50 p-2">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className={`rounded border px-1.5 py-0.5 text-[10px] font-bold ${STAGE_CLASSES[step.stage] || "border-cyber-700 text-cyber-200"}`}>
              {step.stage}
            </span>
            {step.phase === "terminal" && (
              <span className="rounded bg-red-500/20 px-1.5 py-0.5 text-[10px] text-red-200">FINAL TARGET</span>
            )}
          </div>
          <div className="flex items-center gap-1 text-[10px] shrink-0">
            <span style={{ color: prevColor }} className="font-semibold">{step.state_transition?.from}</span>
            <span className="text-cyber-500">→</span>
            <span style={{ color: stateColor }} className="font-bold">
              {ATTACK_STATE_ICONS[step.state_transition?.to]} {step.state_transition?.to}
            </span>
          </div>
        </div>

        <p className="mt-1.5 text-xs text-cyber-100 font-semibold">{step.asset_name || step.asset_ip}</p>
        <p className="text-[10px] text-cyber-400 mt-0.5">{step.label}</p>

        <div className="mt-2 flex flex-wrap gap-2 text-[10px]">
          {step.technique_id && (
            <span className="font-mono text-cyan-300">{step.technique_id} · {step.technique_name}</span>
          )}
          {step.cve_id && (
            <span className="font-mono text-orange-300">
              {step.cve_id}
              {step.cvss_score != null ? ` CVSS${Number(step.cvss_score).toFixed(1)}` : ""}
              {step.is_kev ? " KEV" : ""}
            </span>
          )}
          {step.service && (
            <span className="text-cyber-300">
              {step.service}{step.port ? `:${step.port}` : ""}
            </span>
          )}
          {step.privilege_level && (
            <span className={`rounded px-1 font-semibold ${
              step.privilege_level === "ROOT/ADMIN"
                ? "bg-red-500/20 text-red-200"
                : step.privilege_level === "SHELL"
                  ? "bg-orange-500/20 text-orange-200"
                  : "bg-cyber-800 text-cyber-400"
            }`}>{step.privilege_level}</span>
          )}
          {step.is_lateral_movement && (
            <span className="rounded bg-violet-500/20 px-1 text-violet-200">LATERAL</span>
          )}
          {step.is_critical_impact && (
            <span className="rounded bg-red-500/30 px-1 text-red-200 font-bold animate-pulse">☠ CRITICAL IMPACT</span>
          )}
        </div>
      </div>

      {/* Step dots */}
      <div className="mt-2 flex flex-wrap gap-1 justify-center">
        {replaySteps.map((s, i) => {
          const sc = ATTACK_STATE_COLORS[s.state_transition?.to] || "#475569";
          return (
            <button
              key={i}
              type="button"
              onClick={() => setCurrentStep(i)}
              style={{
                backgroundColor: i === currentStep ? sc : `${sc}33`,
                borderColor: sc,
                width: i === currentStep ? "10px" : "8px",
                height: i === currentStep ? "10px" : "8px",
              }}
              className="rounded-full border transition-all"
              title={`Step ${i + 1}: ${s.asset_name}`}
            />
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main attack simulation panel
// ---------------------------------------------------------------------------
function AttackSimulationPanel({ nodes, onEmulationUpdate, onReplayStep }) {
  const [attackSource, setAttackSource] = useState("");
  const [attackResult, setAttackResult] = useState(null);
  const [attackLoading, setAttackLoading] = useState(false);
  const [attackError, setAttackError] = useState("");
  const [activeChainIndex, setActiveChainIndex] = useState(0);
  const [activeTab, setActiveTab] = useState("chains"); // chains | blast | log | impact | replay
  const [attackFilters, setAttackFilters] = useState({
    highestRisk: true,
    kevOnly: false,
    internetExposedOnly: false,
    criticalOnly: false,
  });

  const attackableNodes = useMemo(() => (
    (() => {
      const scopedNodes = nodes
        .filter((node) => (
          node.type === "assetNode"
          && node.data?.managed
          && node.data?.asset_zone === "lab"
          && node.data?.attack_surface_enabled !== false
        ));
      const attackers = scopedNodes.filter((node) => isKaliOperator(node.data));
      return attackers.length > 0 ? attackers : scopedNodes;
    })()
      .sort((a, b) => {
        const aAttacker = isKaliOperator(a.data);
        const bAttacker = isKaliOperator(b.data);
        if (aAttacker !== bAttacker) return aAttacker ? -1 : 1;
        return (b.data?.risk_score || 0) - (a.data?.risk_score || 0);
      })
  ), [nodes]);

  useEffect(() => {
    if (attackableNodes.length === 0) {
      setAttackSource("");
      setAttackResult(null);
      onEmulationUpdate?.(null);
      return;
    }
    if (!attackSource || !attackableNodes.some((node) => node.id === attackSource)) {
      setAttackSource(attackableNodes[0].id);
    }
  }, [attackableNodes, attackSource]);

  const runSimulation = useCallback(async () => {
    if (!attackSource) return;
    setAttackLoading(true);
    setAttackError("");
    try {
      const response = await api.get("/api/attack/simulate", {
        params: {
          source: attackSource,
          limit: 6,
          highest_risk_only: attackFilters.highestRisk,
          kev_only: attackFilters.kevOnly,
          internet_exposed_only: attackFilters.internetExposedOnly,
          critical_only: attackFilters.criticalOnly,
          emulation_mode: true,
        },
      });
      setAttackResult(response.data);
      setActiveChainIndex(0);
      onEmulationUpdate?.(response.data);
    } catch (err) {
      setAttackResult(null);
      onEmulationUpdate?.(null);
      setAttackError(err.response?.data?.detail || "Attack simulation failed");
    } finally {
      setAttackLoading(false);
    }
  }, [attackFilters, attackSource, onEmulationUpdate]);

  useEffect(() => {
    if (attackSource) {
      runSimulation();
    }
  }, [attackSource, runSimulation]);

  const updateFilter = (key, value) => {
    setAttackFilters((prev) => ({ ...prev, [key]: value }));
  };

  const chains = attackResult?.attack_chains || [];
  const replaySteps = attackResult?.replay_steps || [];
  const progressionLog = attackResult?.progression_log || [];
  const impactSummary = attackResult?.impact_summary || null;

  const TABS = [
    { key: "chains", label: "Attack Chains" },
    { key: "blast",  label: `Blast Radius (${attackResult?.blast_radius_count ?? 0})` },
    { key: "log",    label: "Progression Log" },
    { key: "impact", label: "Impact" },
    { key: "replay", label: "Replay" },
  ];

  return (
    <div className="glass-panel shrink-0 rounded-xl p-4">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="font-display text-lg font-semibold tracking-[0.08em] text-cyber-100">
            Attack State Intelligence
          </h2>
          <p className="panel-subtitle mt-1">Dynamic cyber terrain: state transitions, blast radius, replay.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select
            className="input-base min-w-64 py-1 text-xs"
            value={attackSource}
            onChange={(e) => setAttackSource(e.target.value)}
            disabled={attackableNodes.length === 0}
          >
            {attackableNodes.length === 0 && <option value="">No attack sources</option>}
            {attackableNodes.map((node) => (
              <option key={node.id} value={node.id}>
                {(node.data?.hostname || node.data?.name || node.data?.ip || "unknown")} · Risk {node.data?.risk_score || 0}
              </option>
            ))}
          </select>
          <button type="button" className="btn-secondary py-1 text-xs" onClick={runSimulation} disabled={!attackSource || attackLoading}>
            {attackLoading ? "Simulating…" : "Simulate"}
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="mt-3 flex flex-wrap gap-2 text-xs">
        {[
          ["highestRisk",        "Highest risk"],
          ["kevOnly",            "KEV only"],
          ["internetExposedOnly","Internet exposed"],
          ["criticalOnly",       "Critical assets"],
        ].map(([key, label]) => (
          <label key={key} className="flex items-center gap-2 rounded border border-cyber-700 px-2 py-1 text-cyber-200">
            <input
              type="checkbox"
              checked={attackFilters[key]}
              onChange={(e) => updateFilter(key, e.target.checked)}
            />
            {label}
          </label>
        ))}
        <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-emerald-200">
          LAB · Managed · Attack Surface
        </span>
      </div>

      {attackError && (
        <p className="mt-3 rounded border border-signal-critical/40 bg-signal-critical/20 p-2 text-sm text-red-200">
          {attackError}
        </p>
      )}

      {attackResult && (
        <>
          {/* KPI row */}
          <div className="mt-3 grid grid-cols-4 gap-2 text-xs sm:grid-cols-4 xl:grid-cols-8">
            {[
              ["Blast Radius",  attackResult.blast_radius_count,                        "text-cyber-100"],
              ["Radius Risk",   Number(attackResult.blast_radius_risk || 0).toFixed(1), "text-yellow-300"],
              ["Lateral Score", Number(attackResult.lateral_score || 0).toFixed(1),     "text-violet-300"],
              ["Priv Esc",      attackResult.priv_esc_count,                            "text-red-300"],
              ["Top Priority",  Number((attackResult.attack_chains?.[0]?.priority_score) || 0).toFixed(1), "text-orange-300"],
              ["Confidence",    attackResult.attack_chains?.[0]?.confidence || "—",     "text-orange-200"],
              ["Critical Impact", attackResult.impact_summary?.critical_impact_count ?? 0, "text-red-400"],
              ["KEV Chains",    attackResult.impact_summary?.kev_backed_chains ?? 0,    "text-red-300"],
            ].map(([label, value, cls]) => (
              <div key={label} className="rounded border border-cyber-700 bg-cyber-900/70 px-2 py-1.5 text-center">
                <p className="text-[9px] uppercase tracking-wide text-cyber-400">{label}</p>
                <p className={`mt-0.5 font-display text-base font-bold ${cls}`}>{value}</p>
              </div>
            ))}
          </div>

          {/* Tabs */}
          <div className="mt-3 flex gap-1 border-b border-cyber-700 text-xs">
            {TABS.map((tab) => (
              <button
                key={tab.key}
                type="button"
                className={`px-3 py-1.5 text-[11px] font-semibold transition-colors ${
                  activeTab === tab.key
                    ? "border-b-2 border-cyan-400 text-cyan-200"
                    : "text-cyber-400 hover:text-cyber-200"
                }`}
                onClick={() => setActiveTab(tab.key)}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="mt-3 space-y-3">
            {activeTab === "chains" && (
              <>
                <AttackTimeline timeline={attackResult.attack_timeline} />
                {chains.length === 0 ? (
                  <div className="rounded-lg border border-cyber-700 bg-cyber-900/70 p-3 text-sm text-cyber-300">
                    No realistic exploit-backed attack path matches the current filters.
                  </div>
                ) : (
                  chains.map((chain, index) => (
                    <AttackChainCard
                      key={`${chain.target_id}-${index}`}
                      chain={chain}
                      index={index}
                      isActive={index === activeChainIndex}
                      onSelect={() => setActiveChainIndex(index)}
                    />
                  ))
                )}
              </>
            )}

            {activeTab === "blast" && (
              <BlastRadiusPanel attackResult={attackResult} />
            )}

            {activeTab === "log" && (
              <ProgressionLogPanel log={progressionLog} />
            )}

            {activeTab === "impact" && (
              <AttackImpactPanel impact={impactSummary} />
            )}

            {activeTab === "replay" && (
              <AttackReplayMode
                replaySteps={replaySteps}
                attackStates={attackResult.attack_states || {}}
                onStepChange={onReplayStep}
              />
            )}
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------
export default function TopologyPage() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [meta, setMeta] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [loading, setLoading]           = useState(true);
  const [rebuilding, setRebuilding]     = useState(false);
  const [error, setError]               = useState("");
  const [filterRel, setFilterRel]       = useState("all");
  const [isGraphFullscreen, setIsGraphFullscreen] = useState(false);
  const [emulationResult, setEmulationResult] = useState(null);
  const [layoutLocked, setLayoutLocked] = useState(true);
  const [replayStepIndex, setReplayStepIndex] = useState(-1);
  const [scopeFilters, setScopeFilters] = useState({
    managedOnly: true,
    vulnerableOnly: false,
    criticalOnly: false,
    assetZone: "lab",
  });
  const [autoRefresh, setAutoRefresh] = useState(true);

  const layoutRef = useRef(readStoredLayout());
  const nodesRef = useRef(nodes);

  useEffect(() => {
    nodesRef.current = nodes;
  }, [nodes]);

  const persistLayout = useCallback((nextNodes) => {
    const layout = nextNodes.reduce((acc, node) => {
      acc[node.id] = node.position;
      return acc;
    }, {});
    layoutRef.current = layout;
    writeStoredLayout(layout);
  }, []);

  const loadGraph = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const params = {
        managed_only: scopeFilters.managedOnly,
        vulnerable_only: scopeFilters.vulnerableOnly,
        critical_only: scopeFilters.criticalOnly,
        asset_zone: scopeFilters.assetZone || undefined,
      };
      const res = await api.get("/api/topology/graph", { params });
      const incomingNodes = res.data.nodes || [];
      const mergedNodes = mergeLayout(incomingNodes, layoutRef.current);
      setNodes(mergedNodes);
      setEdges(res.data.edges || []);
      setMeta(res.data.meta || null);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to load topology");
    } finally {
      setLoading(false);
    }
  }, [scopeFilters, setNodes, setEdges]);

  useEffect(() => { loadGraph(); }, [loadGraph]);

  useEffect(() => {
    if (!autoRefresh) return undefined;
    const intervalId = window.setInterval(() => {
      loadGraph();
    }, 20000);
    return () => window.clearInterval(intervalId);
  }, [autoRefresh, loadGraph]);

  const rebuildTopology = async () => {
    setRebuilding(true);
    try {
      await api.post("/api/topology/rebuild");
      await loadGraph();
    } catch (err) {
      setError(err.response?.data?.detail || "Rebuild failed");
    } finally {
      setRebuilding(false);
    }
  };

  const onNodeClick = useCallback((_, node) => {
    if (node.type === "clusterNode") {
      setSelectedNode(null);
      return;
    }
    setSelectedNode(node);
  }, []);

  const onPaneClick = useCallback(() => {
    setSelectedNode(null);
  }, []);

  const onNodeDragStop = useCallback(() => {
    if (layoutLocked) return;
    persistLayout(nodesRef.current);
  }, [layoutLocked, persistLayout]);

  const allRelationships = [...new Set(edges.map((e) => e.data?.relationship || ""))].filter(Boolean).sort();
  const baseVisibleEdges = filterRel === "all"
    ? edges
    : edges.filter((e) => e.data?.relationship === filterRel);

  // Active steps from the top chain (for edge animation)
  const activeStepByEdge = useMemo(() => {
    const steps = emulationResult?.top_chain?.steps || [];
    return new Map(steps.map((step) => [`${step.from_id}->${step.to_id}`, step]));
  }, [emulationResult]);

  // Active replay step for topology highlighting
  const replayActiveAssetId = useMemo(() => {
    if (replayStepIndex < 0) return null;
    const steps = emulationResult?.replay_steps || [];
    return steps[replayStepIndex]?.asset_id || null;
  }, [replayStepIndex, emulationResult]);

  // Merge attack states into node data (and replay highlighting)
  const displayNodes = useMemo(() => {
    const states = emulationResult?.attack_states || {};
    return nodes.map((node) => {
      const state = states[node.id];
      const isReplayActive = replayActiveAssetId === node.id;
      if (!state) return { ...node, data: { ...node.data, is_replay_active: isReplayActive } };
      return {
        ...node,
        data: {
          ...node.data,
          attack_state: state.state,
          is_active_attack: state.active,
          attack_reason: state.reason,
          confidence: state.confidence,
          is_lateral_pivot: state.is_lateral_pivot,
          is_priv_esc_target: state.is_priv_esc_target,
          is_critical_impact: state.is_critical_impact,
          affected_by_chains: state.affected_by_chains,
          pivot_depth: state.pivot_depth,
          is_replay_active: isReplayActive,
        },
      };
    });
  }, [emulationResult, nodes, replayActiveAssetId]);

  // Edge coloring: distinguish attack steps by relationship type
  const visibleEdges = useMemo(() => (
    baseVisibleEdges.map((edge) => {
      const step = activeStepByEdge.get(`${edge.source}->${edge.target}`);
      if (!step) return edge;

      const rel = step.relationship || edge.data?.relationship || "";
      // Lateral movement → purple; priv esc → crimson; initial access → cyan
      let strokeColor = "#22d3ee";
      if (rel === "trusts") strokeColor = "#dc2626";
      else if (["exposes_remote", "shares_files", "routes_through"].includes(rel)) strokeColor = "#a855f7";
      else if (rel === "exposes_database") strokeColor = "#f97316";

      const cve = step.finding?.cve_id;
      return {
        ...edge,
        animated: true,
        label: cve ? `${edge.label || step.relationship} · ${cve}` : edge.label,
        style: {
          ...(edge.style || {}),
          stroke: strokeColor,
          strokeWidth: 3,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: strokeColor,
          width: 18,
          height: 18,
        },
      };
    })
  ), [activeStepByEdge, baseVisibleEdges]);

  // Replay step: highlight active asset's edges
  const finalEdges = useMemo(() => {
    if (!replayActiveAssetId) return visibleEdges;
    return visibleEdges.map((edge) => {
      if (edge.target !== replayActiveAssetId && edge.source !== replayActiveAssetId) return edge;
      return {
        ...edge,
        animated: true,
        style: { ...(edge.style || {}), stroke: "#f59e0b", strokeWidth: 4 },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#f59e0b", width: 20, height: 20 },
      };
    });
  }, [visibleEdges, replayActiveAssetId]);

  const graphContainerClass = isGraphFullscreen
    ? "fixed inset-4 z-50 overflow-hidden rounded-xl border border-cyber-500 bg-cyber-950 shadow-scanner"
    : "relative h-[62vh] min-h-[560px] overflow-hidden rounded-xl border border-cyber-700 bg-cyber-950";

  return (
    <section className="flex min-h-[calc(100vh-2.5rem)] flex-col space-y-3">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 shrink-0">
        <div>
          <h1 className="font-display text-3xl font-bold tracking-[0.1em] text-cyber-100">
            Digital Twin Topology
          </h1>
          <p className="panel-subtitle mt-1">
            Dynamic attack-state terrain with compromise progression and blast radius.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <select className="input-base py-1 text-xs" value={filterRel}
            onChange={(e) => setFilterRel(e.target.value)}>
            <option value="all">All relationships</option>
            {allRelationships.map((r) => (
              <option key={r} value={r}>{r}</option>
            ))}
          </select>
          <label className="flex items-center gap-2 rounded border border-cyber-700 px-2 py-1 text-xs text-cyber-200">
            <input
              type="checkbox"
              checked={scopeFilters.vulnerableOnly}
              onChange={(e) => setScopeFilters((prev) => ({ ...prev, vulnerableOnly: e.target.checked }))}
            />
            Vulnerable Only
          </label>
          <label className="flex items-center gap-2 rounded border border-cyber-700 px-2 py-1 text-xs text-cyber-200">
            <input
              type="checkbox"
              checked={scopeFilters.criticalOnly}
              onChange={(e) => setScopeFilters((prev) => ({ ...prev, criticalOnly: e.target.checked }))}
            />
            Critical Only
          </label>
          <label className="flex items-center gap-2 rounded border border-cyber-700 px-2 py-1 text-xs text-cyber-200">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            Auto Refresh
          </label>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => setLayoutLocked((current) => !current)}
          >
            {layoutLocked ? "Unlock Layout" : "Lock Layout"}
          </button>
          <button type="button" className="btn-secondary" onClick={loadGraph}>Refresh</button>
          <button type="button" className="btn-primary" onClick={rebuildTopology} disabled={rebuilding}>
            {rebuilding ? "Rebuilding…" : "Rebuild"}
          </button>
          <AttackStateLegend />
        </div>
      </div>

      {error && (
        <p className="shrink-0 rounded border border-signal-critical/40 bg-signal-critical/20 p-2 text-sm text-red-200">
          {error}
        </p>
      )}

      {/* Stats */}
      {meta && (
        <div className="flex shrink-0 flex-wrap gap-3 text-xs">
          {[
            ["Assets",    meta.total_assets],
            ["Edges",     meta.total_edges],
            ["Collapsed", meta.clustered_assets || 0],
          ].map(([k, v]) => (
            <span key={k} className="rounded bg-cyber-800 px-2 py-1 text-cyber-200">
              {k}: <strong>{v}</strong>
            </span>
          ))}
          <span className="rounded bg-cyber-800 px-2 py-1 text-cyber-200">
            Layout: <strong>{layoutLocked ? "Locked" : "Unlocked"}</strong>
          </span>
          {meta.excluded && (
            <span className="rounded bg-cyber-900 px-2 py-1 text-cyber-300">
              Excluded: GW {meta.excluded.gateways || 0} · VMware {meta.excluded.vmware || 0} · NAT {meta.excluded.nat || 0}
            </span>
          )}
          {emulationResult && (
            <>
              <span className="rounded bg-violet-900/40 px-2 py-1 text-violet-200">
                Attack States Active
              </span>
              {emulationResult.impact_summary?.critical_impact_count > 0 && (
                <span className="rounded bg-red-900/50 px-2 py-1 text-red-200 font-semibold animate-pulse">
                  ☠ {emulationResult.impact_summary.critical_impact_count} Critical Impact
                </span>
              )}
            </>
          )}
        </div>
      )}

      <AttackSimulationPanel
        nodes={nodes}
        onEmulationUpdate={setEmulationResult}
        onReplayStep={setReplayStepIndex}
      />

      {/* Graph */}
      <div className={graphContainerClass}>
        <div className="absolute right-3 top-3 z-20 flex gap-2">
          <button
            type="button"
            className="btn-secondary bg-cyber-950/90 px-3 py-1 text-xs"
            onClick={() => setIsGraphFullscreen((current) => !current)}
          >
            {isGraphFullscreen ? "Exit Fullscreen" : "Fullscreen"}
          </button>
        </div>
        {loading ? (
          <div className="flex h-full items-center justify-center text-cyber-400">
            Loading topology…
          </div>
        ) : nodes.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-3 text-cyber-400">
            <p>No topology data. Discover assets and run scans first.</p>
            <button type="button" className="btn-primary" onClick={rebuildTopology}>
              Build Topology
            </button>
          </div>
        ) : (
          <ReactFlow
            nodes={displayNodes}
            edges={finalEdges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            onPaneClick={onPaneClick}
            onNodeDragStop={onNodeDragStop}
            nodeTypes={nodeTypesExtended}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            minZoom={0.05}
            maxZoom={4}
            zoomOnScroll
            zoomOnPinch
            panOnDrag
            nodesDraggable={!layoutLocked}
            nodesConnectable={false}
            onlyRenderVisibleElements
          >
            <Background color="#1e293b" gap={20} />
            <Controls />
            <MiniMap
              nodeColor={(n) => {
                const state = n.data?.attack_state;
                if (state && state !== "Untouched") return ATTACK_STATE_COLORS[state] || riskBorder(n.data?.risk_score || 0);
                return riskBorder(n.data?.risk_score || 0);
              }}
              maskColor="rgba(2,6,23,0.7)"
              style={{ background: "#0f172a" }}
            />
          </ReactFlow>
        )}
        {selectedNode && (
          <NodeSidebar
            node={selectedNode}
            onClose={() => setSelectedNode(null)}
          />
        )}
      </div>
    </section>
  );
}
