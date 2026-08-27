"""Attack graph simulation engine for Aegis V2 Digital Twin.

Core concepts
-------------
Attack simulation starts from a "compromised" or "entry point" asset and
walks the topology graph following directed edges. Each hop uses the
highest-exploitability relationship between any pair of nodes.

Key algorithms
--------------
blast_radius         — BFS descendants from a compromised node
attack_chains        — all simple paths to each reachable target (max 5 hops),
                       ranked by total exploitability score
lateral_movement     — count of unique new nodes reachable from a pivot
privilege_escalation — paths through trust/remote edges to critical assets
top_attack_chains    — network-wide most dangerous attack sequences
"""
from __future__ import annotations

import logging
from uuid import UUID

import networkx as nx
from sqlalchemy.orm import Session

import re

from app.models.asset import Asset, AssetZone
from app.models.finding import Finding, FindingSeverity
from app.models.topology import AssetEdge
from app.services.topology_engine import (
    _augment_attacker_edges,
    _is_gateway,
    _is_kali_asset,
    _select_primary_attacker,
    build_analysis_graph,
    ensure_attacker_asset,
)

logger = logging.getLogger("aegis.attack_engine")

# Relationships that imply high-privilege access on the target
_PRIV_ESC_RELATIONSHIPS = {"trusts", "exposes_remote", "exposes_database"}

_CRITICALITY_MULT = {"critical": 2.0, "high": 1.5, "medium": 1.0, "low": 0.5}
_EXPOSURE_MULT = {"external": 1.3, "segmented": 1.15, "internal": 1.0, "isolated": 0.85}

_STAGE_ORDER = {
    "Reconnaissance": 1,
    "Initial Access": 2,
    "Exploitation": 3,
    "Privilege Escalation": 4,
    "Lateral Movement": 5,
    "Persistence": 6,
    "Impact": 7,
}

_REL_STAGE = {
    "resolves_names": "Reconnaissance",
    "connects_to": "Reconnaissance",
    "exposes_web": "Initial Access",
    "exposes_database": "Exploitation",
    "exposes_remote": "Lateral Movement",
    "shares_files": "Lateral Movement",
    "routes_through": "Lateral Movement",
    "trusts": "Privilege Escalation",
}

_ATTACK_RELATIONSHIPS = {
    "exposes_web",
    "exposes_database",
    "exposes_remote",
    "shares_files",
    "trusts",
}

_REACHABILITY_RELATIONSHIPS = {
    "connects_to",
    "routes_through",
    "resolves_names",
}

_STAGE_TECHNIQUE = {
    "Reconnaissance": ("T1046", "Network Service Discovery"),
    "Initial Access": ("T1190", "Exploit Public-Facing Application"),
    "Exploitation": ("T1210", "Exploitation of Remote Services"),
    "Privilege Escalation": ("T1068", "Exploitation for Privilege Escalation"),
    "Lateral Movement": ("T1021", "Remote Services"),
    "Persistence": ("T1053", "Scheduled Task/Job"),
    "Impact": ("T1485", "Data Destruction"),
}

_PORT_SERVICE_HINTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    139: "SMB",
    443: "HTTPS",
    445: "SMB",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP",
    8443: "HTTPS",
    27017: "MongoDB",
}

_RELATIONSHIP_SERVICE_HINTS = {
    "exposes_web": "Web",
    "exposes_database": "Database",
    "exposes_remote": "Remote Service",
    "shares_files": "File Share",
    "resolves_names": "DNS",
    "trusts": "Trust Service",
    "routes_through": "Routing",
    "connects_to": "Network",
}

_RELATIONSHIP_OUTCOMES = {
    "exposes_web": "Application Access",
    "exposes_database": "Database Access",
    "exposes_remote": "Shell Access",
    "shares_files": "SMB/FTP Access",
    "trusts": "Privileged Session",
    "resolves_names": "Name Discovery",
    "routes_through": "Pivot Route",
    "connects_to": "Reachability Confirmed",
}

_MAX_ATTACK_HOPS = 5

_ATTACK_STATE_RANK = {
    "Untouched": 0,
    "Reconnaissance": 1,
    "Vulnerable": 2,
    "Exploitable": 3,
    "Compromised": 4,
    "Privilege Escalated": 5,
    "Pivoted": 6,
    "Critical Impact": 7,
}

# Confidence tiers for attack chains
_CONFIDENCE_TIERS = ("LOW", "MEDIUM", "HIGH", "VERIFIED")

_SEVERITY_RANK = {
    FindingSeverity.CRITICAL: 4,
    FindingSeverity.HIGH: 3,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 1,
    FindingSeverity.INFO: 0,
}


def _risk_level(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "none"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_graph(database: Session, owner_id: str) -> tuple[nx.DiGraph, list[Asset], dict[str, Asset]]:
    owner_uuid = UUID(owner_id)
    ensure_attacker_asset(database, owner_uuid)
    assets = (
        database.query(Asset)
        .filter(
            Asset.owner_id == owner_uuid,
            Asset.managed.is_(True),
            Asset.attack_surface_enabled.is_(True),
            Asset.asset_zone == AssetZone.LAB,
        )
        .all()
    )
    primary_attacker = _select_primary_attacker(assets)
    if primary_attacker:
        assets = [
            asset for asset in assets
            if not _is_kali_asset(asset) or asset.id == primary_attacker.id
        ]
    asset_ids = {a.id for a in assets}
    db_edges = (
        database.query(AssetEdge)
        .filter(AssetEdge.owner_id == owner_uuid)
        .filter(AssetEdge.source_id.in_(asset_ids), AssetEdge.target_id.in_(asset_ids))
        .all()
    )

    findings_map: dict[str, list[Finding]] = {}
    if assets:
        findings = database.query(Finding).filter(Finding.asset_id.in_([a.id for a in assets])).all()
        for finding in findings:
            findings_map.setdefault(str(finding.asset_id), []).append(finding)

    db_edges = _augment_attacker_edges(assets, db_edges, findings_map)
    g        = build_analysis_graph(assets, db_edges)
    asset_map = {str(a.id): a for a in assets}
    return g, assets, asset_map


def _find_attacker_asset(assets: list[Asset]) -> Asset | None:
    return _select_primary_attacker(assets)


def _resolve_source_id(source_id: str | None, assets: list[Asset], asset_map: dict[str, Asset]) -> str | None:
    attacker = _find_attacker_asset(assets)
    if attacker:
        return str(attacker.id)
    if source_id and source_id in asset_map:
        return source_id
    return source_id


def _path_score(g: nx.DiGraph, path: list[str], asset_map: dict[str, Asset]) -> float:
    """Total exploitability along a path × target criticality/exposure."""
    if len(path) < 2:
        return 0.0
    total = sum(
        g[path[i]][path[i + 1]].get("exploitability", 1.0)
        for i in range(len(path) - 1)
    )
    target = asset_map.get(path[-1])
    if target:
        crit = target.criticality.value if hasattr(target.criticality, "value") else str(target.criticality)
        exposure = target.exposure.value if hasattr(target.exposure, "value") else str(target.exposure)
        total *= _CRITICALITY_MULT.get(crit, 1.0) * _EXPOSURE_MULT.get(exposure, 1.0)
    return round(total, 2)


def _extract_port(label: str) -> int | None:
    if not label:
        return None
    match = re.search(r"port\s+(\d+)", label)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _finding_rank(finding: Finding) -> tuple[int, int, float, float]:
    sev_rank = _SEVERITY_RANK.get(finding.severity, 0)
    cvss = float(finding.cvss_score or 0.0)
    epss = float(finding.epss_score or 0.0)
    kev = 1 if finding.is_kev else 0
    return (kev, sev_rank, cvss, epss)


def _relevant_findings(findings: list[Finding], port: int | None) -> list[Finding]:
    scoped = [f for f in findings if port is None or f.port == port]
    if not scoped:
        return []
    return sorted(scoped, key=_finding_rank, reverse=True)


def _primary_finding(findings: list[Finding], port: int | None) -> Finding | None:
    scoped = _relevant_findings(findings, port)
    return scoped[0] if scoped else None


def _finding_cvss(finding: Finding | None) -> float:
    return float(finding.cvss_score or 0.0) if finding else 0.0


def _finding_epss(finding: Finding | None) -> float:
    return float(finding.epss_score or 0.0) if finding else 0.0


def _asset_value(asset: Asset | None, attr: str, default: str = "") -> str:
    if not asset:
        return default
    value = getattr(asset, attr, default)
    if hasattr(value, "value"):
        return value.value
    return str(value) if value is not None else default


def _service_name(finding: Finding | None, relationship: str, port: int | None) -> str:
    service = ""
    if finding:
        service = (
            finding.normalized_service
            or finding.raw_service
            or finding.detected_product
            or ""
        )
    if not service and port is not None:
        service = _PORT_SERVICE_HINTS.get(port, "")
    if not service:
        service = _RELATIONSHIP_SERVICE_HINTS.get(relationship, "Service")
    return service.upper() if service.lower() in {"ftp", "ssh", "smb", "dns", "rdp", "vnc", "http", "https"} else service


def _product_version(finding: Finding | None) -> str | None:
    if not finding:
        return None
    product = finding.detected_product or finding.normalized_service or finding.raw_service
    version = finding.detected_version or finding.extracted_version
    if product and version:
        return f"{product} {version}"
    return product or None


def _is_privilege_escalation_step(relationship: str, finding: Finding | None) -> bool:
    cvss = _finding_cvss(finding)
    severity = finding.severity.value if finding and hasattr(finding.severity, "value") else (
        str(finding.severity) if finding and finding.severity else ""
    )
    return (
        relationship == "trusts"
        or bool(finding and finding.is_kev and cvss >= 8.0)
        or bool(finding and severity == "critical" and cvss >= 8.0)
    )


def _stages_for_step(
    relationship: str,
    target: Asset | None,
    finding: Finding | None,
    hop_index: int,
) -> list[str]:
    stages: list[str] = []

    if relationship in _REACHABILITY_RELATIONSHIPS or finding or relationship in _ATTACK_RELATIONSHIPS:
        stages.append("Reconnaissance")

    if relationship in _ATTACK_RELATIONSHIPS:
        stages.append("Initial Access" if hop_index == 0 else "Lateral Movement")

    if finding and (finding.cve_id or finding.cvss_score is not None):
        stages.append("Exploitation")

    if _is_privilege_escalation_step(relationship, finding):
        stages.append("Privilege Escalation")

    if not stages:
        stages.append(_REL_STAGE.get(relationship, "Exploitation"))

    # Preserve order and remove duplicates.
    seen: set[str] = set()
    ordered: list[str] = []
    for stage in sorted(stages, key=lambda s: _STAGE_ORDER.get(s, 99)):
        if stage not in seen:
            ordered.append(stage)
            seen.add(stage)

    if relationship == "exposes_web" and target and _asset_value(target, "exposure") == "external":
        if "Initial Access" not in seen:
            ordered.append("Initial Access")

    return ordered


def _primary_stage(stages: list[str]) -> str:
    for stage in ("Initial Access", "Exploitation", "Privilege Escalation", "Lateral Movement"):
        if stage in stages:
            return stage
    return stages[0] if stages else "Reconnaissance"


def _feasibility(exploitability: float, finding: Finding | None) -> str:
    if finding and finding.is_kev:
        return "EASY"
    cvss = float(finding.cvss_score or 0.0) if finding else 0.0
    epss = float(finding.epss_score or 0.0) if finding else 0.0
    if exploitability >= 7.0 or cvss >= 8.0 or epss >= 0.4:
        return "EASY"
    if exploitability >= 4.0 or cvss >= 6.0 or epss >= 0.2:
        return "MEDIUM"
    return "HARD"


def _finding_payload(finding: Finding | None) -> dict:
    if not finding:
        return {
            "cve_id": None,
            "cwe_id": None,
            "cvss_score": None,
            "cvss_vector": None,
            "epss_score": None,
            "severity": None,
            "is_kev": False,
            "service": None,
            "product": None,
            "version": None,
            "product_version": None,
            "port": None,
            "protocol": None,
            "title": None,
        }
    service = finding.normalized_service or finding.detected_product or finding.raw_service or ""
    product_version = _product_version(finding)
    return {
        "cve_id": finding.cve_id,
        "cwe_id": finding.cwe_id,
        "cvss_score": float(finding.cvss_score or 0.0) if finding.cvss_score is not None else None,
        "cvss_vector": finding.cvss_vector,
        "epss_score": float(finding.epss_score or 0.0) if finding.epss_score is not None else None,
        "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
        "is_kev": bool(finding.is_kev),
        "service": service or None,
        "product": finding.detected_product,
        "version": finding.detected_version or finding.extracted_version,
        "product_version": product_version,
        "port": finding.port,
        "protocol": finding.protocol,
        "title": finding.title,
    }


def _step_explanation(
    stages: list[str],
    relationship: str,
    finding: Finding | None,
    target: Asset | None,
    service: str,
    port: int | None,
) -> str:
    target_name = target.name if target else "target"
    target_exposure = _asset_value(target, "exposure")
    target_criticality = _asset_value(target, "criticality")
    location = f" port {port}" if port is not None else ""
    service_phrase = f"{service}{location}" if service else relationship.replace("_", " ")

    parts = [f"{' / '.join(stages)} via {service_phrase} on {target_name}"]
    if finding and finding.cve_id:
        metrics = []
        if finding.cvss_score is not None:
            metrics.append(f"CVSS {float(finding.cvss_score):.1f}")
        if finding.epss_score is not None:
            metrics.append(f"EPSS {float(finding.epss_score):.3f}")
        if finding.is_kev:
            metrics.append("CISA KEV")
        metric_text = f" ({', '.join(metrics)})" if metrics else ""
        parts.append(f"exploits {finding.cve_id}{metric_text}")
    if target_exposure or target_criticality:
        context = " / ".join([p for p in (target_exposure, target_criticality) if p])
        parts.append(f"target context: {context}")
    return "; ".join(parts)


def _build_step(
    g: nx.DiGraph,
    src: str,
    tgt: str,
    asset_map: dict[str, Asset],
    findings_map: dict[str, list[Finding]],
    hop_index: int = 0,
) -> dict:
    edge_data  = g[src][tgt] if g.has_edge(src, tgt) else {}
    src_asset  = asset_map.get(src)
    tgt_asset  = asset_map.get(tgt)
    relationship = edge_data.get("relationship", "unknown")
    label = edge_data.get("label", "")
    edge_meta = edge_data.get("meta") or {}
    port = edge_meta.get("port") or _extract_port(label)
    findings = findings_map.get(tgt, [])
    relevant_findings = (
        _relevant_findings(findings, port)
        if port is not None or relationship in _ATTACK_RELATIONSHIPS
        else []
    )
    primary = relevant_findings[0] if relevant_findings else None
    service = _service_name(primary, relationship, port)
    product_version = _product_version(primary)
    stages = _stages_for_step(relationship, tgt_asset, primary, hop_index)
    stage = _primary_stage(stages)
    technique_id = edge_data.get("technique_id") or _STAGE_TECHNIQUE.get(stage, ("", ""))[0]
    technique_name = edge_data.get("technique_name") or _STAGE_TECHNIQUE.get(stage, ("", ""))[1]
    exploitability = round(edge_data.get("exploitability", 1.0), 2)
    feasibility = _feasibility(exploitability, primary)
    explanation = _step_explanation(stages, relationship, primary, tgt_asset, service, port)
    finding_payload = _finding_payload(primary)
    cve_payloads = [_finding_payload(f) for f in relevant_findings if f.cve_id][:3]
    is_priv_esc = _is_privilege_escalation_step(relationship, primary)
    is_attack_step = relationship in _ATTACK_RELATIONSHIPS or bool(primary and primary.cve_id)
    action = f"{service} Enumeration" if service else "Service Enumeration"
    outcome = _RELATIONSHIP_OUTCOMES.get(relationship, "Access Path")
    if primary and primary.cve_id and relationship in {"exposes_remote", "trusts"}:
        outcome = "Shell Access"
    elif primary and primary.cve_id and relationship == "exposes_web":
        outcome = "Application Compromise"
    elif primary and primary.cve_id and relationship == "shares_files":
        outcome = "File Share Pivot"

    return {
        "from_id":        src,
        "to_id":          tgt,
        "from_ip":        src_asset.ip_address or src_asset.target if src_asset else src,
        "to_ip":          tgt_asset.ip_address or tgt_asset.target if tgt_asset else tgt,
        "from_name":      src_asset.name if src_asset else src,
        "to_name":        tgt_asset.name if tgt_asset else tgt,
        "relationship":   relationship,
        "technique_id":   technique_id,
        "technique_name": technique_name,
        "mitre":          [
            {
                "stage": stage_name,
                "technique_id": _STAGE_TECHNIQUE.get(stage_name, ("", ""))[0],
                "technique_name": _STAGE_TECHNIQUE.get(stage_name, ("", ""))[1],
            }
            for stage_name in stages
        ],
        "exploitability": exploitability,
        "label":          label,
        "is_priv_esc":    is_priv_esc,
        "is_attack_step": is_attack_step,
        "is_reachability_step": relationship in _REACHABILITY_RELATIONSHIPS and not is_attack_step,
        "stage":          stage,
        "stages":         stages,
        "stage_order":    _STAGE_ORDER.get(stage, 0),
        "feasibility":    feasibility,
        "explanation":    explanation,
        "finding":        finding_payload,
        "cves":           cve_payloads,
        "port":           port,
        "service":        service,
        "product_version": product_version,
        "attack_action":  action,
        "outcome":        outcome,
    }


def _step_risk(step: dict, target: Asset | None) -> float:
    finding = step.get("finding") or {}
    cvss = float(finding.get("cvss_score") or 0.0)
    epss = float(finding.get("epss_score") or 0.0)
    kev_bonus = 12.0 if finding.get("is_kev") else 0.0
    exploitability = float(step.get("exploitability") or 0.0)
    attack_bonus = 8.0 if step.get("is_attack_step") else 0.0
    port_bonus = 4.0 if step.get("port") else 0.0

    crit = _asset_value(target, "criticality")
    exposure = _asset_value(target, "exposure")
    crit_bonus = {"critical": 16.0, "high": 10.0, "medium": 5.0, "low": 1.0}.get(crit, 0.0)
    exposure_bonus = {"external": 12.0, "segmented": 7.0, "internal": 4.0, "isolated": -4.0}.get(exposure, 0.0)

    return max(0.0, exploitability * 4.0 + cvss * 2.0 + epss * 18.0 + kev_bonus + attack_bonus + port_bonus + crit_bonus + exposure_bonus)


def _attack_path_score(steps: list[dict], target: Asset | None) -> float:
    if not steps:
        return 0.0

    step_scores = [_step_risk(step, target) for step in steps]
    mean_step_score = sum(step_scores) / len(step_scores)
    hop_pressure = min(12.0, max(0, len(steps) - 1) * 3.0)
    target_risk = float(getattr(target, "risk_score", 0.0) or 0.0) * 0.25 if target else 0.0
    score = mean_step_score + hop_pressure + target_risk
    return round(min(score, 100.0), 2)


def _chain_has_exploit_context(steps: list[dict]) -> bool:
    if not steps:
        return False
    if not any(step.get("is_attack_step") for step in steps):
        return False

    terminal = steps[-1]
    if terminal.get("is_reachability_step") and not terminal.get("port"):
        return False

    return any(
        step.get("port")
        or step.get("service")
        or step.get("finding", {}).get("cve_id")
        or step.get("relationship") in _ATTACK_RELATIONSHIPS
        for step in steps
    )


def _stage_detail(stage: str, evidence: list[str], inferred: bool = False) -> dict:
    technique_id, technique_name = _STAGE_TECHNIQUE.get(stage, ("", ""))
    return {
        "stage": stage,
        "order": _STAGE_ORDER.get(stage, 99),
        "technique_id": technique_id,
        "technique_name": technique_name,
        "evidence": evidence[:4],
        "inferred": inferred,
    }


def _build_stage_details(steps: list[dict], target: Asset | None) -> list[dict]:
    evidence_by_stage: dict[str, list[str]] = {}
    inferred: set[str] = set()

    for step in steps:
        for stage in step.get("stages", []):
            evidence = step.get("finding", {}).get("cve_id") or step.get("attack_action") or step.get("relationship")
            if step.get("to_name"):
                evidence = f"{evidence} on {step['to_name']}"
            evidence_by_stage.setdefault(stage, []).append(evidence)

    if any(step.get("outcome") in {"Shell Access", "Privileged Session", "Application Compromise"} for step in steps):
        evidence_by_stage.setdefault("Persistence", []).append("Compromised service could support post-access persistence")
        inferred.add("Persistence")

    target_criticality = _asset_value(target, "criticality")
    if target_criticality in {"critical", "high"}:
        evidence_by_stage.setdefault("Impact", []).append(f"{target.name if target else 'Target'} is {target_criticality} criticality")
        inferred.add("Impact")

    return [
        _stage_detail(stage, evidence_by_stage[stage], stage in inferred)
        for stage in sorted(evidence_by_stage, key=lambda s: _STAGE_ORDER.get(s, 99))
    ]


def _progression_node(node_id: str, label: str, node_type: str, stage: str, meta: dict | None = None) -> dict:
    technique_id, technique_name = _STAGE_TECHNIQUE.get(stage, ("", ""))
    return {
        "id": node_id,
        "label": label,
        "type": node_type,
        "stage": stage,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "meta": meta or {},
    }


def _build_progression(source_asset: Asset | None, steps: list[dict]) -> list[dict]:
    nodes: list[dict] = []
    source_label = source_asset.name if source_asset else "Source"
    source_ip = (source_asset.ip_address or source_asset.target) if source_asset else ""
    nodes.append(_progression_node("source", source_label, "asset", "Reconnaissance", {"ip": source_ip}))

    for index, step in enumerate(steps):
        prefix = f"step-{index}"
        if step.get("port") or step.get("service"):
            nodes.append(_progression_node(
                f"{prefix}-enum",
                step.get("attack_action") or "Service Enumeration",
                "action",
                "Reconnaissance",
                {"port": step.get("port"), "service": step.get("service")},
            ))

        product = step.get("product_version")
        if product:
            nodes.append(_progression_node(
                f"{prefix}-service",
                product,
                "service",
                "Reconnaissance",
                {"service": step.get("service"), "port": step.get("port")},
            ))

        cve_id = step.get("finding", {}).get("cve_id")
        if cve_id:
            nodes.append(_progression_node(
                f"{prefix}-cve",
                cve_id,
                "cve",
                "Exploitation",
                {
                    "cvss_score": step.get("finding", {}).get("cvss_score"),
                    "epss_score": step.get("finding", {}).get("epss_score"),
                    "is_kev": step.get("finding", {}).get("is_kev"),
                },
            ))

        nodes.append(_progression_node(
            f"{prefix}-outcome",
            step.get("outcome") or "Access",
            "outcome",
            step.get("stage") or "Exploitation",
            {"feasibility": step.get("feasibility"), "relationship": step.get("relationship")},
        ))
        nodes.append(_progression_node(
            f"{prefix}-asset",
            step.get("to_name") or step.get("to_ip") or "Target",
            "asset",
            "Lateral Movement" if index < len(steps) - 1 else "Impact",
            {"ip": step.get("to_ip")},
        ))

    compacted: list[dict] = []
    for node in nodes:
        if compacted and compacted[-1]["label"] == node["label"] and compacted[-1]["type"] == node["type"]:
            continue
        compacted.append(node)
    return compacted[:16]


def _chain_feasibility(steps: list[dict]) -> str:
    feasibility_rank = {"EASY": 1, "MEDIUM": 2, "HARD": 3}
    chain_feasibility = "EASY"
    for step in steps:
        step_level = step.get("feasibility", "MEDIUM")
        if feasibility_rank.get(step_level, 2) > feasibility_rank.get(chain_feasibility, 1):
            chain_feasibility = step_level
    return chain_feasibility


def _chain_payload(
    source_id: str,
    target_id: str,
    path: list[str],
    steps: list[dict],
    score: float,
    asset_map: dict[str, Asset],
) -> dict:
    source_asset = asset_map.get(source_id)
    target_asset = asset_map.get(target_id)
    tgt_crit = _asset_value(target_asset, "criticality")
    target_exposure = _asset_value(target_asset, "exposure")
    stage_details = _build_stage_details(steps, target_asset)
    stage_sequence = [detail["stage"] for detail in stage_details]
    kev_count = sum(1 for s in steps if s.get("finding", {}).get("is_kev"))
    exploited_cves = []
    for step in steps:
        for cve in step.get("cves") or []:
            if cve.get("cve_id") and cve["cve_id"] not in {item["cve_id"] for item in exploited_cves}:
                exploited_cves.append(cve)
    critical_cve_count = sum(1 for cve in exploited_cves if cve.get("severity") == "critical")

    chain_feasibility = _chain_feasibility(steps)
    has_priv_esc = any(s["is_priv_esc"] for s in steps)

    # Build partial chain to compute confidence (priority_score needs blast_radius, computed later)
    partial_chain = {
        "steps": steps,
        "exploited_cves": exploited_cves,
        "kev_count": kev_count,
        "feasibility": chain_feasibility,
        "has_priv_esc": has_priv_esc,
        "target_criticality": tgt_crit,
        "target_exposure": target_exposure,
        "hops": len(path) - 1,
    }
    confidence = _compute_confidence(partial_chain)

    return {
        "source_id":    source_id,
        "source_ip":    source_asset.ip_address or source_asset.target if source_asset else source_id,
        "source_name":  source_asset.name if source_asset else source_id,
        "target_id":    target_id,
        "target_ip":    target_asset.ip_address or target_asset.target if target_asset else target_id,
        "target_name":  target_asset.name if target_asset else target_id,
        "target_criticality": tgt_crit,
        "target_exposure": target_exposure,
        "path":         path,
        "steps":        steps,
        "progression":  _build_progression(source_asset, steps),
        "stage_details": stage_details,
        "stage_sequence": stage_sequence,
        "hops":         len(path) - 1,
        "risk_score":   score,
        "score":        score,
        "risk_level":   _risk_level(score),
        "feasibility":  chain_feasibility,
        "confidence":   confidence,
        "priority_score": 0.0,  # Computed post-blast-radius in simulate_from
        "kev_count":    kev_count,
        "critical_cve_count": critical_cve_count,
        "exploited_cves": exploited_cves,
        "has_priv_esc": has_priv_esc,
        "blast_radius_hint": {
            "criticality": tgt_crit,
            "exposure": target_exposure,
            "asset_risk_score": round(target_asset.risk_score or 0.0, 2) if target_asset else 0.0,
        },
    }


def _raise_state(current: str, candidate: str) -> str:
    if _ATTACK_STATE_RANK.get(candidate, 0) > _ATTACK_STATE_RANK.get(current, 0):
        return candidate
    return current


def _state_from_step(step: dict, is_terminal: bool = False, target_criticality: str = "") -> str:
    if step.get("is_priv_esc") and is_terminal and target_criticality in {"critical", "high"}:
        return "Critical Impact"
    if step.get("is_priv_esc"):
        return "Privilege Escalated"
    if step.get("outcome") in {"Shell Access", "Application Compromise", "File Share Pivot", "Privileged Session"}:
        if is_terminal and target_criticality in {"critical", "high"}:
            return "Critical Impact"
        return "Compromised"
    if step.get("finding", {}).get("cve_id"):
        return "Exploitable"
    if step.get("finding", {}).get("severity"):
        return "Vulnerable"
    return "Reconnaissance"


def _build_attack_states(
    assets: list[Asset],
    chains: list[dict],
    source_id: str,
    asset_map: dict[str, Asset] | None = None,
) -> dict[str, dict]:
    states: dict[str, dict] = {}
    for asset in assets:
        aid = str(asset.id)
        is_attacker = _is_kali_asset(asset)
        states[aid] = {
            "state": "Untouched",
            "role": "ATTACKER" if is_attacker else "TARGET",
            "active": False,
            "reason": "No emulated attack activity reached this asset",
            "confidence": "LOW",
            "is_lateral_pivot": False,
            "is_priv_esc_target": False,
            "is_critical_impact": False,
            "affected_by_chains": 0,
            "pivot_depth": 0,
        }

    if source_id in states:
        states[source_id]["state"] = "Pivoted"
        states[source_id]["active"] = True
        states[source_id]["reason"] = "Kali root attack source"
        states[source_id]["confidence"] = "VERIFIED"
        states[source_id]["is_lateral_pivot"] = True

    # Track which chains touch each asset
    chain_touch_count: dict[str, int] = {}

    for chain in chains:
        path = chain.get("path") or []
        steps = chain.get("steps") or []
        chain_confidence = chain.get("confidence", "LOW")

        for index, step in enumerate(steps):
            to_id = step.get("to_id")
            if not to_id or to_id not in states:
                continue
            is_terminal = (index == len(steps) - 1)
            target_asset = (asset_map or {}).get(to_id)
            target_crit = _asset_value(target_asset, "criticality") if target_asset else ""

            candidate = _state_from_step(step, is_terminal=is_terminal, target_criticality=target_crit)
            # Non-terminal compromised/priv-esc assets become pivot points
            if not is_terminal and candidate in {"Compromised", "Privilege Escalated", "Critical Impact"}:
                candidate = "Pivoted"

            states[to_id]["state"] = _raise_state(states[to_id]["state"], candidate)
            states[to_id]["active"] = True
            states[to_id]["reason"] = (
                step.get("explanation") or step.get("attack_action") or "Safe emulation reached asset"
            )
            # Raise confidence if this chain has higher certainty
            if _CONFIDENCE_TIERS.index(chain_confidence) > _CONFIDENCE_TIERS.index(states[to_id]["confidence"]):
                states[to_id]["confidence"] = chain_confidence
            if step.get("is_priv_esc"):
                states[to_id]["is_priv_esc_target"] = True
            if candidate == "Critical Impact":
                states[to_id]["is_critical_impact"] = True
            chain_touch_count[to_id] = chain_touch_count.get(to_id, 0) + 1

        # Intermediate nodes become pivot sources
        for depth, path_asset_id in enumerate(path[1:-1], start=1):
            if path_asset_id in states:
                states[path_asset_id]["state"] = _raise_state(states[path_asset_id]["state"], "Pivoted")
                states[path_asset_id]["active"] = True
                states[path_asset_id]["is_lateral_pivot"] = True
                states[path_asset_id]["pivot_depth"] = max(states[path_asset_id]["pivot_depth"], depth)

    for aid, count in chain_touch_count.items():
        if aid in states:
            states[aid]["affected_by_chains"] = count

    return states


def _timeline_event(index: int, stage: str, label: str, asset_id: str | None = None, meta: dict | None = None) -> dict:
    technique_id, technique_name = _STAGE_TECHNIQUE.get(stage, ("", ""))
    return {
        "index": index,
        "stage": stage,
        "label": label,
        "asset_id": asset_id,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "safe_mode": True,
        "meta": meta or {},
    }


def _build_attack_timeline(chain: dict | None) -> list[dict]:
    if not chain:
        return []

    events = [
        _timeline_event(
            0,
            "Reconnaissance",
            f"{chain.get('source_name') or chain.get('source_ip')} established as Kali attack origin",
            chain.get("source_id"),
        )
    ]

    event_index = 1
    for step in chain.get("steps", []):
        if step.get("attack_action"):
            events.append(_timeline_event(
                event_index,
                "Reconnaissance",
                f"{step['attack_action']} against {step.get('to_name') or step.get('to_ip')}",
                step.get("to_id"),
                {"port": step.get("port"), "service": step.get("service")},
            ))
            event_index += 1

        finding = step.get("finding") or {}
        if finding.get("cve_id"):
            events.append(_timeline_event(
                event_index,
                "Exploitation",
                f"Validated exploitability for {finding['cve_id']} without payload execution",
                step.get("to_id"),
                {
                    "cvss_score": finding.get("cvss_score"),
                    "epss_score": finding.get("epss_score"),
                    "is_kev": finding.get("is_kev"),
                },
            ))
            event_index += 1

        events.append(_timeline_event(
            event_index,
            step.get("stage") or "Lateral Movement",
            f"Safe emulation outcome: {step.get('outcome')} on {step.get('to_name') or step.get('to_ip')}",
            step.get("to_id"),
            {"feasibility": step.get("feasibility"), "relationship": step.get("relationship")},
        ))
        event_index += 1

        if step.get("is_priv_esc"):
            events.append(_timeline_event(
                event_index,
                "Privilege Escalation",
                f"Privilege escalation condition identified on {step.get('to_name') or step.get('to_ip')}",
                step.get("to_id"),
            ))
            event_index += 1

    return events


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------

def _compute_confidence(chain: dict) -> str:
    """Compute attack confidence tier: LOW | MEDIUM | HIGH | VERIFIED."""
    steps = chain.get("steps") or []
    finding = chain.get("exploited_cves") or []
    kev_count = chain.get("kev_count", 0)
    feasibility = chain.get("feasibility", "HARD")
    has_priv_esc = chain.get("has_priv_esc", False)

    # VERIFIED: KEV-backed AND high CVSS AND feasibility EASY
    if kev_count > 0 and feasibility == "EASY":
        any_critical_cvss = any(
            float(cve.get("cvss_score") or 0) >= 9.0
            for cve in finding
        )
        if any_critical_cvss:
            return "VERIFIED"

    # HIGH: CVE-backed with strong CVSS+EPSS OR KEV present
    if kev_count > 0:
        return "HIGH"
    has_high_cvss = any(float(cve.get("cvss_score") or 0) >= 7.0 for cve in finding)
    has_strong_epss = any(float(cve.get("epss_score") or 0) >= 0.2 for cve in finding)
    if has_high_cvss and (has_strong_epss or has_priv_esc):
        return "HIGH"

    # MEDIUM: any CVE present OR known service with moderate exploitability
    if finding or any(s.get("service") for s in steps):
        return "MEDIUM"

    return "LOW"


# ---------------------------------------------------------------------------
# Priority scoring
# ---------------------------------------------------------------------------

def _compute_priority_score(chain: dict, blast_radius_count: int) -> float:
    """Composite attack path priority combining all threat factors."""
    finding = chain.get("exploited_cves") or []
    kev_count = chain.get("kev_count", 0)
    feasibility = chain.get("feasibility", "HARD")
    target_crit = chain.get("target_criticality", "medium")
    target_exposure = chain.get("target_exposure", "internal")
    hops = chain.get("hops", 1)
    has_priv_esc = chain.get("has_priv_esc", False)

    max_cvss = max((float(c.get("cvss_score") or 0) for c in finding), default=0.0)
    max_epss = max((float(c.get("epss_score") or 0) for c in finding), default=0.0)

    cvss_component  = max_cvss * 4.0                                              # 0–40
    epss_component  = min(max_epss * 100.0, 30.0)                                 # 0–30
    kev_component   = min(kev_count * 15.0, 20.0)                                 # 0–20
    feasibility_pts = {"EASY": 15.0, "MEDIUM": 8.0, "HARD": 2.0}.get(feasibility, 2.0)
    crit_pts        = {"critical": 12.0, "high": 8.0, "medium": 4.0, "low": 1.0}.get(target_crit, 2.0)
    exposure_pts    = {"external": 10.0, "segmented": 6.0, "internal": 3.0, "isolated": 0.5}.get(target_exposure, 2.0)
    blast_pts       = min(blast_radius_count * 0.8, 12.0)
    priv_esc_bonus  = 8.0 if has_priv_esc else 0.0
    hop_penalty     = max(0.0, (hops - 1) * 1.5)                                  # longer chains penalized slightly

    raw = (
        cvss_component + epss_component + kev_component
        + feasibility_pts + crit_pts + exposure_pts
        + blast_pts + priv_esc_bonus - hop_penalty
    )
    return round(min(raw, 100.0), 2)


# ---------------------------------------------------------------------------
# Attack progression log
# ---------------------------------------------------------------------------

def _build_progression_log(chain: dict, attack_states: dict[str, dict]) -> list[dict]:
    """Structured per-hop log: exploited service, CVE, privilege level, pivot source, affected assets."""
    steps = chain.get("steps") or []
    log: list[dict] = []

    for index, step in enumerate(steps):
        finding = step.get("finding") or {}
        is_terminal = (index == len(steps) - 1)
        to_id = step.get("to_id", "")
        target_state = (attack_states.get(to_id) or {}).get("state", "Unknown")

        privilege_level = "USER"
        if step.get("is_priv_esc"):
            privilege_level = "ROOT/ADMIN"
        elif step.get("outcome") in {"Shell Access", "Privileged Session"}:
            privilege_level = "SHELL"

        affected_downstream = []
        # Assets reachable from this pivot (from chain path beyond this hop)
        remaining_path = chain.get("path", [])[index + 2:]
        for asset_id in remaining_path:
            state_info = attack_states.get(asset_id) or {}
            affected_downstream.append({
                "asset_id": asset_id,
                "state": state_info.get("state", "Unknown"),
            })

        log.append({
            "hop": index + 1,
            "from_name": step.get("from_name"),
            "from_ip": step.get("from_ip"),
            "to_name": step.get("to_name"),
            "to_ip": step.get("to_ip"),
            "exploited_service": step.get("service"),
            "port": step.get("port"),
            "protocol": step.get("finding", {}).get("protocol"),
            "cve_id": finding.get("cve_id"),
            "cvss_score": finding.get("cvss_score"),
            "epss_score": finding.get("epss_score"),
            "is_kev": finding.get("is_kev", False),
            "technique_id": step.get("technique_id"),
            "technique_name": step.get("technique_name"),
            "stage": step.get("stage"),
            "feasibility": step.get("feasibility"),
            "privilege_level": privilege_level,
            "pivot_source": step.get("from_name") if index > 0 else "Kali Attacker",
            "is_terminal": is_terminal,
            "attack_state_reached": target_state,
            "outcome": step.get("outcome"),
            "affected_downstream": affected_downstream,
            "explanation": step.get("explanation"),
        })

    return log


# ---------------------------------------------------------------------------
# Blast radius exposed services
# ---------------------------------------------------------------------------

def _blast_radius_services(
    reachable_ids: set,
    asset_map: dict[str, Asset],
    findings_map: dict[str, list[Finding]],
) -> list[dict]:
    """Per-asset exposed services reachable after compromise."""
    services: list[dict] = []
    for asset_id in reachable_ids:
        asset = asset_map.get(asset_id)
        if not asset:
            continue
        asset_findings = findings_map.get(asset_id, [])
        seen_ports: set[int] = set()
        for f in sorted(asset_findings, key=_finding_rank, reverse=True):
            if f.port and f.port not in seen_ports:
                seen_ports.add(f.port)
                services.append({
                    "asset_id": asset_id,
                    "asset_name": asset.name,
                    "asset_ip": asset.ip_address or asset.target,
                    "criticality": _asset_value(asset, "criticality"),
                    "port": f.port,
                    "protocol": f.protocol or "tcp",
                    "service": _service_name(f, "", f.port),
                    "cve_id": f.cve_id,
                    "cvss_score": float(f.cvss_score or 0.0) if f.cvss_score is not None else None,
                    "is_kev": bool(f.is_kev),
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                })
    services.sort(key=lambda s: (s.get("is_kev", False), s.get("cvss_score") or 0), reverse=True)
    return services[:40]


# ---------------------------------------------------------------------------
# Impact summary
# ---------------------------------------------------------------------------

def _build_impact_summary(
    chains: list[dict],
    blast_radius_assets: list[dict],
    attack_states: dict[str, dict],
    blast_radius_risk: float,
) -> dict:
    """Compute attack impact: affected assets, cumulative risk, critical exposure."""
    compromised_ids = {
        aid for aid, state in attack_states.items()
        if state.get("state") in {"Compromised", "Privilege Escalated", "Pivoted", "Critical Impact"}
    }
    critical_impact_ids = {
        aid for aid, state in attack_states.items()
        if state.get("state") == "Critical Impact"
    }
    priv_esc_ids = {
        aid for aid, state in attack_states.items()
        if state.get("is_priv_esc_target")
    }

    critical_in_blast = sum(
        1 for a in blast_radius_assets
        if a.get("criticality") in {"critical", "high"}
    )
    external_in_blast = sum(
        1 for a in blast_radius_assets
        if a.get("exposure") == "external"
    )

    # Service categories exposed
    service_categories: set[str] = set()
    for chain in chains:
        for step in chain.get("steps") or []:
            svc = step.get("service") or ""
            if svc:
                if svc.upper() in {"SSH", "TELNET", "RDP", "VNC"}:
                    service_categories.add("Remote Access")
                elif svc.upper() in {"HTTP", "HTTPS", "WEB"}:
                    service_categories.add("Web Services")
                elif svc.upper() in {"MYSQL", "POSTGRESQL", "MSSQL", "ORACLE", "MONGODB", "REDIS", "DATABASE"}:
                    service_categories.add("Database")
                elif svc.upper() in {"SMB", "NFS", "FTP", "FILE SHARE"}:
                    service_categories.add("File Sharing")
                elif svc.upper() in {"DNS"}:
                    service_categories.add("Name Resolution")
                else:
                    service_categories.add("Network Services")

    cumulative_risk_increase = round(blast_radius_risk, 2)
    max_single_chain_risk = max((c.get("risk_score", 0.0) for c in chains), default=0.0)

    return {
        "affected_asset_count": len(compromised_ids),
        "critical_impact_count": len(critical_impact_ids),
        "privilege_escalation_count": len(priv_esc_ids),
        "critical_system_exposure": critical_in_blast,
        "externally_exposed_in_blast_radius": external_in_blast,
        "cumulative_risk_increase": cumulative_risk_increase,
        "max_single_chain_risk": round(max_single_chain_risk, 2),
        "exposed_service_categories": sorted(service_categories),
        "service_category_count": len(service_categories),
        "kev_backed_chains": sum(1 for c in chains if c.get("kev_count", 0) > 0),
        "high_confidence_chains": sum(1 for c in chains if c.get("confidence") in {"HIGH", "VERIFIED"}),
        "total_chains": len(chains),
    }


# ---------------------------------------------------------------------------
# Attack replay steps
# ---------------------------------------------------------------------------

def _build_replay_steps(chain: dict, attack_states: dict[str, dict]) -> list[dict]:
    """
    Ordered, indexed replay steps — each step snapshots the asset state
    change that occurs at that moment in the attack progression.
    """
    if not chain:
        return []

    steps_data = chain.get("steps") or []
    replay: list[dict] = []

    # Step 0: attacker origin
    replay.append({
        "step_index": 0,
        "phase": "origin",
        "stage": "Reconnaissance",
        "label": f"Kali Attacker ({chain.get('source_ip')}) initiates emulated attack",
        "asset_id": chain.get("source_id"),
        "asset_name": chain.get("source_name"),
        "asset_ip": chain.get("source_ip"),
        "state_transition": {"from": "Pivoted", "to": "Pivoted"},
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "cve_id": None,
        "service": None,
        "port": None,
        "privilege_level": "ROOT",
        "is_lateral_movement": False,
        "is_priv_esc": False,
        "is_critical_impact": False,
        "feasibility": "VERIFIED",
    })

    prior_state: dict[str, str] = {}
    for s_idx, step in enumerate(steps_data):
        to_id = step.get("to_id", "")
        current_state = (attack_states.get(to_id) or {}).get("state", "Untouched")
        previous = prior_state.get(to_id, "Untouched")
        prior_state[to_id] = current_state
        finding = step.get("finding") or {}
        is_terminal = (s_idx == len(steps_data) - 1)

        privilege_level = "USER"
        if step.get("is_priv_esc"):
            privilege_level = "ROOT/ADMIN"
        elif step.get("outcome") in {"Shell Access", "Privileged Session"}:
            privilege_level = "SHELL"

        replay.append({
            "step_index": s_idx + 1,
            "phase": "terminal" if is_terminal else "lateral",
            "stage": step.get("stage", "Exploitation"),
            "label": (
                step.get("explanation")
                or f"{step.get('stage')} → {step.get('to_name') or step.get('to_ip')}"
            ),
            "asset_id": to_id,
            "asset_name": step.get("to_name"),
            "asset_ip": step.get("to_ip"),
            "from_asset_id": step.get("from_id"),
            "from_asset_name": step.get("from_name"),
            "state_transition": {"from": previous, "to": current_state},
            "technique_id": step.get("technique_id"),
            "technique_name": step.get("technique_name"),
            "cve_id": finding.get("cve_id"),
            "cvss_score": finding.get("cvss_score"),
            "epss_score": finding.get("epss_score"),
            "is_kev": finding.get("is_kev", False),
            "service": step.get("service"),
            "port": step.get("port"),
            "relationship": step.get("relationship"),
            "privilege_level": privilege_level,
            "outcome": step.get("outcome"),
            "feasibility": step.get("feasibility"),
            "is_lateral_movement": step.get("relationship") in {"exposes_remote", "shares_files", "routes_through"},
            "is_priv_esc": step.get("is_priv_esc", False),
            "is_critical_impact": current_state == "Critical Impact",
            "mitre": step.get("mitre") or [],
        })

    return replay


def _safe_emulation_payload(chain: dict | None, attack_states: dict[str, dict]) -> dict:
    timeline = _build_attack_timeline(chain)
    compromised_count = sum(
        1
        for state in attack_states.values()
        if state.get("state") in {"Compromised", "Privilege Escalated", "Pivoted"}
    )
    return {
        "mode": "SAFE",
        "payloads_executed": False,
        "destructive_actions": False,
        "validations": [
            "LAB-managed attack surface only",
            "Topology reachability confirmed from Kali",
            "Exploitability inferred from service, CVE, CVSS, EPSS, and KEV intelligence",
            "No exploit payloads or destructive commands executed",
        ],
        "timeline": timeline,
        "compromised_count": compromised_count,
    }


# ---------------------------------------------------------------------------
# Blast radius
# ---------------------------------------------------------------------------

def simulate_from(
    database: Session,
    owner_id: str,
    source_id: str | None = None,
    limit: int = 6,
    kev_only: bool = False,
    internet_exposed_only: bool = False,
    critical_only: bool = False,
    highest_risk_only: bool = False,
    emulation_mode: bool = True,
) -> dict:
    """Simulate attacker movement starting from *source_id*.

    Returns blast radius, best attack chain to each reachable node,
    and lateral movement / privilege escalation metrics.
    """
    g, assets, asset_map = _load_graph(database, owner_id)
    source_id = _resolve_source_id(source_id, assets, asset_map)

    if not source_id or source_id not in g:
        return {"error": "Source asset not in topology graph"}

    # Blast radius: all nodes reachable from source
    try:
        reachable_ids = nx.descendants(g, source_id)
    except Exception:
        reachable_ids = set()

    findings_map: dict[str, list[Finding]] = {}
    if assets:
        findings = database.query(Finding).filter(Finding.asset_id.in_([a.id for a in assets])).all()
        for finding in findings:
            findings_map.setdefault(str(finding.asset_id), []).append(finding)

    # For each reachable node find the highest-exploitability path
    chains: list[dict] = []
    priv_esc_paths: list[dict] = []

    for target_id in reachable_ids:
        if target_id == source_id or target_id not in g:
            continue
        try:
            # dijkstra with inv_weight finds the MAX-exploitability path
            best_path = nx.dijkstra_path(
                g, source=source_id, target=target_id, weight="inv_weight"
            )
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue

        if len(best_path) - 1 > _MAX_ATTACK_HOPS:
            continue

        steps = [
            _build_step(g, best_path[i], best_path[i + 1], asset_map, findings_map, i)
            for i in range(len(best_path) - 1)
        ]
        if not _chain_has_exploit_context(steps):
            continue

        target_asset = asset_map.get(target_id)
        score = _attack_path_score(steps, target_asset)
        chain = _chain_payload(source_id, target_id, best_path, steps, score, asset_map)
        chains.append(chain)
        if chain["has_priv_esc"]:
            priv_esc_paths.append(chain)

    chains.sort(key=lambda c: c["risk_score"], reverse=True)
    priv_esc_paths.sort(key=lambda c: c["risk_score"], reverse=True)

    if kev_only:
        chains = [c for c in chains if c.get("kev_count", 0) > 0]
    if internet_exposed_only:
        chains = [c for c in chains if c.get("target_exposure") == "external"]
    if critical_only:
        chains = [c for c in chains if c.get("target_criticality") in ("critical", "high")]

    # Lateral movement score: reachable × mean target risk
    reachable_assets = [asset_map[rid] for rid in reachable_ids if rid in asset_map]
    lateral_score = round(
        len(reachable_ids) * (
            sum(a.risk_score or 0.0 for a in reachable_assets) / max(len(reachable_assets), 1)
        ) / 10.0,
        2,
    )
    blast_radius_risk = round(sum(a.risk_score or 0.0 for a in reachable_assets), 2)
    blast_radius_assets = [
        {
            "asset_id": str(asset.id),
            "asset_ip": asset.ip_address or asset.target,
            "asset_name": asset.name,
            "criticality": asset.criticality.value if hasattr(asset.criticality, "value") else str(asset.criticality),
            "exposure": asset.exposure.value if hasattr(asset.exposure, "value") else str(asset.exposure),
            "risk_score": round(asset.risk_score or 0.0, 2),
        }
        for asset in sorted(reachable_assets, key=lambda a: (a.risk_score or 0.0), reverse=True)
    ]
    blast_radius_critical_count = sum(
        1 for asset in reachable_assets
        if (asset.criticality.value if hasattr(asset.criticality, "value") else str(asset.criticality)) in {"critical", "high"}
    )
    blast_radius_exposed_count = sum(
        1 for asset in reachable_assets
        if (asset.exposure.value if hasattr(asset.exposure, "value") else str(asset.exposure)) == "external"
    )

    source_asset = asset_map.get(source_id)
    max_items = min(max(1, limit), 20)

    # Compute priority scores now that we have blast_radius_count
    blast_count = len(reachable_ids)
    for chain in chains:
        chain["priority_score"] = _compute_priority_score(chain, blast_count)

    # Sort by priority_score (dominates risk_score for ordering)
    chains.sort(key=lambda c: c["priority_score"], reverse=True)
    priv_esc_paths.sort(key=lambda c: c["priority_score"], reverse=True)

    if highest_risk_only:
        chains = chains[:max_items]

    top_chain = chains[0] if chains else None
    attack_states = _build_attack_states(assets, chains, source_id, asset_map)
    emulation = _safe_emulation_payload(top_chain, attack_states) if emulation_mode else None
    attacker_asset = _find_attacker_asset(assets)

    # New analytics payloads
    blast_services = _blast_radius_services(reachable_ids, asset_map, findings_map)
    impact_summary = _build_impact_summary(chains, blast_radius_assets, attack_states, blast_radius_risk)
    top_chain_replay = _build_replay_steps(top_chain, attack_states) if top_chain else []
    top_chain_progression_log = _build_progression_log(top_chain, attack_states) if top_chain else []

    return {
        "attacker_id":         str(attacker_asset.id) if attacker_asset else source_id,
        "attacker_name":       attacker_asset.name if attacker_asset else (source_asset.name if source_asset else "Kali"),
        "attacker_ip":         attacker_asset.ip_address or attacker_asset.target if attacker_asset else (source_asset.ip_address or source_asset.target if source_asset else source_id),
        "source_id":          source_id,
        "source_ip":          source_asset.ip_address or source_asset.target if source_asset else source_id,
        "blast_radius_count": blast_count,
        "blast_radius_ids":   list(reachable_ids),
        "blast_radius_assets": blast_radius_assets[:25],
        "blast_radius_services": blast_services,
        "blast_radius_critical_count": blast_radius_critical_count,
        "blast_radius_exposed_count": blast_radius_exposed_count,
        "lateral_score":      lateral_score,
        "blast_radius_risk":  blast_radius_risk,
        "priv_esc_count":     len(priv_esc_paths),
        "attack_chains":      chains[:max_items],
        "priv_esc_paths":     priv_esc_paths[:5],
        "top_chain":          top_chain,
        "attack_states":      attack_states,
        "attack_timeline":    emulation["timeline"] if emulation else [],
        "emulation":          emulation,
        "replay_steps":       top_chain_replay,
        "progression_log":    top_chain_progression_log,
        "impact_summary":     impact_summary,
        "attack_state_catalog": [
            {"state": state, "rank": rank}
            for state, rank in sorted(_ATTACK_STATE_RANK.items(), key=lambda x: x[1])
        ],
        "confidence_catalog": list(_CONFIDENCE_TIERS),
        "stage_catalog": [
            {
                "stage": stage,
                "order": order,
                "technique_id": _STAGE_TECHNIQUE[stage][0],
                "technique_name": _STAGE_TECHNIQUE[stage][1],
            }
            for stage, order in sorted(_STAGE_ORDER.items(), key=lambda item: item[1])
        ],
        "filters": {
            "kev_only": kev_only,
            "internet_exposed_only": internet_exposed_only,
            "critical_only": critical_only,
            "highest_risk_only": highest_risk_only,
            "emulation_mode": emulation_mode,
        },
    }


# ---------------------------------------------------------------------------
# Network-wide top attack chains
# ---------------------------------------------------------------------------

def top_attack_chains(
    database: Session,
    owner_id: str,
    limit: int = 10,
    kev_only: bool = False,
    internet_exposed_only: bool = False,
    critical_only: bool = False,
) -> dict:
    """Return the N most dangerous attack chains across the entire network."""
    g, assets, asset_map = _load_graph(database, owner_id)

    findings_map: dict[str, list[Finding]] = {}
    if assets:
        findings = database.query(Finding).filter(Finding.asset_id.in_([a.id for a in assets])).all()
        for finding in findings:
            findings_map.setdefault(str(finding.asset_id), []).append(finding)

    all_chains: list[dict] = []
    # For each non-gateway node as source, find chains to critical/high targets
    targets = [
        a for a in assets
        if not _is_gateway(a.ip_address or a.target or "")
        and (a.criticality.value if hasattr(a.criticality, "value") else str(a.criticality)) in ("critical", "high")
    ]
    if not targets:
        targets = [a for a in assets if not _is_gateway(a.ip_address or a.target or "")]

    seen_pairs: set[tuple[str, str]] = set()
    attacker = _find_attacker_asset(assets)
    sources = [attacker] if attacker else assets
    for source in sources:
        if source is None:
            continue
        sid = str(source.id)
        if sid not in g:
            continue
        for target in targets:
            tid = str(target.id)
            if tid == sid or (sid, tid) in seen_pairs or tid not in g:
                continue
            seen_pairs.add((sid, tid))
            try:
                path = nx.dijkstra_path(g, source=sid, target=tid, weight="inv_weight")
                if len(path) < 2:
                    continue
                if len(path) - 1 > _MAX_ATTACK_HOPS:
                    continue
                steps = [
                    _build_step(g, path[i], path[i + 1], asset_map, findings_map, i)
                    for i in range(len(path) - 1)
                ]
                if not _chain_has_exploit_context(steps):
                    continue
                score = _attack_path_score(steps, target)
                all_chains.append(_chain_payload(sid, tid, path, steps, score, asset_map))
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                pass

    all_chains.sort(key=lambda c: c["score"], reverse=True)
    if kev_only:
        all_chains = [c for c in all_chains if c.get("kev_count", 0) > 0]
    if internet_exposed_only:
        all_chains = [c for c in all_chains if c.get("target_exposure") == "external"]
    if critical_only:
        all_chains = [c for c in all_chains if c.get("target_criticality") in ("critical", "high")]
    return {"chains": all_chains[:limit], "total": len(all_chains)}


# ---------------------------------------------------------------------------
# Per-asset metrics
# ---------------------------------------------------------------------------

def asset_attack_metrics(database: Session, owner_id: str) -> list[dict]:
    """Return blast radius and lateral movement score for every asset."""
    g, assets, asset_map = _load_graph(database, owner_id)
    results = []

    for asset in assets:
        aid = str(asset.id)
        if aid not in g:
            continue
        try:
            reachable = nx.descendants(g, aid)
        except Exception:
            reachable = set()

        inbound = list(g.predecessors(aid))
        crit = asset.criticality.value if hasattr(asset.criticality, "value") else str(asset.criticality)

        # Pivot score: reachable nodes from here (higher = more dangerous pivot)
        pivot_score = round(
            len(reachable) * _CRITICALITY_MULT.get(crit, 1.0), 2
        )

        results.append({
            "asset_id":      aid,
            "asset_ip":      asset.ip_address or asset.target,
            "asset_name":    asset.name,
            "criticality":   crit,
            "risk_score":    asset.risk_score or 0.0,
            "blast_radius":  len(reachable),
            "pivot_score":   pivot_score,
            "inbound_paths": len(inbound),
            "is_gateway":    _is_gateway(asset.ip_address or asset.target or ""),
        })

    results.sort(key=lambda r: r["pivot_score"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Public: replay and impact endpoints
# ---------------------------------------------------------------------------

def get_attack_replay(
    database: Session,
    owner_id: str,
    source_id: str | None = None,
    chain_index: int = 0,
) -> dict:
    """Return ordered replay steps for the best attack chain from source."""
    result = simulate_from(
        database=database,
        owner_id=owner_id,
        source_id=source_id,
        limit=max(chain_index + 1, 6),
        emulation_mode=False,
    )
    if "error" in result:
        return result
    chains = result.get("attack_chains") or []
    if not chains:
        return {"replay_steps": [], "chain": None, "total_steps": 0}
    chain = chains[min(chain_index, len(chains) - 1)]
    attack_states = result.get("attack_states") or {}
    replay_steps = _build_replay_steps(chain, attack_states)
    return {
        "replay_steps": replay_steps,
        "total_steps": len(replay_steps),
        "chain": {
            "source_name": chain.get("source_name"),
            "target_name": chain.get("target_name"),
            "hops": chain.get("hops"),
            "risk_score": chain.get("risk_score"),
            "confidence": chain.get("confidence"),
            "priority_score": chain.get("priority_score"),
            "feasibility": chain.get("feasibility"),
        },
        "attack_state_catalog": result.get("attack_state_catalog") or [],
    }


def get_attack_impact(
    database: Session,
    owner_id: str,
    source_id: str | None = None,
) -> dict:
    """Return full impact summary for a simulated attack from source."""
    result = simulate_from(
        database=database,
        owner_id=owner_id,
        source_id=source_id,
        limit=20,
        emulation_mode=False,
    )
    if "error" in result:
        return result
    return {
        "impact_summary": result.get("impact_summary") or {},
        "blast_radius_assets": result.get("blast_radius_assets") or [],
        "blast_radius_services": result.get("blast_radius_services") or [],
        "blast_radius_count": result.get("blast_radius_count", 0),
        "blast_radius_risk": result.get("blast_radius_risk", 0.0),
        "attack_states": result.get("attack_states") or {},
        "priv_esc_count": result.get("priv_esc_count", 0),
        "lateral_score": result.get("lateral_score", 0.0),
        "top_chain_priority": (result.get("attack_chains") or [{}])[0].get("priority_score", 0.0),
        "confidence_distribution": _confidence_distribution(result.get("attack_chains") or []),
    }


def _confidence_distribution(chains: list[dict]) -> dict[str, int]:
    dist: dict[str, int] = {tier: 0 for tier in _CONFIDENCE_TIERS}
    for chain in chains:
        tier = chain.get("confidence", "LOW")
        if tier in dist:
            dist[tier] += 1
    return dist
