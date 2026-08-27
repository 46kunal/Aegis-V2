"""Digital twin topology engine.

Infers asset relationships from network scan data and stores them as a
directed graph in the asset_edges table. Uses NetworkX for in-memory
graph analysis (centrality, reachability, attack paths).

Two-graph architecture
----------------------
Display graph  (MultiDiGraph) — all N edges; used for React Flow output.
Analysis graph (DiGraph)      — one edge per pair (max exploitability);
                                used for Dijkstra / centrality / blast radius.

Relationship inference rules
----------------------------
connects_to       — assets share a /24 subnet (direct L2 reachability)
routes_through    — asset is a gateway for others (.1 / .254 last octet)
trusts            — rlogin(513) / rsh(514) / rexec(512) ports open
exposes_database  — MySQL, PostgreSQL, MSSQL, Redis, MongoDB ports open
exposes_web       — HTTP/HTTPS/AJP ports open
shares_files      — SMB, NFS, FTP ports open
resolves_names    — DNS port 53 open
exposes_remote    — VNC, X11, RDP, SSH ports open
"""
from __future__ import annotations

import ipaddress
import logging
import math
import uuid
from collections import Counter
from types import SimpleNamespace
from uuid import UUID

import networkx as nx
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.asset import (
    Asset,
    AssetCriticality,
    AssetExposure,
    AssetStatus,
    AssetType,
    AssetZone,
)
from app.models.finding import Finding, FindingSeverity
from app.models.topology import AssetEdge

logger = logging.getLogger("aegis.topology")

MAX_TOPOLOGY_NODES = 30

SYSTEM_ATTACKER_NAME = "Kali-Attacker"
SYSTEM_ATTACKER_HOSTNAME = "kali-attacker"
SYSTEM_ATTACKER_TARGET = "kali-attacker"
SYSTEM_ATTACKER_OS = "Kali Linux"

DEFAULT_ALIAS_MAP = {
    "192.168.11.129": "Metasploitable",
    "192.168.11.130": "Ubuntu-Lab",
    "192.168.11.132": "Windows-Lab",
}

ROLE_ORDER = {
    "ATTACKER": 0,
    "WEB": 1,
    "DATABASE": 1,
    "SERVER": 2,
    "TARGET": 3,
    "INFRASTRUCTURE": 4,
}

# ---------------------------------------------------------------------------
# Port classification tables
# ---------------------------------------------------------------------------

_TRUST_PORTS   = {512, 513, 514}
_DB_PORTS      = {3306, 5432, 1433, 1521, 5984, 6379, 27017, 9200}
_WEB_PORTS     = {80, 443, 8080, 8443, 8000, 8009, 3000, 4443}
_FILE_PORTS    = {21, 139, 445, 2049, 2121}
_DNS_PORTS     = {53}
_REMOTE_PORTS  = {22, 23, 3389, 5900, 5901, 6000, 6001}

_PORT_RELATIONSHIPS: dict[frozenset[int], tuple[str, str, float, str, str]] = {
    frozenset(_TRUST_PORTS):  ("trusts",           "rlogin/rsh trust service",    9.0, "T1021.004", "Remote Services: Unix rlogin/rsh"),
    frozenset(_DB_PORTS):     ("exposes_database",  "database service",            7.0, "T1213",    "Data from Information Repositories"),
    frozenset(_FILE_PORTS):   ("shares_files",      "file sharing service",        6.0, "T1021.002","Remote Services: SMB/Admin Shares"),
    frozenset(_REMOTE_PORTS): ("exposes_remote",    "remote access service",       5.0, "T1021.005","Remote Services: VNC/RDP/SSH"),
    frozenset(_WEB_PORTS):    ("exposes_web",       "web service",                 3.0, "T1190",    "Exploit Public-Facing Application"),
    frozenset(_DNS_PORTS):    ("resolves_names",    "DNS resolver",                2.0, "T1071.004","Application Layer Protocol: DNS"),
}

_SUBNET_TECHNIQUES = {
    "connects_to":    ("T1018",     "Remote System Discovery"),
    "routes_through": ("T1090.002", "Proxy: External Proxy"),
}


def _classify_port(port: int) -> tuple[str, str, float, str, str] | None:
    for port_set, rel_data in _PORT_RELATIONSHIPS.items():
        if port in port_set:
            return rel_data
    return None


def _is_gateway(ip: str) -> bool:
    try:
        last = int(ip.rsplit(".", 1)[-1])
        return last in (1, 254)
    except (ValueError, IndexError):
        return False


def _is_vmware_device(asset: Asset) -> bool:
    fingerprint = (asset.os_fingerprint or "").lower()
    name = (asset.name or "").lower()
    host = (asset.hostname or "").lower()
    return any(token in (fingerprint + name + host) for token in ("vmware", "vsphere", "vcenter", "esxi"))


def _is_nat_device(asset: Asset) -> bool:
    name = (asset.name or "").lower()
    host = (asset.hostname or "").lower()
    return any(token in (name + host) for token in ("nat", "router", "gateway"))


def _is_kali_asset(asset: Asset) -> bool:
    fingerprint = " ".join([
        asset.name or "",
        asset.hostname or "",
        asset.target or "",
        asset.ip_address or "",
        asset.os_fingerprint or "",
    ]).lower()
    return "kali" in fingerprint


def _select_primary_attacker(assets: list[Asset]) -> Asset | None:
    attackers = [asset for asset in assets if _is_kali_asset(asset)]
    if not attackers:
        return None

    def _score(asset: Asset) -> int:
        score = 0
        if (asset.discovery_status or "") == "system":
            score += 50
        if (asset.name or "").strip().lower() == SYSTEM_ATTACKER_NAME.lower():
            score += 40
        if (asset.hostname or "").strip().lower() == SYSTEM_ATTACKER_HOSTNAME.lower():
            score += 30
        if asset.ip_address:
            score += 10
        if asset.managed:
            score += 5
        if asset.asset_zone == AssetZone.LAB:
            score += 5
        return score

    return max(attackers, key=_score)


def _dedupe_attackers(assets: list[Asset]) -> tuple[list[Asset], Asset | None]:
    primary = _select_primary_attacker(assets)
    if primary is None:
        return assets, None

    filtered = [asset for asset in assets if not _is_kali_asset(asset) or asset.id == primary.id]
    return filtered, primary


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _infer_attacker_ip(assets: list[Asset]) -> str | None:
    candidates = []
    for asset in assets:
        for value in (asset.ip_address, asset.target):
            if value and _is_ipv4(value):
                candidates.append(value)
                break
    if not candidates:
        return None

    prefixes = [value.rsplit(".", 1)[0] for value in candidates]
    prefix = Counter(prefixes).most_common(1)[0][0]
    used_octets = {
        int(value.rsplit(".", 1)[1])
        for value in candidates
        if value.startswith(prefix + ".")
    }

    for octet in (10, 11, 12, 13, 14, 15, 16, 20, 30, 40, 50, 60, 128, 200, 210, 220, 230, 240, 250):
        if octet not in used_octets:
            return f"{prefix}.{octet}"
    return None


def ensure_attacker_asset(
    database: Session,
    owner_uuid: UUID,
    assets: list[Asset] | None = None,
) -> Asset | None:
    if assets is None:
        assets = database.query(Asset).filter(Asset.owner_id == owner_uuid).all()

    attackers = [asset for asset in assets if _is_kali_asset(asset)]
    attacker = _select_primary_attacker(assets)
    if attacker is None:
        inferred_ip = _infer_attacker_ip(assets)
        attacker = Asset(
            owner_id=owner_uuid,
            name=SYSTEM_ATTACKER_NAME,
            target=inferred_ip or SYSTEM_ATTACKER_TARGET,
            ip_address=inferred_ip,
            hostname=SYSTEM_ATTACKER_HOSTNAME,
            os_fingerprint=SYSTEM_ATTACKER_OS,
            asset_type=AssetType.HOST,
            status=AssetStatus.ACTIVE,
            criticality=AssetCriticality.LOW,
            exposure=AssetExposure.INTERNAL,
            managed=True,
            asset_zone=AssetZone.LAB,
            topology_visible=True,
            attack_surface_enabled=True,
            discovery_status="system",
            risk_score=0.0,
        )
        try:
            database.add(attacker)
            database.commit()
            database.refresh(attacker)
            assets.append(attacker)
        except IntegrityError:
            database.rollback()
            attacker = next(
                (asset for asset in database.query(Asset).filter(Asset.owner_id == owner_uuid).all() if _is_kali_asset(asset)),
                None,
            )
        return attacker

    updated = False
    if not attacker.ip_address:
        donor = next((asset for asset in attackers if asset.ip_address), None)
        if donor:
            attacker.ip_address = donor.ip_address
            attacker.target = donor.ip_address
            updated = True
    if not attacker.managed:
        attacker.managed = True
        updated = True
    if not attacker.topology_visible:
        attacker.topology_visible = True
        updated = True
    if not attacker.attack_surface_enabled:
        attacker.attack_surface_enabled = True
        updated = True
    if attacker.asset_zone != AssetZone.LAB:
        attacker.asset_zone = AssetZone.LAB
        updated = True
    if not attacker.os_fingerprint:
        attacker.os_fingerprint = SYSTEM_ATTACKER_OS
        updated = True
    if attacker.discovery_status is None:
        attacker.discovery_status = "system"
        updated = True
    if not (attacker.name or "").strip():
        attacker.name = SYSTEM_ATTACKER_NAME
        updated = True
    if not (attacker.hostname or "").strip():
        attacker.hostname = SYSTEM_ATTACKER_HOSTNAME
        updated = True
    if not (attacker.target or "").strip():
        attacker.target = attacker.ip_address or SYSTEM_ATTACKER_TARGET
        updated = True
    if attacker.discovery_status == "system" and not attacker.ip_address:
        inferred_ip = _infer_attacker_ip(assets)
        if inferred_ip:
            attacker.ip_address = inferred_ip
            attacker.target = inferred_ip
            updated = True

    if updated:
        database.commit()
        database.refresh(attacker)
    return attacker


def _asset_role(asset: Asset, open_ports: set[int] | None = None) -> str:
    if _is_kali_asset(asset):
        return "ATTACKER"
    if _is_gateway(asset.ip_address or asset.target or ""):
        return "INFRASTRUCTURE"
    if _is_vmware_device(asset) or _is_nat_device(asset):
        return "INFRASTRUCTURE"

    name = " ".join([
        asset.name or "",
        asset.hostname or "",
        asset.target or "",
        asset.os_fingerprint or "",
    ]).lower()

    if any(token in name for token in ("db", "database", "postgres", "mysql", "mssql", "mongo", "redis", "oracle")):
        return "DATABASE"
    if any(token in name for token in ("web", "nginx", "apache", "http", "frontend", "tomcat")):
        return "WEB"

    if open_ports:
        if open_ports & _DB_PORTS:
            return "DATABASE"
        if open_ports & _WEB_PORTS:
            return "WEB"
        if open_ports & (_REMOTE_PORTS | _FILE_PORTS | _TRUST_PORTS):
            return "SERVER"

    if hasattr(asset, "asset_type") and asset.asset_type == AssetType.WEBAPP:
        return "WEB"
    return "TARGET"


def _asset_alias(asset: Asset) -> str | None:
    ip = (asset.ip_address or asset.target or "").strip()
    if ip in DEFAULT_ALIAS_MAP:
        return DEFAULT_ALIAS_MAP[ip]
    if _is_kali_asset(asset):
        return SYSTEM_ATTACKER_NAME

    hostname = (asset.hostname or "").strip()
    name = (asset.name or "").strip()
    target = (asset.target or "").strip()
    ip = (asset.ip_address or "").strip()
    if name and name not in {hostname, target, ip}:
        return name
    return None


def _should_exclude_asset(asset: Asset) -> bool:
    if _is_kali_asset(asset):
        return False
    if _is_gateway(asset.ip_address or asset.target or ""):
        return True
    if _is_vmware_device(asset):
        return True
    if _is_nat_device(asset):
        return True
    return False


def _territory_group(asset: Asset) -> str:
    zone = asset.asset_zone.value if hasattr(asset.asset_zone, "value") else str(asset.asset_zone)
    if zone == AssetZone.LAB.value:
        return "lab"
    if zone == AssetZone.INFRASTRUCTURE.value:
        return "infrastructure"
    if zone in (AssetZone.EXTERNAL.value, AssetZone.DMZ.value):
        return "external"
    return "unknown"


def _same_subnet(ip1: str, ip2: str, prefix: int = 24) -> bool:
    try:
        net = ipaddress.ip_network(f"{ip1}/{prefix}", strict=False)
        return ipaddress.ip_address(ip2) in net
    except ValueError:
        return False


def _exploitability(
    base_weight: float,
    findings_for_port: list[Finding],
) -> float:
    """Compute CVE/KEV/EPSS-boosted exploitability score for an edge."""
    kev_boost  = 0.4 if any(f.is_kev for f in findings_for_port) else 0.0
    cvss_vals  = [float(f.cvss_score) for f in findings_for_port if f.cvss_score]
    epss_vals  = [float(f.epss_score) for f in findings_for_port if f.epss_score]
    cvss_boost = (max(cvss_vals) / 10.0) * 0.3 if cvss_vals else 0.0
    epss_boost = max(epss_vals) * 0.2 if epss_vals else 0.0
    return round(min(base_weight * (1.0 + kev_boost + cvss_boost + epss_boost), 10.0), 3)


# ---------------------------------------------------------------------------
# Analysis graph (DiGraph — max exploitability per pair)
# ---------------------------------------------------------------------------

def build_analysis_graph(assets: list[Asset], edges: list[AssetEdge]) -> nx.DiGraph:
    """Build a DiGraph keeping the highest-exploitability edge per directed pair.

    Edge attribute 'inv_weight' = 1/exploitability so that Dijkstra's
    minimum-cost algorithm finds the maximum-exploitability (most dangerous) path.
    """
    g: nx.DiGraph = nx.DiGraph()
    for asset in assets:
        g.add_node(
            str(asset.id),
            ip=asset.ip_address or asset.target,
            name=asset.name,
            risk_score=asset.risk_score or 0.0,
            criticality=asset.criticality.value if hasattr(asset.criticality, "value") else str(asset.criticality),
            exposure=asset.exposure.value if hasattr(asset.exposure, "value") else str(asset.exposure),
            is_gateway=_is_gateway(asset.ip_address or asset.target or ""),
        )

    # For each directed pair keep only the highest exploitability edge
    best: dict[tuple[str, str], AssetEdge] = {}
    for edge in edges:
        key = (str(edge.source_id), str(edge.target_id))
        score = edge.exploitability_score or edge.weight
        if key not in best or score > (best[key].exploitability_score or best[key].weight):
            best[key] = edge

    for (src, tgt), edge in best.items():
        expl = edge.exploitability_score or edge.weight
        g.add_edge(
            src, tgt,
            weight=edge.weight,
            exploitability=expl,
            inv_weight=1.0 / max(expl, 0.01),
            relationship=edge.relationship,
            technique_id=edge.technique_id or "",
            technique_name=edge.technique_name or edge.relationship,
            label=edge.label or edge.relationship,
            meta=edge.meta or {},
        )
    return g


# ---------------------------------------------------------------------------
# Relationship inference (with MITRE + exploitability)
# ---------------------------------------------------------------------------

def _infer_edges(
    assets: list[Asset],
    findings_map: dict[str, list[Finding]],
) -> list[dict]:
    edges: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    def add(src: str, tgt: str, rel: str, label: str, weight: float,
            exploitability: float, technique_id: str, technique_name: str,
            source: str, meta: dict | None = None) -> None:
        key = (src, tgt, rel)
        if key in seen or src == tgt:
            return
        seen.add(key)
        edges.append({
            "source_id": src, "target_id": tgt,
            "relationship": rel, "label": label,
            "weight": weight, "exploitability_score": exploitability,
            "technique_id": technique_id, "technique_name": technique_name,
            "inferred_from": source,
            "meta": meta or {},
        })

    gateways     = [a for a in assets if _is_gateway(a.ip_address or a.target or "")]
    non_gateways = [a for a in assets if not _is_gateway(a.ip_address or a.target or "")]
    attackers    = [a for a in assets if _is_kali_asset(a)]

    # 1. Same-subnet connectivity
    t_ct, t_cn = _SUBNET_TECHNIQUES["connects_to"]
    for i, a1 in enumerate(assets):
        for a2 in assets[i + 1:]:
            ip1 = a1.ip_address or a1.target or ""
            ip2 = a2.ip_address or a2.target or ""
            if ip1 and ip2 and _same_subnet(ip1, ip2):
                add(str(a1.id), str(a2.id), "connects_to", "same subnet",
                    1.0, 1.0, t_ct, t_cn, "subnet_analysis")
                add(str(a2.id), str(a1.id), "connects_to", "same subnet",
                    1.0, 1.0, t_ct, t_cn, "subnet_analysis")

    # 1b. Attacker origin connectivity (ensures Kali is always reachable)
    if attackers:
        for attacker in attackers:
            for asset in assets:
                if str(asset.id) == str(attacker.id):
                    continue
                add(str(attacker.id), str(asset.id), "connects_to", "attacker origin",
                    1.0, 1.0, t_ct, t_cn, "attacker_origin", {"origin": "attacker"})

    # 2. Gateway routing
    t_rt, t_rn = _SUBNET_TECHNIQUES["routes_through"]
    for gw in gateways:
        for other in non_gateways:
            add(str(other.id), str(gw.id), "routes_through", "default gateway",
                0.5, 0.5, t_rt, t_rn, "subnet_analysis")

    # 3. Service-based relationships
    for asset in assets:
        asset_findings = findings_map.get(str(asset.id), [])
        port_to_findings: dict[int, list[Finding]] = {}
        for f in asset_findings:
            if f.port:
                port_to_findings.setdefault(f.port, []).append(f)

        open_ports = set(port_to_findings.keys())

        for port in open_ports:
            rel_data = _classify_port(port)
            if rel_data is None:
                continue
            rel_type, rel_label, base_weight, tech_id, tech_name = rel_data

            port_findings = port_to_findings.get(port, [])
            expl = _exploitability(base_weight, port_findings)

            for peer in assets:
                if str(peer.id) == str(asset.id):
                    continue
                peer_ip = peer.ip_address or peer.target or ""
                host_ip = asset.ip_address or asset.target or ""
                peer_is_attacker = _is_kali_asset(peer)
                if not _same_subnet(peer_ip, host_ip) and not peer_is_attacker:
                    continue

                add(str(peer.id), str(asset.id), rel_type,
                    f"{rel_label} on port {port}",
                    base_weight, expl, tech_id, tech_name, "port_scan",
                    {
                        "port": port,
                        "service": rel_label,
                        "cves": [f.cve_id for f in port_findings if f.cve_id][:5],
                        "kev": any(f.is_kev for f in port_findings),
                        "max_cvss": max([float(f.cvss_score) for f in port_findings if f.cvss_score] or [0.0]),
                        "max_epss": max([float(f.epss_score) for f in port_findings if f.epss_score] or [0.0]),
                    })

    return edges


def _augment_attacker_edges(
    assets: list[Asset],
    edges: list[AssetEdge],
    findings_map: dict[str, list[Finding]],
) -> list[AssetEdge]:
    attacker = _select_primary_attacker(assets)
    if attacker is None:
        return edges

    existing = {
        (str(edge.source_id), str(edge.target_id), edge.relationship)
        for edge in edges
    }
    attacker_id = str(attacker.id)
    augmented = list(edges)
    t_ct, t_cn = _SUBNET_TECHNIQUES["connects_to"]

    for asset in assets:
        if str(asset.id) == attacker_id:
            continue
        target_id = str(asset.id)

        key = (attacker_id, target_id, "connects_to")
        if key not in existing:
            augmented.append(SimpleNamespace(
                id=uuid.uuid4(),
                owner_id=attacker.owner_id,
                source_id=attacker.id,
                target_id=asset.id,
                relationship="connects_to",
                label="attacker origin",
                weight=1.0,
                exploitability_score=1.0,
                technique_id=t_ct,
                technique_name=t_cn,
                inferred_from="attacker_origin",
                meta={"origin": "attacker"},
            ))
            existing.add(key)

        port_to_findings: dict[int, list[Finding]] = {}
        for finding in findings_map.get(target_id, []):
            if finding.port:
                port_to_findings.setdefault(finding.port, []).append(finding)

        for port, port_findings in port_to_findings.items():
            rel_data = _classify_port(port)
            if rel_data is None:
                continue
            rel_type, rel_label, base_weight, tech_id, tech_name = rel_data
            key = (attacker_id, target_id, rel_type)
            if key in existing:
                continue
            expl = _exploitability(base_weight, port_findings)
            augmented.append(SimpleNamespace(
                id=uuid.uuid4(),
                owner_id=attacker.owner_id,
                source_id=attacker.id,
                target_id=asset.id,
                relationship=rel_type,
                label=f"{rel_label} on port {port}",
                weight=base_weight,
                exploitability_score=expl,
                technique_id=tech_id,
                technique_name=tech_name,
                inferred_from="attacker_origin",
                meta={
                    "port": port,
                    "service": rel_label,
                    "cves": [f.cve_id for f in port_findings if f.cve_id][:5],
                    "kev": any(f.is_kev for f in port_findings),
                    "max_cvss": max([float(f.cvss_score) for f in port_findings if f.cvss_score] or [0.0]),
                    "max_epss": max([float(f.epss_score) for f in port_findings if f.epss_score] or [0.0]),
                    "origin": "attacker",
                },
            ))
            existing.add(key)

    return augmented


# ---------------------------------------------------------------------------
# Topology rebuild
# ---------------------------------------------------------------------------

def rebuild_topology(database: Session, owner_id: str) -> int:
    try:
        owner_uuid = UUID(owner_id)
    except (TypeError, ValueError):
        return 0

    ensure_attacker_asset(database, owner_uuid)

    assets = database.query(Asset).filter(Asset.owner_id == owner_uuid).all()
    if not assets:
        return 0

    findings_map: dict[str, list[Finding]] = {
        str(a.id): database.query(Finding).filter(Finding.asset_id == a.id).all()
        for a in assets
    }

    manual_edge_keys = {
        (str(edge.source_id), str(edge.target_id), edge.relationship)
        for edge in database.query(AssetEdge)
        .filter(AssetEdge.owner_id == owner_uuid, AssetEdge.inferred_from == "manual")
        .all()
    }

    try:
        database.query(AssetEdge).filter(
            AssetEdge.owner_id == owner_uuid,
            or_(AssetEdge.inferred_from.is_(None), AssetEdge.inferred_from != "manual"),
        ).delete(synchronize_session="fetch")
        database.flush()

        inferred = [
            edge
            for edge in _infer_edges(assets, findings_map)
            if (edge["source_id"], edge["target_id"], edge["relationship"]) not in manual_edge_keys
        ]

        for e in inferred:
            database.add(AssetEdge(
                owner_id=owner_uuid,
                source_id=UUID(e["source_id"]),
                target_id=UUID(e["target_id"]),
                relationship=e["relationship"],
                label=e["label"],
                weight=e["weight"],
                exploitability_score=e["exploitability_score"],
                technique_id=e["technique_id"],
                technique_name=e["technique_name"],
                inferred_from=e["inferred_from"],
                meta=e.get("meta") or {},
            ))

        database.commit()
    except IntegrityError:
        database.rollback()
        logger.warning("topology: skipped rebuild for owner %s because duplicate edges already exist", owner_id)
        return 0
    logger.info("topology: rebuilt %d edges for owner %s", len(inferred), owner_id)
    return len(inferred)


# ---------------------------------------------------------------------------
# Graph retrieval (React Flow format)
# ---------------------------------------------------------------------------

def _fallback_circular_positions(assets: list[Asset]) -> dict[str, tuple[float, float]]:
    gateways = [a for a in assets if _is_gateway(a.ip_address or a.target or "")]
    others   = sorted(
        [a for a in assets if not _is_gateway(a.ip_address or a.target or "")],
        key=lambda a: (a.risk_score or 0.0),
        reverse=True,
    )
    positions: dict[str, tuple[float, float]] = {}
    for i, gw in enumerate(gateways):
        angle = (2 * math.pi * i / max(len(gateways), 1)) + math.pi / 4
        positions[str(gw.id)] = (round(150 * math.cos(angle), 1),
                                  round(150 * math.sin(angle), 1))
    n = len(others)
    radius = max(320, n * 60)
    for i, asset in enumerate(others):
        angle = (2 * math.pi * i / max(n, 1)) - math.pi / 2
        positions[str(asset.id)] = (round(radius * math.cos(angle), 1),
                                     round(radius * math.sin(angle), 1))
    return positions


def _attacker_centric_positions(
    assets: list[Asset],
    graph: nx.DiGraph,
    role_map: dict[str, str],
    risk_map: dict[str, float],
    finding_counts: dict[str, int],
) -> dict[str, tuple[float, float]]:
    attacker = _select_primary_attacker(assets)
    if attacker is None:
        return _fallback_circular_positions(assets)

    attacker_id = str(attacker.id)
    positions: dict[str, tuple[float, float]] = {attacker_id: (0.0, 0.0)}
    undirected = graph.to_undirected()

    rings: dict[int, list[Asset]] = {}
    for asset in assets:
        aid = str(asset.id)
        if aid == attacker_id:
            continue
        role = role_map.get(aid, "TARGET")
        risk = risk_map.get(aid, 0.0)
        vulnerable = finding_counts.get(aid, 0) > 0 or risk >= 50

        if role in {"WEB", "DATABASE", "SERVER"}:
            ring = 1 if vulnerable else 2
        elif role == "TARGET":
            ring = 2 if vulnerable else 3
        elif role == "INFRASTRUCTURE":
            ring = 4
        else:
            ring = 3

        try:
            distance = nx.shortest_path_length(undirected, source=attacker_id, target=aid)
            ring = max(ring, min(max(int(distance), 1), 4))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pass

        rings.setdefault(ring, []).append(asset)

    for distance, ring_assets in rings.items():
        ordered = sorted(
            ring_assets,
            key=lambda asset: (
                ROLE_ORDER.get(role_map.get(str(asset.id), "TARGET"), 5),
                -(risk_map.get(str(asset.id), 0.0)),
                asset.hostname or asset.name or asset.ip_address or asset.target or "",
            ),
        )
        radius = 220 + (distance - 1) * 220
        start_angle = -math.pi / 2
        for index, asset in enumerate(ordered):
            angle = start_angle + (2 * math.pi * index / max(len(ordered), 1))
            positions[str(asset.id)] = (
                round(radius * math.cos(angle), 1),
                round(radius * math.sin(angle), 1),
            )

    return positions


def get_graph(
    database: Session,
    owner_id: str,
    asset_zone: AssetZone | None = None,
    vulnerable_only: bool = False,
    critical_only: bool = False,
    managed_only: bool = True,
) -> dict:
    try:
        owner_uuid = UUID(owner_id)
    except (TypeError, ValueError):
        return {"nodes": [], "edges": [], "meta": {"total_assets": 0, "total_edges": 0, "attack_paths": []}}

    attacker_asset = ensure_attacker_asset(database, owner_uuid)

    query = database.query(Asset).filter(Asset.owner_id == owner_uuid)
    if managed_only:
        query = query.filter(Asset.managed.is_(True))
    query = query.filter(Asset.topology_visible.is_(True))
    if asset_zone is None:
        query = query.filter(Asset.asset_zone == AssetZone.LAB)
    else:
        query = query.filter(Asset.asset_zone == asset_zone)

    assets = query.all()
    if attacker_asset and attacker_asset not in assets:
        assets.append(attacker_asset)
    assets, attacker_asset = _dedupe_attackers(assets)
    if not assets:
        return {"nodes": [], "edges": [], "meta": {"total_assets": 0, "total_edges": 0, "attack_paths": []}}

    excluded_gateways = sum(1 for a in assets if _is_gateway(a.ip_address or a.target or ""))
    excluded_vmware = sum(1 for a in assets if _is_vmware_device(a))
    excluded_nat = sum(1 for a in assets if _is_nat_device(a))
    assets = [a for a in assets if not _should_exclude_asset(a)]
    if not assets:
        return {
            "nodes": [],
            "edges": [],
            "meta": {
                "total_assets": 0,
                "total_edges": 0,
                "attack_paths": [],
                "excluded": {
                    "gateways": excluded_gateways,
                    "vmware": excluded_vmware,
                    "nat": excluded_nat,
                },
            },
        }

    findings_map: dict[str, list[Finding]] = {
        str(a.id): database.query(Finding).filter(Finding.asset_id == a.id).all()
        for a in assets
    }

    if vulnerable_only:
        assets = [a for a in assets if findings_map.get(str(a.id))]
        if attacker_asset and attacker_asset not in assets:
            assets.append(attacker_asset)
        if not assets:
            return {"nodes": [], "edges": [], "meta": {"total_assets": 0, "total_edges": 0, "attack_paths": []}}

    if critical_only:
        assets = [
            a for a in assets
            if any(f.severity == FindingSeverity.CRITICAL for f in findings_map.get(str(a.id), []))
        ]
        if attacker_asset and attacker_asset not in assets:
            assets.append(attacker_asset)
        if not assets:
            return {"nodes": [], "edges": [], "meta": {"total_assets": 0, "total_edges": 0, "attack_paths": []}}

    asset_ids = {a.id for a in assets}
    db_edges = (
        database.query(AssetEdge)
        .filter(AssetEdge.owner_id == owner_uuid)
        .filter(AssetEdge.source_id.in_(asset_ids), AssetEdge.target_id.in_(asset_ids))
        .all()
    )
    db_edges = _augment_attacker_edges(assets, db_edges, findings_map)

    analysis_g = build_analysis_graph(assets, db_edges)

    centrality: dict[str, float] = {}
    if len(analysis_g.nodes) > 1:
        try:
            centrality = nx.betweenness_centrality(
                analysis_g, weight="inv_weight", normalized=True
            )
        except Exception:
            pass

    open_ports_map: dict[str, list[int]] = {}
    role_map: dict[str, str] = {}
    risk_map: dict[str, float] = {}
    finding_counts: dict[str, int] = {}
    for asset in assets:
        aid = str(asset.id)
        af = findings_map.get(aid, [])
        ports = sorted({f.port for f in af if f.port})
        open_ports_map[aid] = ports
        role_map[aid] = _asset_role(asset, set(ports))
        risk_map[aid] = float(asset.risk_score or 0.0)
        finding_counts[aid] = len(af)

    def _sort_key(asset: Asset) -> tuple[float, int, str]:
        crit = asset.criticality.value if hasattr(asset.criticality, "value") else str(asset.criticality)
        crit_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(crit, 0)
        return (float(asset.risk_score or 0.0), crit_rank, asset.name or "")

    attacker_asset = _select_primary_attacker(assets)
    visible_assets = assets
    hidden_assets: list[Asset] = []
    if len(assets) > MAX_TOPOLOGY_NODES:
        ordered = sorted(assets, key=_sort_key, reverse=True)
        visible_assets = ordered[:MAX_TOPOLOGY_NODES]
        if attacker_asset and attacker_asset not in visible_assets:
            visible_assets = visible_assets[:-1] + [attacker_asset]
        hidden_assets = [a for a in ordered if a not in visible_assets]

    positions = _attacker_centric_positions(
        visible_assets,
        analysis_g,
        role_map,
        risk_map,
        finding_counts,
    )

    # Nodes
    nodes = []
    for asset in visible_assets:
        aid = str(asset.id)
        af  = findings_map.get(aid, [])
        open_ports = open_ports_map.get(aid, [])
        critical_cve_count = sum(1 for f in af if f.severity == FindingSeverity.CRITICAL and f.cve_id)
        critical_findings = sum(1 for f in af if f.severity == FindingSeverity.CRITICAL)
        nodes.append({
            "id": aid,
            "type": "assetNode",
            "position": {"x": positions.get(aid, (0, 0))[0],
                         "y": positions.get(aid, (0, 0))[1]},
            "data": {
                "label":        asset.name or asset.ip_address or asset.target,
                "ip":           asset.ip_address or asset.target,
                "alias":        _asset_alias(asset),
                "role":         role_map.get(aid, "TARGET"),
                "is_attacker":  _is_kali_asset(asset),
                "central_node": bool(attacker_asset and aid == str(attacker_asset.id)),
                "attack_state": "Untouched",
                "name":         asset.name,
                "hostname":     asset.hostname,
                "risk_score":   round(asset.risk_score or 0.0, 1),
                "criticality":  asset.criticality.value if hasattr(asset.criticality, "value") else str(asset.criticality),
                "exposure":     asset.exposure.value    if hasattr(asset.exposure,    "value") else str(asset.exposure),
                "is_gateway":   _is_gateway(asset.ip_address or asset.target or ""),
                "managed":      bool(asset.managed),
                "topology_visible": bool(asset.topology_visible),
                "attack_surface_enabled": bool(asset.attack_surface_enabled),
                "asset_zone":   asset.asset_zone.value if hasattr(asset.asset_zone, "value") else str(asset.asset_zone),
                "open_ports":   open_ports,
                "port_count":   len(open_ports),
                "finding_count": finding_counts.get(aid, len(af)),
                "critical_finding_count": critical_findings,
                "critical_cve_count": critical_cve_count,
                "kev_count":    sum(1 for f in af if f.is_kev),
                "os_fingerprint": asset.os_fingerprint,
                "centrality":   round(centrality.get(aid, 0.0), 4),
            },
        })

    cluster_map: dict[str, list[Asset]] = {}
    if hidden_assets:
        for asset in hidden_assets:
            key = _territory_group(asset)
            cluster_map.setdefault(key, []).append(asset)

        cluster_labels = {
            "lab": "LAB Territory",
            "infrastructure": "Infrastructure",
            "external": "External",
            "unknown": "Unknown",
        }
        cluster_keys = [k for k in ("lab", "infrastructure", "external", "unknown") if cluster_map.get(k)]

        radius = max(420, len(visible_assets) * 60)
        for i, key in enumerate(cluster_keys):
            angle = (2 * math.pi * i / max(len(cluster_keys), 1)) + math.pi / 6
            cid = f"cluster:{key}"
            nodes.append({
                "id": cid,
                "type": "clusterNode",
                "position": {"x": round(radius * math.cos(angle), 1), "y": round(radius * math.sin(angle), 1)},
                "data": {
                    "label": cluster_labels.get(key, "Grouped assets"),
                    "group": key,
                    "count": len(cluster_map[key]),
                },
            })

    # Edges — ALL edges for display (MultiDiGraph behaviour via React Flow)
    rf_edges = []
    visible_ids = {str(a.id) for a in visible_assets}
    hidden_cluster_ids = {}
    for key, assets_in_group in cluster_map.items():
        for asset in assets_in_group:
            hidden_cluster_ids[str(asset.id)] = f"cluster:{key}"

    aggregated: dict[tuple[str, str], dict] = {}
    for edge in db_edges:
        src = str(edge.source_id)
        tgt = str(edge.target_id)
        expl = edge.exploitability_score or edge.weight

        if src in visible_ids and tgt in visible_ids:
            rf_edges.append({
                "id":     str(edge.id),
                "source": src,
                "target": tgt,
                "label":  edge.label or edge.relationship,
                "type":   "smoothstep",
                "animated": expl >= 7.0,
                "data": {
                    "relationship":      edge.relationship,
                    "weight":            edge.weight,
                    "exploitability":    expl,
                    "technique_id":      edge.technique_id,
                    "technique_name":    edge.technique_name,
                    "inferred_from":     edge.inferred_from,
                    "meta":              edge.meta or {},
                },
                "style":      _edge_style(expl),
                "labelStyle": {"fontSize": 10, "fill": "#94a3b8"},
            })
            continue

        src_cluster = hidden_cluster_ids.get(src)
        tgt_cluster = hidden_cluster_ids.get(tgt)
        if not src_cluster and src not in visible_ids:
            continue
        if not tgt_cluster and tgt not in visible_ids:
            continue

        agg_src = src_cluster or src
        agg_tgt = tgt_cluster or tgt
        key = (agg_src, agg_tgt)
        payload = aggregated.get(key)
        if payload is None:
            aggregated[key] = {
                "id": f"agg:{agg_src}->{agg_tgt}",
                "source": agg_src,
                "target": agg_tgt,
                "count": 1,
                "max_expl": expl,
            }
        else:
            payload["count"] += 1
            payload["max_expl"] = max(payload["max_expl"], expl)

    for payload in aggregated.values():
        expl = payload["max_expl"]
        rf_edges.append({
            "id": payload["id"],
            "source": payload["source"],
            "target": payload["target"],
            "label": f"grouped ×{payload['count']}",
            "type": "smoothstep",
            "animated": False,
            "data": {
                "relationship": "grouped",
                "weight": expl,
                "exploitability": expl,
                "technique_id": "",
                "technique_name": "Grouped assets",
                "inferred_from": "cluster",
            },
            "style": _edge_style(expl),
            "labelStyle": {"fontSize": 9, "fill": "#94a3b8"},
        })

    return {
        "nodes": nodes,
        "edges": rf_edges,
        "meta": {
            "total_assets":  len(assets),
            "total_edges":   len(rf_edges),
            "attack_paths":  [],
            "clustered_assets": len(hidden_assets),
            "excluded": {
                "gateways": excluded_gateways,
                "vmware": excluded_vmware,
                "nat": excluded_nat,
            },
        },
    }


def _edge_style(exploitability: float) -> dict:
    if exploitability >= 9.0:
        return {"stroke": "#ef4444", "strokeWidth": 3}
    if exploitability >= 7.0:
        return {"stroke": "#f97316", "strokeWidth": 2}
    if exploitability >= 5.0:
        return {"stroke": "#eab308", "strokeWidth": 2}
    if exploitability >= 3.0:
        return {"stroke": "#3b82f6", "strokeWidth": 1.5}
    return {"stroke": "#475569", "strokeWidth": 1}
