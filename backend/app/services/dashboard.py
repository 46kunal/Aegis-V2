from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
import xml.etree.ElementTree as ET
from uuid import UUID

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetExposure, AssetStatus
from app.models.finding import Finding, FindingSeverity
from app.models.scan import Scan, ScanStatus


class DashboardServiceError(Exception):
    pass


def _extract_open_ports(raw_xml: str | None) -> list[tuple[str, str, str]]:
    if not raw_xml:
        return []

    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError:
        return []

    exposed_ports: list[tuple[str, str, str]] = []
    for port in root.findall("host/ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue

        service_node = port.find("service")
        service_name = (service_node.get("name") if service_node is not None else None) or "unknown"
        exposed_ports.append(
            (
                port.get("portid") or "unknown",
                port.get("protocol") or "tcp",
                service_name,
            )
        )

    return exposed_ports


def get_dashboard_summary(database: Session, owner_id: str) -> dict:
    try:
        owner_uuid = UUID(owner_id)
    except (TypeError, ValueError) as exc:
        raise DashboardServiceError("Invalid user identifier") from exc

    asset_counts = (
        database.query(
            func.count(Asset.id).label("total_assets"),
            func.count(case((Asset.status == AssetStatus.ACTIVE, 1))).label("active_assets"),
        )
        .filter(Asset.owner_id == owner_uuid)
        .one()
    )

    total_scans = (
        database.query(func.count(Scan.id))
        .join(Asset, Scan.asset_id == Asset.id)
        .filter(Asset.owner_id == owner_uuid)
        .scalar()
        or 0
    )

    finding_counts = (
        database.query(
            func.count(Finding.id).label("total_findings"),
            func.count(case((Finding.severity == FindingSeverity.CRITICAL, 1))).label("critical_findings"),
        )
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Asset.owner_id == owner_uuid)
        .one()
    )

    finding_severity_rows = (
        database.query(Finding.severity, func.count(Finding.id).label("count"))
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Asset.owner_id == owner_uuid)
        .group_by(Finding.severity)
        .all()
    )

    recent_scan_rows = (
        database.query(
            Scan.id.label("scan_id"),
            Asset.id.label("asset_id"),
            Asset.name.label("asset_name"),
            Scan.mode,
            Scan.status,
            Scan.progress,
            Scan.created_at,
        )
        .join(Asset, Scan.asset_id == Asset.id)
        .filter(Asset.owner_id == owner_uuid)
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )

    # Use stored contextual risk_score (computed by risk_engine after each scan)
    risky_asset_rows = (
        database.query(
            Asset.id.label("asset_id"),
            Asset.name.label("asset_name"),
            Asset.target.label("target"),
            Asset.criticality.label("criticality"),
            Asset.exposure.label("exposure"),
            Asset.risk_score.label("risk_score"),
            func.count(Finding.id).label("findings"),
            func.count(case((Finding.severity == FindingSeverity.CRITICAL, 1))).label("critical_findings"),
            func.count(case((Finding.is_kev.is_(True), 1))).label("kev_findings"),
        )
        .outerjoin(Finding, Finding.asset_id == Asset.id)
        .filter(Asset.owner_id == owner_uuid)
        .group_by(Asset.id, Asset.name, Asset.target, Asset.criticality, Asset.exposure, Asset.risk_score)
        .order_by(func.coalesce(Asset.risk_score, 0).desc(), func.count(Finding.id).desc(), Asset.name.asc())
        .limit(5)
        .all()
    )

    exposure_rows = (
        database.query(Asset.exposure, func.count(Asset.id).label("count"))
        .filter(Asset.owner_id == owner_uuid)
        .group_by(Asset.exposure)
        .all()
    )
    exposure_breakdown = {
        e.value: 0 for e in AssetExposure
    }
    for row in exposure_rows:
        key = row.exposure.value if hasattr(row.exposure, "value") else str(row.exposure)
        if key in exposure_breakdown:
            exposure_breakdown[key] = int(row.count or 0)

    kev_total = (
        database.query(func.count(Finding.id))
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Asset.owner_id == owner_uuid, Finding.is_kev.is_(True))
        .scalar()
        or 0
    )

    completed_scan_xml_rows = (
        database.query(Scan.raw_xml)
        .join(Asset, Scan.asset_id == Asset.id)
        .filter(Asset.owner_id == owner_uuid, Scan.status == ScanStatus.COMPLETED)
        .order_by(Scan.created_at.desc())
        .limit(150)
        .all()
    )

    port_counter: Counter[tuple[str, str, str]] = Counter()
    for row in completed_scan_xml_rows:
        for item in _extract_open_ports(row.raw_xml):
            port_counter[item] += 1

    top_exposed_ports = [
        {
            "port": port,
            "protocol": protocol,
            "service": service,
            "count": count,
        }
        for (port, protocol, service), count in port_counter.most_common(8)
    ]

    utc_today = datetime.now(UTC).date()
    trend_start = utc_today - timedelta(days=13)
    trend_start_dt = datetime.combine(trend_start, datetime.min.time(), tzinfo=UTC)
    trend_rows = (
        database.query(
            func.date_trunc("day", Scan.created_at).label("day"),
            func.count(Scan.id).label("total"),
            func.count(case((Scan.status == ScanStatus.COMPLETED, 1))).label("completed"),
            func.count(case((Scan.status == ScanStatus.FAILED, 1))).label("failed"),
        )
        .join(Asset, Scan.asset_id == Asset.id)
        .filter(Asset.owner_id == owner_uuid, Scan.created_at >= trend_start_dt)
        .group_by(func.date_trunc("day", Scan.created_at))
        .order_by(func.date_trunc("day", Scan.created_at).asc())
        .all()
    )

    trend_map: dict[str, dict[str, int]] = {}
    for row in trend_rows:
        day_label = row.day.date().isoformat()
        trend_map[day_label] = {
            "total": int(row.total or 0),
            "completed": int(row.completed or 0),
            "failed": int(row.failed or 0),
        }

    scan_trends = []
    for offset in range(14):
        day = trend_start + timedelta(days=offset)
        label = day.isoformat()
        point = trend_map.get(label, {"total": 0, "completed": 0, "failed": 0})
        scan_trends.append({"date": label, **point})

    severity_bucket = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for row in finding_severity_rows:
        key = row.severity.value if hasattr(row.severity, "value") else str(row.severity)
        if key in severity_bucket:
            severity_bucket[key] = int(row.count or 0)

    return {
        "total_assets": int(asset_counts.total_assets or 0),
        "active_assets": int(asset_counts.active_assets or 0),
        "total_scans": int(total_scans),
        "total_findings": int(finding_counts.total_findings or 0),
        "critical_findings": int(finding_counts.critical_findings or 0),
        "findings_by_severity": [
            {"severity": "critical", "count": severity_bucket["critical"]},
            {"severity": "high", "count": severity_bucket["high"]},
            {"severity": "medium", "count": severity_bucket["medium"]},
            {"severity": "low", "count": severity_bucket["low"]},
            {"severity": "info", "count": severity_bucket["info"]},
        ],
        "top_exposed_ports": top_exposed_ports,
        "scan_trends": scan_trends,
        "recent_scans": [
            {
                "scan_id": row.scan_id,
                "asset_id": row.asset_id,
                "asset_name": row.asset_name,
                "mode": row.mode.value if hasattr(row.mode, "value") else str(row.mode),
                "status": row.status.value if hasattr(row.status, "value") else str(row.status),
                "progress": int(row.progress or 0),
                "created_at": row.created_at,
            }
            for row in recent_scan_rows
        ],
        "kev_findings": int(kev_total),
        "exposure_breakdown": [
            {"exposure": k, "count": v} for k, v in exposure_breakdown.items()
        ],
        "top_risky_assets": [
            {
                "asset_id": row.asset_id,
                "asset_name": row.asset_name,
                "target": row.target,
                "criticality": row.criticality.value if hasattr(row.criticality, "value") else str(row.criticality),
                "exposure": row.exposure.value if hasattr(row.exposure, "value") else str(row.exposure),
                "findings": int(row.findings or 0),
                "critical_findings": int(row.critical_findings or 0),
                "kev_findings": int(row.kev_findings or 0),
                "risk_score": round(float(row.risk_score or 0), 2),
            }
            for row in risky_asset_rows
        ],
    }
