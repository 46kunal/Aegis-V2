from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, case, func
from sqlalchemy.orm import Session, aliased

from app.models.asset import Asset
from app.models.finding import Finding, FindingSeverity
from app.models.report import Report
from app.models.scan import Scan, ScanMode, ScanStatus, ScanType

logger = logging.getLogger("aegis.scan_engine")

STALE_SCAN_TIMEOUT_MINUTES = 30


class ScanEngineError(Exception):
    pass


def _to_scan_mode(value: str) -> ScanMode:
    try:
        return ScanMode(value)
    except ValueError as exc:
        raise ScanEngineError("Invalid scan mode") from exc


def _scan_query_for_owner(database: Session, owner_uuid: UUID):
    latest_report_subquery = (
        database.query(
            Report.scan_id.label("scan_id"),
            func.max(func.coalesce(Report.generated_at, Report.created_at)).label("latest_report_timestamp"),
        )
        .group_by(Report.scan_id)
        .subquery()
    )

    latest_report = aliased(Report)

    return (
        database.query(
            Scan.id.label("scan_id"),
            Scan.asset_id.label("asset_id"),
            Asset.name.label("asset_name"),
            Asset.target.label("asset_target"),
            Scan.mode.label("mode"),
            Scan.status.label("status"),
            Scan.progress.label("progress"),
            Scan.summary.label("summary"),
            Scan.error_message.label("error_message"),
            Scan.celery_task_id.label("celery_task_id"),
            func.count(Finding.id).label("finding_count"),
            func.count(case((Finding.severity == FindingSeverity.CRITICAL, 1))).label("critical_finding_count"),
            latest_report.id.label("latest_report_id"),
            Scan.created_at.label("created_at"),
            Scan.started_at.label("started_at"),
            Scan.completed_at.label("completed_at"),
        )
        .join(Asset, Scan.asset_id == Asset.id)
        .outerjoin(Finding, Finding.scan_id == Scan.id)
        .outerjoin(latest_report_subquery, latest_report_subquery.c.scan_id == Scan.id)
        .outerjoin(
            latest_report,
            and_(
                latest_report.scan_id == Scan.id,
                func.coalesce(latest_report.generated_at, latest_report.created_at)
                == latest_report_subquery.c.latest_report_timestamp,
            ),
        )
        .filter(Asset.owner_id == owner_uuid)
        .group_by(
            Scan.id,
            Asset.id,
            Asset.name,
            Asset.target,
            Scan.celery_task_id,
            latest_report.id,
        )
    )


def create_scan_job(database: Session, owner_id: str, asset_id: UUID, mode: str) -> Scan:
    asset = database.query(Asset).filter(Asset.id == asset_id, Asset.owner_id == UUID(owner_id)).first()
    if asset is None:
        raise ScanEngineError("Asset not found")

    scan = Scan(
        asset_id=asset.id,
        requested_by_id=UUID(owner_id),
        mode=_to_scan_mode(mode),
        scan_type=ScanType.NETWORK,
        status=ScanStatus.QUEUED,
        progress=0,
        summary="Scan queued",
    )
    database.add(scan)
    database.commit()
    database.refresh(scan)
    return scan


def list_scan_jobs(database: Session, owner_id: str, limit: int, offset: int) -> dict:
    try:
        owner_uuid = UUID(owner_id)
    except (TypeError, ValueError) as exc:
        raise ScanEngineError("Invalid user identifier") from exc

    base_query = _scan_query_for_owner(database=database, owner_uuid=owner_uuid)
    total = (
        database.query(func.count(Scan.id))
        .join(Asset, Scan.asset_id == Asset.id)
        .filter(Asset.owner_id == owner_uuid)
        .scalar()
        or 0
    )

    rows = base_query.order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()

    return {
        "items": [
            {
                "scan_id": row.scan_id,
                "asset_id": row.asset_id,
                "asset_name": row.asset_name,
                "asset_target": row.asset_target,
                "mode": row.mode.value if hasattr(row.mode, "value") else str(row.mode),
                "status": row.status.value if hasattr(row.status, "value") else str(row.status),
                "progress": int(row.progress or 0),
                "summary": row.summary,
                "error_message": row.error_message,
                "celery_task_id": row.celery_task_id,
                "finding_count": int(row.finding_count or 0),
                "critical_finding_count": int(row.critical_finding_count or 0),
                "latest_report_id": row.latest_report_id,
                "created_at": row.created_at,
                "started_at": row.started_at,
                "completed_at": row.completed_at,
            }
            for row in rows
        ],
        "total": int(total),
        "limit": limit,
        "offset": offset,
    }


def get_scan_job_detail(database: Session, owner_id: str, scan_id: str) -> dict:
    try:
        owner_uuid = UUID(owner_id)
        scan_uuid = UUID(scan_id)
    except (TypeError, ValueError) as exc:
        raise ScanEngineError("Invalid identifier") from exc

    row = _scan_query_for_owner(database=database, owner_uuid=owner_uuid).filter(Scan.id == scan_uuid).first()
    if row is None:
        raise ScanEngineError("Scan not found")

    findings = (
        database.query(Finding)
        .filter(Finding.scan_id == scan_uuid)
        .order_by(Finding.created_at.desc())
        .limit(50)
        .all()
    )

    return {
        "scan_id": row.scan_id,
        "asset_id": row.asset_id,
        "asset_name": row.asset_name,
        "asset_target": row.asset_target,
        "mode": row.mode.value if hasattr(row.mode, "value") else str(row.mode),
        "status": row.status.value if hasattr(row.status, "value") else str(row.status),
        "progress": int(row.progress or 0),
        "summary": row.summary,
        "error_message": row.error_message,
        "celery_task_id": row.celery_task_id,
        "finding_count": int(row.finding_count or 0),
        "critical_finding_count": int(row.critical_finding_count or 0),
        "latest_report_id": row.latest_report_id,
        "created_at": row.created_at,
        "started_at": row.started_at,
        "completed_at": row.completed_at,
        "findings": [
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                "cvss_score": float(finding.cvss_score) if finding.cvss_score is not None else None,
                "port": finding.port,
                "protocol": finding.protocol,
                "detected_product": finding.detected_product,
                "detected_version": finding.detected_version,
                "cpe": finding.cpe,
                "script_output": finding.script_output,
                "raw_service": finding.raw_service,
                "normalized_service": finding.normalized_service,
                "extracted_version": finding.extracted_version,
                "generated_cpe": finding.generated_cpe,
                "cve_id": finding.cve_id,
                "cwe_id": finding.cwe_id,
                "cvss_vector": finding.cvss_vector,
                "epss_score": float(finding.epss_score) if finding.epss_score is not None else None,
                "references": finding.references,
                "published_date": finding.published_date,
                "created_at": finding.created_at,
            }
            for finding in findings
        ],
    }


def retry_scan_job(database: Session, owner_id: str, scan_id: str) -> Scan:
    try:
        owner_uuid = UUID(owner_id)
        scan_uuid = UUID(scan_id)
    except (TypeError, ValueError) as exc:
        raise ScanEngineError("Invalid identifier") from exc

    existing_scan = (
        database.query(Scan)
        .join(Asset, Scan.asset_id == Asset.id)
        .filter(Scan.id == scan_uuid, Asset.owner_id == owner_uuid)
        .first()
    )
    if existing_scan is None:
        raise ScanEngineError("Scan not found")
    if existing_scan.status != ScanStatus.FAILED:
        raise ScanEngineError("Only failed scans can be retried")

    retried_scan = Scan(
        asset_id=existing_scan.asset_id,
        requested_by_id=owner_uuid,
        mode=existing_scan.mode,
        scan_type=existing_scan.scan_type,
        status=ScanStatus.QUEUED,
        progress=0,
        summary="Scan retry queued",
    )
    database.add(retried_scan)
    database.commit()
    database.refresh(retried_scan)
    return retried_scan


def mark_scan_running(database: Session, scan: Scan, task_id: str) -> None:
    scan.status = ScanStatus.RUNNING
    scan.progress = 10
    scan.celery_task_id = task_id
    scan.started_at = datetime.now(UTC)
    scan.error_message = None
    database.commit()


def mark_scan_progress(database: Session, scan: Scan, progress: int, summary: str | None = None) -> None:
    bounded = max(0, min(100, progress))
    scan.progress = bounded
    if summary is not None:
        scan.summary = summary
    database.commit()


def mark_scan_completed(database: Session, scan: Scan, raw_xml: str, summary: str) -> None:
    scan.status = ScanStatus.COMPLETED
    scan.progress = 100
    scan.raw_xml = raw_xml
    scan.summary = summary
    scan.completed_at = datetime.now(UTC)
    database.commit()


def mark_scan_failed(database: Session, scan: Scan, error_message: str) -> None:
    scan.status = ScanStatus.FAILED
    scan.error_message = error_message
    scan.summary = "Scan failed"
    scan.completed_at = datetime.now(UTC)
    database.commit()


def cancel_scan_job(database: Session, owner_id: str, scan_id: str) -> Scan:
    try:
        owner_uuid = UUID(owner_id)
        scan_uuid = UUID(scan_id)
    except (TypeError, ValueError) as exc:
        raise ScanEngineError("Invalid identifier") from exc

    scan = (
        database.query(Scan)
        .join(Asset, Scan.asset_id == Asset.id)
        .filter(Scan.id == scan_uuid, Asset.owner_id == owner_uuid)
        .first()
    )
    if scan is None:
        raise ScanEngineError("Scan not found")
    if scan.status not in (ScanStatus.QUEUED, ScanStatus.RUNNING):
        raise ScanEngineError("Only queued or running scans can be cancelled")

    # Revoke the celery task if possible
    if scan.celery_task_id:
        try:
            from app.workers.celery_app import celery_app as celery_instance
            celery_instance.control.revoke(scan.celery_task_id, terminate=True)
        except Exception:
            logger.warning("Failed to revoke celery task %s", scan.celery_task_id)

    scan.status = ScanStatus.CANCELLED
    scan.summary = "Scan cancelled by user"
    scan.completed_at = datetime.now(UTC)
    database.commit()
    database.refresh(scan)
    return scan


def timeout_stale_scans(database: Session) -> int:
    """Mark scans stuck in queued/running for longer than the timeout as failed.

    Returns the number of scans that were timed out.
    """
    cutoff = datetime.now(UTC) - timedelta(minutes=STALE_SCAN_TIMEOUT_MINUTES)
    stale_scans = (
        database.query(Scan)
        .filter(
            Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]),
            Scan.created_at < cutoff,
        )
        .all()
    )

    for scan in stale_scans:
        scan.status = ScanStatus.FAILED
        scan.error_message = "Scan timed out (stale — no worker progress)"
        scan.summary = "Scan failed"
        scan.completed_at = datetime.now(UTC)

    if stale_scans:
        database.commit()
        logger.info("timeout_stale_scans: marked %d stale scans as failed", len(stale_scans))

    return len(stale_scans)
