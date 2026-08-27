from __future__ import annotations

from uuid import UUID

from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session, aliased

from app.models.asset import Asset, AssetCriticality, AssetStatus, AssetType, AssetZone
from app.models.scan import Scan, ScanStatus


class AssetServiceError(Exception):
    pass


def _to_asset_status(value: str | None) -> AssetStatus | None:
    if value is None:
        return None
    try:
        return AssetStatus(value)
    except ValueError as exc:
        raise AssetServiceError("Invalid asset status filter") from exc


def _to_asset_criticality(value: str | None) -> AssetCriticality | None:
    if value is None:
        return None
    try:
        return AssetCriticality(value)
    except ValueError as exc:
        raise AssetServiceError("Invalid criticality filter") from exc


def _to_asset_type(value: str | None) -> AssetType | None:
    if value is None:
        return None
    try:
        return AssetType(value)
    except ValueError as exc:
        raise AssetServiceError("Invalid asset type filter") from exc


def _to_asset_zone(value: str | None) -> AssetZone | None:
    if value is None:
        return None
    try:
        return AssetZone(value.lower())
    except ValueError as exc:
        raise AssetServiceError("Invalid asset zone filter") from exc


def _to_scan_status(value: str | None) -> ScanStatus | None:
    if value is None:
        return None
    try:
        return ScanStatus(value)
    except ValueError as exc:
        raise AssetServiceError("Invalid last scan status filter") from exc


def list_assets(
    database: Session,
    owner_id: str,
    search: str | None,
    asset_status: str | None,
    criticality: str | None,
    asset_type: str | None,
    discovery_status: str | None,
    last_scan_status: str | None,
    managed: bool | None,
    asset_zone: str | None,
    limit: int,
    offset: int,
) -> dict:
    try:
        owner_uuid = UUID(owner_id)
    except (TypeError, ValueError) as exc:
        raise AssetServiceError("Invalid user identifier") from exc

    resolved_asset_status = _to_asset_status(asset_status)
    resolved_criticality = _to_asset_criticality(criticality)
    resolved_asset_type = _to_asset_type(asset_type)
    resolved_last_scan_status = _to_scan_status(last_scan_status)
    resolved_asset_zone = _to_asset_zone(asset_zone)

    latest_scan_subquery = (
        database.query(
            Scan.asset_id.label("asset_id"),
            func.max(Scan.created_at).label("latest_scan_created_at"),
        )
        .group_by(Scan.asset_id)
        .subquery()
    )

    latest_scan = aliased(Scan)

    query = (
        database.query(
            Asset,
            latest_scan.status.label("last_scan_status"),
            latest_scan.progress.label("last_scan_progress"),
            latest_scan.created_at.label("last_scanned_at"),
        )
        .outerjoin(latest_scan_subquery, latest_scan_subquery.c.asset_id == Asset.id)
        .outerjoin(
            latest_scan,
            and_(
                latest_scan.asset_id == Asset.id,
                latest_scan.created_at == latest_scan_subquery.c.latest_scan_created_at,
            ),
        )
        .filter(Asset.owner_id == owner_uuid)
    )

    if search:
        wildcard = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Asset.name.ilike(wildcard),
                Asset.target.ilike(wildcard),
                Asset.ip_address.ilike(wildcard),
                Asset.hostname.ilike(wildcard),
                Asset.mac_address.ilike(wildcard),
            )
        )

    if resolved_asset_status is not None:
        query = query.filter(Asset.status == resolved_asset_status)
    if resolved_criticality is not None:
        query = query.filter(Asset.criticality == resolved_criticality)
    if resolved_asset_type is not None:
        query = query.filter(Asset.asset_type == resolved_asset_type)
    if managed is not None:
        query = query.filter(Asset.managed.is_(managed))
    if resolved_asset_zone is not None:
        query = query.filter(Asset.asset_zone == resolved_asset_zone)
    if discovery_status:
        query = query.filter(func.lower(func.coalesce(Asset.discovery_status, "unknown")) == discovery_status.lower())
    if resolved_last_scan_status is not None:
        query = query.filter(latest_scan.status == resolved_last_scan_status)

    total = query.with_entities(func.count(func.distinct(Asset.id))).scalar() or 0

    rows = (
        query.order_by(Asset.updated_at.desc(), Asset.name.asc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    items = [
        {
            "id": asset.id,
            "name": asset.name,
            "target": asset.target,
            "ip_address": asset.ip_address,
            "hostname": asset.hostname,
            "mac_address": asset.mac_address,
            "asset_type": asset.asset_type.value,
            "status": asset.status.value,
            "criticality": asset.criticality.value,
            "exposure": asset.exposure.value if hasattr(asset, "exposure") and asset.exposure else "internal",
            "managed": bool(asset.managed),
            "asset_zone": asset.asset_zone.value if hasattr(asset.asset_zone, "value") else str(asset.asset_zone),
            "topology_visible": bool(asset.topology_visible),
            "attack_surface_enabled": bool(asset.attack_surface_enabled),
            "risk_score": asset.risk_score,
            "discovery_status": asset.discovery_status,
            "os_fingerprint": asset.os_fingerprint,
            "last_scan_status": last_scan_status_value.value if hasattr(last_scan_status_value, "value") else last_scan_status_value,
            "last_scan_progress": last_scan_progress,
            "last_scanned_at": last_scanned_at,
            "updated_at": asset.updated_at,
        }
        for asset, last_scan_status_value, last_scan_progress, last_scanned_at in rows
    ]

    return {
        "items": items,
        "total": int(total),
        "limit": limit,
        "offset": offset,
    }
