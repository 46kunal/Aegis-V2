import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.asset import Asset, AssetCriticality, AssetExposure, AssetZone
from app.routes.deps import get_current_user_id
from app.schemas.assets import AssetsListResponse, BulkAssetUpdateRequest, BulkAssetUpdateResponse, PatchAssetRequest
from app.schemas.discovery import DiscoverAssetsRequest, DiscoverAssetsResponse, DiscoveredDevice
from app.services.assets import AssetServiceError, list_assets
from app.services.asset_discovery import DiscoveryError, discover_assets

router = APIRouter(prefix="/api/assets", tags=["assets"])
logger = logging.getLogger("aegis.assets")


def _parse_asset_zone(value: str | None) -> AssetZone | None:
    if value is None:
        return None
    try:
        return AssetZone(value.lower())
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid asset zone value") from exc


@router.get("", response_model=AssetsListResponse, status_code=status.HTTP_200_OK)
def get_assets(
    search: str | None = None,
    asset_status: str | None = None,
    criticality: str | None = None,
    asset_type: str | None = None,
    discovery_status: str | None = None,
    last_scan_status: str | None = None,
    managed: bool | None = None,
    asset_zone: str | None = None,
    limit: int = 25,
    offset: int = 0,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> AssetsListResponse:
    bounded_limit = max(1, min(200, limit))
    bounded_offset = max(0, offset)

    try:
        payload = list_assets(
            database=database,
            owner_id=user_id,
            search=search,
            asset_status=asset_status,
            criticality=criticality,
            asset_type=asset_type,
            discovery_status=discovery_status,
            last_scan_status=last_scan_status,
            managed=managed,
            asset_zone=asset_zone,
            limit=bounded_limit,
            offset=bounded_offset,
        )
    except AssetServiceError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return AssetsListResponse(**payload)


@router.post("/discover", response_model=DiscoverAssetsResponse, status_code=status.HTTP_200_OK)
def discover(
    payload: DiscoverAssetsRequest,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> DiscoverAssetsResponse:
    try:
        devices = discover_assets(database=database, owner_id=user_id, cidr=payload.cidr)
    except DiscoveryError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return DiscoverAssetsResponse(
        cidr=payload.cidr,
        discovered_count=len(devices),
        devices=[DiscoveredDevice(**device) for device in devices],
    )


@router.patch("/bulk", response_model=BulkAssetUpdateResponse, status_code=status.HTTP_200_OK)
def bulk_update_assets(
    payload: BulkAssetUpdateRequest,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> BulkAssetUpdateResponse:
    payload_dict = payload.model_dump() if hasattr(payload, "model_dump") else payload.dict()
    logger.info("assets_bulk_update_received", extra={"payload": payload_dict})
    try:
        owner_uuid = user_id if isinstance(user_id, UUID) else UUID(str(user_id))
    except (TypeError, ValueError) as exc:
        detail = {"message": "Invalid identifier", "user_id": str(user_id)}
        logger.warning("assets_bulk_update_invalid_user", extra={"error": str(exc), **detail})
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc

    if not payload.asset_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No assets selected")

    uuid_ids: list[UUID] = []
    ip_targets: list[str] = []
    invalid_ids: list[str] = []
    for raw_id in payload.asset_ids:
        if not raw_id:
            continue
        try:
            uuid_ids.append(UUID(raw_id))
        except (TypeError, ValueError):
            if isinstance(raw_id, str) and raw_id.strip():
                ip_targets.append(raw_id.strip())
            else:
                invalid_ids.append(str(raw_id))

    if not uuid_ids and not ip_targets:
        detail = {"message": "No valid asset identifiers provided", "invalid_ids": invalid_ids}
        logger.warning("assets_bulk_update_invalid_ids", extra=detail)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

    query = database.query(Asset).filter(Asset.owner_id == owner_uuid)
    if uuid_ids and ip_targets:
        query = query.filter(
            (Asset.id.in_(uuid_ids)) | (Asset.ip_address.in_(ip_targets)) | (Asset.target.in_(ip_targets))
        )
    elif uuid_ids:
        query = query.filter(Asset.id.in_(uuid_ids))
    else:
        query = query.filter((Asset.ip_address.in_(ip_targets)) | (Asset.target.in_(ip_targets)))

    assets = query.all()
    if not assets:
        detail = {"message": "Assets not found", "asset_ids": payload.asset_ids}
        logger.warning("assets_bulk_update_not_found", extra=detail)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)

    for asset in assets:
        if payload.criticality is not None:
            try:
                asset.criticality = AssetCriticality(payload.criticality)
            except ValueError as exc:
                detail = {"message": "Invalid criticality value", "value": payload.criticality}
                logger.warning("assets_bulk_update_invalid_criticality", extra=detail)
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc

        if payload.exposure is not None:
            try:
                asset.exposure = AssetExposure(payload.exposure)
            except ValueError as exc:
                detail = {"message": "Invalid exposure value", "value": payload.exposure}
                logger.warning("assets_bulk_update_invalid_exposure", extra=detail)
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc

        if payload.managed is not None:
            asset.managed = bool(payload.managed)
            if payload.topology_visible is None and asset.managed:
                asset.topology_visible = True
            if payload.attack_surface_enabled is None and asset.managed:
                asset.attack_surface_enabled = True

        if payload.asset_zone is not None:
            asset.asset_zone = _parse_asset_zone(payload.asset_zone)

        if payload.topology_visible is not None:
            asset.topology_visible = bool(payload.topology_visible)

        if payload.attack_surface_enabled is not None:
            asset.attack_surface_enabled = bool(payload.attack_surface_enabled)

    database.commit()
    logger.info("assets_bulk_update_success", extra={"updated": len(assets)})
    return BulkAssetUpdateResponse(updated=len(assets))


@router.patch("/{asset_id}", status_code=status.HTTP_200_OK)
def patch_asset(
    asset_id: str,
    payload: PatchAssetRequest,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> dict:
    try:
        asset_uuid = UUID(asset_id)
        owner_uuid = UUID(user_id)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid identifier") from exc

    asset = database.query(Asset).filter(Asset.id == asset_uuid, Asset.owner_id == owner_uuid).first()
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    if payload.criticality is not None:
        try:
            asset.criticality = AssetCriticality(payload.criticality)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid criticality value") from exc

    if payload.exposure is not None:
        try:
            asset.exposure = AssetExposure(payload.exposure)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid exposure value") from exc

    if payload.managed is not None:
        asset.managed = bool(payload.managed)
        if payload.topology_visible is None and asset.managed:
            asset.topology_visible = True
        if payload.attack_surface_enabled is None and asset.managed:
            asset.attack_surface_enabled = True

    if payload.asset_zone is not None:
        asset.asset_zone = _parse_asset_zone(payload.asset_zone)

    if payload.topology_visible is not None:
        asset.topology_visible = bool(payload.topology_visible)

    if payload.attack_surface_enabled is not None:
        asset.attack_surface_enabled = bool(payload.attack_surface_enabled)

    database.commit()

    # Recompute risk score immediately after criticality/exposure change
    try:
        from app.services.risk_engine import recompute_asset_risk
        recompute_asset_risk(database, asset)
    except Exception:
        pass

    return {
        "id": str(asset.id),
        "criticality": asset.criticality.value,
        "exposure": asset.exposure.value,
        "managed": bool(asset.managed),
        "asset_zone": asset.asset_zone.value if hasattr(asset.asset_zone, "value") else str(asset.asset_zone),
        "topology_visible": bool(asset.topology_visible),
        "attack_surface_enabled": bool(asset.attack_surface_enabled),
        "risk_score": asset.risk_score,
    }


@router.get("/discovered", response_model=AssetsListResponse, status_code=status.HTTP_200_OK)
def get_discovered_assets(
    search: str | None = None,
    asset_status: str | None = None,
    criticality: str | None = None,
    asset_type: str | None = None,
    discovery_status: str | None = None,
    last_scan_status: str | None = None,
    asset_zone: str | None = None,
    limit: int = 25,
    offset: int = 0,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> AssetsListResponse:
    bounded_limit = max(1, min(200, limit))
    bounded_offset = max(0, offset)

    try:
        payload = list_assets(
            database=database,
            owner_id=user_id,
            search=search,
            asset_status=asset_status,
            criticality=criticality,
            asset_type=asset_type,
            discovery_status=discovery_status,
            last_scan_status=last_scan_status,
            managed=False,
            asset_zone=asset_zone,
            limit=bounded_limit,
            offset=bounded_offset,
        )
    except AssetServiceError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return AssetsListResponse(**payload)


@router.patch("/bulk", response_model=BulkAssetUpdateResponse, status_code=status.HTTP_200_OK)
def bulk_update_assets(
    payload: BulkAssetUpdateRequest,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> BulkAssetUpdateResponse:
    payload_dict = payload.model_dump() if hasattr(payload, "model_dump") else payload.dict()
    logger.info("assets_bulk_update_received", extra={"payload": payload_dict})
    try:
        owner_uuid = user_id if isinstance(user_id, UUID) else UUID(str(user_id))
    except (TypeError, ValueError) as exc:
        detail = {"message": "Invalid identifier", "user_id": str(user_id)}
        logger.warning("assets_bulk_update_invalid_user", extra={"error": str(exc), **detail})
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc

    if not payload.asset_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No assets selected")

    uuid_ids: list[UUID] = []
    ip_targets: list[str] = []
    invalid_ids: list[str] = []
    for raw_id in payload.asset_ids:
        if not raw_id:
            continue
        try:
            uuid_ids.append(UUID(raw_id))
        except (TypeError, ValueError):
            if isinstance(raw_id, str) and raw_id.strip():
                ip_targets.append(raw_id.strip())
            else:
                invalid_ids.append(str(raw_id))

    if not uuid_ids and not ip_targets:
        detail = {"message": "No valid asset identifiers provided", "invalid_ids": invalid_ids}
        logger.warning("assets_bulk_update_invalid_ids", extra=detail)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

    query = database.query(Asset).filter(Asset.owner_id == owner_uuid)
    if uuid_ids and ip_targets:
        query = query.filter(
            (Asset.id.in_(uuid_ids)) | (Asset.ip_address.in_(ip_targets)) | (Asset.target.in_(ip_targets))
        )
    elif uuid_ids:
        query = query.filter(Asset.id.in_(uuid_ids))
    else:
        query = query.filter((Asset.ip_address.in_(ip_targets)) | (Asset.target.in_(ip_targets)))

    assets = query.all()
    if not assets:
        detail = {"message": "Assets not found", "asset_ids": payload.asset_ids}
        logger.warning("assets_bulk_update_not_found", extra=detail)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)

    for asset in assets:
        if payload.criticality is not None:
            try:
                asset.criticality = AssetCriticality(payload.criticality)
            except ValueError as exc:
                detail = {"message": "Invalid criticality value", "value": payload.criticality}
                logger.warning("assets_bulk_update_invalid_criticality", extra=detail)
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc

        if payload.exposure is not None:
            try:
                asset.exposure = AssetExposure(payload.exposure)
            except ValueError as exc:
                detail = {"message": "Invalid exposure value", "value": payload.exposure}
                logger.warning("assets_bulk_update_invalid_exposure", extra=detail)
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc

        if payload.managed is not None:
            asset.managed = bool(payload.managed)
            if payload.topology_visible is None and asset.managed:
                asset.topology_visible = True
            if payload.attack_surface_enabled is None and asset.managed:
                asset.attack_surface_enabled = True

        if payload.asset_zone is not None:
            asset.asset_zone = _parse_asset_zone(payload.asset_zone)

        if payload.topology_visible is not None:
            asset.topology_visible = bool(payload.topology_visible)

        if payload.attack_surface_enabled is not None:
            asset.attack_surface_enabled = bool(payload.attack_surface_enabled)

    database.commit()
    logger.info("assets_bulk_update_success", extra={"updated": len(assets)})
    return BulkAssetUpdateResponse(updated=len(assets))


@router.delete("/clear", status_code=status.HTTP_200_OK)
def clear_assets(
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> dict[str, object]:
    if not settings.dev_mode:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Clear assets is only available in DEV_MODE",
        )

    owner_uuid = UUID(user_id)
    deleted = database.query(Asset).filter(Asset.owner_id == owner_uuid).delete(synchronize_session="fetch")
    database.commit()

    return {"deleted_count": deleted, "message": f"Cleared {deleted} assets (cascade includes scans/findings)"}
