from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class AssetListItem(BaseModel):
    id: UUID
    name: str
    target: str
    ip_address: str | None = None
    hostname: str | None = None
    mac_address: str | None = None
    asset_type: str
    status: str
    criticality: str
    exposure: str
    managed: bool
    asset_zone: str
    topology_visible: bool
    attack_surface_enabled: bool
    risk_score: float | None = None
    discovery_status: str | None = None
    os_fingerprint: str | None = None
    last_scan_status: str | None = None
    last_scan_progress: int | None = None
    last_scanned_at: datetime | None = None
    updated_at: datetime


class AssetsListResponse(BaseModel):
    items: list[AssetListItem]
    total: int
    limit: int
    offset: int


class PatchAssetRequest(BaseModel):
    criticality: str | None = None
    exposure: str | None = None
    managed: bool | None = None
    asset_zone: str | None = None
    topology_visible: bool | None = None
    attack_surface_enabled: bool | None = None


class BulkAssetUpdateRequest(BaseModel):
    asset_ids: list[str]
    managed: bool | None = None
    asset_zone: str | None = None
    topology_visible: bool | None = None
    attack_surface_enabled: bool | None = None
    criticality: str | None = None
    exposure: str | None = None


class BulkAssetUpdateResponse(BaseModel):
    updated: int
