from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class RecentScanItem(BaseModel):
    scan_id: UUID
    asset_id: UUID
    asset_name: str
    mode: str
    status: str
    progress: int
    created_at: datetime


class RiskyAssetItem(BaseModel):
    asset_id: UUID
    asset_name: str
    target: str
    criticality: str
    exposure: str
    findings: int
    critical_findings: int
    kev_findings: int
    risk_score: float


class ExposureCountItem(BaseModel):
    exposure: str
    count: int


class SeverityCountItem(BaseModel):
    severity: str
    count: int


class ExposedPortItem(BaseModel):
    port: str
    protocol: str
    service: str
    count: int


class ScanTrendItem(BaseModel):
    date: str
    total: int
    completed: int
    failed: int


class DashboardSummaryResponse(BaseModel):
    total_assets: int
    active_assets: int
    total_scans: int
    total_findings: int
    critical_findings: int
    kev_findings: int
    findings_by_severity: list[SeverityCountItem]
    exposure_breakdown: list[ExposureCountItem]
    top_exposed_ports: list[ExposedPortItem]
    scan_trends: list[ScanTrendItem]
    recent_scans: list[RecentScanItem]
    top_risky_assets: list[RiskyAssetItem]
