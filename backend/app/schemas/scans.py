from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class ScanListItem(BaseModel):
    scan_id: UUID
    asset_id: UUID
    asset_name: str
    asset_target: str
    mode: str
    status: str
    progress: int
    summary: str | None = None
    error_message: str | None = None
    celery_task_id: str | None = None
    finding_count: int
    critical_finding_count: int
    latest_report_id: UUID | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None


class ScanListResponse(BaseModel):
    items: list[ScanListItem]
    total: int
    limit: int
    offset: int


class ScanFindingItem(BaseModel):
    id: UUID
    title: str
    severity: str
    cvss_score: float | None = None
    port: int | None = None
    protocol: str | None = None
    detected_product: str | None = None
    detected_version: str | None = None
    cpe: str | None = None
    script_output: str | None = None
    raw_service: str | None = None
    normalized_service: str | None = None
    extracted_version: str | None = None
    generated_cpe: str | None = None
    cve_id: str | None = None
    cwe_id: str | None = None
    cvss_vector: str | None = None
    epss_score: float | None = None
    references: list[str] | dict | None = None
    published_date: datetime | None = None
    created_at: datetime


class ScanDetailResponse(BaseModel):
    scan_id: UUID
    asset_id: UUID
    asset_name: str
    asset_target: str
    mode: str
    status: str
    progress: int
    summary: str | None = None
    error_message: str | None = None
    celery_task_id: str | None = None
    finding_count: int
    critical_finding_count: int
    latest_report_id: UUID | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    findings: list[ScanFindingItem]
