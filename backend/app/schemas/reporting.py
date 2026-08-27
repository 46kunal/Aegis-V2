from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class GenerateScanReportResponse(BaseModel):
    report_id: UUID
    scan_id: UUID
    status: str
    storage_path: str
    download_url: str
    generated_at: datetime
