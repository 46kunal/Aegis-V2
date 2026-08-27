from datetime import datetime
from uuid import UUID

from pydantic import BaseModel
from typing import Literal


class StartScanRequest(BaseModel):
    asset_id: UUID
    mode: Literal["fast", "smart_fast", "medium", "full", "super_full"]


class StartScanResponse(BaseModel):
    scan_id: UUID
    task_id: str
    status: str
    mode: str
    created_at: datetime
