from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.asset import Asset
from app.models.report import Report
from app.routes.deps import get_current_user_id
from app.schemas.reporting import GenerateScanReportResponse
from app.services.reporting import ReportServiceError, generate_scan_report

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.post("/scan/{scan_id}", response_model=GenerateScanReportResponse, status_code=status.HTTP_201_CREATED)
def create_scan_report(
    scan_id: str,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> GenerateScanReportResponse:
    try:
        result = generate_scan_report(database=database, owner_id=user_id, scan_id=scan_id)
    except ReportServiceError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return GenerateScanReportResponse(**result)


@router.get("/download/{report_id}")
def download_report(
    report_id: str,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> FileResponse:
    try:
        report_uuid = UUID(report_id)
        user_uuid = UUID(user_id)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid identifier") from exc

    report = (
        database.query(Report)
        .join(Asset, Asset.id == Report.asset_id)
        .filter(Report.id == report_uuid, Asset.owner_id == user_uuid)
        .first()
    )
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    file_path = Path(report.storage_path)
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file missing")

    return FileResponse(path=file_path, media_type="application/pdf", filename=file_path.name)
