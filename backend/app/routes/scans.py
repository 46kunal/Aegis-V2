from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.routes.deps import get_current_user_id
from app.schemas.scans import ScanDetailResponse, ScanListResponse
from app.schemas.scan_engine import StartScanRequest, StartScanResponse
from app.services.scan_engine import (
    ScanEngineError,
    cancel_scan_job,
    create_scan_job,
    get_scan_job_detail,
    list_scan_jobs,
    mark_scan_failed,
    retry_scan_job,
)
from app.workers.scan_tasks import execute_scan

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _enqueue_scan_task(scan_id: str) -> str:
    try:
        task = execute_scan.delay(scan_id)
    except Exception as exc:
        raise ScanEngineError("Scan queue is unavailable") from exc
    return task.id


@router.get("", response_model=ScanListResponse, status_code=status.HTTP_200_OK)
def list_scans(
    limit: int = 50,
    offset: int = 0,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> ScanListResponse:
    bounded_limit = max(1, min(200, limit))
    bounded_offset = max(0, offset)

    try:
        payload = list_scan_jobs(database=database, owner_id=user_id, limit=bounded_limit, offset=bounded_offset)
    except ScanEngineError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return ScanListResponse(**payload)


@router.post("/start", response_model=StartScanResponse, status_code=status.HTTP_202_ACCEPTED)
def start_scan(
    payload: StartScanRequest,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> StartScanResponse:
    try:
        scan = create_scan_job(
            database=database,
            owner_id=user_id,
            asset_id=payload.asset_id,
            mode=payload.mode,
        )
    except ScanEngineError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    try:
        task_id = _enqueue_scan_task(scan_id=str(scan.id))
    except ScanEngineError as exc:
        mark_scan_failed(database=database, scan=scan, error_message="Scan queue is unavailable — is the Celery worker running?")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    scan.celery_task_id = task_id
    database.commit()
    database.refresh(scan)

    return StartScanResponse(
        scan_id=scan.id,
        task_id=task_id,
        status=scan.status.value,
        mode=scan.mode.value,
        created_at=scan.created_at,
    )


@router.get("/{scan_id}", response_model=ScanDetailResponse, status_code=status.HTTP_200_OK)
def get_scan(
    scan_id: str,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> ScanDetailResponse:
    try:
        payload = get_scan_job_detail(database=database, owner_id=user_id, scan_id=scan_id)
    except ScanEngineError as exc:
        if str(exc) == "Scan not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return ScanDetailResponse(**payload)


@router.post("/{scan_id}/retry", response_model=StartScanResponse, status_code=status.HTTP_202_ACCEPTED)
def retry_scan(
    scan_id: str,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> StartScanResponse:
    try:
        scan = retry_scan_job(database=database, owner_id=user_id, scan_id=scan_id)
    except ScanEngineError as exc:
        if str(exc) == "Scan not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    try:
        task_id = _enqueue_scan_task(scan_id=str(scan.id))
    except ScanEngineError as exc:
        mark_scan_failed(database=database, scan=scan, error_message="Scan queue is unavailable")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    scan.celery_task_id = task_id
    database.commit()
    database.refresh(scan)

    return StartScanResponse(
        scan_id=scan.id,
        task_id=task_id,
        status=scan.status.value,
        mode=scan.mode.value,
        created_at=scan.created_at,
    )


@router.post("/{scan_id}/cancel", status_code=status.HTTP_200_OK)
def cancel_scan(
    scan_id: str,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> dict[str, str]:
    try:
        scan = cancel_scan_job(database=database, owner_id=user_id, scan_id=scan_id)
    except ScanEngineError as exc:
        if str(exc) == "Scan not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return {"scan_id": str(scan.id), "status": scan.status.value}
