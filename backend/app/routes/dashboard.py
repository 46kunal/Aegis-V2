from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.routes.deps import get_current_user_id
from app.schemas.dashboard import DashboardSummaryResponse
from app.services.dashboard import DashboardServiceError, get_dashboard_summary

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummaryResponse, status_code=status.HTTP_200_OK)
def summary(
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> DashboardSummaryResponse:
    try:
        payload = get_dashboard_summary(database=database, owner_id=user_id)
    except DashboardServiceError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return DashboardSummaryResponse(**payload)
