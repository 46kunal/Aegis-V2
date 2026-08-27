from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.routes.deps import get_current_user_id
from app.models.asset import AssetZone
from app.services.topology_engine import get_graph, rebuild_topology

router = APIRouter(prefix="/api/topology", tags=["topology"])


@router.get("/graph", status_code=status.HTTP_200_OK)
def topology_graph(
    asset_zone: str | None = None,
    vulnerable_only: bool = False,
    critical_only: bool = False,
    managed_only: bool = True,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> dict:
    """Return the full topology graph in React Flow format."""
    zone_value = None
    if asset_zone:
        try:
            zone_value = AssetZone(asset_zone.lower())
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid asset zone") from exc

    return get_graph(
        database=database,
        owner_id=user_id,
        asset_zone=zone_value,
        vulnerable_only=bool(vulnerable_only),
        critical_only=bool(critical_only),
        managed_only=bool(managed_only),
    )


@router.post("/rebuild", status_code=status.HTTP_200_OK)
def topology_rebuild(
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> dict:
    """Recompute all topology edges from current scan data."""
    count = rebuild_topology(database=database, owner_id=user_id)
    return {"edges_created": count}
