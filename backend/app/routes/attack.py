from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.routes.deps import get_current_user_id
from app.services.attack_engine import (
    asset_attack_metrics,
    get_attack_impact,
    get_attack_replay,
    simulate_from,
    top_attack_chains,
)

router = APIRouter(prefix="/api/attack", tags=["attack"])


@router.get("/simulate", status_code=status.HTTP_200_OK)
def simulate_attack(
    source: str | None = None,
    limit: int = 6,
    kev_only: bool = False,
    internet_exposed_only: bool = False,
    critical_only: bool = False,
    highest_risk_only: bool = True,
    emulation_mode: bool = True,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> dict:
    """Simulate attacker movement from a compromised asset.

    Returns blast radius, ranked attack chains to each reachable target,
    lateral movement score, and privilege escalation paths.
    """
    try:
        result = simulate_from(
            database=database,
            owner_id=user_id,
            source_id=source,
            limit=limit,
            kev_only=kev_only,
            internet_exposed_only=internet_exposed_only,
            critical_only=critical_only,
            highest_risk_only=highest_risk_only,
            emulation_mode=emulation_mode,
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    if "error" in result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=result["error"])
    return result


@router.get("/chains", status_code=status.HTTP_200_OK)
def attack_chains(
    limit: int = 10,
    kev_only: bool = False,
    internet_exposed_only: bool = False,
    critical_only: bool = False,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> dict:
    """Return the top N most dangerous attack chains across the network."""
    bounded = max(1, min(50, limit))
    return top_attack_chains(
        database=database,
        owner_id=user_id,
        limit=bounded,
        kev_only=kev_only,
        internet_exposed_only=internet_exposed_only,
        critical_only=critical_only,
    )


@router.get("/metrics", status_code=status.HTTP_200_OK)
def attack_metrics(
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> dict:
    """Return blast radius, pivot score, and inbound paths for every asset."""
    metrics = asset_attack_metrics(database=database, owner_id=user_id)
    return {"assets": metrics}


@router.get("/replay", status_code=status.HTTP_200_OK)
def attack_replay(
    source: str | None = None,
    chain_index: int = 0,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> dict:
    """Return ordered replay steps for step-through attack visualization.

    Each step includes the asset state transition, technique, CVE, privilege
    level, and lateral movement flags needed for the frontend replay mode.
    """
    try:
        result = get_attack_replay(
            database=database,
            owner_id=user_id,
            source_id=source,
            chain_index=max(0, min(chain_index, 19)),
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    if "error" in result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=result["error"])
    return result


@router.get("/impact", status_code=status.HTTP_200_OK)
def attack_impact(
    source: str | None = None,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> dict:
    """Return full attack impact estimation for a given source.

    Includes cumulative risk increase, critical system exposure,
    exposed service categories, and confidence distribution.
    """
    try:
        result = get_attack_impact(
            database=database,
            owner_id=user_id,
            source_id=source,
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    if "error" in result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=result["error"])
    return result
