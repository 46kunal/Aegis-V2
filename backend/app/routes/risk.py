from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.asset import Asset
from app.models.finding import Finding, FindingSeverity
from app.routes.deps import get_current_user_id
from app.services.risk_engine import finding_risk_breakdown, recompute_all_assets

router = APIRouter(prefix="/api/risk", tags=["risk"])


@router.get("/assets", status_code=status.HTTP_200_OK)
def risk_ranked_assets(
    limit: int = 20,
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> dict:
    """Return assets ordered by contextual risk score with per-asset breakdown."""
    try:
        owner_uuid = UUID(user_id)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid identifier") from exc

    bounded = max(1, min(100, limit))
    assets = (
        database.query(Asset)
        .filter(Asset.owner_id == owner_uuid)
        .order_by(Asset.risk_score.desc().nullslast(), Asset.name.asc())
        .limit(bounded)
        .all()
    )

    result = []
    for asset in assets:
        findings = (
            database.query(Finding)
            .filter(Finding.asset_id == asset.id)
            .all()
        )

        criticality = asset.criticality.value if hasattr(asset.criticality, "value") else str(asset.criticality)
        exposure    = asset.exposure.value    if hasattr(asset.exposure,    "value") else str(asset.exposure)

        kev_findings = [f for f in findings if f.is_kev]
        critical_findings = [f for f in findings if f.severity == FindingSeverity.CRITICAL]

        top_findings = []
        for f in sorted(
            findings,
            key=lambda x: float(x.cvss_score or 0),
            reverse=True,
        )[:5]:
            breakdown = finding_risk_breakdown(
                cvss_score  = float(f.cvss_score) if f.cvss_score is not None else None,
                epss_score  = float(f.epss_score) if f.epss_score is not None else None,
                is_kev      = bool(f.is_kev),
                criticality = criticality,
                exposure    = exposure,
            )
            top_findings.append({
                "finding_id":       str(f.id),
                "title":            f.title,
                "cve_id":           f.cve_id,
                "cwe_id":           f.cwe_id,
                "is_kev":           f.is_kev,
                "cvss_score":       float(f.cvss_score) if f.cvss_score else None,
                "epss_score":       float(f.epss_score) if f.epss_score else None,
                "contextual_score": breakdown["score"],
                "breakdown":        breakdown,
            })

        result.append({
            "asset_id":          str(asset.id),
            "asset_name":        asset.name,
            "target":            asset.target,
            "criticality":       criticality,
            "exposure":          exposure,
            "risk_score":        asset.risk_score or 0.0,
            "finding_count":     len(findings),
            "critical_count":    len(critical_findings),
            "kev_count":         len(kev_findings),
            "open_port_count":   len({f.port for f in findings if f.port}),
            "top_findings":      top_findings,
        })

    return {"assets": result, "total": len(result)}


@router.post("/recompute", status_code=status.HTTP_200_OK)
def recompute_scores(
    user_id: str = Depends(get_current_user_id),
    database: Session = Depends(get_db),
) -> dict:
    """Force-recompute risk scores for all assets owned by the current user."""
    count = recompute_all_assets(database=database, owner_id=user_id)
    return {"recomputed": count}
