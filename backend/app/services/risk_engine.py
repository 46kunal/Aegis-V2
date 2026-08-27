"""Contextual risk scoring engine for Aegis V2.

Formula
-------
Per-finding score (0–100):
  base       = cvss_score / 10.0
  epss_boost = 1.0 + (epss × 2.0)          →  1.0 (no data) to 3.0 (near-certain exploit)
  kev_boost  = 1.5 if actively exploited (CISA KEV) else 1.0
  crit_mult  = {critical: 2.0, high: 1.5, medium: 1.0, low: 0.7}
  exp_mult   = {external: 1.5, internal: 1.0, segmented: 0.7, isolated: 0.3}
  MAX_RAW    = 1.0 × 3.0 × 1.5 × 2.0 × 1.5 = 13.5
  score      = min(base × epss_boost × kev_boost × crit_mult × exp_mult / 13.5 × 100, 100)

Per-asset score (0–100):
  scores  = sorted finding scores (desc)
  breadth = min(len(scores) / 20 × 100, 100)   ← attack surface width
  score   = 0.60 × scores[0]
          + 0.30 × mean(scores[:5])
          + 0.10 × breadth
"""
from __future__ import annotations

import logging
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetCriticality, AssetExposure
from app.models.finding import Finding

logger = logging.getLogger("aegis.risk_engine")

# ---------------------------------------------------------------------------
# Weight tables
# ---------------------------------------------------------------------------

_CRITICALITY_MULT: dict[str, float] = {
    AssetCriticality.CRITICAL.value: 2.0,
    AssetCriticality.HIGH.value:     1.5,
    AssetCriticality.MEDIUM.value:   1.0,
    AssetCriticality.LOW.value:      0.7,
}

_EXPOSURE_MULT: dict[str, float] = {
    AssetExposure.EXTERNAL.value:   1.5,
    AssetExposure.INTERNAL.value:   1.0,
    AssetExposure.SEGMENTED.value:  0.7,
    AssetExposure.ISOLATED.value:   0.3,
}

_MAX_RAW = 1.0 * 3.0 * 1.5 * 2.0 * 1.5  # = 13.5


# ---------------------------------------------------------------------------
# Per-finding score
# ---------------------------------------------------------------------------

def compute_finding_risk_score(
    cvss_score: float | None,
    epss_score: float | None,
    is_kev: bool,
    criticality: str,
    exposure: str,
) -> float:
    """Return a contextual risk score 0–100 for a single finding."""
    base = (cvss_score or 0.0) / 10.0
    if base <= 0.0:
        return 0.0

    epss = max(0.0, min(1.0, epss_score or 0.0))
    epss_boost  = 1.0 + (epss * 2.0)
    kev_boost   = 1.5 if is_kev else 1.0
    crit_mult   = _CRITICALITY_MULT.get(criticality, 1.0)
    exp_mult    = _EXPOSURE_MULT.get(exposure, 1.0)

    raw = base * epss_boost * kev_boost * crit_mult * exp_mult
    return round(min(raw / _MAX_RAW * 100.0, 100.0), 2)


def finding_risk_breakdown(
    cvss_score: float | None,
    epss_score: float | None,
    is_kev: bool,
    criticality: str,
    exposure: str,
) -> dict:
    """Return the full scoring breakdown for transparency."""
    base = (cvss_score or 0.0) / 10.0
    epss = max(0.0, min(1.0, epss_score or 0.0))
    epss_boost = 1.0 + (epss * 2.0)
    kev_boost  = 1.5 if is_kev else 1.0
    crit_mult  = _CRITICALITY_MULT.get(criticality, 1.0)
    exp_mult   = _EXPOSURE_MULT.get(exposure, 1.0)
    raw        = base * epss_boost * kev_boost * crit_mult * exp_mult
    score      = round(min(raw / _MAX_RAW * 100.0, 100.0), 2)

    return {
        "score":       score,
        "cvss_base":   round(base * 10.0, 1),
        "epss_pct":    round(epss * 100, 2),
        "epss_boost":  round(epss_boost, 3),
        "kev_boost":   kev_boost,
        "crit_mult":   crit_mult,
        "exp_mult":    exp_mult,
    }


# ---------------------------------------------------------------------------
# Per-asset score
# ---------------------------------------------------------------------------

def compute_asset_risk_score(
    finding_scores: list[float],
) -> float:
    """Aggregate per-finding scores into a single asset risk score 0–100."""
    if not finding_scores:
        return 0.0

    scores = sorted(finding_scores, reverse=True)
    top = scores[0]
    top5_mean = sum(scores[:5]) / min(len(scores), 5)
    breadth = min(len(scores) / 20.0 * 100.0, 100.0)

    raw = 0.60 * top + 0.30 * top5_mean + 0.10 * breadth
    return round(min(raw, 100.0), 2)


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def recompute_asset_risk(database: Session, asset: Asset) -> float:
    """Recompute and persist the risk score for *asset* from its current findings."""
    findings = (
        database.query(Finding)
        .filter(Finding.asset_id == asset.id)
        .all()
    )

    criticality = asset.criticality.value if hasattr(asset.criticality, "value") else str(asset.criticality)
    exposure    = asset.exposure.value    if hasattr(asset.exposure,    "value") else str(asset.exposure)

    scores = [
        compute_finding_risk_score(
            cvss_score  = float(f.cvss_score) if f.cvss_score is not None else None,
            epss_score  = float(f.epss_score) if f.epss_score is not None else None,
            is_kev      = bool(f.is_kev),
            criticality = criticality,
            exposure    = exposure,
        )
        for f in findings
    ]

    asset.risk_score = compute_asset_risk_score(scores)
    database.commit()
    logger.info(
        "risk_engine: asset %s risk_score=%.2f (%d findings)",
        asset.id, asset.risk_score, len(findings),
    )
    return asset.risk_score


def recompute_all_assets(database: Session, owner_id: str) -> int:
    """Recompute risk scores for every asset belonging to *owner_id*."""
    owner_uuid = UUID(owner_id)
    assets = database.query(Asset).filter(Asset.owner_id == owner_uuid).all()
    for asset in assets:
        recompute_asset_risk(database, asset)
    return len(assets)
