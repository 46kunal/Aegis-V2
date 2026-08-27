"""NVD API 2.0 client with local PostgreSQL caching.

Rate limits (without API key): 5 req / 30 s  → enforce 6.5 s sleep.
Rate limits (with    API key): 50 req / 30 s  → enforce 0.7 s sleep.
Get a free key at https://nvd.nist.gov/developers/request-an-api-key
"""
from __future__ import annotations

import datetime
import logging
import time
from urllib.parse import quote
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.cve_cache import CVECache

logger = logging.getLogger("aegis.nvd_client")

_DELAY_WITH_KEY = 0.7
_DELAY_NO_KEY = 6.5
CACHE_EXPIRY_DAYS = 7
_CPE_PARTS = 13
_MAX_RETRIES = 3
_RETRY_STATUSES = {429, 500, 502, 503, 504}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _request_delay() -> float:
    return _DELAY_WITH_KEY if settings.nvd_api_key else _DELAY_NO_KEY


def _is_valid_cpe(cpe: str) -> bool:
    if not cpe:
        return False
    if not cpe.startswith("cpe:2.3:"):
        return False
    parts = cpe.split(":")
    return len(parts) == _CPE_PARTS


def _nvd_headers() -> dict[str, str]:
    headers: dict[str, str] = {"User-Agent": "Aegis-V2/1.0"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    return headers


def _retry_sleep(attempt: int, retry_after: str | None = None) -> None:
    if retry_after:
        try:
            delay = max(1.0, float(retry_after))
            time.sleep(delay)
            return
        except ValueError:
            pass
    time.sleep(min(2 ** attempt, 8))


def _fetch_nvd(cpe: str) -> dict[str, Any] | None:
    encoded = quote(cpe, safe="")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={encoded}"
    for attempt in range(1, _MAX_RETRIES + 1):
        time.sleep(_request_delay())
        try:
            response = httpx.get(url, headers=_nvd_headers(), timeout=15.0)
        except httpx.RequestError as exc:
            logger.warning("nvd_api: request failed for %s (attempt %d): %s", cpe, attempt, exc)
            _retry_sleep(attempt)
            continue

        if response.status_code == 200:
            try:
                payload = response.json()
            except ValueError as exc:
                logger.warning("nvd_api: invalid JSON for %s: %s", cpe, exc)
                return None
            vuln_count = len(payload.get("vulnerabilities") or [])
            logger.info("nvd_api: %d CVEs for %s", vuln_count, cpe)
            return payload

        if response.status_code in _RETRY_STATUSES:
            logger.warning("nvd_api: status %d for %s (attempt %d)", response.status_code, cpe, attempt)
            _retry_sleep(attempt, response.headers.get("Retry-After"))
            continue

        logger.warning("nvd_api: status %d for CPE %s", response.status_code, cpe)
        return None

    return None


def _fetch_epss(cve_id: str) -> float | None:
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            response = httpx.get(url, timeout=10.0)
        except httpx.RequestError as exc:
            logger.warning("epss_api: request failed for %s (attempt %d): %s", cve_id, attempt, exc)
            _retry_sleep(attempt)
            continue

        if response.status_code == 200:
            data = response.json()
            entries = data.get("data") or []
            if entries:
                raw = entries[0].get("epss")
                if raw is not None:
                    return float(raw)
            return None

        if response.status_code in _RETRY_STATUSES:
            logger.warning("epss_api: status %d for %s (attempt %d)", response.status_code, cve_id, attempt)
            _retry_sleep(attempt, response.headers.get("Retry-After"))
            continue

        logger.warning("epss_api: status %d for %s", response.status_code, cve_id)
        return None

    return None


def _extract_cvss(cve: dict[str, Any]) -> tuple[float, str, str]:
    """Return (base_score, vector_string, base_severity) trying v3.1 → v3.0 → v2.0."""
    metrics = cve.get("metrics", {})

    # CVSS v3.1
    entries_31 = metrics.get("cvssMetricV31") or []
    if entries_31:
        data = entries_31[0].get("cvssData", {})
        return (
            float(data.get("baseScore", 0)),
            data.get("vectorString") or "",
            data.get("baseSeverity") or "",
        )

    # CVSS v3.0 fallback
    entries_30 = metrics.get("cvssMetricV30") or []
    if entries_30:
        data = entries_30[0].get("cvssData", {})
        return (
            float(data.get("baseScore", 0)),
            data.get("vectorString") or "",
            data.get("baseSeverity") or "",
        )

    # CVSS v2.0 last-resort fallback
    entries_v2 = metrics.get("cvssMetricV2") or []
    if entries_v2:
        entry = entries_v2[0]
        data = entry.get("cvssData", {})
        # NVD v2 stores baseSeverity at the metric level, not inside cvssData
        severity = entry.get("baseSeverity") or ""
        return (
            float(data.get("baseScore", 0)),
            data.get("vectorString") or "",
            severity,
        )

    return 0.0, "", ""


def _severity_from_score(score: float) -> str:
    """Map a CVSS numeric score to a severity label when baseSeverity is absent."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _extract_cwes(cve: dict[str, Any]) -> list[str]:
    """Extract CWE weakness identifiers from the NVD weaknesses array."""
    cwes: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = desc.get("value") or ""
            if value.startswith("CWE-") and value not in cwes:
                cwes.append(value)
    return cwes


def _parse_nvd_response(nvd_data: dict[str, Any]) -> dict[str, Any] | None:
    """Pick the highest-CVSS CVE from an NVD API response and return enriched data."""
    vulnerabilities = nvd_data.get("vulnerabilities") or []
    if not vulnerabilities:
        return None

    best: tuple[float, dict[str, Any]] | None = None
    for vuln in vulnerabilities:
        cve = vuln.get("cve") or {}
        score, _, _ = _extract_cvss(cve)
        if best is None or score > best[0]:
            best = (score, cve)

    if best is None:
        return None

    top_score, top_cve = best
    score, vector, severity = _extract_cvss(top_cve)

    # Normalise severity: prefer NVD label, fall back to score-based
    severity_clean = severity.lower() if severity else _severity_from_score(score)

    description = ""
    for desc in top_cve.get("descriptions") or []:
        if desc.get("lang") == "en":
            description = (desc.get("value") or "").strip()
            break

    references = [
        ref.get("url")
        for ref in (top_cve.get("references") or [])
        if ref.get("url")
    ]

    cwes = _extract_cwes(top_cve)

    cve_id: str | None = top_cve.get("id")
    epss: float | None = _fetch_epss(cve_id) if cve_id else None

    return {
        "cve_id": cve_id,
        "cvss_score": score,
        "cvss_vector": vector or None,
        "severity": severity_clean,
        "description": description,
        "references": references,
        "published_date": top_cve.get("published"),
        "epss_score": epss,
        "cwe_ids": cwes,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_vulnerability_intelligence(
    database: Session,
    cpe: str,
) -> dict[str, Any] | None:
    """Return enriched CVE data for *cpe*, using a local DB cache.

    Returns a dict with keys:
        cve_id, cvss_score, cvss_vector, severity, description,
        references, published_date, epss_score, cwe_ids
    or None if no CVE was found for this CPE.
    """
    if not cpe:
        return None
    if not _is_valid_cpe(cpe):
        logger.warning("nvd_client: skipped invalid CPE %s", cpe)
        return None

    # ── Cache read ────────────────────────────────────────────────────────
    cache_entry = database.query(CVECache).filter(CVECache.cpe_uri == cpe).first()
    if cache_entry:
        age = datetime.datetime.now(datetime.UTC) - cache_entry.updated_at
        if age.days < CACHE_EXPIRY_DAYS:
            stored = cache_entry.cve_data
            # Empty dict means "no CVE found for this CPE" — avoid re-querying
            return stored if stored else None

    # ── NVD fetch ─────────────────────────────────────────────────────────
    logger.info("nvd_client: fetching NVD data for CPE %s", cpe)
    nvd_data = _fetch_nvd(cpe)

    result: dict[str, Any] = {}
    if nvd_data:
        parsed = _parse_nvd_response(nvd_data)
        if parsed:
            result = parsed
            logger.info(
                "nvd_client: found %s (CVSS %.1f %s) for %s",
                result.get("cve_id"),
                result.get("cvss_score", 0),
                result.get("severity", ""),
                cpe,
            )
        else:
            logger.debug("nvd_client: no CVEs in NVD response for %s", cpe)

    # ── Cache write ───────────────────────────────────────────────────────
    now = datetime.datetime.now(datetime.UTC)
    if cache_entry:
        cache_entry.cve_data = result
        cache_entry.updated_at = now
    else:
        database.add(CVECache(cpe_uri=cpe, cve_data=result, updated_at=now))

    database.commit()

    return result if result else None
