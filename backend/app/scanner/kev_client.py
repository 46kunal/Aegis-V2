"""CISA Known Exploited Vulnerabilities (KEV) catalog client.

Fetches the full catalog once and caches it in the kev_catalog table.
Refreshes automatically when the cache is older than REFRESH_HOURS.
The catalog URL is public, no authentication required.
"""
from __future__ import annotations

import datetime
import logging

import httpx
from sqlalchemy.orm import Session

from app.models.kev_catalog import KevCatalog

logger = logging.getLogger("aegis.kev_client")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REFRESH_HOURS = 24
_in_memory_kev: set[str] = set()


def _load_in_memory(database: Session) -> None:
    """Populate the in-memory set from the database (fast O(1) lookups)."""
    global _in_memory_kev
    rows = database.query(KevCatalog.cve_id).all()
    _in_memory_kev = {row.cve_id for row in rows}
    logger.info("kev_client: loaded %d KEV entries into memory", len(_in_memory_kev))


def refresh_kev_catalog(database: Session, force: bool = False) -> int:
    """Fetch KEV catalog from CISA and upsert into kev_catalog table.

    Returns the number of CVE entries stored. Skips refresh if cache is fresh.
    """
    newest = (
        database.query(KevCatalog.updated_at)
        .order_by(KevCatalog.updated_at.desc())
        .first()
    )

    if not force and newest is not None:
        age = datetime.datetime.now(datetime.UTC) - newest.updated_at
        if age.total_seconds() < REFRESH_HOURS * 3600:
            logger.debug(
                "kev_client: cache fresh (age %.1fh), skipping refresh",
                age.total_seconds() / 3600,
            )
            if not _in_memory_kev:
                _load_in_memory(database)
            return len(_in_memory_kev)

    logger.info("kev_client: fetching KEV catalog from CISA")
    try:
        response = httpx.get(KEV_URL, timeout=30.0, follow_redirects=True)
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        logger.error("kev_client: failed to fetch KEV catalog: %s", exc)
        if not _in_memory_kev:
            _load_in_memory(database)
        return len(_in_memory_kev)

    vulnerabilities = data.get("vulnerabilities") or []
    now = datetime.datetime.now(datetime.UTC)
    count = 0

    for vuln in vulnerabilities:
        cve_id = vuln.get("cveID") or ""
        if not cve_id:
            continue

        date_added_raw = vuln.get("dateAdded")
        date_added = None
        if date_added_raw:
            try:
                date_added = datetime.date.fromisoformat(date_added_raw)
            except ValueError:
                pass

        existing = database.query(KevCatalog).filter(KevCatalog.cve_id == cve_id).first()
        if existing:
            existing.vulnerability_name = vuln.get("vulnerabilityName")
            existing.product = vuln.get("product")
            existing.date_added = date_added
            existing.updated_at = now
        else:
            database.add(KevCatalog(
                cve_id=cve_id,
                vulnerability_name=vuln.get("vulnerabilityName"),
                product=vuln.get("product"),
                date_added=date_added,
                updated_at=now,
            ))
        count += 1

    database.commit()
    _load_in_memory(database)
    logger.info("kev_client: stored %d KEV entries", count)
    return count


def is_kev(cve_id: str | None) -> bool:
    """Return True if the CVE ID is in the CISA KEV catalog (in-memory O(1) check)."""
    if not cve_id:
        return False
    return cve_id in _in_memory_kev


def ensure_loaded(database: Session) -> None:
    """Called at startup — refresh if stale, otherwise just warm the in-memory set."""
    refresh_kev_catalog(database)
