from __future__ import annotations

import logging
from ipaddress import ip_address, ip_network
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from uuid import UUID

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.asset import Asset
from app.models.scan import Scan, ScanMode
from app.scanner.nmap_parser import extract_asset_identity, parse_and_create_findings
from app.services.scan_engine import mark_scan_completed, mark_scan_failed, mark_scan_progress, mark_scan_running
from app.workers.celery_app import celery_app


logger = logging.getLogger("aegis.scan.worker")
HOSTNAME_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")


def _scan_command(mode: ScanMode, target: str) -> tuple[list[str], int]:
    base = [settings.nmap_binary]
    if mode == ScanMode.FAST:
        return base + ["-Pn", "-F", "--open", "-oX", "-", target], settings.scan_timeout_fast_seconds
    if mode == ScanMode.SMART_FAST:
        return (
            base
            + ["-Pn", "-F", "-sV", "--version-light", "-T4", "--open", "-oX", "-", target],
            settings.scan_timeout_smart_fast_seconds,
        )
    if mode == ScanMode.MEDIUM:
        return base + ["-Pn", "-sV", "--version-light", "--top-ports", "200", "--open", "-oX", "-", target], settings.scan_timeout_medium_seconds
    if mode == ScanMode.FULL:
        return base + ["-Pn", "-sV", "-sC", "-O", "-p-", "--open", "-oX", "-", target], settings.scan_timeout_full_seconds
    if mode == ScanMode.SUPER_FULL:
        return (
            base + ["-Pn", "-sV", "-sC", "-O", "-p-", "--open", "-oX", "-", target],
            settings.scan_timeout_super_full_seconds,
        )
    raise ValueError(f"Unsupported scan mode: {mode}")


def _normalize_scan_target(target: str) -> str:
    normalized = target.strip()
    if not normalized:
        raise ValueError("Asset target is empty")
    if normalized.startswith("-") or any(character.isspace() for character in normalized):
        raise ValueError("Asset target is invalid")

    try:
        ip_address(normalized)
        return normalized
    except ValueError:
        pass

    try:
        ip_network(normalized, strict=False)
        return normalized
    except ValueError:
        pass

    if HOSTNAME_TARGET_PATTERN.fullmatch(normalized) and ".." not in normalized and not normalized.endswith("-"):
        return normalized

    raise ValueError("Asset target is invalid")


def _host_summary(xml_output: str) -> str:
    root = ET.fromstring(xml_output)
    hosts = root.findall("host")
    up_hosts = 0
    for host in hosts:
        status = host.find("status")
        if status is not None and status.get("state") == "up":
            up_hosts += 1
    return f"Scan completed: {up_hosts} hosts up"


@celery_app.task(name="scan.execute")
def execute_scan(scan_id: str) -> dict[str, str]:
    database = SessionLocal()
    scan: Scan | None = None
    try:
        scan = database.query(Scan).filter(Scan.id == UUID(scan_id)).first()
        if scan is None:
            return {"status": "missing", "scan_id": scan_id}

        task_id = execute_scan.request.id or ""
        mark_scan_running(database, scan, task_id)

        asset = database.query(Asset).filter(Asset.id == scan.asset_id).first()
        if asset is None:
            mark_scan_failed(database, scan, "Asset not found")
            return {"status": "failed", "scan_id": scan_id}

        target_candidate = asset.ip_address or asset.target or ""
        try:
            target = _normalize_scan_target(target_candidate)
        except ValueError as exc:
            mark_scan_failed(database, scan, str(exc))
            return {"status": "failed", "scan_id": scan_id}

        command, timeout = _scan_command(scan.mode, target)
        mark_scan_progress(database, scan, 40, "Executing nmap scan")

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True,
                stdin=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            mark_scan_failed(database, scan, "nmap binary not found")
            return {"status": "failed", "scan_id": scan_id}
        except subprocess.TimeoutExpired:
            mark_scan_failed(database, scan, "scan timed out")
            return {"status": "failed", "scan_id": scan_id}
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()
            mark_scan_failed(database, scan, f"nmap failed: {stderr or 'unknown error'}")
            return {"status": "failed", "scan_id": scan_id}

        xml_output = completed.stdout
        scan.raw_xml = xml_output
        database.commit()
        mark_scan_progress(database, scan, 80, "Parsing scan output")

        try:
            host_summary = _host_summary(xml_output)
        except ET.ParseError:
            mark_scan_failed(database, scan, "invalid nmap XML output")
            return {"status": "failed", "scan_id": scan_id}

        mark_scan_progress(database, scan, 90, "Creating findings from scan output")

        try:
            finding_count, risky_count, os_fingerprint = parse_and_create_findings(
                database=database,
                scan=scan,
                xml_output=xml_output,
                fallback_target=target,
            )
        except ET.ParseError:
            mark_scan_failed(database, scan, "invalid nmap XML output")
            return {"status": "failed", "scan_id": scan_id}

        identity = extract_asset_identity(xml_output, target)

        # Store passive identity hints on the asset if discovered.
        if os_fingerprint and asset is not None:
            asset.os_fingerprint = os_fingerprint
        if identity.get("hostname") and asset is not None:
            asset.hostname = identity["hostname"]
        if identity.get("ip") and asset is not None and not asset.ip_address:
            asset.ip_address = identity["ip"]
        if asset is not None and (os_fingerprint or identity.get("hostname") or identity.get("ip")):
            database.commit()

        # Mark KEV findings and recompute contextual risk score
        try:
            from app.models.finding import Finding as FindingModel
            from app.scanner.kev_client import is_kev
            from app.services.risk_engine import recompute_asset_risk

            kev_count = 0
            scan_findings = (
                database.query(FindingModel)
                .filter(FindingModel.scan_id == scan.id, FindingModel.cve_id.isnot(None))
                .all()
            )
            for finding in scan_findings:
                if is_kev(finding.cve_id):
                    finding.is_kev = True
                    kev_count += 1

            if kev_count:
                database.commit()
                logger.info("kev_check: %d KEV findings on scan %s", kev_count, scan_id)

            if asset is not None:
                recompute_asset_risk(database, asset)
        except Exception:
            logger.exception("risk_engine: post-scan enrichment failed for scan %s", scan_id)

        # Rebuild digital twin topology edges
        try:
            from app.services.topology_engine import rebuild_topology

            if asset is not None:
                owner_str = str(asset.owner_id)
                edge_count = rebuild_topology(database, owner_str)
                logger.info("topology: rebuilt %d edges after scan %s", edge_count, scan_id)
        except Exception:
            logger.exception("topology: rebuild failed after scan %s", scan_id)

        summary = f"{host_summary}. Findings: {finding_count} (risky: {risky_count})"

        mark_scan_completed(database, scan, xml_output, summary)
        return {
            "status": "completed",
            "scan_id": scan_id,
            "completed_at": datetime.now(UTC).isoformat(),
        }
    except Exception as exc:
        logger.exception("scan_execution_failed", extra={"scan_id": scan_id})
        if scan is not None:
            try:
                database.rollback()
            except Exception:
                pass
            try:
                mark_scan_failed(database, scan, f"unexpected scan failure: {exc}")
            except Exception:
                logger.exception("scan_mark_failed_write_error", extra={"scan_id": scan_id})
        return {"status": "failed", "scan_id": scan_id}
    finally:
        database.close()
