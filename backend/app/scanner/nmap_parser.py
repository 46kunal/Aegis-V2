"""Parse nmap XML output into structured Finding rows.

Intelligence pipeline per open port:
  1. Extract service metadata (product, version, CPE, NSE scripts, OS)
  2. For each unique CPE, query NVD for real CVE / CVSS data (cached)
  3. Pick the worst-scoring CVE across all CPEs on that port
  4. Create a Finding row with full vulnerability metadata
"""
from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from decimal import Decimal

from sqlalchemy.orm import Session

from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.scan import Scan
from app.scanner.nvd_client import get_vulnerability_intelligence
from app.scanner.kev_client import is_kev

logger = logging.getLogger("aegis.parser")

_CPE_PARTS = 13
_VENDOR_PRODUCT_MAP: dict[str, tuple[str, str]] = {
    "apache_httpd": ("apache", "http_server"),
    "openssh": ("openbsd", "openssh"),
    "samba": ("samba", "samba"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "mysql": ("oracle", "mysql"),
    "microsoft_iis": ("microsoft", "internet_information_services"),
    "microsoft_sql_server": ("microsoft", "sql_server"),
    "microsoft_exchange": ("microsoft", "exchange_server"),
    "microsoft_rdp": ("microsoft", "terminal_services"),
    "microsoft_smb": ("microsoft", "smb"),
}


# ---------------------------------------------------------------------------
# XML parsing helpers
# ---------------------------------------------------------------------------

def _text_or_none(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _extract_cpe_list(service_node: ET.Element | None) -> list[str]:
    """Return all CPE strings from a <service> element, deduplicated."""
    if service_node is None:
        return []
    seen: set[str] = set()
    result: list[str] = []
    for cpe_elem in service_node.findall("cpe"):
        text = (cpe_elem.text or "").strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def _is_valid_cpe(cpe: str) -> bool:
    if not cpe:
        return False
    if not cpe.startswith("cpe:2.3:"):
        return False
    return len(cpe.split(":")) == _CPE_PARTS


def _sanitize_cpe_component(value: str | None, allow_wildcard: bool = True) -> str:
    if value is None:
        return "*" if allow_wildcard else ""
    lowered = value.strip().lower().replace(" ", "_")
    cleaned = re.sub(r"[^a-z0-9._-]", "", lowered)
    if not cleaned:
        return "*" if allow_wildcard else ""
    return cleaned


def _normalize_service(raw_service: str | None, product: str | None, extrainfo: str | None) -> str | None:
    parts = [raw_service or "", product or "", extrainfo or ""]
    hay = " ".join(parts).lower()

    if "apache" in hay and ("httpd" in hay or "http" in hay):
        return "apache_httpd"
    if "openssh" in hay or (raw_service or "").lower() == "ssh":
        return "openssh"
    if "samba" in hay or "smb" in hay:
        return "samba"
    if "vsftpd" in hay:
        return "vsftpd"
    if "mysql" in hay:
        return "mysql"

    if "microsoft" in hay or "ms-" in hay or "microsoft" in (product or "").lower():
        if "iis" in hay or "httpapi" in hay:
            return "microsoft_iis"
        if "sql server" in hay or "mssql" in hay:
            return "microsoft_sql_server"
        if "exchange" in hay:
            return "microsoft_exchange"
        if "rdp" in hay or "terminal services" in hay:
            return "microsoft_rdp"
        if "smb" in hay or "netbios" in hay:
            return "microsoft_smb"

    if raw_service:
        return _sanitize_cpe_component(raw_service, allow_wildcard=False) or None
    if product:
        return _sanitize_cpe_component(product, allow_wildcard=False) or None
    return None


def _extract_version(product: str | None, version: str | None, extrainfo: str | None) -> str | None:
    if version:
        return version.strip()

    for source in [product, extrainfo]:
        if not source:
            continue
        match = re.search(r"\b(\d+(?:\.\d+){0,3}[a-z0-9._-]*)\b", source.lower())
        if match:
            return match.group(1)
    return None


def _generate_cpe(normalized_service: str | None, extracted_version: str | None) -> str | None:
    if not normalized_service:
        return None
    vendor_product = _VENDOR_PRODUCT_MAP.get(normalized_service)
    if not vendor_product:
        return None

    vendor, product = vendor_product
    vendor_clean = _sanitize_cpe_component(vendor, allow_wildcard=False)
    product_clean = _sanitize_cpe_component(product, allow_wildcard=False)
    if not vendor_clean or not product_clean:
        return None

    version_clean = _sanitize_cpe_component(extracted_version or "*", allow_wildcard=True)
    return f"cpe:2.3:a:{vendor_clean}:{product_clean}:{version_clean}:*:*:*:*:*:*:*"


def _extract_script_output(port_node: ET.Element) -> str | None:
    """Collect all NSE script output from a <port>, truncated to 4000 chars."""
    scripts = port_node.findall("script")
    if not scripts:
        return None
    parts = [
        f"[{s.get('id') or 'unknown'}] {(s.get('output') or '').strip()}"
        for s in scripts
    ]
    combined = "\n".join(parts)
    return combined[:4000] if combined else None


def _extract_hostname_from_script_output(script_output: str | None) -> str | None:
    if not script_output:
        return None
    patterns = [
        r"NetBIOS computer name:\s*([A-Za-z0-9_.-]+)",
        r"Computer name:\s*([A-Za-z0-9_.-]+)",
        r"DNS_Computer_Name:\s*([A-Za-z0-9_.-]+)",
        r"FQDN:\s*([A-Za-z0-9_.-]+)",
        r"Name:\s*([A-Za-z0-9_.-]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, script_output, flags=re.IGNORECASE)
        if match:
            candidate = match.group(1).strip().strip(".")
            if candidate and candidate.lower() not in {"unknown", "workgroup"}:
                return candidate
    return None


def _extract_os_matches(host_node: ET.Element) -> str | None:
    os_node = host_node.find("os")
    if os_node is None:
        return None
    matches = []
    for osmatch in os_node.findall("osmatch"):
        name = osmatch.get("name")
        accuracy = osmatch.get("accuracy")
        if name:
            matches.append(f"{name} ({accuracy}%)" if accuracy else name)
    return "; ".join(matches[:5]) if matches else None


def _extract_hostnames(host_node: ET.Element) -> str | None:
    names = [
        h.get("name")
        for h in host_node.findall("hostnames/hostname")
        if h.get("name")
    ]
    return ", ".join(names) if names else None


# ---------------------------------------------------------------------------
# CVE intelligence helpers
# ---------------------------------------------------------------------------

def _severity_from_score(score: float) -> FindingSeverity:
    if score >= 9.0:
        return FindingSeverity.CRITICAL
    if score >= 7.0:
        return FindingSeverity.HIGH
    if score >= 4.0:
        return FindingSeverity.MEDIUM
    if score > 0.0:
        return FindingSeverity.LOW
    return FindingSeverity.INFO


def _best_cve_for_port(
    database: Session,
    cpe_list: list[str],
) -> dict | None:
    """Query NVD for all CPEs on this port, return the worst-scoring result."""
    best: dict | None = None
    for cpe in cpe_list:
        logger.info("cve_lookup: querying %s", cpe)
        intel = get_vulnerability_intelligence(database, cpe)
        if intel is None:
            logger.warning("cve_lookup: no CVE matches for %s", cpe)
            continue
        if best is None or (intel.get("cvss_score") or 0) > (best.get("cvss_score") or 0):
            best = intel
    if best:
        logger.info(
            "cve_lookup: matched %s (CVSS %.1f)",
            best.get("cve_id"),
            best.get("cvss_score", 0.0),
        )
    return best


# ---------------------------------------------------------------------------
# Public parser
# ---------------------------------------------------------------------------

def extract_structured_ports(xml_output: str) -> dict:
    """Parse nmap XML into a dict with key 'hosts', each containing 'ports'."""
    root = ET.fromstring(xml_output)
    hosts: list[dict] = []

    for host in root.findall("host"):
        state = host.find("status")
        if state is None or state.get("state") != "up":
            continue

        ip: str | None = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                break

        hostname = _extract_hostnames(host)
        os_fingerprint = _extract_os_matches(host)
        ports: list[dict] = []

        for port in host.findall("ports/port"):
            port_state = port.find("state")
            if port_state is None or port_state.get("state") != "open":
                continue

            port_id = port.get("portid")
            if port_id is None or not port_id.isdigit():
                continue

            service = port.find("service")
            script_output = _extract_script_output(port)
            ports.append({
                "port": int(port_id),
                "protocol": port.get("protocol") or "tcp",
                "service": _text_or_none(service.get("name")) if service is not None else None,
                "product": _text_or_none(service.get("product")) if service is not None else None,
                "version": _text_or_none(service.get("version")) if service is not None else None,
                "extrainfo": _text_or_none(service.get("extrainfo")) if service is not None else None,
                "cpe_list": _extract_cpe_list(service),
                "script_output": script_output,
            })

            if hostname is None:
                hostname = _extract_hostname_from_script_output(script_output)

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "os_fingerprint": os_fingerprint,
            "ports": ports,
        })

    return {"hosts": hosts}


def extract_asset_identity(xml_output: str, fallback_target: str) -> dict:
    """Return passive identity hints from nmap XML without creating findings."""
    parsed = extract_structured_ports(xml_output)
    for host in parsed["hosts"]:
        return {
            "ip": host.get("ip") or fallback_target,
            "hostname": host.get("hostname"),
            "os_fingerprint": host.get("os_fingerprint"),
            "identity_sources": [
                source
                for source, value in (
                    ("nmap_hostname", host.get("hostname")),
                    ("os_detection", host.get("os_fingerprint")),
                )
                if value
            ],
        }
    return {
        "ip": fallback_target,
        "hostname": None,
        "os_fingerprint": None,
        "identity_sources": [],
    }


def parse_and_create_findings(
    database: Session,
    scan: Scan,
    xml_output: str,
    fallback_target: str,
) -> tuple[int, int, str | None]:
    """Parse nmap XML, create Finding rows, return (count, risky_count, os_fingerprint).

    risky_count = findings with CVSS >= 4.0 (medium and above).
    os_fingerprint = first OS guess seen, to be written back to the Asset.
    """
    parsed = extract_structured_ports(xml_output)

    finding_count = 0
    risky_count = 0
    first_os_fingerprint: str | None = None

    for host in parsed["hosts"]:
        ip = host["ip"] or fallback_target
        hostname = host["hostname"] or ip
        os_fp = host.get("os_fingerprint")

        if os_fp and first_os_fingerprint is None:
            first_os_fingerprint = os_fp

        for port_data in host["ports"]:
            port_num: int = port_data["port"]
            protocol: str = port_data["protocol"]
            raw_service: str | None = port_data["service"]
            service: str = raw_service or "unknown"
            product: str | None = port_data["product"]
            version: str | None = port_data["version"]
            extrainfo: str | None = port_data["extrainfo"]
            raw_cpe_list: list[str] = port_data["cpe_list"]
            script_output: str | None = port_data["script_output"]

            normalized_service = _normalize_service(raw_service, product, extrainfo)
            extracted_version = _extract_version(product, version, extrainfo)
            generated_cpe = _generate_cpe(normalized_service, extracted_version)

            if extracted_version:
                logger.info(
                    "service_version: %s %s (port %s)",
                    normalized_service or service,
                    extracted_version,
                    port_num,
                )

            cpe_list = []
            for cpe in raw_cpe_list:
                cleaned = cpe.strip().lower()
                if _is_valid_cpe(cleaned):
                    cpe_list.append(cleaned)
                else:
                    logger.warning("cpe_validation: dropped invalid CPE %s", cpe)
            if raw_cpe_list and not cpe_list:
                logger.warning("cpe_validation: dropped invalid CPEs for %s:%s", ip, port_num)

            if not cpe_list and generated_cpe:
                if _is_valid_cpe(generated_cpe):
                    cpe_list.append(generated_cpe)
                    logger.info(
                        "cpe_generated: %s -> %s",
                        normalized_service or service,
                        generated_cpe,
                    )
                else:
                    logger.warning("cpe_generated_invalid: %s", generated_cpe)

            if cpe_list:
                logger.info("cpe_candidates: %s", ", ".join(cpe_list))

            if not cpe_list:
                logger.warning(
                    "cpe_missing: service=%s product=%s version=%s",
                    service,
                    product or "unknown",
                    extracted_version or "unknown",
                )

            # ── Fetch best CVE across all CPEs on this port ───────────────
            cve_data = _best_cve_for_port(database, cpe_list)

            # ── Derive severity, score, and metadata ──────────────────────
            if cve_data:
                raw_score = cve_data.get("cvss_score") or 0.0
                cvss_score: Decimal | None = Decimal(str(raw_score))
                severity = _severity_from_score(raw_score)
                if raw_score >= 4.0:
                    risky_count += 1

                cve_id: str | None = cve_data.get("cve_id")
                cwe_ids: list[str] = cve_data.get("cwe_ids") or []
                cwe_id: str | None = cwe_ids[0] if cwe_ids else None
                cvss_vector: str | None = cve_data.get("cvss_vector") or None
                epss_score_raw = cve_data.get("epss_score")
                epss_score: Decimal | None = Decimal(str(epss_score_raw)) if epss_score_raw is not None else None
                references: list[str] | None = cve_data.get("references") or None
                published_date = None
                published_str = cve_data.get("published_date")
                if published_str:
                    try:
                        from dateutil.parser import parse as date_parse
                        published_date = date_parse(published_str)
                    except Exception:
                        pass
                cve_description: str = cve_data.get("description") or ""
                kev_flag = is_kev(cve_id)
            else:
                cvss_score = None
                cve_id = None
                cwe_id = None
                cvss_vector = None
                epss_score = None
                references = None
                published_date = None
                cve_description = ""
                kev_flag = False

                # Heuristic: flag plaintext legacy protocols without CVE data
                if port_num == 21:
                    severity = FindingSeverity.LOW
                    cve_description = "FTP transmits credentials in cleartext. Replace with SFTP/FTPS."
                    risky_count += 1
                elif port_num == 23:
                    severity = FindingSeverity.LOW
                    cve_description = "Telnet transmits all traffic in cleartext. Replace with SSH."
                    risky_count += 1
                else:
                    severity = FindingSeverity.INFO

            # ── Build human-readable description ──────────────────────────
            version_parts = [p for p in [product, version, extrainfo] if p]
            version_display = " ".join(version_parts) if version_parts else "unknown"
            cpe_display = ", ".join(cpe_list) if cpe_list else None

            desc_parts = [
                f"Host: {hostname} ({ip})",
                f"Port: {port_num}/{protocol} — {service}",
                f"Version: {version_display}",
            ]
            if cpe_display:
                desc_parts.append(f"CPE: {cpe_display}")
            if os_fp:
                desc_parts.append(f"OS: {os_fp}")
            if cve_id:
                desc_parts.append(f"CVE: {cve_id}")
            if cve_description:
                # Truncate long NVD descriptions
                truncated = cve_description[:500] + ("…" if len(cve_description) > 500 else "")
                desc_parts.append(f"Detail: {truncated}")

            description = "\n".join(desc_parts)

            # ── Build remediation text ────────────────────────────────────
            if cve_id:
                remediation = (
                    f"Apply vendor security patches for {cve_id}. "
                    "Restrict unnecessary network exposure via firewall rules. "
                    "Enforce strong authentication, network segmentation, and least-privilege access."
                )
            else:
                remediation = (
                    f"{cve_description} " if cve_description else ""
                ).strip() or (
                    "Restrict unnecessary network exposure using firewall rules and segmentation. "
                    "Disable unused services and enforce strong authentication."
                )

            finding = Finding(
                scan_id=scan.id,
                asset_id=scan.asset_id,
                title=f"Open port {port_num}/{protocol} ({service})",
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                status=FindingStatus.OPEN,
                remediation=remediation,
                port=port_num,
                protocol=protocol,
                detected_product=product,
                detected_version=version,
                cpe=cpe_display,
                script_output=script_output,
                raw_service=raw_service,
                normalized_service=normalized_service,
                extracted_version=extracted_version,
                generated_cpe=generated_cpe,
                cve_id=cve_id,
                cwe_id=cwe_id,
                cvss_vector=cvss_vector,
                epss_score=epss_score,
                references=references,
                published_date=published_date,
                is_kev=kev_flag,
            )
            database.add(finding)
            finding_count += 1

    database.commit()
    logger.info(
        "parse_results: %d findings (%d risky), os_fingerprint=%s",
        finding_count,
        risky_count,
        first_os_fingerprint or "none",
    )
    return finding_count, risky_count, first_os_fingerprint
