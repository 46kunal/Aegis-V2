from __future__ import annotations

from datetime import UTC, datetime
import hashlib
from pathlib import Path
from uuid import UUID
import xml.etree.ElementTree as ET

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from sqlalchemy import case
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.asset import Asset
from app.models.finding import Finding, FindingSeverity
from app.models.report import Report, ReportStatus, ReportType
from app.models.scan import Scan, ScanStatus


class ReportServiceError(Exception):
    pass


def _extract_open_ports(raw_xml: str | None) -> list[dict[str, str]]:
    if not raw_xml:
        return []

    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError:
        return []

    ports: list[dict[str, str]] = []
    for host in root.findall("host"):
        host_ip = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                host_ip = addr.get("addr") or ""
                break

        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            service_node = port.find("service")
            service_name = (service_node.get("name") if service_node is not None else None) or "unknown"
            product = (service_node.get("product") if service_node is not None else None) or ""
            version = (service_node.get("version") if service_node is not None else None) or ""
            version_text = " ".join(part for part in [product, version] if part).strip() or "unknown"

            ports.append(
                {
                    "host": host_ip or "unknown",
                    "port": port.get("portid") or "unknown",
                    "protocol": port.get("protocol") or "tcp",
                    "service": service_name,
                    "version": version_text,
                }
            )

    return ports


def _risk_summary(findings: list[Finding]) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        key = finding.severity.value
        if key in summary:
            summary[key] += 1
    return summary


def _overall_risk(summary: dict[str, int]) -> str:
    if summary["critical"] > 0:
        return "Critical"
    if summary["high"] > 0:
        return "High"
    if summary["medium"] > 0:
        return "Medium"
    if summary["low"] > 0:
        return "Low"
    return "Informational"


def _draw_heading(pdf: canvas.Canvas, title: str, y: float) -> float:
    pdf.setFont("Helvetica-Bold", 12)
    pdf.setFillColor(colors.HexColor("#0B2E4F"))
    pdf.drawString(40, y, title)
    pdf.setFillColor(colors.black)
    return y - 18


def _draw_wrapped_text(pdf: canvas.Canvas, text: str, y: float, width: int = 95, font_size: int = 9) -> float:
    pdf.setFont("Helvetica", font_size)
    words = text.split()
    line = []
    while words:
        line.append(words.pop(0))
        if len(" ".join(line)) >= width:
            pdf.drawString(40, y, " ".join(line))
            y -= 12
            line = []
            if y < 60:
                pdf.showPage()
                y = 800
                pdf.setFont("Helvetica", font_size)
    if line:
        pdf.drawString(40, y, " ".join(line))
        y -= 12
    return y


def _draw_pdf(
    output_path: Path,
    asset: Asset,
    scan: Scan,
    open_ports: list[dict[str, str]],
    findings: list[Finding],
) -> None:
    pdf = canvas.Canvas(str(output_path), pagesize=A4)
    y = 810

    pdf.setFont("Helvetica-Bold", 20)
    pdf.setFillColor(colors.HexColor("#0B2E4F"))
    pdf.drawString(40, y, "Aegis V2 Security Assessment")
    y -= 30

    pdf.setFont("Helvetica", 10)
    pdf.setFillColor(colors.black)
    pdf.drawString(40, y, f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    y -= 24

    y = _draw_heading(pdf, "Target Information", y)
    target_lines = [
        f"Asset: {asset.name}",
        f"Target: {asset.target}",
        f"IP: {asset.ip_address or 'N/A'}",
        f"Hostname: {asset.hostname or 'N/A'}",
        f"Scan Date: {(scan.completed_at or scan.created_at).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Scan Mode: {scan.mode.value}",
        f"Scan Status: {scan.status.value}",
    ]
    for line in target_lines:
        pdf.drawString(40, y, line)
        y -= 14

    y -= 8
    y = _draw_heading(pdf, "Open Ports", y)
    if open_ports:
        for port in open_ports[:60]:
            text = f"{port['host']}:{port['port']}/{port['protocol']} - {port['service']} ({port['version']})"
            y = _draw_wrapped_text(pdf, text, y, width=110, font_size=9)
            if y < 80:
                pdf.showPage()
                y = 810
    else:
        pdf.drawString(40, y, "No open ports parsed from scan output.")
        y -= 14

    if y < 120:
        pdf.showPage()
        y = 810

    y = _draw_heading(pdf, "Findings", y)
    if findings:
        for finding in findings[:80]:
            pdf.setFont("Helvetica-Bold", 10)
            pdf.drawString(40, y, f"[{finding.severity.value.upper()}] {finding.title}")
            y -= 12
            pdf.setFont("Helvetica", 9)
            y = _draw_wrapped_text(pdf, finding.description, y, width=110, font_size=9)
            if finding.cvss_score is not None:
                pdf.drawString(40, y, f"CVSS Estimate: {float(finding.cvss_score):.1f}")
                y -= 12
            if finding.remediation:
                y = _draw_wrapped_text(pdf, f"Recommendation: {finding.remediation}", y, width=110, font_size=9)
            y -= 8
            if y < 80:
                pdf.showPage()
                y = 810
    else:
        pdf.drawString(40, y, "No findings were generated for this scan.")
        y -= 14

    if y < 140:
        pdf.showPage()
        y = 810

    summary = _risk_summary(findings)
    y = _draw_heading(pdf, "Risk Summary", y)
    pdf.drawString(40, y, f"Overall Risk: {_overall_risk(summary)}")
    y -= 14
    pdf.drawString(40, y, f"Critical: {summary['critical']}  High: {summary['high']}  Medium: {summary['medium']}  Low: {summary['low']}")
    y -= 22

    y = _draw_heading(pdf, "Recommendations", y)
    recommendations = [
        "Close or filter unnecessary exposed services at network boundaries.",
        "Prioritize remediation of critical and high severity findings.",
        "Apply vendor security updates and verify service versions are current.",
        "Enforce segmentation and least-privilege access to scanned assets.",
        "Schedule recurring scans to detect drift and new exposures.",
    ]
    for item in recommendations:
        y = _draw_wrapped_text(pdf, f"- {item}", y, width=110, font_size=10)

    pdf.showPage()
    pdf.save()


def generate_scan_report(database: Session, owner_id: str, scan_id: str) -> dict:
    try:
        owner_uuid = UUID(owner_id)
        scan_uuid = UUID(scan_id)
    except (TypeError, ValueError) as exc:
        raise ReportServiceError("Invalid identifier") from exc

    scan = (
        database.query(Scan)
        .join(Asset, Asset.id == Scan.asset_id)
        .filter(Scan.id == scan_uuid, Asset.owner_id == owner_uuid)
        .first()
    )
    if scan is None:
        raise ReportServiceError("Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise ReportServiceError("Scan must be completed before report generation")

    asset = database.query(Asset).filter(Asset.id == scan.asset_id).first()
    if asset is None:
        raise ReportServiceError("Associated asset not found")

    severity_rank = case(
        (Finding.severity == FindingSeverity.CRITICAL, 5),
        (Finding.severity == FindingSeverity.HIGH, 4),
        (Finding.severity == FindingSeverity.MEDIUM, 3),
        (Finding.severity == FindingSeverity.LOW, 2),
        else_=1,
    )

    findings = (
        database.query(Finding)
        .filter(Finding.scan_id == scan.id)
        .order_by(
            severity_rank.desc(),
            Finding.cvss_score.desc().nullslast(),
            Finding.created_at.desc(),
        )
        .all()
    )

    open_ports = _extract_open_ports(scan.raw_xml)

    output_dir = Path(settings.report_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = f"scan-report-{scan.id}.pdf"
    output_path = output_dir / filename

    _draw_pdf(output_path=output_path, asset=asset, scan=scan, open_ports=open_ports, findings=findings)

    file_bytes = output_path.read_bytes()
    checksum = hashlib.sha256(file_bytes).hexdigest()

    report = Report(
        generated_by_id=owner_uuid,
        asset_id=asset.id,
        scan_id=scan.id,
        report_type=ReportType.TECHNICAL,
        status=ReportStatus.READY,
        title=f"Aegis Scan Report - {asset.name}",
        storage_path=str(output_path),
        checksum=checksum,
        generated_at=datetime.now(UTC),
    )
    database.add(report)
    database.commit()
    database.refresh(report)

    return {
        "report_id": report.id,
        "scan_id": scan.id,
        "status": report.status.value,
        "storage_path": report.storage_path,
        "download_url": f"{settings.public_base_url}/api/reports/download/{report.id}",
        "generated_at": report.generated_at,
    }
