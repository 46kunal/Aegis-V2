from __future__ import annotations

import uuid

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base
from app.models import Asset, Finding, Scan, User
from app.models.asset import AssetCriticality, AssetStatus, AssetType
from app.models.finding import FindingSeverity
from app.models.scan import ScanMode, ScanStatus, ScanType
from app.models.user import UserRole
from app.scanner import nmap_parser
from app.scanner.nmap_parser import parse_and_create_findings


@compiles(JSONB, "sqlite")
def _compile_jsonb_for_sqlite(type_, compiler, **kw) -> str:
    return "JSON"


SAMPLE_XML = """
<nmaprun>
  <host>
    <status state="up" />
    <address addr="10.0.0.10" addrtype="ipv4" />
    <hostnames>
      <hostname name="lab-host.local" />
    </hostnames>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open" />
        <service name="ftp" product="vsftpd" version="3.0.3">
          <cpe>cpe:/a:vsftpd:vsftpd:3.0.3</cpe>
        </service>
        <script id="banner" output="220 vsftpd 3.0.3" />
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <service name="ssh" product="OpenSSH" version="9.0">
          <cpe>cpe:/a:openbsd:openssh:9.0</cpe>
        </service>
        <script id="ssh-hostkey" output="ssh-rsa fingerprint" />
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="Apache httpd" version="2.4.57">
          <cpe>cpe:/a:apache:http_server:2.4.57</cpe>
        </service>
        <script id="http-title" output="It works" />
      </port>
      <port protocol="tcp" portid="445">
        <state state="open" />
        <service name="microsoft-ds" product="Samba smbd" version="4.19.0">
          <cpe>cpe:/a:samba:samba:4.19.0</cpe>
        </service>
        <script id="smb-os-discovery" output="Samba server" />
      </port>
    </ports>
  </host>
</nmaprun>
""".strip()


def _seed_scan(database: Session) -> Scan:
    user = User(
        id=uuid.uuid4(),
        email="persistence-debug@example.com",
        full_name="Persistence Debug",
        password_hash="debug",
        role=UserRole.USER,
        is_active=True,
    )
    database.add(user)
    database.flush()

    asset = Asset(
        id=uuid.uuid4(),
        owner_id=user.id,
        name="Persistence Debug Host",
        target="10.0.0.10",
        ip_address="10.0.0.10",
        hostname="lab-host.local",
        discovery_status="up",
        asset_type=AssetType.HOST,
        status=AssetStatus.ACTIVE,
        criticality=AssetCriticality.MEDIUM,
    )
    database.add(asset)
    database.flush()

    scan = Scan(
        id=uuid.uuid4(),
        asset_id=asset.id,
        requested_by_id=user.id,
        mode=ScanMode.FULL,
        scan_type=ScanType.NETWORK,
        status=ScanStatus.RUNNING,
        progress=90,
        summary="Persistence debug",
    )
    database.add(scan)
    database.commit()
    database.refresh(scan)
    return scan


def _print_finding(prefix: str, finding: Finding) -> None:
    print(
        prefix,
        {
            "title": finding.title,
            "port": finding.port,
            "protocol": finding.protocol,
            "detected_product": finding.detected_product,
            "detected_version": finding.detected_version,
            "cpe": finding.cpe,
            "script_output": finding.script_output,
            "severity": finding.severity.value if isinstance(finding.severity, FindingSeverity) else finding.severity,
        },
    )


def main() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, class_=Session)

    findings_columns = {column["name"] for column in inspect(engine).get_columns("findings")}
    expected_columns = {"detected_product", "detected_version", "cpe", "script_output"}
    print("DEBUG_SCHEMA_FINDINGS_COLUMNS", sorted(expected_columns & findings_columns))

    @event.listens_for(SessionLocal, "before_flush")
    def _before_flush(session: Session, flush_context, instances) -> None:
        for obj in session.new:
            if isinstance(obj, Finding):
                _print_finding("DEBUG_FINDING_BEFORE_INSERT", obj)

    @event.listens_for(SessionLocal, "after_commit")
    def _after_commit(session: Session) -> None:
        print("DEBUG_COMMIT_SUCCESS")

    database = SessionLocal()
    nmap_parser._best_cve_for_port = lambda database, cpe_list: None

    scan = _seed_scan(database)
    count, risky_count, os_fingerprint = parse_and_create_findings(
        database=database,
        scan=scan,
        xml_output=SAMPLE_XML,
        fallback_target="10.0.0.10",
    )

    rows = (
        database.query(Finding)
        .filter(Finding.scan_id == scan.id)
        .order_by(Finding.port.asc())
        .all()
    )

    print("DEBUG_PARSE_RESULT", {"count": count, "risky_count": risky_count, "os_fingerprint": os_fingerprint})
    print("DEBUG_DB_ROW_COUNT", len(rows))
    for row in rows:
        _print_finding("DEBUG_FINDING_AFTER_COMMIT", row)

    assert count == 4
    assert len(rows) == 4
    assert expected_columns <= findings_columns
    assert any(row.detected_product == "vsftpd" for row in rows)
    assert any(row.detected_product == "OpenSSH" for row in rows)
    assert any("Apache" in (row.detected_product or "") for row in rows)
    assert any("Samba" in (row.detected_product or "") for row in rows)
    assert all(row.cpe and row.cpe.startswith("cpe:/a:") for row in rows)
    assert all(row.script_output for row in rows)


if __name__ == "__main__":
    main()
