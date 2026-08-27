from __future__ import annotations

import subprocess
import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app import models  # noqa: F401
from app.core.database import Base
from app.models.asset import Asset, AssetCriticality, AssetStatus, AssetType
from app.models.finding import Finding
from app.models.scan import Scan, ScanMode, ScanStatus, ScanType
from app.models.user import User, UserRole
from app.workers import scan_tasks

SAMPLE_XML = """
<nmaprun>
  <host>
    <status state="up" />
    <address addr="10.0.0.10" addrtype="ipv4" />
    <hostnames>
      <hostname name="edge-router.local" />
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <service name="ssh" product="OpenSSH" version="9.0" />
      </port>
      <port protocol="tcp" portid="445">
        <state state="open" />
        <service name="microsoft-ds" product="Samba" version="4.19" />
      </port>
    </ports>
  </host>
</nmaprun>
""".strip()


def _build_session() -> sessionmaker:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    return session_factory


def _seed_scan(session_factory, mode: ScanMode = ScanMode.FAST, target: str = "10.0.0.10") -> uuid.UUID:
    session = session_factory()
    user = User(
        id=uuid.uuid4(),
        email="scanner@example.com",
        full_name="Scanner User",
        password_hash="hashed",
        role=UserRole.USER,
        is_active=True,
    )
    session.add(user)
    session.flush()

    asset = Asset(
        id=uuid.uuid4(),
        owner_id=user.id,
        name="Edge Router",
        target=target,
        ip_address=target if "://" not in target else None,
        hostname="edge-router.local",
        mac_address=None,
        discovery_status="up",
        asset_type=AssetType.HOST,
        status=AssetStatus.ACTIVE,
        criticality=AssetCriticality.HIGH,
    )
    session.add(asset)
    session.flush()

    scan = Scan(
        id=uuid.uuid4(),
        asset_id=asset.id,
        requested_by_id=user.id,
        mode=mode,
        scan_type=ScanType.NETWORK,
        status=ScanStatus.QUEUED,
        progress=0,
        summary="queued",
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    scan_id = scan.id
    session.close()
    return scan_id


def test_scan_command_profiles_match_required_modes():
    fast_command, _ = scan_tasks._scan_command(ScanMode.FAST, "10.0.0.10")
    medium_command, _ = scan_tasks._scan_command(ScanMode.MEDIUM, "10.0.0.10")
    full_command, _ = scan_tasks._scan_command(ScanMode.FULL, "10.0.0.10")

    assert fast_command[1:] == ["-Pn", "-F", "--open", "-oX", "-", "10.0.0.10"]
    assert medium_command[1:] == ["-Pn", "-sV", "--version-light", "--top-ports", "200", "--open", "-oX", "-", "10.0.0.10"]
    assert full_command[1:] == ["-Pn", "-sV", "-sC", "-O", "-p-", "--open", "-oX", "-", "10.0.0.10"]


def test_execute_scan_success_stores_xml_and_creates_findings(monkeypatch):
    session_factory = _build_session()
    scan_id = _seed_scan(session_factory=session_factory, mode=ScanMode.FAST)

    milestones: list[tuple[int, str | None]] = []
    original_mark_scan_progress = scan_tasks.mark_scan_progress

    def tracking_mark_scan_progress(database: Session, scan_obj: Scan, progress: int, summary: str | None = None) -> None:
        milestones.append((progress, summary))
        original_mark_scan_progress(database, scan_obj, progress, summary)

    def fake_subprocess_run(*args, **kwargs):
        assert kwargs["timeout"] > 0
        assert kwargs["stdin"] == subprocess.DEVNULL
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout=SAMPLE_XML, stderr="")

    monkeypatch.setattr(scan_tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(scan_tasks, "mark_scan_progress", tracking_mark_scan_progress)
    monkeypatch.setattr(scan_tasks.subprocess, "run", fake_subprocess_run)

    result = scan_tasks.execute_scan.run(str(scan_id))

    verification_session = session_factory()
    refreshed_scan = verification_session.get(Scan, scan_id)
    findings = verification_session.query(Finding).filter(Finding.scan_id == scan_id).all()

    assert result["status"] == "completed"
    assert refreshed_scan is not None
    assert refreshed_scan.status == ScanStatus.COMPLETED
    assert refreshed_scan.progress == 100
    assert refreshed_scan.raw_xml == SAMPLE_XML
    assert refreshed_scan.summary == "Scan completed: 1 hosts up. Findings: 2 (risky ports: 1)"
    assert refreshed_scan.completed_at is not None
    assert milestones == [
        (40, "Executing nmap scan"),
        (80, "Parsing scan output"),
        (90, "Creating findings from scan output"),
    ]
    assert len(findings) == 2
    assert any(finding.title.startswith("Open port 445/") for finding in findings)
    verification_session.close()


def test_execute_scan_timeout_marks_scan_failed(monkeypatch):
    session_factory = _build_session()
    scan_id = _seed_scan(session_factory=session_factory, mode=ScanMode.MEDIUM)

    def fake_subprocess_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs["timeout"])

    monkeypatch.setattr(scan_tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(scan_tasks.subprocess, "run", fake_subprocess_run)

    result = scan_tasks.execute_scan.run(str(scan_id))

    verification_session = session_factory()
    refreshed_scan = verification_session.get(Scan, scan_id)
    findings = verification_session.query(Finding).filter(Finding.scan_id == scan_id).all()

    assert result["status"] == "failed"
    assert refreshed_scan is not None
    assert refreshed_scan.status == ScanStatus.FAILED
    assert refreshed_scan.error_message == "scan timed out"
    assert refreshed_scan.completed_at is not None
    assert refreshed_scan.raw_xml is None
    assert findings == []
    verification_session.close()


def test_execute_scan_invalid_target_is_rejected(monkeypatch):
    session_factory = _build_session()
    scan_id = _seed_scan(session_factory=session_factory, mode=ScanMode.FAST, target="-sS")

    def should_not_run_subprocess(*args, **kwargs):
        raise AssertionError("subprocess.run should not be invoked for invalid targets")

    monkeypatch.setattr(scan_tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(scan_tasks.subprocess, "run", should_not_run_subprocess)

    result = scan_tasks.execute_scan.run(str(scan_id))

    verification_session = session_factory()
    refreshed_scan = verification_session.get(Scan, scan_id)

    assert result["status"] == "failed"
    assert refreshed_scan is not None
    assert refreshed_scan.status == ScanStatus.FAILED
    assert refreshed_scan.error_message == "Asset target is invalid"
    verification_session.close()
