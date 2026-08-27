import enum
import uuid

from sqlalchemy import Boolean, Column, DateTime, Enum, ForeignKey, Index, Integer, Numeric, String, Text, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.core.database import Base


class FindingSeverity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_scan_id", "scan_id"),
        Index("ix_findings_asset_id", "asset_id"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_status", "status"),
        Index("ix_findings_is_kev", "is_kev"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(Enum(FindingSeverity, name="finding_severity", values_callable=lambda e: [m.value for m in e]), nullable=False)
    cvss_score = Column(Numeric(4, 1), nullable=True)
    status = Column(Enum(FindingStatus, name="finding_status", values_callable=lambda e: [m.value for m in e]), nullable=False, default=FindingStatus.OPEN)
    cve_id = Column(String(40), nullable=True)
    cwe_id = Column(String(32), nullable=True)
    is_kev = Column(Boolean, nullable=False, default=False)
    cvss_vector = Column(String(128), nullable=True)
    epss_score = Column(Numeric(5, 4), nullable=True)
    references = Column(JSONB, nullable=True)
    published_date = Column(DateTime(timezone=True), nullable=True)
    remediation = Column(Text, nullable=True)

    # ── Structured service intelligence fields ───────────────────────
    port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    detected_product = Column(String(255), nullable=True)
    detected_version = Column(String(255), nullable=True)
    cpe = Column(String(512), nullable=True)
    script_output = Column(Text, nullable=True)
    raw_service = Column(String(128), nullable=True)
    normalized_service = Column(String(128), nullable=True)
    extracted_version = Column(String(128), nullable=True)
    generated_cpe = Column(String(512), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    scan = relationship("Scan", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")

