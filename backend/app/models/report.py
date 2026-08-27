import enum
import uuid

from sqlalchemy import Column, DateTime, Enum, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.core.database import Base


class ReportType(str, enum.Enum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance"
    INCIDENT = "incident"


class ReportStatus(str, enum.Enum):
    PENDING = "pending"
    READY = "ready"
    FAILED = "failed"


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (
        Index("ix_reports_generated_by_id", "generated_by_id"),
        Index("ix_reports_asset_id", "asset_id"),
        Index("ix_reports_scan_id", "scan_id"),
        Index("ix_reports_status", "status"),
        Index("ix_reports_created_at", "created_at"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    generated_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    report_type = Column(Enum(ReportType, name="report_type", values_callable=lambda e: [m.value for m in e]), nullable=False)
    status = Column(Enum(ReportStatus, name="report_status", values_callable=lambda e: [m.value for m in e]), nullable=False, default=ReportStatus.PENDING)
    title = Column(String(255), nullable=False)
    storage_path = Column(Text, nullable=False)
    checksum = Column(String(128), nullable=True)
    generated_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    generated_by = relationship("User", back_populates="reports")
    asset = relationship("Asset", back_populates="reports")
    scan = relationship("Scan", back_populates="reports")
