import enum
import uuid

from sqlalchemy import Column, DateTime, Enum, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.core.database import Base


class ScanType(str, enum.Enum):
    BASELINE = "baseline"
    NETWORK = "network"
    WEB = "web"
    CONFIG = "config"
    COMPLIANCE = "compliance"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanMode(str, enum.Enum):
    FAST = "fast"
    SMART_FAST = "smart_fast"
    MEDIUM = "medium"
    FULL = "full"
    SUPER_FULL = "super_full"


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_asset_id", "asset_id"),
        Index("ix_scans_requested_by_id", "requested_by_id"),
        Index("ix_scans_status", "status"),
        Index("ix_scans_mode", "mode"),
        Index("ix_scans_created_at", "created_at"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    requested_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    mode = Column(Enum(ScanMode, name="scan_mode", values_callable=lambda e: [m.value for m in e]), nullable=False, default=ScanMode.FAST)
    scan_type = Column(Enum(ScanType, name="scan_type", values_callable=lambda e: [m.value for m in e]), nullable=False, default=ScanType.BASELINE)
    status = Column(Enum(ScanStatus, name="scan_status", values_callable=lambda e: [m.value for m in e]), nullable=False, default=ScanStatus.QUEUED)
    progress = Column(Integer, nullable=False, default=0)
    celery_task_id = Column(String(255), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    summary = Column(Text, nullable=True)
    raw_xml = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    asset = relationship("Asset", back_populates="scans")
    requested_by = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan")
