import enum
import uuid

from sqlalchemy import Boolean, Column, DateTime, Enum, Float, ForeignKey, Index, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.core.database import Base


class AssetType(str, enum.Enum):
    HOST = "host"
    DOMAIN = "domain"
    IP = "ip"
    WEBAPP = "webapp"
    CLOUD = "cloud"
    API = "api"


class AssetStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    RETIRED = "retired"


class AssetCriticality(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AssetExposure(str, enum.Enum):
    INTERNAL = "internal"      # reachable only inside the network
    EXTERNAL = "external"      # internet-facing
    SEGMENTED = "segmented"    # behind network segmentation / VLAN
    ISOLATED = "isolated"      # air-gapped / no lateral reachability


class AssetZone(str, enum.Enum):
    LAB = "lab"
    INTERNAL = "internal"
    EXTERNAL = "external"
    DMZ = "dmz"
    INFRASTRUCTURE = "infrastructure"
    UNKNOWN = "unknown"


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        Index("ix_assets_owner_id", "owner_id"),
        Index("ix_assets_asset_type", "asset_type"),
        Index("ix_assets_status", "status"),
        Index("ix_assets_criticality", "criticality"),
        Index("ix_assets_exposure", "exposure"),
        Index("ix_assets_managed", "managed"),
        Index("ix_assets_asset_zone", "asset_zone"),
        Index("ix_assets_topology_visible", "topology_visible"),
        Index("ix_assets_risk_score", "risk_score"),
        Index("ix_assets_ip_address", "ip_address"),
        Index("ix_assets_mac_address", "mac_address"),
        UniqueConstraint("owner_id", "ip_address", name="uq_assets_owner_ip_address"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    target = Column(Text, nullable=False)
    ip_address = Column(String(64), nullable=True)
    hostname = Column(String(255), nullable=True)
    mac_address = Column(String(64), nullable=True)
    discovery_status = Column(String(16), nullable=True)
    os_fingerprint = Column(String(512), nullable=True)
    asset_type = Column(Enum(AssetType, name="asset_type", values_callable=lambda e: [m.value for m in e]), nullable=False)
    status = Column(Enum(AssetStatus, name="asset_status", values_callable=lambda e: [m.value for m in e]), nullable=False, default=AssetStatus.ACTIVE)
    criticality = Column(
        Enum(AssetCriticality, name="asset_criticality", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=AssetCriticality.MEDIUM,
    )
    exposure = Column(
        Enum(AssetExposure, name="asset_exposure", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=AssetExposure.INTERNAL,
    )
    managed = Column(Boolean, nullable=False, default=False, server_default="false")
    asset_zone = Column(
        Enum(AssetZone, name="asset_zone", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=AssetZone.UNKNOWN,
        server_default="unknown",
    )
    topology_visible = Column(Boolean, nullable=False, default=True, server_default="true")
    attack_surface_enabled = Column(Boolean, nullable=False, default=True, server_default="true")
    risk_score = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    owner = relationship("User", back_populates="assets")
    scans = relationship("Scan", back_populates="asset", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="asset")
