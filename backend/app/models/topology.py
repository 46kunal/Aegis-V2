import uuid

from sqlalchemy import Column, DateTime, Float, ForeignKey, Index, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID

from app.core.database import Base


class AssetEdge(Base):
    """Directed relationship edge between two assets in the digital twin graph."""
    __tablename__ = "asset_edges"
    __table_args__ = (
        Index("ix_asset_edges_owner_id", "owner_id"),
        Index("ix_asset_edges_source_id", "source_id"),
        Index("ix_asset_edges_target_id", "target_id"),
        Index("ix_asset_edges_relationship", "relationship"),
        UniqueConstraint("source_id", "target_id", "relationship", name="uq_asset_edges_src_tgt_rel"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    source_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    target_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    relationship = Column(String(48), nullable=False)
    label = Column(String(255), nullable=True)
    weight = Column(Float, nullable=False, default=1.0)
    exploitability_score = Column(Float, nullable=True)   # CVE/KEV/EPSS-boosted weight
    technique_id = Column(String(20), nullable=True)       # MITRE ATT&CK technique (T1021.004)
    technique_name = Column(String(128), nullable=True)    # human-readable technique name
    inferred_from = Column(String(64), nullable=True)
    meta = Column(JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
