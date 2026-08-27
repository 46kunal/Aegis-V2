import datetime

from sqlalchemy import Column, Date, DateTime, Index, String, func

from app.core.database import Base


class KevCatalog(Base):
    """CISA Known Exploited Vulnerabilities catalog cache."""
    __tablename__ = "kev_catalog"
    __table_args__ = (
        Index("ix_kev_catalog_date_added", "date_added"),
    )

    cve_id = Column(String(40), primary_key=True)
    vulnerability_name = Column(String(512), nullable=True)
    product = Column(String(255), nullable=True)
    date_added = Column(Date, nullable=True)
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        default=datetime.datetime.now(datetime.UTC),
    )
