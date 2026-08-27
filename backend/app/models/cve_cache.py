import datetime

from sqlalchemy import Column, DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base

class CVECache(Base):
    __tablename__ = "cve_cache"
    
    cpe_uri = Column(String(512), primary_key=True)
    cve_data = Column(JSONB, nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
