import enum
import uuid

from sqlalchemy import Boolean, Column, DateTime, Enum, Index, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.core.database import Base


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    USER = "user"


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        Index("ix_users_email", "email"),
        Index("ix_users_role", "role"),
        Index("ix_users_is_active", "is_active"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(320), nullable=False, unique=True)
    full_name = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole, name="user_role", values_callable=lambda e: [m.value for m in e]), nullable=False, default=UserRole.USER)
    is_active = Column(Boolean, nullable=False, default=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    assets = relationship("Asset", back_populates="owner", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="requested_by")
    reports = relationship("Report", back_populates="generated_by")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
