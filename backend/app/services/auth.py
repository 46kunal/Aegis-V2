from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import and_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import (
    TokenError,
    assert_token_type,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    token_fingerprint,
    verify_password,
)
from app.models.refresh_token import RefreshToken
from app.models.user import User, UserRole


class AuthError(Exception):
    pass


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _serialize_user(user: User) -> dict:
    return {
        "id": str(user.id),
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role.value,
        "is_active": user.is_active,
        "created_at": user.created_at,
    }


def _issue_tokens(database: Session, user: User) -> dict:
    access_token = create_access_token(subject=str(user.id), role=user.role.value)
    refresh_token = create_refresh_token(subject=str(user.id), role=user.role.value)

    payload = decode_token(refresh_token)
    expires_at = datetime.fromtimestamp(payload["exp"], tz=UTC)

    database.add(
        RefreshToken(
            user_id=user.id,
            token_hash=token_fingerprint(refresh_token),
            expires_at=expires_at,
        )
    )
    database.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


def register_user(database: Session, email: str, full_name: str, password: str, role: str = "user") -> dict:
    role = role.lower()
    requested_role = role.strip()
    if requested_role not in {UserRole.ADMIN.value, UserRole.USER.value}:
        raise AuthError("Invalid role")
    if requested_role == UserRole.ADMIN.value:
        raise AuthError("Admin role cannot be assigned through self-registration")

    normalized_email = _normalize_email(email)
    existing = database.query(User).filter(User.email == normalized_email).first()
    if existing is not None:
        raise AuthError("Email is already registered")

    user = User(
        email=normalized_email,
        full_name=full_name.strip(),
        password_hash=hash_password(password),
        role=UserRole(requested_role),
        is_active=True,
    )
    database.add(user)
    database.commit()
    database.refresh(user)

    tokens = _issue_tokens(database, user)
    return {"user": _serialize_user(user), "tokens": tokens}


def login_user(database: Session, email: str, password: str) -> dict:
    normalized_email = _normalize_email(email)
    user = database.query(User).filter(User.email == normalized_email).first()
    if user is None or not verify_password(password, user.password_hash):
        raise AuthError("Invalid credentials")
    if not user.is_active:
        raise AuthError("User is inactive")

    user.last_login_at = datetime.now(UTC)
    database.commit()

    tokens = _issue_tokens(database, user)
    return {"user": _serialize_user(user), "tokens": tokens}


def refresh_user_tokens(database: Session, refresh_token: str) -> dict:
    try:
        payload = decode_token(refresh_token)
        assert_token_type(payload, "refresh")
    except TokenError as exc:
        raise AuthError(str(exc)) from exc

    user_id = payload.get("sub")
    if user_id is None:
        raise AuthError("Invalid token subject")

    token_hash = token_fingerprint(refresh_token)
    now = datetime.now(UTC)

    record = (
        database.query(RefreshToken)
        .filter(
            and_(
                RefreshToken.token_hash == token_hash,
                RefreshToken.revoked_at.is_(None),
                RefreshToken.expires_at > now,
            )
        )
        .first()
    )
    if record is None:
        raise AuthError("Refresh token is invalid or expired")

    try:
        parsed_user_id = UUID(str(user_id))
    except (TypeError, ValueError) as exc:
        raise AuthError("Invalid token subject") from exc

    user = database.query(User).filter(User.id == parsed_user_id).first()
    if user is None or not user.is_active:
        raise AuthError("User not found or inactive")

    record.revoked_at = now
    database.commit()

    tokens = _issue_tokens(database, user)
    return {"user": _serialize_user(user), "tokens": tokens}


def get_current_user_profile(database: Session, user_id: str) -> dict:
    try:
        parsed_user_id = UUID(user_id)
    except (TypeError, ValueError) as exc:
        raise AuthError("Invalid user identifier") from exc

    user = database.query(User).filter(User.id == parsed_user_id).first()
    if user is None or not user.is_active:
        raise AuthError("User not found or inactive")
    return _serialize_user(user)
