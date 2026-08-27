from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class TokenError(Exception):
    pass


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def _encode_token(subject: str, role: str, token_type: str, expires_delta: timedelta) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": subject,
        "role": role,
        "type": token_type,
        "jti": str(uuid4()),
        "iat": now,
        "nbf": now,
        "exp": now + expires_delta,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def create_access_token(subject: str, role: str) -> str:
    return _encode_token(
        subject=subject,
        role=role,
        token_type="access",
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
    )


def create_refresh_token(subject: str, role: str) -> str:
    return _encode_token(
        subject=subject,
        role=role,
        token_type="refresh",
        expires_delta=timedelta(days=settings.refresh_token_expire_days),
    )


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError as exc:
        raise TokenError("Invalid token") from exc


def assert_token_type(payload: dict, expected_type: str) -> None:
    token_type = payload.get("type")
    if token_type != expected_type:
        raise TokenError("Invalid token type")


def token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
