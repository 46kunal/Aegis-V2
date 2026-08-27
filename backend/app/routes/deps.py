import logging

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings
from app.core.security import assert_token_type, decode_token, TokenError

logger = logging.getLogger("aegis.deps")

bearer_scheme = HTTPBearer(auto_error=False)

# ---------------------------------------------------------------------------
# DEV_MODE: cached demo user UUID (populated on first call)
# ---------------------------------------------------------------------------
_dev_user_id: str | None = None


def _get_dev_user_id() -> str:
    """Return the demo admin user ID, creating the user if necessary."""
    global _dev_user_id
    if _dev_user_id is not None:
        return _dev_user_id

    from app.core.database import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    database = SessionLocal()
    try:
        user = database.query(User).first()
        if user is None:
            user = User(
                email="admin@aegis.local",
                full_name="Aegis Admin",
                password_hash=hash_password("admin123"),
                role=UserRole.ADMIN,
                is_active=True,
            )
            database.add(user)
            database.commit()
            database.refresh(user)
            logger.warning("DEV_MODE: seeded demo admin user admin@aegis.local / admin123")

        _dev_user_id = str(user.id)
        return _dev_user_id
    finally:
        database.close()


def get_current_user_id(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> str:
    # ── DEV_MODE bypass ──────────────────────────────────────────────────
    if settings.dev_mode:
        return _get_dev_user_id()
    # ── Normal production flow ───────────────────────────────────────────

    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    try:
        payload = decode_token(credentials.credentials)
        assert_token_type(payload, "access")
    except TokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    subject = payload.get("sub")
    if not subject:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")

    return str(subject)
