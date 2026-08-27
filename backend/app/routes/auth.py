from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.schemas.auth import AuthResponse, LoginRequest, RefreshRequest, RegisterRequest, TokenPairResponse, UserResponse
from app.routes.deps import get_current_user_id
from app.services.auth import AuthError, get_current_user_profile, login_user, refresh_user_tokens, register_user

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.get("/dev-status")
def dev_status() -> dict:
    return {"dev_mode": settings.dev_mode}


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, database: Session = Depends(get_db)) -> AuthResponse:
    try:
        result = register_user(
            database=database,
            email=payload.email,
            full_name=payload.full_name,
            password=payload.password,
            role=payload.role,
        )
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return AuthResponse(user=UserResponse(**result["user"]), tokens=TokenPairResponse(**result["tokens"]))


@router.post("/login", response_model=AuthResponse)
def login(payload: LoginRequest, database: Session = Depends(get_db)) -> AuthResponse:
    try:
        result = login_user(database=database, email=payload.email, password=payload.password)
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    return AuthResponse(user=UserResponse(**result["user"]), tokens=TokenPairResponse(**result["tokens"]))


@router.post("/refresh", response_model=AuthResponse)
def refresh(payload: RefreshRequest, database: Session = Depends(get_db)) -> AuthResponse:
    try:
        result = refresh_user_tokens(database=database, refresh_token=payload.refresh_token)
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    return AuthResponse(user=UserResponse(**result["user"]), tokens=TokenPairResponse(**result["tokens"]))


@router.get("/me", response_model=UserResponse)
def me(user_id: str = Depends(get_current_user_id), database: Session = Depends(get_db)) -> UserResponse:
    try:
        user = get_current_user_profile(database=database, user_id=user_id)
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    return UserResponse(**user)
