from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class RegisterRequest(BaseModel):
    email: str
    full_name: str = Field(min_length=2, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    role: Literal["Admin", "User", "admin", "user"] = "User"

    @field_validator("role", mode="before")
    @classmethod
    def lowercase_role(cls, v: str) -> str:
        return v.lower() if isinstance(v, str) else v


class LoginRequest(BaseModel):
    email: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenPairResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime


class AuthResponse(BaseModel):
    user: UserResponse
    tokens: TokenPairResponse
