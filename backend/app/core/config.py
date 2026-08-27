from functools import lru_cache
import json
from typing import Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        enable_decoding=False,
        extra="ignore",
    )

    project_name: str = "Aegis V2"
    environment: str = "development"
    database_url: str = "postgresql+psycopg2://aegis:aegis@localhost:5432/aegis"
    secret_key: str = "change-me"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    redis_url: str = "redis://localhost:6379/0"
    nmap_binary: str = "nmap"
    scan_timeout_fast_seconds: int = 180
    scan_timeout_smart_fast_seconds: int = 300
    scan_timeout_medium_seconds: int = 600
    scan_timeout_full_seconds: int = 3600
    scan_timeout_super_full_seconds: int = 7200
    report_output_dir: str = "generated-reports"
    public_base_url: str = "http://localhost:8000"
    cors_origins: list[str] = ["http://localhost:5173"]
    log_level: str = "INFO"
    dev_mode: bool = False
    # NVD API key from https://nvd.nist.gov/developers/request-an-api-key
    # Without key: 5 req/30s (6.5s sleep enforced). With key: 50 req/30s (0.7s sleep).
    nvd_api_key: str | None = None

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: Any) -> list[str]:
        if value is None:
            return []

        if isinstance(value, str):
            raw_value = value.strip()
            if not raw_value:
                return []

            if raw_value.startswith("["):
                try:
                    decoded = json.loads(raw_value)
                except json.JSONDecodeError as exc:
                    raise ValueError("CORS_ORIGINS must be a JSON array or comma-separated origins") from exc
                if not isinstance(decoded, list):
                    raise ValueError("CORS_ORIGINS JSON value must be an array")
                return [str(origin).strip() for origin in decoded if str(origin).strip()]

            return [origin.strip() for origin in raw_value.split(",") if origin.strip()]

        if isinstance(value, (list, tuple, set)):
            return [str(origin).strip() for origin in value if str(origin).strip()]

        raise ValueError("CORS_ORIGINS must be a JSON array or comma-separated origins")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
