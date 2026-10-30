"""Environment-based configuration.

Settings are read from environment variables and the project's `.env` file.
A missing or incomplete LLM configuration is NOT an error: the system degrades
to the deterministic fallback investigator (see `Settings.llm_enabled`).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from agentsoc.exceptions import ConfigurationError

# src/agentsoc/config.py -> project root is two levels above the package.
PROJECT_ROOT = Path(__file__).resolve().parents[2]

LLMProvider = Literal["groq", "none"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    llm_provider: LLMProvider = "none"
    groq_api_key: SecretStr | None = None
    groq_model: str | None = None
    groq_base_url: str = "https://api.groq.com/openai/v1"

    llm_timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    llm_max_retries: int = Field(default=2, ge=0, le=5)
    llm_max_tokens: int = Field(default=2000, ge=1, le=8000)

    db_path: Path = Field(default=Path("data/agentsoc.db"), validation_alias="AGENTSOC_DB_PATH")
    log_level: LogLevel = "INFO"

    @field_validator("llm_provider", "log_level", mode="before")
    @classmethod
    def _normalise_case(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        value = value.strip()
        return value.upper() if value.upper() in LogLevel.__args__ else value.lower()

    @field_validator("groq_api_key", "groq_model", mode="before")
    @classmethod
    def _blank_to_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("groq_base_url")
    @classmethod
    def _require_https(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("GROQ_BASE_URL must use https://")
        return value.rstrip("/")

    @field_validator("db_path")
    @classmethod
    def _resolve_db_path(cls, value: Path) -> Path:
        return value if value.is_absolute() else PROJECT_ROOT / value

    @property
    def llm_disabled_reason(self) -> str | None:
        """Why the LLM investigator is unavailable, or None if it is usable."""
        if self.llm_provider == "none":
            return "LLM_PROVIDER is 'none'"
        if self.groq_api_key is None:
            return "GROQ_API_KEY is not set"
        if self.groq_model is None:
            return "GROQ_MODEL is not set"
        return None

    @property
    def llm_enabled(self) -> bool:
        return self.llm_disabled_reason is None

    def secret_values(self) -> list[str]:
        """Raw secret strings, for log redaction only."""
        return [self.groq_api_key.get_secret_value()] if self.groq_api_key else []


def load_settings(**overrides: object) -> Settings:
    """Build Settings, converting validation failures into ConfigurationError.

    Only field locations and messages are reported — never input values,
    which could contain secrets.
    """
    try:
        return Settings(**overrides)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()
        )
        raise ConfigurationError(f"Invalid configuration: {problems}") from None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton. Call `get_settings.cache_clear()` in tests."""
    return load_settings()
