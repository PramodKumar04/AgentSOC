"""Verify the development environment: settings load, and (if enabled) the
configured LLM endpoint is reachable and the configured model is available.

Only lists models — sends no prompts and no project data.

Usage:  python scripts/check_environment.py
"""

from __future__ import annotations

import os
import sys

from dotenv import dotenv_values

from agentsoc.config import PROJECT_ROOT, get_settings
from agentsoc.exceptions import ConfigurationError

SECRET_VARS = ("GROQ_API_KEY",)


def _warn_env_overrides() -> None:
    """OS environment variables take precedence over .env (pydantic-settings).
    A stale system-wide key silently shadows the project's key, so name it."""
    dotenv = dotenv_values(PROJECT_ROOT / ".env")
    for name, file_value in dotenv.items():
        os_value = os.environ.get(name)
        if os_value is None or not file_value or os_value == file_value:
            continue
        shown = (
            (f"{os_value[:8]}...", f"{file_value[:8]}...")
            if name in SECRET_VARS else (os_value, file_value)
        )
        print(f"[WARN] {name} from the OS environment ({shown[0]}) overrides .env ({shown[1]}). "
              f"Remove the OS variable or make them match.")


def main() -> int:
    _warn_env_overrides()
    try:
        settings = get_settings()
    except ConfigurationError as exc:
        print(f"[FAIL] {exc}")
        return 1

    print(f"[ OK ] settings loaded (provider={settings.llm_provider}, log={settings.log_level})")
    if not settings.llm_enabled:
        print(f"[INFO] LLM disabled: {settings.llm_disabled_reason} -> fallback investigator only")
        return 0

    from openai import OpenAI, OpenAIError

    client = OpenAI(
        api_key=settings.groq_api_key.get_secret_value(),
        base_url=settings.groq_base_url,
        timeout=settings.llm_timeout_seconds,
        max_retries=0,
    )
    try:
        available = sorted(m.id for m in client.models.list())
    except OpenAIError as exc:
        print(f"[FAIL] cannot reach {settings.groq_base_url}: {type(exc).__name__}")
        return 1

    print(f"[ OK ] reached {settings.groq_base_url} ({len(available)} models visible)")
    if settings.groq_model in available:
        print(f"[ OK ] configured model '{settings.groq_model}' is available")
        return 0
    print(f"[FAIL] model '{settings.groq_model}' not available. Options: {', '.join(available)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
