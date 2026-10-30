"""Structured JSON logging with secret redaction.

Each log line is one JSON object. Structured fields are passed via
`logger.info("msg", extra={"context": {...}})`. Known secret values and
common API-key shapes are redacted from both the message and the context,
so an accidental `log(settings)` or an LLM error echoing a key cannot leak it.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

REDACTED = "[REDACTED]"

# Groq (gsk_), xAI (xai-), OpenAI/Anthropic-style (sk-, sk-ant-) keys.
_KEY_PATTERN = re.compile(r"\b(?:gsk_|xai-|sk-ant-|sk-)[A-Za-z0-9_\-]{16,}")


class Redactor:
    def __init__(self, secrets: Iterable[str] = ()) -> None:
        # Longest first so a secret that contains another is fully replaced.
        self._secrets = sorted({s for s in secrets if s}, key=len, reverse=True)

    def redact(self, value: Any) -> Any:
        if isinstance(value, str):
            for secret in self._secrets:
                value = value.replace(secret, REDACTED)
            return _KEY_PATTERN.sub(REDACTED, value)
        if isinstance(value, dict):
            return {k: self.redact(v) for k, v in value.items()}
        if isinstance(value, list | tuple):
            return [self.redact(v) for v in value]
        return value


class JsonFormatter(logging.Formatter):
    def __init__(self, redactor: Redactor) -> None:
        super().__init__()
        self._redactor = redactor

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        context = getattr(record, "context", None)
        if context is not None:
            payload["context"] = context
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(self._redactor.redact(payload), default=str)


def configure_logging(level: str = "INFO", secrets: Iterable[str] = ()) -> None:
    """Install the JSON handler on the `agentsoc` logger. Safe to call repeatedly."""
    logger = logging.getLogger("agentsoc")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter(Redactor(secrets)))
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False


def get_logger(name: str) -> logging.Logger:
    """Return a logger under the `agentsoc` namespace."""
    return logging.getLogger(name if name.startswith("agentsoc") else f"agentsoc.{name}")
