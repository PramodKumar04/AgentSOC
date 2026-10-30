"""Provider interface and the error vocabulary every provider maps to.

Error messages are written by us, never copied from SDK exceptions, so they
cannot carry API keys or request bodies.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from agentsoc.exceptions import AgentSOCError


class LLMError(AgentSOCError):
    """Base for provider failures. `kind` is a short, display-safe category."""

    kind = "error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.safe_message = message


class LLMTimeoutError(LLMError):
    kind = "timeout"


class LLMRateLimitError(LLMError):
    kind = "rate_limited"


class LLMAuthError(LLMError):
    kind = "authentication"


class LLMUnavailableError(LLMError):
    kind = "unavailable"


class LLMInvalidResponseError(LLMError):
    """The service answered, but not with usable JSON (e.g. truncated or malformed)."""

    kind = "invalid_response"


class LLMProvider(ABC):
    """Returns one JSON object as text for a system + user prompt."""

    name: str
    model: str

    @abstractmethod
    def complete_json(self, system: str, user: str, feedback: str | None = None) -> str:
        """`feedback` carries validation errors from a previous attempt (repair round)."""


class SimulatedOutageProvider(LLMProvider):
    """Always fails as an unavailable service. Used to demonstrate fallback honestly."""

    name = "simulated-outage"
    model = "none"

    def complete_json(self, system: str, user: str, feedback: str | None = None) -> str:
        raise LLMUnavailableError("simulated outage (demo switch); no request was sent")
