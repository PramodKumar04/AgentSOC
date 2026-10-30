"""LLM providers behind one replaceable interface."""

from agentsoc.investigator.llm.base import (
    LLMAuthError,
    LLMError,
    LLMInvalidResponseError,
    LLMProvider,
    LLMRateLimitError,
    LLMTimeoutError,
    LLMUnavailableError,
    SimulatedOutageProvider,
)

__all__ = [
    "LLMAuthError",
    "LLMError",
    "LLMInvalidResponseError",
    "LLMProvider",
    "LLMRateLimitError",
    "LLMTimeoutError",
    "LLMUnavailableError",
    "SimulatedOutageProvider",
]
