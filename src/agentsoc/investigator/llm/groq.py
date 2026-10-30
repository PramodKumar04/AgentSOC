"""Groq provider (groq.com, OpenAI-compatible API) via the official `openai` SDK.

Note: Groq is not xAI "Grok". The project brief says Grok; the configured key
and endpoint are Groq's. Another provider is one more `LLMProvider` subclass.
"""

from __future__ import annotations

import openai

from agentsoc.config import Settings
from agentsoc.investigator.llm.base import (
    LLMAuthError,
    LLMInvalidResponseError,
    LLMProvider,
    LLMRateLimitError,
    LLMTimeoutError,
    LLMUnavailableError,
)

# gpt-oss models spend completion tokens on reasoning; "low" keeps answers fast and within
# budget (measured: ~1 s and ~3x fewer tokens than the default on a small probe).
REASONING_EFFORT = "low"


class GroqProvider(LLMProvider):
    name = "groq"

    def __init__(self, settings: Settings, client: openai.OpenAI | None = None) -> None:
        if settings.groq_api_key is None or settings.groq_model is None:
            raise LLMAuthError("Groq is not configured (missing API key or model)")
        self.model = settings.groq_model
        self._max_tokens = settings.llm_max_tokens
        self._client = client or openai.OpenAI(
            api_key=settings.groq_api_key.get_secret_value(),
            base_url=settings.groq_base_url,
            timeout=settings.llm_timeout_seconds,
            max_retries=settings.llm_max_retries,  # SDK backoff on 429 / 5xx / connection errors
        )

    def complete_json(self, system: str, user: str, feedback: str | None = None) -> str:
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        if feedback:
            messages.append({"role": "user", "content": feedback})
        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=messages,
                response_format={"type": "json_object"},
                temperature=0.2,
                max_completion_tokens=self._max_tokens,
                reasoning_effort=REASONING_EFFORT,
            )
        except openai.APITimeoutError:
            raise LLMTimeoutError("Groq request timed out") from None
        except openai.RateLimitError:
            raise LLMRateLimitError("Groq rate limit reached (HTTP 429)") from None
        except (openai.AuthenticationError, openai.PermissionDeniedError) as exc:
            raise LLMAuthError(f"Groq rejected the credentials (HTTP {exc.status_code})") from None
        except openai.APIConnectionError:
            raise LLMUnavailableError("Groq is unreachable (network error)") from None
        except openai.BadRequestError as exc:
            # e.g. json_validate_failed: the model produced invalid JSON in JSON mode.
            raise LLMInvalidResponseError(
                f"Groq rejected the request/output (HTTP {exc.status_code})") from None
        except openai.APIStatusError as exc:
            raise LLMUnavailableError(f"Groq service error (HTTP {exc.status_code})") from None

        choice = response.choices[0] if response.choices else None
        if choice is None or not choice.message.content:
            raise LLMInvalidResponseError("Groq returned an empty response")
        if choice.finish_reason == "length":
            raise LLMInvalidResponseError("Groq response was truncated (token limit reached)")
        return choice.message.content
