"""Investigator Agent: LLM investigation with validation, one repair round, and a
deterministic fallback. Never raises for LLM problems — the caller always gets a
valid `InvestigationResult` whose `source`/`provider` say what produced it."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Iterable
from datetime import UTC, datetime

from pydantic import ValidationError

from agentsoc.config import Settings
from agentsoc.investigator.fallback import fallback_investigation
from agentsoc.investigator.grounding import InvestigationValidationError, parse_and_ground
from agentsoc.investigator.llm.base import LLMError, LLMInvalidResponseError, LLMProvider
from agentsoc.investigator.prompts import SYSTEM_PROMPT, build_user_prompt, injection_warnings
from agentsoc.logging_setup import get_logger
from agentsoc.schemas import AuthEvent, Incident, InvestigationResult, InvestigationSource

logger = get_logger(__name__)
FALLBACK_PROVIDER = "deterministic"


def incident_sha256(incident: Incident) -> str:
    return hashlib.sha256(incident.model_dump_json().encode("utf-8")).hexdigest()


def build_provider(settings: Settings) -> tuple[LLMProvider | None, str | None]:
    """(provider, None) when usable, else (None, reason)."""
    if not settings.llm_enabled:
        return None, settings.llm_disabled_reason
    from agentsoc.investigator.llm.groq import GroqProvider

    try:
        return GroqProvider(settings), None
    except LLMError as exc:
        return None, exc.safe_message


def _short(text: str) -> str:
    return text if len(text) <= 300 else text[:297] + "..."


class InvestigatorAgent:
    def __init__(self, provider: LLMProvider | None, *, disabled_reason: str | None = None,
                 repair_attempts: int = 1) -> None:
        self.provider = provider
        self.disabled_reason = disabled_reason
        self.repair_attempts = repair_attempts

    def investigate(
        self, incident: Incident, events: Iterable[AuthEvent], *, is_admin: bool = False
    ) -> InvestigationResult:
        start = time.perf_counter()
        evidence = {e.event_id: e for e in events if e.event_id in set(incident.event_ids)}
        warnings = injection_warnings(incident, list(evidence.values()))
        missing = len(set(incident.event_ids) - set(evidence))
        if missing:
            warnings.append(f"{missing} of {len(incident.event_ids)} evidence events could not "
                            "be loaded; the investigation uses the available events only.")
        sha = incident_sha256(incident)

        if self.provider is None:
            warnings.append(f"LLM not used: {self.disabled_reason or 'no provider configured'}; "
                            "deterministic fallback used.")
            return self._fallback(incident, evidence, is_admin, sha, warnings, start)

        user_prompt = build_user_prompt(incident, list(evidence.values()))
        feedback: str | None = None
        last_errors: list[str] = []
        for attempt in range(1 + self.repair_attempts):
            try:
                text = self.provider.complete_json(SYSTEM_PROMPT, user_prompt, feedback)
                hypotheses, conclusion, extra = parse_and_ground(text, incident)
                conclusion = conclusion.model_copy(update={
                    "alternative_hypothesis_ids": [
                        h for h in conclusion.alternative_hypothesis_ids
                        if h != conclusion.most_plausible_hypothesis_id]})
                result = InvestigationResult(
                    incident_id=incident.incident_id, incident_sha256=sha,
                    hypotheses=hypotheses, conclusion=conclusion,
                    source=InvestigationSource.LLM, provider=self.provider.name,
                    model=self.provider.model,
                    latency_ms=round((time.perf_counter() - start) * 1000, 1),
                    warnings=[_short(w) for w in warnings + extra
                              + ([f"Accepted after {attempt} repair round(s)."]
                                 if attempt else [])],
                    created_at=datetime.now(UTC),
                )
                logger.info("llm investigation accepted", extra={"context": {
                    "incident": incident.incident_id, "attempts": attempt + 1}})
                return result
            except (InvestigationValidationError, ValidationError, LLMInvalidResponseError) as exc:
                last_errors = (exc.errors if isinstance(exc, InvestigationValidationError)
                               else [getattr(exc, "safe_message", None) or str(exc)[:200]])
                feedback = ("Your previous answer failed validation:\n- "
                            + "\n- ".join(last_errors[:8])
                            + "\nReturn a corrected JSON object with the required structure. "
                            "Cite only event_id values from the data block.")
                logger.warning("llm output rejected", extra={"context": {
                    "incident": incident.incident_id, "attempt": attempt + 1,
                    "errors": last_errors[:5]}})
            except LLMError as exc:
                warnings.append(f"LLM provider failed ({exc.kind}): {exc.safe_message}; "
                                "deterministic fallback used.")
                logger.warning("llm provider failed", extra={"context": {
                    "incident": incident.incident_id, "kind": exc.kind}})
                return self._fallback(incident, evidence, is_admin, sha, warnings, start)

        warnings.append(f"LLM output failed validation after {1 + self.repair_attempts} "
                        f"attempt(s) ({'; '.join(last_errors[:2])}); deterministic fallback used.")
        return self._fallback(incident, evidence, is_admin, sha, warnings, start)

    @staticmethod
    def _fallback(incident: Incident, evidence: dict[str, AuthEvent], is_admin: bool,
                  sha: str, warnings: list[str], start: float) -> InvestigationResult:
        hypotheses, conclusion = fallback_investigation(incident, evidence, is_admin=is_admin)
        return InvestigationResult(
            incident_id=incident.incident_id, incident_sha256=sha,
            hypotheses=hypotheses, conclusion=conclusion,
            source=InvestigationSource.FALLBACK, provider=FALLBACK_PROVIDER, model=None,
            latency_ms=round((time.perf_counter() - start) * 1000, 1),
            warnings=[_short(w) for w in warnings],
            created_at=datetime.now(UTC),
        )
