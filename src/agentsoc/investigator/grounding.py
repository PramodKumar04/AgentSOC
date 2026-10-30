"""Parse and validate LLM output against the incident it claims to investigate.

Strict on facts (event IDs, confidence ranges, ATT&CK format, hypothesis mix);
lenient only on presentation (over-long text is clipped, unknown keys ignored).
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from agentsoc.exceptions import AgentSOCError
from agentsoc.schemas import Hypothesis, HypothesisKind, Incident
from agentsoc.schemas.investigation import InvestigationConclusion

_TELEMETRY_TERMS = re.compile(
    r"\b(powershell|mimikatz|malware|credential[- ]dump\w*|lsass|geolocation|geo-?ip|"
    r"edr alert|process tree)\b",
    re.IGNORECASE,
)


class InvestigationValidationError(AgentSOCError):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


class _Draft(BaseModel):
    model_config = ConfigDict(extra="ignore")
    hypotheses: list[dict[str, Any]]
    conclusion: dict[str, Any]


_TEXT_LIMITS = {"title": 300, "narrative": 2000, "summary": 2000, "uncertainty": 2000}
_LIST_LIMITS = {"missing_information": 10, "next_steps": 10, "evidence_gaps": 15,
                "evidence_notes": 40, "attack_techniques": 10}


def _clip(item: dict[str, Any], allowed: set[str]) -> dict[str, Any]:
    out = {k: v for k, v in item.items() if k in allowed}
    for key, limit in _TEXT_LIMITS.items():
        if isinstance(out.get(key), str):
            out[key] = out[key][:limit]
    for key, limit in _LIST_LIMITS.items():
        if isinstance(out.get(key), list):
            out[key] = [x[:300] if isinstance(x, str) else x for x in out[key][:limit]]
    if isinstance(out.get("evidence_notes"), list):
        out["evidence_notes"] = [
            {"event_id": n.get("event_id"), "relevance": str(n.get("relevance", ""))[:300]}
            for n in out["evidence_notes"] if isinstance(n, dict)
        ]
    if isinstance(out.get("kind"), str):
        out["kind"] = out["kind"].strip().upper()
    return out


def _load_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass
    raise InvestigationValidationError(["response is not valid JSON"])


def _errors(exc: ValidationError, prefix: str) -> list[str]:
    return [f"{prefix}{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()][:8]


def parse_and_ground(
    text: str, incident: Incident
) -> tuple[list[Hypothesis], InvestigationConclusion, list[str]]:
    """Return (hypotheses, conclusion, warnings) or raise InvestigationValidationError."""
    try:
        draft = _Draft.model_validate(_load_json(text))
    except ValidationError as exc:
        raise InvestigationValidationError(_errors(exc, "")) from None

    errors: list[str] = []
    hypotheses: list[Hypothesis] = []
    for index, raw in enumerate(draft.hypotheses[:10]):
        if not isinstance(raw, dict):
            errors.append(f"hypotheses.{index}: not an object")
            continue
        try:
            hypotheses.append(Hypothesis(**_clip(raw, set(Hypothesis.model_fields))))
        except ValidationError as exc:
            errors.extend(_errors(exc, f"hypotheses.{index}."))
    try:
        conclusion = InvestigationConclusion(
            **_clip(draft.conclusion, set(InvestigationConclusion.model_fields)
                    - {"is_proof_of_compromise"})
        )
    except ValidationError as exc:
        errors.extend(_errors(exc, "conclusion."))
        conclusion = None
    if errors:
        raise InvestigationValidationError(errors)

    known = set(incident.event_ids)
    for h in hypotheses:
        cited = set(h.supporting_event_ids) | set(h.contradicting_event_ids)
        unknown = sorted(cited - known)
        if unknown:
            errors.append(f"{h.hypothesis_id} cites event IDs not in incident "
                          f"{incident.incident_id}: {unknown[:5]}")
        if h.kind is HypothesisKind.MALICIOUS and not h.supporting_event_ids:
            errors.append(f"{h.hypothesis_id} is MALICIOUS but cites no supporting evidence")
    kinds = {h.kind for h in hypotheses}
    if HypothesisKind.BENIGN not in kinds:
        errors.append("at least one BENIGN hypothesis is required")
    if HypothesisKind.MALICIOUS not in kinds:
        errors.append("at least one MALICIOUS hypothesis is required (competing explanations)")
    ids = [h.hypothesis_id for h in hypotheses]
    if len(set(ids)) != len(ids):
        errors.append("hypothesis_id values must be unique")
    if conclusion.most_plausible_hypothesis_id not in ids:
        errors.append("conclusion.most_plausible_hypothesis_id is not a hypothesis")
    if not set(conclusion.alternative_hypothesis_ids) <= set(ids):
        errors.append("conclusion.alternative_hypothesis_ids reference unknown hypotheses")
    if errors:
        raise InvestigationValidationError(errors)

    warnings = []
    text_blob = " ".join([h.narrative + " " + h.title for h in hypotheses]
                         + [conclusion.summary, conclusion.uncertainty])
    mentioned = sorted({m.group(0).lower() for m in _TELEMETRY_TERMS.finditer(text_blob)})
    if mentioned:
        warnings.append(
            f"LLM text mentions {', '.join(mentioned)}; authentication logs contain no such "
            "telemetry — read these as missing evidence, not observations."
        )
    return hypotheses, conclusion, warnings
