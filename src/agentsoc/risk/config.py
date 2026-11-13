"""RSEM configuration. Every weight and threshold is a heuristic starting point, not an
empirically calibrated value. It has its own hash, separate from detection and structural
configuration. Unknown keys are rejected so a typo cannot silently fall back to a default."""

from __future__ import annotations

import hashlib
import math
from pathlib import Path

from pydantic import Field, ValidationError, model_validator

from agentsoc.exceptions import ConfigurationError
from agentsoc.schemas import Severity
from agentsoc.schemas.common import Contract, UnitInterval
from agentsoc.schemas.response import ActionType


class RiskWeights(Contract):
    credential_pressure: UnitInterval = 0.15
    access_novelty: UnitInterval = 0.10
    movement_depth: UnitInterval = 0.35
    sequence_breadth: UnitInterval = 0.10
    sensitive_exposure: UnitInterval = 0.30

    @model_validator(mode="after")
    def _check(self) -> RiskWeights:
        if not math.isclose(sum(self.model_dump().values()), 1.0, abs_tol=1e-9):
            raise ValueError("risk weights must sum to 1")
        return self


class ConfidenceWeights(Contract):
    evidence_found: UnitInterval = 0.30
    structural_support: UnitInterval = 0.25
    baseline_coverage: UnitInterval = 0.15
    context_complete: UnitInterval = 0.10
    investigation_quality: UnitInterval = 0.20

    @model_validator(mode="after")
    def _check(self) -> ConfidenceWeights:
        if not math.isclose(sum(self.model_dump().values()), 1.0, abs_tol=1e-9):
            raise ValueError("confidence weights must sum to 1")
        return self


class RiskBands(Contract):
    medium_at: float = Field(default=20.0, gt=0)
    high_at: float = Field(default=45.0, gt=0)
    critical_at: float = Field(default=70.0, gt=0, le=100)

    @model_validator(mode="after")
    def _check(self) -> RiskBands:
        if not self.medium_at < self.high_at < self.critical_at:
            raise ValueError("bands must satisfy medium_at < high_at < critical_at")
        return self

    def band(self, score: float) -> Severity:
        if score >= self.critical_at:
            return Severity.CRITICAL
        if score >= self.high_at:
            return Severity.HIGH
        return Severity.MEDIUM if score >= self.medium_at else Severity.LOW


class ActionProfile(Contract):
    containment: UnitInterval
    business_impact: UnitInterval


def _default_actions() -> dict[ActionType, ActionProfile]:
    """Isolate, disable and monitor use the paper's Table V; the others are assumptions."""
    table = {
        ActionType.MONITOR_ONLY: (0.15, 0.00),
        ActionType.ENABLE_MFA: (0.40, 0.10),
        ActionType.REVOKE_SESSION: (0.60, 0.15),
        ActionType.RESTRICT_PRIVILEGES: (0.65, 0.30),
        ActionType.QUARANTINE_ACCESS: (0.75, 0.35),
        ActionType.DISABLE_ACCOUNT: (0.84, 0.30),
        ActionType.ISOLATE_HOST: (0.92, 0.15),
    }
    return {k: ActionProfile(containment=c, business_impact=i) for k, (c, i) in table.items()}


class RiskConfig(Contract):
    weights: RiskWeights = Field(default_factory=RiskWeights)
    bands: RiskBands = Field(default_factory=RiskBands)

    fail_then_success_value: UnitInterval = 0.8
    failure_burst_value: UnitInterval = 0.5
    novelty_saturation_events: int = Field(default=5, ge=1)
    depth_two_hop_value: UnitInterval = 0.6
    depth_step_per_hop: UnitInterval = 0.25
    inferred_hop_discount: UnitInterval = 0.5
    ambiguous_hop_discount: UnitInterval = 0.2
    breadth_saturation_events: int = Field(default=4, ge=1)
    breadth_account_switch_credit: UnitInterval = 0.5
    sensitive_observed_value: UnitInterval = 1.0
    sensitive_inferred_value: UnitInterval = 0.5
    sensitive_ambiguous_value: UnitInterval = 0.2

    missing_evidence_penalty: UnitInterval = 0.2
    truncated_context_penalty: UnitInterval = 0.1
    infeasible_finding_penalty: UnitInterval = 0.1
    quality_floor: UnitInterval = 0.6
    admin_factor: UnitInterval = 0.85
    jump_route_factor: UnitInterval = 0.85

    confidence: ConfidenceWeights = Field(default_factory=ConfidenceWeights)
    confidence_moderate_at: float = Field(default=40.0, gt=0)
    confidence_high_at: float = Field(default=70.0, le=100)
    full_baseline_seconds: int = Field(default=172_800, ge=1)
    llm_investigation_quality: UnitInterval = 0.8
    fallback_investigation_quality: UnitInterval = 0.5
    validated_proposals_bonus: UnitInterval = 0.2
    unsupported_proposal_penalty: UnitInterval = 0.4
    injection_flag_quality_cap: UnitInterval = 0.3

    alpha: float = Field(default=0.7, ge=0)
    beta: float = Field(default=0.3, ge=0)
    actions: dict[ActionType, ActionProfile] = Field(default_factory=_default_actions)
    partial_coverage: UnitInterval = 0.6
    sensitive_host_impact: UnitInterval = 0.4
    admin_account_impact: UnitInterval = 0.2
    destructive_min_confidence: float = Field(default=50.0, ge=0, le=100)
    max_actions: int = Field(default=5, ge=1)

    @model_validator(mode="after")
    def _check(self) -> RiskConfig:
        if not (self.inferred_hop_discount >= self.ambiguous_hop_discount):
            raise ValueError("an ambiguous link cannot count more than an inferred one")
        if not (self.sensitive_observed_value >= self.sensitive_inferred_value
                >= self.sensitive_ambiguous_value):
            raise ValueError("sensitive values must fall from observed to inferred to ambiguous")
        if not self.confidence_moderate_at < self.confidence_high_at:
            raise ValueError("confidence levels must be ordered")
        missing = set(ActionType) - set(self.actions)
        if missing:
            raise ValueError(f"action profiles missing: {sorted(missing)}")
        return self

    def sha256(self) -> str:
        return hashlib.sha256(self.model_dump_json().encode("utf-8")).hexdigest()


def load_risk_config(path: str | Path | None = None) -> RiskConfig:
    """Defaults when `path` is None; otherwise a JSON file (unknown keys rejected)."""
    if path is None:
        return RiskConfig()
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"cannot read risk config {path}: {exc.strerror}") from None
    try:
        return RiskConfig.model_validate_json(text)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        raise ConfigurationError(f"invalid risk config: {problems}") from None
