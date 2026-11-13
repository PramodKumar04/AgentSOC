"""Detection configuration. Every threshold is a tunable heuristic, not a
scientifically established attack boundary. Unknown keys are rejected so a
typo in the JSON file cannot silently fall back to a default."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from pydantic import Field, ValidationError, field_validator, model_validator

from agentsoc.detection.catalog import RuleId
from agentsoc.exceptions import ConfigurationError
from agentsoc.schemas import AuthOrientation, Identifier, Severity
from agentsoc.schemas.common import Contract

DEFAULT_EXCLUDED_USER_PATTERNS = [
    r".+\$@.+",  # machine accounts, e.g. C625$@DOM1
    r"ANONYMOUS LOGON@.+",
    r"(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)@.+",
]


class FailureBurstConfig(Contract):
    enabled: bool = True
    min_failures: int = Field(default=5, ge=2)
    window_seconds: int = Field(default=600, ge=1)
    severity: Severity = Severity.MEDIUM


class FailThenSuccessConfig(Contract):
    enabled: bool = True
    min_failures: int = Field(default=3, ge=1)
    window_seconds: int = Field(default=600, ge=1)
    severity: Severity = Severity.HIGH


class NoveltyConfig(Contract):
    enabled: bool = True
    severity: Severity = Severity.LOW


class MultiHostConfig(Contract):
    enabled: bool = True
    min_new_hosts: int = Field(default=3, ge=2)
    window_seconds: int = Field(default=3600, ge=1)
    severity: Severity = Severity.MEDIUM


class LateralChainConfig(Contract):
    enabled: bool = True
    min_hops: int = Field(default=2, ge=2)
    max_hop_gap_seconds: int = Field(default=1800, ge=1)
    severity: Severity = Severity.HIGH


class CrossAccountPivotConfig(Contract):
    enabled: bool = True
    window_seconds: int = Field(default=1800, ge=1)
    max_evidence_arrivals: int = Field(default=3, ge=1)
    severity: Severity = Severity.LOW


class SensitiveAccessConfig(Contract):
    enabled: bool = True
    hosts: list[Identifier] = Field(default_factory=list)
    severity: Severity = Severity.HIGH


DEFAULT_POINTS: dict[RuleId, int] = {
    RuleId.FAILURE_BURST: 2,
    RuleId.FAIL_THEN_SUCCESS: 3,
    RuleId.NEW_SRC_HOST: 1,
    RuleId.NEW_DST_HOST: 1,
    RuleId.MULTI_HOST_SPREAD: 2,
    RuleId.LATERAL_CHAIN: 3,
    RuleId.SENSITIVE_HOST_ACCESS: 3,
    RuleId.CROSS_ACCOUNT_PIVOT: 1,
}
# Config files written before these rules existed stay valid and get the default points.
RULES_ADDED_AFTER_1_0 = (RuleId.CROSS_ACCOUNT_PIVOT,)


class SeverityPolicy(Contract):
    """Incident severity = band(sum of points over the incident's DISTINCT rules)."""

    points: dict[RuleId, int] = Field(default_factory=lambda: dict(DEFAULT_POINTS))
    medium_at: int = Field(default=3, ge=1)
    high_at: int = Field(default=5, ge=1)
    critical_at: int = Field(default=8, ge=1)
    downgrade_admin_users: bool = True
    jump_host_point_reduction: int = Field(default=1, ge=0)

    @field_validator("points", mode="before")
    @classmethod
    def _fill_later_rules(cls, points: object) -> object:
        if not isinstance(points, dict):
            return points
        return {**{r.value: DEFAULT_POINTS[r] for r in RULES_ADDED_AFTER_1_0}, **points}

    @model_validator(mode="after")
    def _check(self) -> SeverityPolicy:
        missing = set(RuleId) - set(self.points)
        if missing:
            raise ValueError(f"points missing for rules: {sorted(missing)}")
        if any(p < 0 for p in self.points.values()):
            raise ValueError("points must be >= 0")
        if not self.medium_at < self.high_at < self.critical_at:
            raise ValueError("thresholds must satisfy medium_at < high_at < critical_at")
        return self


class DetectionConfig(Contract):
    baseline_seconds: int = Field(default=172_800, ge=0)
    access_orientations: list[AuthOrientation] = Field(
        default_factory=lambda: [AuthOrientation.LOGON]
    )
    failure_orientations: list[AuthOrientation] = Field(
        default_factory=lambda: [AuthOrientation.LOGON, AuthOrientation.TGT, AuthOrientation.TGS]
    )
    excluded_user_patterns: list[str] = Field(
        default_factory=lambda: list(DEFAULT_EXCLUDED_USER_PATTERNS)
    )
    admin_users: list[Identifier] = Field(default_factory=list)
    jump_hosts: list[str] = Field(default_factory=list)  # regexes, full match on the host name
    collapse_exact_duplicates: bool = True
    correlation_gap_seconds: int = Field(default=3600, ge=0)

    failure_burst: FailureBurstConfig = Field(default_factory=FailureBurstConfig)
    fail_then_success: FailThenSuccessConfig = Field(default_factory=FailThenSuccessConfig)
    new_src_host: NoveltyConfig = Field(default_factory=NoveltyConfig)
    new_dst_host: NoveltyConfig = Field(default_factory=NoveltyConfig)
    multi_host_spread: MultiHostConfig = Field(default_factory=MultiHostConfig)
    lateral_chain: LateralChainConfig = Field(default_factory=LateralChainConfig)
    sensitive_host_access: SensitiveAccessConfig = Field(default_factory=SensitiveAccessConfig)
    cross_account_pivot: CrossAccountPivotConfig = Field(default_factory=CrossAccountPivotConfig)
    severity_policy: SeverityPolicy = Field(default_factory=SeverityPolicy)

    @field_validator("excluded_user_patterns", "jump_hosts")
    @classmethod
    def _compile(cls, patterns: list[str]) -> list[str]:
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"invalid regex {pattern!r}: {exc}") from None
        return patterns

    def is_excluded(self, user: str) -> bool:
        return any(re.fullmatch(p, user) for p in self.excluded_user_patterns)

    def is_jump_host(self, host: str) -> bool:
        return any(re.fullmatch(p, host) for p in self.jump_hosts)

    def sha256(self) -> str:
        return hashlib.sha256(self.model_dump_json().encode("utf-8")).hexdigest()


def load_detection_config(path: str | Path | None = None) -> DetectionConfig:
    """Defaults when `path` is None; otherwise a JSON file (unknown keys rejected)."""
    if path is None:
        return DetectionConfig()
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"cannot read detection config {path}: {exc.strerror}") from None
    try:
        return DetectionConfig.model_validate_json(text)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        raise ConfigurationError(f"invalid detection config: {problems}") from None
