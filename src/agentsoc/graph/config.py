"""Structural configuration. Separate from the detection config, with its own hash, so
tuning the SSE never changes a detection run's recorded configuration. Unknown keys are
rejected so a typo cannot silently fall back to a default."""

from __future__ import annotations

import hashlib
from pathlib import Path

from pydantic import Field, ValidationError

from agentsoc.exceptions import ConfigurationError
from agentsoc.schemas.common import Contract


class StructuralConfig(Contract):
    max_link_gap_seconds: int = Field(default=1800, ge=1)
    max_expansion_hops: int = Field(default=3, ge=0)
    max_links_per_event: int = Field(default=8, ge=1)
    max_context_events: int = Field(default=2000, ge=1)
    max_paths: int = Field(default=20, ge=1)
    max_anchors_compared: int = Field(default=200, ge=1)
    max_choke_targets: int = Field(default=10, ge=0)
    # More other accounts than this arriving on a host makes an account switch there weak.
    ambiguous_link_accounts: int = Field(default=3, ge=0)

    def sha256(self) -> str:
        return hashlib.sha256(self.model_dump_json().encode("utf-8")).hexdigest()


def load_structural_config(path: str | Path | None = None) -> StructuralConfig:
    """Defaults when `path` is None; otherwise a JSON file (unknown keys rejected)."""
    if path is None:
        return StructuralConfig()
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"cannot read structural config {path}: {exc.strerror}") from None
    try:
        return StructuralConfig.model_validate_json(text)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        raise ConfigurationError(f"invalid structural config: {problems}") from None
