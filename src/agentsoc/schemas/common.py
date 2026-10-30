"""Shared types and base model for all contracts.

Identifiers (users, hosts, IDs) come from untrusted logs and untrusted LLM
output, so they are restricted to a conservative character set. This blocks
quotes, braces, newlines and other characters used in prompt-injection and
log-injection payloads, while still accepting LANL values such as
`U1234@DOM1`, `C586$@DOM1` and `ANONYMOUS LOGON@C586`.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

IDENTIFIER_MAX_LEN = 128

# Words of [A-Za-z0-9_.$@?-] separated by single spaces.
_IDENTIFIER_REGEX = r"^[A-Za-z0-9_.$@?\-]+( [A-Za-z0-9_.$@?\-]+)*$"

Identifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, max_length=IDENTIFIER_MAX_LEN, pattern=_IDENTIFIER_REGEX
    ),
]

# Free text (descriptions, narratives) — length-bounded; content is still untrusted.
ShortText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=300)]
LongText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]

UnitInterval = Annotated[float, Field(ge=0.0, le=1.0)]


class Contract(BaseModel):
    """Base for every inter-layer contract: immutable, no unknown fields."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
