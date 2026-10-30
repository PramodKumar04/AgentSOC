"""Ingestion outcomes shared by all input parsers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from pydantic import Field

from agentsoc.schemas import AuthEvent, DatasetSource
from agentsoc.schemas.common import Contract


class RejectReason(StrEnum):
    LINE_TOO_LONG = "LINE_TOO_LONG"
    ENCODING_ERROR = "ENCODING_ERROR"
    WRONG_FIELD_COUNT = "WRONG_FIELD_COUNT"
    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
    INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
    INVALID_ORIENTATION = "INVALID_ORIENTATION"
    INVALID_OUTCOME = "INVALID_OUTCOME"
    INVALID_FIELD = "INVALID_FIELD"


class RejectedRecord(Contract):
    """A source line that could not become an AuthEvent.

    `raw_excerpt` is untrusted text kept for data-quality review only; rejected
    records are never forwarded to detection or to the LLM.
    """

    line: int = Field(ge=1)
    reason: RejectReason
    field: str | None = Field(default=None, max_length=32)
    detail: str = Field(max_length=300)
    raw_excerpt: str = Field(max_length=200)


@dataclass(frozen=True)
class IngestionResult:
    source_file: str
    dataset: DatasetSource
    parser_version: str
    base_time: datetime
    skip: int
    limit: int | None
    input_sha256: str  # SHA-256 over the raw bytes of the lines actually consumed
    lines_read: int
    blank_lines: int
    out_of_order: int
    exact_duplicates: int
    events: list[AuthEvent]  # sorted by (timestamp, source line)
    rejected: list[RejectedRecord]
