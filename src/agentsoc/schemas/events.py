"""Canonical authentication event (Layer 1 output).

Field set follows the LANL `auth.txt` columns so LANL, synthetic and uploaded
data all normalise into one model:
    time, source user@domain, destination user@domain, source computer,
    destination computer, authentication type, logon type,
    authentication orientation, success/failure
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import AwareDatetime, Field

from agentsoc.schemas.common import Contract, Identifier


class AuthOrientation(StrEnum):
    LOGON = "LogOn"
    LOGOFF = "LogOff"
    TGS = "TGS"
    TGT = "TGT"
    AUTHMAP = "AuthMap"
    # Present in real LANL auth.txt (6,550 / 6,092 records in days 0-2) but missing from
    # the original contract; found during LANL validation, where they were wrongly rejected.
    SCREEN_LOCK = "ScreenLock"
    SCREEN_UNLOCK = "ScreenUnlock"
    UNKNOWN = "?"


class AuthOutcome(StrEnum):
    SUCCESS = "Success"
    FAILURE = "Fail"


class DatasetSource(StrEnum):
    SYNTHETIC = "synthetic"
    LANL = "lanl"
    UPLOAD = "upload"


class RawRef(Contract):
    """Pointer back to the original record, so every derived claim is traceable."""

    file: str = Field(min_length=1, max_length=260)
    line: int = Field(ge=1)


class AuthEvent(Contract):
    event_id: Identifier
    timestamp: AwareDatetime
    src_user: Identifier
    dst_user: Identifier | None = None
    src_host: Identifier
    dst_host: Identifier
    auth_type: Identifier | None = None
    logon_type: Identifier | None = None
    orientation: AuthOrientation
    outcome: AuthOutcome
    dataset: DatasetSource
    raw_ref: RawRef
