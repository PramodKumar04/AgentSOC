"""Column mapping: turn one record from a mapped source (CSV with a header, an organisational
database table) into an `AuthEvent`, or a `RejectedRecord` that says why not.

Policy, the same as the LANL parser: values are validated, never repaired or guessed.
  * A required field comes from a column or from a constant that an administrator has
    explicitly confirmed (`confirmed_constants`). Nothing is filled in silently.
  * Orientation and outcome values must equal AgentSOC's own values, or be listed in the
    field's `values` map. Anything else is rejected with the field named.
  * A time without a zone is rejected unless the mapping names the zone to assume.
  * The record's own identifier is kept: the event ID is `<prefix>.<record id>`.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import Field, StringConstraints, ValidationError, field_validator, model_validator

from agentsoc.perception.records import RejectedRecord, RejectReason
from agentsoc.schemas import AuthEvent, AuthOrientation, AuthOutcome, DatasetSource
from agentsoc.schemas.common import Contract
from agentsoc.schemas.events import RawRef

MAPPING_VERSION = 1

FieldName = Literal["src_user", "dst_user", "src_host", "dst_host", "auth_type", "logon_type",
                    "orientation", "outcome"]
REQUIRED_FIELDS: tuple[str, ...] = ("src_user", "src_host", "dst_host", "orientation", "outcome")
ENUM_FIELDS: dict[str, type[StrEnum]] = {"orientation": AuthOrientation, "outcome": AuthOutcome}

# Column names are matched against the real header / table columns before use; this only
# keeps obviously hostile names out of configuration and error messages.
ColumnName = Annotated[str, StringConstraints(min_length=1, max_length=63,
                                              pattern=r"^[A-Za-z0-9_][A-Za-z0-9_ .\-]*$")]
_RECORD_ID = re.compile(r"[A-Za-z0-9_.\-]{1,96}")
PREFIX_PATTERN = r"^[a-z0-9][a-z0-9_\-]{0,30}$"
_EARLIEST = datetime(1970, 1, 1, tzinfo=UTC)
_LATEST = datetime(2200, 1, 1, tzinfo=UTC)
_EPOCH_SECONDS = re.compile(r"[0-9]{1,11}(\.[0-9]{1,6})?")
_EPOCH_MILLIS = re.compile(r"[0-9]{1,14}")
_EXCERPT = 200
_REASON_FOR = {"orientation": RejectReason.INVALID_ORIENTATION,
               "outcome": RejectReason.INVALID_OUTCOME}


class TimestampFormat(StrEnum):
    ISO8601 = "iso8601"            # 2026-11-13T09:00:05Z, 2026-11-13 09:00:05+05:30
    EPOCH_SECONDS = "epoch_seconds"
    EPOCH_MILLIS = "epoch_millis"
    # Database date/time values are accepted with any format.


class TimestampMapping(Contract):
    column: ColumnName
    format: TimestampFormat = TimestampFormat.ISO8601
    # IANA zone for values without one (e.g. "Europe/London"); None rejects them. In a
    # daylight-saving overlap the first occurrence is used.
    naive_timezone: str | None = Field(default=None, max_length=64)

    @field_validator("naive_timezone")
    @classmethod
    def _known_zone(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                ZoneInfo(value)
            except (ZoneInfoNotFoundError, ValueError):
                raise ValueError("unknown time zone") from None
        return value


class FieldMapping(Contract):
    column: ColumnName | None = None
    constant: str | None = Field(default=None, min_length=1, max_length=128)
    # Source value -> AgentSOC value, for orientation and outcome only.
    values: dict[Annotated[str, StringConstraints(max_length=64)],
                 Annotated[str, StringConstraints(max_length=64)]] = Field(
        default_factory=dict, max_length=64)

    @model_validator(mode="after")
    def _one_source(self) -> FieldMapping:
        if (self.column is None) == (self.constant is None):
            raise ValueError("give either a column or a constant")
        if self.values and self.column is None:
            raise ValueError("a value map needs a column")
        return self


class MappingSpec(Contract):
    version: Literal[1] = MAPPING_VERSION
    record_id: ColumnName
    timestamp: TimestampMapping
    fields: dict[FieldName, FieldMapping]
    # Every constant must be listed here: the administrator's explicit confirmation that a
    # value the source does not contain is applied to every record.
    confirmed_constants: list[FieldName] = Field(default_factory=list)

    @model_validator(mode="after")
    def _complete_and_consistent(self) -> MappingSpec:
        missing = [f for f in REQUIRED_FIELDS if f not in self.fields]
        if missing:
            raise ValueError(f"required fields are not mapped: {', '.join(missing)}")
        constants = {name for name, m in self.fields.items() if m.constant is not None}
        unconfirmed = sorted(constants - set(self.confirmed_constants))
        if unconfirmed:
            raise ValueError(f"constants must be confirmed: {', '.join(unconfirmed)}")
        stray = sorted(set(self.confirmed_constants) - constants)
        if stray:
            raise ValueError(f"confirmed fields are not constants: {', '.join(stray)}")
        for name, m in self.fields.items():
            enum = ENUM_FIELDS.get(name)
            if m.values and enum is None:
                raise ValueError(f"{name} cannot have a value map")
            if enum is not None:
                allowed = {e.value for e in enum}
                for target in [*m.values.values(), *([m.constant] if m.constant else [])]:
                    if target not in allowed:
                        raise ValueError(f"{name}: '{target}' is not one of {sorted(allowed)}")
            elif m.constant is not None:
                _validate_identifier(name, m.constant)
        return self

    @property
    def columns(self) -> set[str]:
        return {self.record_id, self.timestamp.column} | {
            m.column for m in self.fields.values() if m.column}

    def sha256(self) -> str:
        canonical = json.dumps(self.model_dump(mode="json"), sort_keys=True,
                               separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def disclosures(self) -> list[str]:
        """Plain statements of every value AgentSOC sets rather than reads."""
        out = [f"{name} is not read from the source: every event is set to "
               f"'{m.constant}' (confirmed by an administrator)."
               for name, m in sorted(self.fields.items()) if m.constant is not None]
        if self.timestamp.naive_timezone:
            out.append(f"Times without a zone are read as {self.timestamp.naive_timezone}.")
        return out


def _validate_identifier(name: str, value: str) -> None:
    probe = {"event_id": "probe", "timestamp": _EARLIEST, "src_user": "u", "src_host": "h",
             "dst_host": "h", "orientation": "LogOn", "outcome": "Success",
             "dataset": "upload", "raw_ref": {"file": "f", "line": 1}, name: value}
    try:
        AuthEvent.model_validate(probe)
    except ValidationError:
        raise ValueError(f"{name}: constant has unsupported characters") from None


class _RejectError(Exception):
    def __init__(self, reason: RejectReason, detail: str, field: str | None = None) -> None:
        super().__init__(detail)
        self.reason, self.detail, self.field = reason, detail, field


def _text(value: object, field: str) -> str | None:
    """A cell as text. Only plain scalar types are accepted; nothing is coerced from bytes."""
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        if "�" in stripped:
            raise _RejectError(RejectReason.ENCODING_ERROR, "value is not valid UTF-8", field)
        return stripped or None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | Decimal | UUID):
        return str(value)
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else repr(value)
    raise _RejectError(RejectReason.UNSUPPORTED_VALUE,
                  f"{type(value).__name__} values are not supported", field)


def _timestamp(value: object, spec: TimestampMapping) -> datetime:
    field = "timestamp"
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, date):
        raise _RejectError(RejectReason.INVALID_TIMESTAMP, "a date without a time is not enough",
                           field)
    else:
        text = _text(value, field)
        if text is None:
            raise _RejectError(RejectReason.MISSING_REQUIRED_FIELD, "timestamp is empty", field)
        try:
            if spec.format is TimestampFormat.ISO8601:
                moment = datetime.fromisoformat(text)
            elif spec.format is TimestampFormat.EPOCH_SECONDS:
                if not _EPOCH_SECONDS.fullmatch(text):
                    raise ValueError
                moment = _EARLIEST + timedelta(seconds=float(Decimal(text)))
            else:
                if not _EPOCH_MILLIS.fullmatch(text):
                    raise ValueError
                moment = _EARLIEST + timedelta(milliseconds=int(text))
        except (ValueError, OverflowError):
            raise _RejectError(RejectReason.INVALID_TIMESTAMP,
                          f"not a valid {spec.format.value} time", field) from None
    if moment.utcoffset() is None:
        if spec.naive_timezone is None:
            raise _RejectError(RejectReason.INVALID_TIMESTAMP,
                          "time has no zone and the mapping names none", field)
        moment = moment.replace(tzinfo=ZoneInfo(spec.naive_timezone))
    moment = moment.astimezone(UTC)
    if not _EARLIEST <= moment < _LATEST:
        raise _RejectError(RejectReason.INVALID_TIMESTAMP, "time is outside 1970-2200", field)
    return moment


def record_id_text(value: object) -> str:
    """The record's own identifier, kept unchanged; refused if it cannot be an event ID."""
    text = _text(value, "record_id")
    if text is None:
        raise _RejectError(RejectReason.MISSING_REQUIRED_FIELD, "record identifier is empty",
                      "record_id")
    if not _RECORD_ID.fullmatch(text):
        raise _RejectError(RejectReason.INVALID_FIELD,
                      "record identifier must be 1-96 of A-Z a-z 0-9 _ . -", "record_id")
    return text


def usable_record_id(value: object) -> str | None:
    try:
        return record_id_text(value)
    except _RejectError:
        return None


def _excerpt(row: Mapping[str, object], spec: MappingSpec) -> str:
    picked = {c: row.get(c) for c in sorted(spec.columns)}
    return json.dumps(picked, default=str, ensure_ascii=False)[:_EXCERPT]


def map_record(row: Mapping[str, object], spec: MappingSpec, *, ref: RawRef, prefix: str,
               dataset: DatasetSource) -> AuthEvent | RejectedRecord:
    """Never raises for bad content: returns a RejectedRecord naming the field and reason."""
    try:
        record_id = record_id_text(row.get(spec.record_id))
        values: dict[str, object] = {
            "event_id": f"{prefix}.{record_id}",
            "timestamp": _timestamp(row.get(spec.timestamp.column), spec.timestamp),
            "dataset": dataset, "raw_ref": ref}
        for name, m in spec.fields.items():
            raw = m.constant if m.constant is not None else _text(row.get(m.column), name)
            if raw is None:
                if name in REQUIRED_FIELDS:
                    raise _RejectError(RejectReason.MISSING_REQUIRED_FIELD, f"{name} is empty",
                                       name)
                continue
            enum = ENUM_FIELDS.get(name)
            if enum is not None:
                canonical = m.values.get(raw, raw)
                if canonical not in {e.value for e in enum}:
                    raise _RejectError(_REASON_FOR[name],
                                  f"{name} value is not mapped to an AgentSOC value", name)
                raw = canonical
            values[name] = raw
        try:
            return AuthEvent.model_validate(values)
        except ValidationError as exc:
            location = exc.errors()[0]["loc"]
            field = str(location[0]) if location else None
            raise _RejectError(RejectReason.INVALID_FIELD,
                          "value has unsupported characters or is too long", field) from None
    except _RejectError as reject:
        return RejectedRecord(line=ref.line, reason=reject.reason, field=reject.field,
                              detail=reject.detail[:300], raw_excerpt=_excerpt(row, spec))
