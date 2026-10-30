"""Hash-chained audit records.

Each record stores the SHA-256 of its own canonical content plus the previous
record's hash. Editing, deleting or reordering any record breaks the chain,
which `verify_chain` detects. This is tamper-evidence, not tamper-proofing:
an attacker who can rewrite the whole log can rebuild the chain.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Annotated

from pydantic import AwareDatetime, Field, StringConstraints

from agentsoc.schemas.common import Contract, Identifier

GENESIS_HASH = "0" * 64

Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
DetailValue = str | int | float | bool | None


class AuditRecord(Contract):
    sequence: int = Field(ge=0)
    timestamp: AwareDatetime
    actor: Identifier
    event_type: Identifier
    subject_id: Identifier
    details: dict[str, DetailValue] = Field(default_factory=dict)
    prev_hash: Sha256Hex
    record_hash: Sha256Hex

    @staticmethod
    def compute_hash(
        *,
        sequence: int,
        timestamp: AwareDatetime,
        actor: str,
        event_type: str,
        subject_id: str,
        details: dict[str, DetailValue],
        prev_hash: str,
    ) -> str:
        canonical = json.dumps(
            {
                "sequence": sequence,
                "timestamp": timestamp.isoformat(),
                "actor": actor,
                "event_type": event_type,
                "subject_id": subject_id,
                "details": details,
                "prev_hash": prev_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @classmethod
    def create(
        cls,
        previous: AuditRecord | None,
        *,
        timestamp: AwareDatetime,
        actor: str,
        event_type: str,
        subject_id: str,
        details: dict[str, DetailValue] | None = None,
    ) -> AuditRecord:
        """Build the next record in a chain (`previous=None` starts a new chain)."""
        fields = {
            "sequence": 0 if previous is None else previous.sequence + 1,
            "timestamp": timestamp,
            "actor": actor,
            "event_type": event_type,
            "subject_id": subject_id,
            "details": details or {},
            "prev_hash": GENESIS_HASH if previous is None else previous.record_hash,
        }
        return cls(**fields, record_hash=cls.compute_hash(**fields))

    def hash_is_valid(self) -> bool:
        return self.record_hash == self.compute_hash(
            sequence=self.sequence,
            timestamp=self.timestamp,
            actor=self.actor,
            event_type=self.event_type,
            subject_id=self.subject_id,
            details=self.details,
            prev_hash=self.prev_hash,
        )


def verify_chain(records: Sequence[AuditRecord]) -> int | None:
    """Return the index of the first broken record, or None if the chain is intact."""
    expected_prev = GENESIS_HASH
    for index, record in enumerate(records):
        if (
            record.sequence != index
            or record.prev_hash != expected_prev
            or not record.hash_is_valid()
        ):
            return index
        expected_prev = record.record_hash
    return None
