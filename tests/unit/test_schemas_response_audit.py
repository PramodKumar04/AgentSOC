from datetime import timedelta

import pytest
from pydantic import ValidationError

from agentsoc.schemas import (
    GENESIS_HASH,
    ActionStatus,
    ActionType,
    AuditRecord,
    InvalidTransitionError,
    ResponseAction,
    verify_chain,
)
from tests.conftest import T0


def action(**overrides) -> ResponseAction:
    data = {
        "action_id": "ACT-1",
        "incident_id": "INC-1",
        "action_type": ActionType.ISOLATE_HOST,
        "target": "WS-FIN-07",
        "rationale": "Highest composite score; contains suspected pivot host.",
        "requires_approval": True,
    }
    data.update(overrides)
    return ResponseAction(**data)


class TestResponseAction:
    def test_cannot_be_constructed_as_live(self):
        with pytest.raises(ValidationError):
            action(dry_run=False)

    def test_approval_required_path(self):
        a = action().transition_to(ActionStatus.PENDING_APPROVAL)
        a = a.transition_to(ActionStatus.APPROVED).transition_to(ActionStatus.SIMULATED)
        assert a.transition_to(ActionStatus.VERIFIED).status is ActionStatus.VERIFIED

    def test_cannot_skip_human_approval(self):
        with pytest.raises(InvalidTransitionError, match="human approval"):
            action().transition_to(ActionStatus.APPROVED)

    def test_low_impact_action_may_auto_approve(self):
        a = action(action_type=ActionType.MONITOR_ONLY, requires_approval=False)
        assert a.transition_to(ActionStatus.APPROVED).status is ActionStatus.APPROVED

    @pytest.mark.parametrize(
        ("start_path", "illegal"),
        [
            ([], ActionStatus.SIMULATED),  # cannot simulate unapproved
            ([ActionStatus.PENDING_APPROVAL, ActionStatus.REJECTED], ActionStatus.APPROVED),
        ],
    )
    def test_illegal_transitions(self, start_path, illegal):
        a = action()
        for step in start_path:
            a = a.transition_to(step)
        with pytest.raises(InvalidTransitionError):
            a.transition_to(illegal)

    def test_transition_returns_copy(self):
        original = action()
        original.transition_to(ActionStatus.PENDING_APPROVAL)
        assert original.status is ActionStatus.PROPOSED


def build_chain(n: int) -> list[AuditRecord]:
    records: list[AuditRecord] = []
    for i in range(n):
        records.append(
            AuditRecord.create(
                records[-1] if records else None,
                timestamp=T0 + timedelta(seconds=i),
                actor="analyst-1",
                event_type="ACTION_STATUS_CHANGED",
                subject_id=f"ACT-{i}",
                details={"to": "APPROVED", "dry_run": True},
            )
        )
    return records


class TestAuditChain:
    def test_genesis(self):
        (first,) = build_chain(1)
        assert first.sequence == 0 and first.prev_hash == GENESIS_HASH

    def test_intact_chain_verifies(self):
        assert verify_chain(build_chain(5)) is None

    def test_empty_chain_verifies(self):
        assert verify_chain([]) is None

    def test_detects_modified_record(self):
        chain = build_chain(4)
        chain[2] = chain[2].model_copy(update={"actor": "mallory"})
        assert verify_chain(chain) == 2

    def test_detects_deleted_record(self):
        chain = build_chain(4)
        del chain[1]
        assert verify_chain(chain) == 1

    def test_detects_reordering(self):
        chain = build_chain(3)
        chain[0], chain[1] = chain[1], chain[0]
        assert verify_chain(chain) == 0

    def test_survives_json_round_trip(self):
        chain = [AuditRecord.model_validate_json(r.model_dump_json()) for r in build_chain(3)]
        assert verify_chain(chain) is None

    def test_rejects_malformed_hash(self):
        record = build_chain(1)[0]
        with pytest.raises(ValidationError):
            AuditRecord(**{**record.model_dump(), "prev_hash": "not-a-hash"})
