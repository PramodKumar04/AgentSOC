"""Response actions and their lifecycle (Action & Playbook Layer).

Action primitives are taken from the paper (Sec. III-C) plus the two actions
used in its POC (Table V). `dry_run` is typed as `Literal[True]`: this
prototype cannot represent a live action at all.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from agentsoc.schemas.common import Contract, Identifier, LongText
from agentsoc.schemas.risk import ActionScore


class ActionType(StrEnum):
    REVOKE_SESSION = "REVOKE_SESSION"
    RESTRICT_PRIVILEGES = "RESTRICT_PRIVILEGES"
    ENABLE_MFA = "ENABLE_MFA"
    QUARANTINE_ACCESS = "QUARANTINE_ACCESS"
    MONITOR_ONLY = "MONITOR_ONLY"
    ISOLATE_HOST = "ISOLATE_HOST"
    DISABLE_ACCOUNT = "DISABLE_ACCOUNT"


class ActionStatus(StrEnum):
    PROPOSED = "PROPOSED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    SIMULATED = "SIMULATED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"


ALLOWED_TRANSITIONS: dict[ActionStatus, frozenset[ActionStatus]] = {
    ActionStatus.PROPOSED: frozenset({ActionStatus.PENDING_APPROVAL, ActionStatus.APPROVED}),
    ActionStatus.PENDING_APPROVAL: frozenset({ActionStatus.APPROVED, ActionStatus.REJECTED}),
    ActionStatus.APPROVED: frozenset({ActionStatus.SIMULATED, ActionStatus.FAILED}),
    ActionStatus.SIMULATED: frozenset({ActionStatus.VERIFIED, ActionStatus.FAILED}),
    ActionStatus.REJECTED: frozenset(),
    ActionStatus.VERIFIED: frozenset(),
    ActionStatus.FAILED: frozenset(),
}


class InvalidTransitionError(ValueError):
    pass


class ResponseAction(Contract):
    action_id: Identifier
    incident_id: Identifier
    action_type: ActionType
    target: Identifier
    rationale: LongText
    requires_approval: bool
    score: ActionScore | None = None
    status: ActionStatus = ActionStatus.PROPOSED
    dry_run: Literal[True] = True

    def transition_to(self, new_status: ActionStatus) -> ResponseAction:
        """Return a copy in `new_status`, enforcing the lifecycle.

        An action that requires approval cannot skip PENDING_APPROVAL.
        """
        if new_status not in ALLOWED_TRANSITIONS[self.status]:
            raise InvalidTransitionError(f"{self.status} -> {new_status} is not allowed")
        if (
            self.requires_approval
            and self.status is ActionStatus.PROPOSED
            and new_status is ActionStatus.APPROVED
        ):
            raise InvalidTransitionError(
                "action requires human approval; route via PENDING_APPROVAL"
            )
        return self.model_copy(update={"status": new_status})

