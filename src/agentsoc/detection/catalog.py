"""Rule catalogue: identifiers and the explanatory text attached to incidents.

Each rule documents benign explanations, limitations and information it cannot
see, so every incident states its own uncertainty.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from agentsoc.schemas import DatasetSource


class RuleId(StrEnum):
    FAILURE_BURST = "FAILURE_BURST"
    FAIL_THEN_SUCCESS = "FAIL_THEN_SUCCESS"
    NEW_SRC_HOST = "NEW_SRC_HOST"
    NEW_DST_HOST = "NEW_DST_HOST"
    MULTI_HOST_SPREAD = "MULTI_HOST_SPREAD"
    LATERAL_CHAIN = "LATERAL_CHAIN"
    SENSITIVE_HOST_ACCESS = "SENSITIVE_HOST_ACCESS"


@dataclass(frozen=True)
class RuleInfo:
    title: str
    benign_explanations: tuple[str, ...]
    limitations: tuple[str, ...]
    missing_information: tuple[str, ...]


_BASELINE_LIMIT = (
    "First-seen is relative to the baseline window only; a short baseline yields more "
    "first-seen events, and users with no baseline activity are not evaluated."
)

CATALOG: dict[RuleId, RuleInfo] = {
    RuleId.FAILURE_BURST: RuleInfo(
        title="Repeated authentication failures",
        benign_explanations=(
            "User mistyped or forgot a password.",
            "A service, mapped drive or scheduled task is retrying with a stale password.",
        ),
        limitations=(
            "Count-based heuristic; the threshold is not an empirically calibrated "
            "attack boundary.",
            "Cannot distinguish password guessing from stale credentials.",
        ),
        missing_information=(
            "Failure reason codes (bad password, expired, locked) are not in the data.",
            "Whether the account was locked out afterwards.",
        ),
    ),
    RuleId.FAIL_THEN_SUCCESS: RuleInfo(
        title="Success after repeated failures",
        benign_explanations=(
            "User recovered from a typo or remembered the password.",
            "Password was reset and the user then authenticated.",
        ),
        limitations=(
            "A success after failures is consistent with both guessing and legitimate recovery.",
            "Failures and success need not share a source host.",
        ),
        missing_information=(
            "MFA status of the successful authentication.",
            "Helpdesk or password-reset records for the account.",
        ),
    ),
    RuleId.NEW_SRC_HOST: RuleInfo(
        title="Authentication from a first-seen source host",
        benign_explanations=(
            "User working from a new, shared or replacement workstation.",
            "Remote access through a jump host or VDI.",
        ),
        limitations=(_BASELINE_LIMIT,),
        missing_information=("Asset inventory or assignment record for the source host.",),
    ),
    RuleId.NEW_DST_HOST: RuleInfo(
        title="Authentication to a first-seen destination host",
        benign_explanations=(
            "New project, role change or newly deployed server.",
            "Legitimate first-time use of a shared service.",
        ),
        limitations=(_BASELINE_LIMIT,),
        missing_information=(
            "Access-request or change-management records.",
            "Whether the account is authorised for the destination host.",
        ),
    ),
    RuleId.MULTI_HOST_SPREAD: RuleInfo(
        title="Several first-seen destination hosts in a short interval",
        benign_explanations=(
            "Administrative maintenance across several servers.",
            "Onboarding or a new application that touches multiple hosts.",
        ),
        limitations=(
            "Counts first-seen destinations only; familiar hosts are ignored.",
            "Window and count thresholds are configurable heuristics.",
        ),
        missing_information=("Purpose of the access (ticket, maintenance window).",),
    ),
    RuleId.LATERAL_CHAIN: RuleInfo(
        title="Sequential host-to-host authentication chain",
        benign_explanations=(
            "Administrators routinely hop through jump hosts or bastions.",
            "Application service flows can authenticate host-to-host.",
        ),
        limitations=(
            "Shows sequential authentication by one account, not that each host was controlled.",
            "Requires each hop's source to equal the previous hop's destination; "
            "pivots that switch accounts or go via unlogged channels are missed.",
        ),
        missing_information=(
            "Process and command-line telemetry on intermediate hosts.",
            "Network flow data confirming the connections.",
        ),
    ),
    RuleId.SENSITIVE_HOST_ACCESS: RuleInfo(
        title="First-seen access to a configured sensitive host",
        benign_explanations=("Authorised first-time access, e.g. new role or audit task.",),
        limitations=(
            "Sensitivity comes from a static configured list, not asset-criticality scoring.",
        ),
        missing_information=(
            "Data-access logs on the sensitive host.",
            "Authorisation records for the account.",
        ),
    ),
}

GENERIC_LIMITATION = "Indicates suspicious behaviour only; it does not confirm compromise."
GENERIC_MISSING = (
    "Endpoint, process and network telemetry are not part of authentication logs; "
    "no malware, PowerShell or credential-dumping evidence is available."
)
ADMIN_EXPLANATION = (
    "Principal is a configured administrative account; broad or novel host access may be expected."
)

DATASET_LIMITATIONS: dict[DatasetSource, tuple[str, ...]] = {
    DatasetSource.SYNTHETIC: (
        "Evidence is synthetic; this incident demonstrates detection logic, "
        "not a real-world observation.",
    ),
    DatasetSource.LANL: (
        "LANL timestamps are relative offsets; time-of-day and calendar context are unavailable.",
        "LANL identities are anonymised; user roles and asset criticality are unknown.",
    ),
    DatasetSource.UPLOAD: ("Provenance of uploaded data is asserted by the uploader.",),
}

DATASET_FLAGS: dict[DatasetSource, str] = {
    DatasetSource.SYNTHETIC: "synthetic-data",
    DatasetSource.LANL: "lanl-data",
    DatasetSource.UPLOAD: "uploaded-data",
}
