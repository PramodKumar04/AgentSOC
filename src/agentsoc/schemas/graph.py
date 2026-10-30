"""Structural Simulation Engine (SSE) output.

A verdict is about the *modelled* topology only: FEASIBLE does not prove an
attack happened, and INFEASIBLE does not prove the environment is clean.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, model_validator

from agentsoc.schemas.common import Contract, Identifier, ShortText


class Feasibility(StrEnum):
    FEASIBLE = "FEASIBLE"
    CONDITIONALLY_FEASIBLE = "CONDITIONALLY_FEASIBLE"
    INFEASIBLE = "INFEASIBLE"


class Edge(Contract):
    source: Identifier
    target: Identifier


class PathValidation(Contract):
    hypothesis_id: Identifier
    verdict: Feasibility
    checked_path: list[Identifier] = Field(default_factory=list)
    missing_edges: list[Edge] = Field(default_factory=list)
    conditions: list[ShortText] = Field(default_factory=list)
    reasons: list[ShortText] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_verdict(self) -> PathValidation:
        if self.verdict is Feasibility.FEASIBLE and (self.missing_edges or self.conditions):
            raise ValueError("FEASIBLE verdict cannot have missing edges or conditions")
        if self.verdict is Feasibility.CONDITIONALLY_FEASIBLE and not self.conditions:
            raise ValueError("CONDITIONALLY_FEASIBLE verdict must state its conditions")
        return self
