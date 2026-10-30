"""Investigation (NCE), path validation (SSE) and risk (RSEM) contracts."""

import pytest
from pydantic import ValidationError

from agentsoc.schemas import (
    ActionScore,
    Feasibility,
    Hypothesis,
    HypothesisKind,
    IncidentRiskAssessment,
    InvestigationResult,
    InvestigationSource,
    PathValidation,
    RiskComponent,
)
from tests.conftest import hypothesis_data, investigation_data


class TestHypothesis:
    @pytest.mark.parametrize("confidence", [-0.01, 1.01])
    def test_confidence_bounded(self, confidence):
        with pytest.raises(ValidationError):
            Hypothesis(**hypothesis_data(confidence=confidence))

    @pytest.mark.parametrize("technique", ["T1078", "T1021.002"])
    def test_valid_attack_ids(self, technique):
        assert Hypothesis(**hypothesis_data(attack_techniques=[technique]))

    @pytest.mark.parametrize("technique", ["t1078", "T107", "T1021.2", "TA0008", "Lateral"])
    def test_invalid_attack_ids(self, technique):
        with pytest.raises(ValidationError):
            Hypothesis(**hypothesis_data(attack_techniques=[technique]))

    def test_benign_cannot_have_techniques(self):
        with pytest.raises(ValidationError, match="benign"):
            Hypothesis(**hypothesis_data(kind=HypothesisKind.BENIGN))

    def test_event_cannot_support_and_contradict(self):
        with pytest.raises(ValidationError, match="both support and contradict"):
            Hypothesis(**hypothesis_data(contradicting_event_ids=["EVT-0001"]))

    def test_path_nodes_reject_injection(self):
        with pytest.raises(ValidationError):
            Hypothesis(**hypothesis_data(proposed_path=["WS-1", "run: rm -rf /"]))

    def test_narrative_length_bounded(self):
        with pytest.raises(ValidationError):
            Hypothesis(**hypothesis_data(narrative="x" * 2001))


class TestInvestigationResult:
    def test_valid(self, investigation):
        assert len(investigation.hypotheses) == 2

    def test_requires_a_benign_hypothesis(self):
        only_malicious = [Hypothesis(**hypothesis_data())]
        with pytest.raises(ValidationError, match="BENIGN"):
            InvestigationResult(**investigation_data(hypotheses=only_malicious))

    def test_hypothesis_ids_unique(self, investigation):
        h1, h3 = investigation.hypotheses
        dupes = [h1, h1, h3]
        with pytest.raises(ValidationError, match="unique"):
            InvestigationResult(**investigation_data(hypotheses=dupes))

    def test_llm_source_requires_provenance(self):
        with pytest.raises(ValidationError, match="provider and model"):
            InvestigationResult(**investigation_data(model=None))

    def test_fallback_needs_no_provider(self):
        result = InvestigationResult(
            **investigation_data(source=InvestigationSource.FALLBACK, provider=None, model=None)
        )
        assert result.source is InvestigationSource.FALLBACK

    def test_parses_llm_style_json(self, investigation):
        parsed = InvestigationResult.model_validate_json(investigation.model_dump_json())
        assert parsed == investigation


class TestPathValidation:
    def test_feasible(self):
        pv = PathValidation(
            hypothesis_id="H1", verdict=Feasibility.FEASIBLE, checked_path=["A", "B"],
            reasons=["edge A->B permitted (SMB)"],
        )
        assert pv.verdict is Feasibility.FEASIBLE

    def test_feasible_cannot_have_missing_edges(self):
        with pytest.raises(ValidationError):
            PathValidation(
                hypothesis_id="H1", verdict=Feasibility.FEASIBLE,
                missing_edges=[{"source": "A", "target": "B"}], reasons=["x"],
            )

    def test_conditional_requires_conditions(self):
        with pytest.raises(ValidationError, match="conditions"):
            PathValidation(
                hypothesis_id="H2", verdict=Feasibility.CONDITIONALLY_FEASIBLE, reasons=["x"]
            )

    def test_reason_required(self):
        with pytest.raises(ValidationError):
            PathValidation(hypothesis_id="H3", verdict=Feasibility.INFEASIBLE, reasons=[])


class TestActionScore:
    @pytest.mark.parametrize(
        ("containment", "impact", "expected"),
        # Paper Table V, α=0.7, β=0.3 — reproduces the published composites.
        [(0.92, 0.15, 0.599), (0.84, 0.30, 0.498), (0.15, 0.00, 0.105)],
    )
    def test_reproduces_paper_table_v(self, containment, impact, expected):
        score = ActionScore.compute(containment, impact, alpha=0.7, beta=0.3)
        assert score.composite == pytest.approx(expected, abs=1e-9)

    def test_rejects_composite_inconsistent_with_formula(self):
        with pytest.raises(ValidationError, match="α·C"):
            ActionScore(containment=0.9, business_impact=0.1, alpha=0.7, beta=0.3, composite=0.99)

    def test_inputs_bounded(self):
        with pytest.raises(ValidationError):
            ActionScore.compute(1.5, 0.1, alpha=0.7, beta=0.3)


class TestIncidentRisk:
    def test_valid_and_contribution(self):
        component = RiskComponent(
            name="asset_criticality", value=0.9, weight=0.25, explanation="finance DB, 9/10"
        )
        risk = IncidentRiskAssessment(
            incident_id="INC-1", score=72.5, band="HIGH", components=[component]
        )
        assert component.contribution == pytest.approx(0.225)
        assert risk.band == "HIGH"

    @pytest.mark.parametrize("score", [-1, 100.1])
    def test_score_range(self, score):
        component = RiskComponent(name="x", value=0.5, weight=1, explanation="e")
        with pytest.raises(ValidationError):
            IncidentRiskAssessment(incident_id="I", score=score, band="LOW", components=[component])
