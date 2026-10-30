"""Dashboard end-to-end with Streamlit's AppTest (headless, no network: LLM disabled or
simulated outage). Data is built from the SYNTHETIC scenario in a temporary root."""

import pytest
from streamlit.testing.v1 import AppTest

from agentsoc import app_data
from agentsoc.config import PROJECT_ROOT, get_settings

APP = str(PROJECT_ROOT / "app" / "streamlit_app.py")


@pytest.fixture
def app_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSOC_DATA_ROOT", str(tmp_path))
    monkeypatch.setenv("LLM_PROVIDER", "none")
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


def run_app() -> AppTest:
    at = AppTest.from_file(APP, default_timeout=120).run()
    assert not at.exception, [e.value for e in at.exception]
    return at


def hypothesis_labels(at):
    return [e.label for e in at.expander if e.label.startswith(("🔴", "🟢"))]


def test_overview_and_default_selection(app_env):
    at = run_app()
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Incidents"] == "3" and metrics["Critical"] == "1"
    assert metrics["Detections"] == "15"
    assert at.sidebar.selectbox(key="incident_id").value == "INC-00002"  # alice, CRITICAL
    assert any("SYNTHETIC" in m.value for m in at.markdown)


def test_investigation_runs_only_on_click_and_uses_fallback(app_env):
    at = run_app()
    assert hypothesis_labels(at) == []  # nothing generated on page load
    at.button(key="inv_INC-00002").click().run()
    assert not at.exception
    assert len(hypothesis_labels(at)) == 3
    assert any("LLM not used" in w.value for w in at.warning)
    assert any("not proof of compromise" in i.value for i in at.info)


def test_simulated_outage_falls_back(app_env, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_" + "Z" * 52)
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    get_settings.cache_clear()
    at = run_app()
    at.sidebar.toggle(key="outage").set_value(True).run()
    at.button(key="inv_INC-00002").click().run()
    assert not at.exception
    assert any("simulated outage" in w.value for w in at.warning)
    assert len(hypothesis_labels(at)) == 3


def test_selecting_another_incident_does_not_reuse_results(app_env):
    at = run_app()
    at.button(key="inv_INC-00002").click().run()
    at.sidebar.selectbox(key="incident_id").set_value("INC-00001").run()  # carol
    assert hypothesis_labels(at) == []
    assert any("No investigation yet" in i.value for i in at.info)
    at.button(key="inv_INC-00001").click().run()
    labels = hypothesis_labels(at)
    assert labels and any("misconfiguration" in label for label in labels)


def test_zero_incident_dataset(app_env, monkeypatch):
    sample = PROJECT_ROOT / "data" / "samples" / "lanl_format_synthetic_sample.txt"
    monkeypatch.setattr(app_data, "DEMO_INPUT", sample)
    at = run_app()
    assert {m.label: m.value for m in at.metric}["Incidents"] == "0"
    assert any("no incidents" in i.value.lower() for i in at.info)
