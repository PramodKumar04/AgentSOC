import pytest

from agentsoc.config import PROJECT_ROOT, load_settings
from agentsoc.exceptions import ConfigurationError

FAKE_KEY = "gsk_" + "x" * 40


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    """Tests must not see the developer's real .env or shell variables."""
    for var in (
        "LLM_PROVIDER", "GROQ_API_KEY", "GROQ_MODEL", "GROQ_BASE_URL", "LLM_TIMEOUT_SECONDS",
        "LLM_MAX_RETRIES", "LLM_MAX_TOKENS", "AGENTSOC_DB_PATH", "LOG_LEVEL",
    ):
        monkeypatch.delenv(var, raising=False)


def settings(**kwargs):
    return load_settings(_env_file=None, **kwargs)


def test_defaults_disable_llm_without_error():
    s = settings()
    assert s.llm_provider == "none"
    assert not s.llm_enabled
    assert s.llm_disabled_reason == "LLM_PROVIDER is 'none'"


def test_groq_fully_configured_is_enabled():
    s = settings(llm_provider="groq", groq_api_key=FAKE_KEY, groq_model="m")
    assert s.llm_enabled
    assert s.llm_disabled_reason is None


@pytest.mark.parametrize(
    ("key", "model", "reason"),
    [(None, "m", "GROQ_API_KEY is not set"), (FAKE_KEY, None, "GROQ_MODEL is not set"),
     ("   ", "m", "GROQ_API_KEY is not set")],
)
def test_incomplete_groq_config_falls_back(key, model, reason):
    s = settings(llm_provider="groq", groq_api_key=key, groq_model=model)
    assert not s.llm_enabled
    assert s.llm_disabled_reason == reason


def test_reads_environment_variables_case_insensitively(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "GROQ")
    monkeypatch.setenv("GROQ_API_KEY", FAKE_KEY)
    monkeypatch.setenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    monkeypatch.setenv("LOG_LEVEL", "debug")
    s = settings()
    assert s.llm_provider == "groq"
    assert s.log_level == "DEBUG"
    assert s.llm_enabled


def test_secret_is_masked_in_repr_and_dump():
    s = settings(llm_provider="groq", groq_api_key=FAKE_KEY, groq_model="m")
    assert FAKE_KEY not in repr(s)
    assert FAKE_KEY not in str(s.model_dump())
    assert s.secret_values() == [FAKE_KEY]


def test_relative_db_path_resolves_to_project_root():
    s = settings(db_path="data/test.db")
    assert s.db_path == PROJECT_ROOT / "data" / "test.db"


@pytest.mark.parametrize(
    "overrides",
    [
        {"llm_provider": "openai"},
        {"llm_timeout_seconds": 0},
        {"llm_timeout_seconds": 500},
        {"llm_max_retries": -1},
        {"llm_max_tokens": 0},
        {"groq_base_url": "http://api.groq.com/openai/v1"},
        {"log_level": "VERBOSE"},
    ],
)
def test_invalid_values_raise_configuration_error(overrides):
    with pytest.raises(ConfigurationError):
        settings(**overrides)


def test_configuration_error_does_not_echo_secret_input():
    with pytest.raises(ConfigurationError) as exc_info:
        settings(groq_api_key=FAKE_KEY, llm_max_tokens=-5)
    assert FAKE_KEY not in str(exc_info.value)
