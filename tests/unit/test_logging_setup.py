import json
import logging

import pytest

from agentsoc.logging_setup import REDACTED, Redactor, configure_logging, get_logger

SECRET = "my-custom-secret-value-123"
GROQ_KEY = "gsk_" + "A1b2C3d4" * 6


@pytest.fixture
def log_lines(capsys):
    # The handler binds sys.stderr when created, so tests call configure_logging
    # in the test body (after pytest has installed capture), not in this fixture.
    def read() -> list[dict]:
        return [json.loads(line) for line in capsys.readouterr().err.strip().splitlines()]

    yield read
    logging.getLogger("agentsoc").handlers.clear()


def test_emits_one_json_object_per_line(log_lines):
    configure_logging("DEBUG", secrets=[SECRET])
    get_logger("perception").info("ingested %d events", 3, extra={"context": {"file": "a.csv"}})
    (line,) = log_lines()
    assert line["level"] == "INFO"
    assert line["logger"] == "agentsoc.perception"
    assert line["msg"] == "ingested 3 events"
    assert line["context"] == {"file": "a.csv"}
    assert line["ts"].endswith("+00:00")


def test_redacts_configured_secret_and_key_patterns(log_lines):
    configure_logging("DEBUG", secrets=[SECRET])
    get_logger("x").warning(
        f"auth failed with {SECRET}", extra={"context": {"header": f"Bearer {GROQ_KEY}"}}
    )
    raw = json.dumps(log_lines())
    assert SECRET not in raw
    assert GROQ_KEY not in raw
    assert raw.count(REDACTED) == 2


def test_log_injection_newlines_stay_inside_one_json_line(log_lines):
    configure_logging("DEBUG", secrets=[SECRET])
    get_logger("x").info("user=evil\n{\"level\": \"CRITICAL\", \"msg\": \"forged\"}")
    lines = log_lines()
    assert len(lines) == 1
    assert lines[0]["level"] == "INFO"


def test_level_filtering(capsys):
    configure_logging("WARNING")
    get_logger("x").info("hidden")
    get_logger("x").warning("shown")
    out = capsys.readouterr().err
    assert "hidden" not in out and "shown" in out
    logging.getLogger("agentsoc").handlers.clear()


def test_configure_is_idempotent():
    configure_logging()
    configure_logging()
    assert len(logging.getLogger("agentsoc").handlers) == 1
    logging.getLogger("agentsoc").handlers.clear()


def test_redactor_handles_nested_and_non_string_values():
    r = Redactor([SECRET])
    assert r.redact({"a": [SECRET, 5, None], "b": {"c": SECRET}}) == {
        "a": [REDACTED, 5, None],
        "b": {"c": REDACTED},
    }


def test_short_strings_resembling_prefixes_are_not_redacted():
    assert Redactor().redact("task-list sk-1") == "task-list sk-1"
