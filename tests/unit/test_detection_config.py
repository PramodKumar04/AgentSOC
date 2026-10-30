import json

import pytest

from agentsoc.config import PROJECT_ROOT
from agentsoc.detection.config import DetectionConfig, load_detection_config
from agentsoc.exceptions import ConfigurationError


def write(tmp_path, data) -> str:
    path = tmp_path / "detection.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_committed_default_file_matches_code_defaults():
    assert load_detection_config(PROJECT_ROOT / "config" / "detection.json") == DetectionConfig()


def test_none_gives_defaults():
    assert load_detection_config(None) == DetectionConfig()


def test_partial_file_overrides_selected_values(tmp_path):
    cfg = load_detection_config(write(tmp_path, {"failure_burst": {"min_failures": 8}}))
    assert cfg.failure_burst.min_failures == 8
    assert cfg.failure_burst.window_seconds == 600


@pytest.mark.parametrize(
    "data",
    [
        {"failur_burst": {}},  # typo in a key
        {"failure_burst": {"min_failures": 1}},
        {"excluded_user_patterns": ["(unclosed"]},
        {"severity_policy": {"medium_at": 5, "high_at": 5, "critical_at": 8}},
        {"severity_policy": {"points": {"FAILURE_BURST": 1}}},
        {"admin_users": ["bad user\nname"]},
        {"baseline_seconds": -1},
        {"access_orientations": ["Login"]},
    ],
)
def test_invalid_configs_rejected(tmp_path, data):
    with pytest.raises(ConfigurationError):
        load_detection_config(write(tmp_path, data))


def test_missing_file(tmp_path):
    with pytest.raises(ConfigurationError, match="cannot read"):
        load_detection_config(tmp_path / "nope.json")


def test_hash_is_stable_and_sensitive():
    assert DetectionConfig().sha256() == DetectionConfig().sha256()
    assert DetectionConfig().sha256() != DetectionConfig(baseline_seconds=1).sha256()


def test_exclusion_matching():
    cfg = DetectionConfig()
    assert cfg.is_excluded("C625$@DOM1")
    assert cfg.is_excluded("ANONYMOUS LOGON@C586")
    assert not cfg.is_excluded("U22@DOM1")
