import pytest

from agentsoc.auth import passwords as pw


def test_round_trip_and_unique_salts():
    first, second = pw.hash_password("correct horse 42"), pw.hash_password("correct horse 42")
    assert first != second
    assert pw.verify_password("correct horse 42", first)
    assert not pw.verify_password("correct horse 43", first)
    assert "correct horse" not in first


@pytest.mark.parametrize("stored", [
    "", "plain", "md5$abc", "scrypt$x$8$1$AAAA$AAAA",
    "scrypt$1048576$8$1$AAAA$AAAA",  # a huge cost factor would exhaust memory
    "scrypt$32768$64$1$AAAA$AAAA",
    "scrypt$1000$8$1$AAAA$AAAA",  # not a power of two
])
def test_malformed_or_unsafe_stored_values_fail_closed(stored):
    assert pw.verify_password("anything at all", stored) is False


@pytest.mark.parametrize(("password", "message"), [
    ("short", "between"), ("x" * 129, "between"), ("my-name-alice-1", "username"),
    ("aaaaaaaaaaaaaa", "repetitive"),
])
def test_policy(password, message):
    with pytest.raises(pw.PasswordPolicyError, match=message):
        pw.check_policy(password, "alice")


def test_dummy_hash_verifies_nothing():
    assert not pw.verify_password("", pw.dummy_hash())


@pytest.mark.parametrize("stored", [
    "scrypt$262144$1$1$AAAA$AAAA",  # 2^18: within scrypt's memory limit, above our bound
    "scrypt$32768$17$1$AAAA$AAAA",
    "scrypt$32768$8$5$AAAA$AAAA",
])
def test_out_of_bounds_cost_is_refused_before_deriving(stored, monkeypatch):
    calls = []
    monkeypatch.setattr(pw, "_derive", lambda *a: calls.append(a) or b"")
    assert pw.verify_password("anything at all", stored) is False
    assert calls == []
