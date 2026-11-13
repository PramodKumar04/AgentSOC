"""Encrypted credential storage: nothing in clear, nothing leaked, keys rotate."""

import io
import logging

import pytest
from pydantic import SecretStr

from agentsoc.audit import AuditLog
from agentsoc.credentials import (
    CredentialError,
    CredentialStoreUnavailableError,
    EncryptedCredentialStore,
    generate_key,
)
from agentsoc.logging_setup import configure_logging, get_logger
from agentsoc.store import appdb

SECRET = "Pg-Service-Password-9f3c"


@pytest.fixture
def parts(tmp_path):
    key = generate_key()
    audit = AuditLog(tmp_path / "activity.jsonl")
    store = EncryptedCredentialStore(tmp_path / "app.db", SecretStr(key), audit)
    return store, key, audit, tmp_path


def raw_db(tmp_path) -> bytes:
    return b"".join(p.read_bytes() for p in tmp_path.glob("app.db*"))


def test_round_trip_without_plaintext_on_disk(parts):
    store, _, _, tmp = parts
    store.put("pg.prod", SecretStr(SECRET), actor="admin1")
    assert store.get("pg.prod").get_secret_value() == SECRET
    assert SECRET.encode() not in raw_db(tmp)


def test_listing_and_audit_never_show_the_secret(parts):
    store, _, audit, _ = parts
    store.put("pg.prod", SecretStr(SECRET), actor="admin1")
    store.delete("pg.prod", actor="admin1")
    assert [i.ref for i in store.list()] == []
    events = [(r.event_type, r.actor, r.subject_id) for r in audit.read()]
    assert events == [("credential.stored", "admin1", "pg.prod"),
                      ("credential.deleted", "admin1", "pg.prod")]
    assert SECRET not in audit.path.read_text(encoding="utf-8")


def test_wrong_key_fails_without_revealing_anything(parts, tmp_path):
    store, _, audit, _ = parts
    store.put("pg.prod", SecretStr(SECRET), actor="admin1")
    other = EncryptedCredentialStore(tmp_path / "app.db", SecretStr(generate_key()), audit)
    with pytest.raises(CredentialError) as info:
        other.get("pg.prod")
    assert SECRET not in str(info.value)


def test_ciphertext_moved_to_another_reference_is_refused(parts):
    store, _, _, tmp = parts
    store.put("pg.prod", SecretStr(SECRET), actor="admin1")
    store.put("pg.test", SecretStr("something-else"), actor="admin1")
    with appdb.transaction(tmp / "app.db") as conn:
        stolen = conn.execute(
            "SELECT ciphertext FROM credentials WHERE ref='pg.prod'").fetchone()[0]
        conn.execute("UPDATE credentials SET ciphertext = ? WHERE ref = 'pg.test'", (stolen,))
    with pytest.raises(CredentialError, match="does not belong"):
        store.get("pg.test")


def test_tampered_ciphertext_is_refused(parts):
    store, _, _, tmp = parts
    store.put("pg.prod", SecretStr(SECRET), actor="admin1")
    with appdb.transaction(tmp / "app.db") as conn:
        conn.execute("UPDATE credentials SET ciphertext = substr(ciphertext, 1, 40) || 'AAAA' "
                     "|| substr(ciphertext, 45)")
    with pytest.raises(CredentialError, match="could not be decrypted"):
        store.get("pg.prod")


def test_flipped_byte_in_binary_ciphertext_is_refused(parts):
    store, _, _, tmp = parts
    store.put("pg.prod", SecretStr(SECRET), actor="admin1")
    with appdb.transaction(tmp / "app.db") as conn:
        blob = bytearray(conn.execute("SELECT ciphertext FROM credentials").fetchone()[0])
        blob[60] ^= 1
        conn.execute("UPDATE credentials SET ciphertext = ?", (bytes(blob),))
    with pytest.raises(CredentialError, match="could not be decrypted"):
        store.get("pg.prod")


def test_rotation_moves_everything_to_the_new_key(parts):
    store, old, audit, tmp = parts
    store.put("pg.prod", SecretStr(SECRET), actor="admin1")
    new = generate_key()
    both = EncryptedCredentialStore(tmp / "app.db", SecretStr(f"{new},{old}"), audit)
    assert both.rotate(actor="cli") == 1
    only_new = EncryptedCredentialStore(tmp / "app.db", SecretStr(new), audit)
    assert only_new.get("pg.prod").get_secret_value() == SECRET
    with pytest.raises(CredentialError):
        EncryptedCredentialStore(tmp / "app.db", SecretStr(old), audit).get("pg.prod")


@pytest.mark.parametrize("keys", [None, SecretStr(""), SecretStr("not-a-key")])
def test_missing_or_invalid_key_disables_storage(tmp_path, keys):
    with pytest.raises(CredentialStoreUnavailableError) as info:
        EncryptedCredentialStore(tmp_path / "app.db", keys, AuditLog(tmp_path / "a.jsonl"))
    assert "not-a-key" not in str(info.value)


@pytest.mark.parametrize("ref", ["", "UPPER", "../escape", "a" * 65, "with space"])
def test_references_are_validated(parts, ref):
    store, *_ = parts
    with pytest.raises(CredentialError):
        store.put(ref, SecretStr(SECRET), actor="admin1")


def test_empty_secret_is_refused(parts):
    store, *_ = parts
    with pytest.raises(CredentialError):
        store.put("pg.prod", SecretStr(""), actor="admin1")


def test_retrieved_secret_is_redacted_from_logs(parts):
    store, *_ = parts
    store.put("pg.prod", SecretStr(SECRET), actor="admin1")
    configure_logging("INFO")
    buffer = io.StringIO()
    logger = logging.getLogger("agentsoc")
    logger.handlers[0].stream = buffer
    store.get("pg.prod")
    get_logger("test").info(f"connecting with {SECRET}", extra={"context": {"dsn": SECRET}})
    configure_logging("INFO")  # reconfiguring must not forget it
    logger.handlers[0].stream = buffer
    get_logger("test").info(f"again {SECRET}")
    assert SECRET not in buffer.getvalue() and buffer.getvalue().count("[REDACTED]") == 3
