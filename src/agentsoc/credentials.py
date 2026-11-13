"""Credential storage for data-source connections (database passwords, URIs).

`CredentialStore` is the interface the rest of AgentSOC uses; a production secret manager
(Vault, a cloud KMS, Windows Credential Manager) can replace `EncryptedCredentialStore`
without changing callers.

`EncryptedCredentialStore` keeps Fernet ciphertext (AES-128-CBC with HMAC-SHA256) in the
application database. Keys come only from `AGENTSOC_CREDENTIAL_KEY`, comma-separated; the
first key encrypts and every listed key can decrypt, which is how keys are rotated. Each
ciphertext names the reference it was stored under, so a ciphertext copied to another
reference is refused. Secrets are never returned by the API, written to the audit log, or
included in error messages, and a retrieved secret is registered for log redaction.

Limitations: the key sits in the server's environment, so anyone who can read both the
environment and the database can decrypt. Losing every configured key makes stored
credentials unrecoverable; they must then be entered again.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from pydantic import SecretStr

from agentsoc.audit import AuditEventType, AuditLog
from agentsoc.exceptions import AgentSOCError
from agentsoc.logging_setup import register_secret
from agentsoc.store import appdb

REF_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
FORMAT_VERSION = 1


class CredentialError(AgentSOCError):
    """A credential operation failed. The message never contains the secret."""


class CredentialStoreUnavailableError(CredentialError):
    pass


@dataclass(frozen=True)
class CredentialInfo:
    ref: str
    created_at: str
    updated_at: str
    updated_by: str


class CredentialStore(Protocol):
    def put(self, ref: str, secret: SecretStr, *, actor: str) -> None: ...
    def get(self, ref: str) -> SecretStr: ...
    def delete(self, ref: str, *, actor: str) -> bool: ...
    def list(self) -> list[CredentialInfo]: ...


def generate_key() -> str:
    return Fernet.generate_key().decode("ascii")


def _as_bytes(value: object) -> bytes:
    """A damaged row can come back as text; treat it as data to verify, never trust it."""
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)


def _check_ref(ref: str) -> None:
    if not REF_PATTERN.match(ref):
        raise CredentialError("Credential references are 1-64 lower-case letters, digits, "
                              "'.', '_' or '-'.")


class EncryptedCredentialStore:
    def __init__(self, db_path: str | Path, keys: SecretStr | None, audit: AuditLog) -> None:
        if keys is None or not keys.get_secret_value().strip():
            raise CredentialStoreUnavailableError(
                "Credential storage is not configured: set AGENTSOC_CREDENTIAL_KEY.")
        try:
            parts = [k.strip() for k in keys.get_secret_value().split(",") if k.strip()]
            self._fernet = MultiFernet([Fernet(k) for k in parts])
        except (ValueError, TypeError):
            raise CredentialStoreUnavailableError(
                "AGENTSOC_CREDENTIAL_KEY is not a valid Fernet key list.") from None
        self.db_path = Path(db_path)
        self.audit = audit
        appdb.migrate(self.db_path)

    def put(self, ref: str, secret: SecretStr, *, actor: str) -> None:
        _check_ref(ref)
        value = secret.get_secret_value()
        if not value:
            raise CredentialError("An empty credential cannot be stored.")
        token = self._fernet.encrypt(json.dumps(
            {"v": FORMAT_VERSION, "ref": ref, "secret": value}).encode("utf-8"))
        now = datetime.now(UTC).isoformat()
        with appdb.transaction(self.db_path) as conn:
            conn.execute(
                "INSERT INTO credentials (ref, ciphertext, created_at, updated_at, updated_by) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(ref) DO UPDATE SET "
                "ciphertext = excluded.ciphertext, updated_at = excluded.updated_at, "
                "updated_by = excluded.updated_by", (ref, token, now, now, actor))
        self.audit.append(AuditEventType.CREDENTIAL_STORED, ref, actor=actor)

    def get(self, ref: str) -> SecretStr:
        """For server-side connection code only. Never send the result to a client."""
        _check_ref(ref)
        with appdb.reader(self.db_path) as conn:
            row = conn.execute("SELECT ciphertext FROM credentials WHERE ref = ?",
                               (ref,)).fetchone()
        if row is None:
            raise CredentialError(f"No credential is stored under '{ref}'.")
        try:
            payload = json.loads(self._fernet.decrypt(_as_bytes(row["ciphertext"])))
        except (InvalidToken, ValueError, TypeError):
            raise CredentialError(f"Credential '{ref}' could not be decrypted with the "
                                  "configured keys.") from None
        if payload.get("v") != FORMAT_VERSION or payload.get("ref") != ref:
            raise CredentialError(f"Credential '{ref}' does not belong to this reference.")
        register_secret(payload["secret"])
        return SecretStr(payload["secret"])

    def delete(self, ref: str, *, actor: str) -> bool:
        _check_ref(ref)
        with appdb.transaction(self.db_path) as conn:
            deleted = conn.execute("DELETE FROM credentials WHERE ref = ?", (ref,)).rowcount > 0
        if deleted:
            self.audit.append(AuditEventType.CREDENTIAL_DELETED, ref, actor=actor)
        return deleted

    def list(self) -> list[CredentialInfo]:
        with appdb.reader(self.db_path) as conn:
            return [CredentialInfo(r["ref"], r["created_at"], r["updated_at"], r["updated_by"])
                    for r in conn.execute("SELECT ref, created_at, updated_at, updated_by "
                                          "FROM credentials ORDER BY ref")]

    def rotate(self, *, actor: str) -> int:
        """Re-encrypt everything with the first key. Afterwards older keys can be removed."""
        with appdb.transaction(self.db_path) as conn:
            rows = conn.execute("SELECT ref, ciphertext FROM credentials").fetchall()
            for row in rows:
                try:
                    fresh = self._fernet.rotate(_as_bytes(row["ciphertext"]))
                except (InvalidToken, ValueError, TypeError):
                    raise CredentialError(
                        f"Credential '{row['ref']}' could not be decrypted with the configured "
                        "keys; nothing was rotated.") from None
                conn.execute("UPDATE credentials SET ciphertext = ? WHERE ref = ?",
                             (fresh, row["ref"]))
        self.audit.append(AuditEventType.CREDENTIAL_KEYS_ROTATED, "credentials",
                          {"count": len(rows)}, actor=actor)
        return len(rows)


class UnavailableCredentialStore:
    """Used when no key is configured: nothing can be stored or read, and every attempt
    says why. Nothing falls back to storing plaintext."""

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def put(self, ref: str, secret: SecretStr, *, actor: str) -> None:
        raise CredentialStoreUnavailableError(self.reason)

    def get(self, ref: str) -> SecretStr:
        raise CredentialStoreUnavailableError(self.reason)

    def delete(self, ref: str, *, actor: str) -> bool:
        return False

    def list(self) -> list[CredentialInfo]:
        return []


def open_credential_store(db_path: str | Path, keys: SecretStr | None,
                          audit: AuditLog) -> EncryptedCredentialStore | UnavailableCredentialStore:
    try:
        return EncryptedCredentialStore(db_path, keys, audit)
    except CredentialStoreUnavailableError as exc:
        return UnavailableCredentialStore(str(exc))
