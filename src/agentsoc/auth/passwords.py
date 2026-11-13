"""Password hashing with scrypt (Python standard library; no extra dependency).

Stored form: scrypt$<n>$<r>$<p>$<salt b64>$<hash b64>. Parameters are read back from the
stored value but bounded, so an edited database row cannot make verification exhaust
memory or CPU.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from functools import lru_cache

N, R, P = 2**15, 8, 1
DKLEN = 32
_MAX_N = 2**17
_MAXMEM = 256 * 1024 * 1024
MIN_LENGTH, MAX_LENGTH = 12, 128


class PasswordPolicyError(ValueError):
    pass


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          maxmem=_MAXMEM, dklen=DKLEN)


def check_policy(password: str, username: str) -> None:
    if not MIN_LENGTH <= len(password) <= MAX_LENGTH:
        raise PasswordPolicyError(
            f"Password must be between {MIN_LENGTH} and {MAX_LENGTH} characters.")
    if username and username.lower() in password.lower():
        raise PasswordPolicyError("Password must not contain the username.")
    if len(set(password)) < 5:
        raise PasswordPolicyError("Password is too repetitive.")


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    return f"scrypt${N}${R}${P}${_b64(salt)}${_b64(_derive(password, salt, N, R, P))}"


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time check. Any malformed or out-of-bounds stored value fails closed."""
    try:
        scheme, n, r, p, salt, expected = encoded.split("$")
        n, r, p = int(n), int(r), int(p)
        if scheme != "scrypt" or not (2 <= n <= _MAX_N and n & (n - 1) == 0) or not (
                1 <= r <= 16 and 1 <= p <= 4):
            return False
        actual = _derive(password, base64.b64decode(salt), n, r, p)
        return hmac.compare_digest(actual, base64.b64decode(expected))
    except (ValueError, TypeError):
        return False


@lru_cache(maxsize=1)
def dummy_hash() -> str:
    """Verified against when the account does not exist, so timing does not reveal that."""
    return hash_password(os.urandom(16).hex())
