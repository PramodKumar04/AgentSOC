"""Credential-store key management.

Usage:
    python scripts/manage_credentials.py generate-key
        Print a new key. Put it in AGENTSOC_CREDENTIAL_KEY (for example in .env) and back
        it up somewhere separate from the database: without it, stored credentials are lost.
    python scripts/manage_credentials.py rotate
        With AGENTSOC_CREDENTIAL_KEY="NEW_KEY,OLD_KEY", re-encrypt every stored credential
        with NEW_KEY. Afterwards OLD_KEY can be removed from the variable.
    python scripts/manage_credentials.py list
        Show stored references and when they changed (never the secrets).
"""

import argparse
import sys

from agentsoc.app_data import data_root
from agentsoc.audit import AuditLog
from agentsoc.config import get_settings
from agentsoc.credentials import CredentialError, EncryptedCredentialStore, generate_key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Credential-store key management.")
    parser.add_argument("command", choices=["generate-key", "rotate", "list"])
    args = parser.parse_args(argv)
    if args.command == "generate-key":
        print(generate_key())
        return 0
    settings = get_settings()
    try:
        store = EncryptedCredentialStore(settings.db_path, settings.credential_key,
                                         AuditLog(data_root() / "activity_log.jsonl"))
        if args.command == "rotate":
            print(f"Re-encrypted {store.rotate(actor='cli')} credential(s) with the first key.")
        else:
            for info in store.list():
                print(f"{info.ref:40} updated {info.updated_at} by {info.updated_by}")
    except CredentialError as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
