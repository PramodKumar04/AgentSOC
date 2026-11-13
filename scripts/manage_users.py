"""Manage AgentSOC accounts from the command line (also how the first administrator is made).

Usage:
    python scripts/manage_users.py create USERNAME --role admin|analyst
    python scripts/manage_users.py reset-password USERNAME
    python scripts/manage_users.py list

Passwords are read with a hidden prompt, or from the environment variable named by
--password-env (for automation). They are never accepted as a command-line argument,
which would leave them in shell history.
"""

import argparse
import getpass
import os
import sys

from agentsoc.app_data import data_root
from agentsoc.audit import AuditLog
from agentsoc.auth.passwords import PasswordPolicyError
from agentsoc.auth.service import AuthError, AuthService, Role
from agentsoc.config import get_settings

ACTOR = "cli"


def _password(args) -> str:
    if args.password_env:
        value = os.environ.get(args.password_env)
        if not value:
            raise SystemExit(f"Environment variable {args.password_env} is not set.")
        return value
    first = getpass.getpass("Password: ")
    if first != getpass.getpass("Repeat password: "):
        raise SystemExit("Passwords do not match.")
    return first


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("username")
    create.add_argument("--role", choices=[r.value for r in Role], required=True)
    create.add_argument("--password-env")
    reset = sub.add_parser("reset-password")
    reset.add_argument("username")
    reset.add_argument("--password-env")
    sub.add_parser("list")
    parser.add_argument("--db", help="application database (default: AGENTSOC_DB_PATH)")
    parser.add_argument("--activity-log", help="default: <data root>/activity_log.jsonl")
    args = parser.parse_args(argv)

    settings = get_settings()
    audit = AuditLog(args.activity_log or data_root() / "activity_log.jsonl")
    auth = AuthService(args.db or settings.db_path, audit, settings)
    try:
        if args.command == "create":
            info = auth.create_user(args.username, _password(args), Role(args.role), actor=ACTOR)
            print(f"Created {info.username} ({info.role.value}).")
        elif args.command == "reset-password":
            auth.reset_password(args.username, _password(args), actor=ACTOR)
            print(f"Password reset for {args.username}; their sessions were ended.")
        else:
            for u in auth.list_users():
                state = "disabled" if u.disabled else "locked" if u.locked else "active"
                print(f"{u.username:32} {u.role.value:8} {state}")
    except (AuthError, PasswordPolicyError) as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
