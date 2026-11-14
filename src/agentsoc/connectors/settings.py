"""The database engines AgentSOC can read, and the one connection type they share.

Settings carry an `engine` field so a stored or submitted connection is always read by the
right engine. Connections saved before MySQL support have no `engine`; `with_engine` fills it
in from the source's `kind`.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field, SecretStr

from agentsoc.connectors.base import SourceConnector
from agentsoc.connectors.mysql import MySQLConnector, MySQLSettings
from agentsoc.connectors.postgres import PostgresConnector, PostgresSettings

ConnectionSettings = Annotated[PostgresSettings | MySQLSettings, Field(discriminator="engine")]
ENGINES = ("postgresql", "mysql")


def with_engine(data: Any, default: str = "postgresql") -> Any:
    """Fill in `engine` for a connection written before the field existed."""
    if isinstance(data, dict) and "engine" not in data:
        return {**data, "engine": default}
    return data


def connector_for(settings: PostgresSettings | MySQLSettings,
                  password: SecretStr) -> SourceConnector:
    if isinstance(settings, MySQLSettings):
        return MySQLConnector(settings, password)
    return PostgresConnector(settings, password)
