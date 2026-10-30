"""Explicit exception hierarchy. Every AgentSOC error derives from AgentSOCError
so the pipeline and dashboard can catch project errors without swallowing bugs."""


class AgentSOCError(Exception):
    """Base class for all AgentSOC errors."""


class ConfigurationError(AgentSOCError):
    """Settings are missing or invalid. Messages must never contain secret values."""


class IngestionError(AgentSOCError):
    """An input file cannot be read at all (missing, unreadable, corrupt archive).

    Individual malformed records are NOT errors: they are rejected and reported.
    """


class DatasetIntegrityError(AgentSOCError):
    """A processed dataset does not match its manifest or contains invalid records."""


class DetectionError(AgentSOCError):
    """Detection produced or received inconsistent evidence (e.g. an unknown event ID)."""
