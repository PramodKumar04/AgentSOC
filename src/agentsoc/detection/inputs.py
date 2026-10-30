"""Load processed datasets for detection — verified only.

Builds on the Phase 1 loader (hash + count check against the manifest) and adds
checks that matter when several datasets are analysed together.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from agentsoc.exceptions import DatasetIntegrityError
from agentsoc.schemas import AuthEvent
from agentsoc.store.datasets import DatasetManifest, load_events, load_manifest


@dataclass(frozen=True)
class VerifiedInput:
    directory: Path
    manifest: DatasetManifest
    events: list[AuthEvent]


def load_verified_inputs(dataset_dirs: Sequence[str | Path]) -> list[VerifiedInput]:
    if not dataset_dirs:
        raise DatasetIntegrityError("no input datasets given")
    inputs: list[VerifiedInput] = []
    seen_ids: set[str] = set()
    for raw_dir in dataset_dirs:
        directory = Path(raw_dir)
        manifest = load_manifest(directory)
        events = load_events(directory, verify=True)
        mismatched = sum(e.dataset is not manifest.dataset for e in events)
        if mismatched:
            raise DatasetIntegrityError(
                f"{directory.name}: {mismatched} events disagree with manifest provenance "
                f"'{manifest.dataset}'"
            )
        ids = {e.event_id for e in events}
        clash = ids & seen_ids
        if clash:
            raise DatasetIntegrityError(
                f"{directory.name}: event_ids already loaded from another input, "
                f"e.g. {sorted(clash)[:3]}"
            )
        seen_ids |= ids
        inputs.append(VerifiedInput(directory, manifest, events))
    return inputs
