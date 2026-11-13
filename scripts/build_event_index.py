"""Build the searchable event index for data sources. The datasets are only read.

Usage:
    python scripts/build_event_index.py --all
    python scripts/build_event_index.py --source demo
"""

import argparse
import sys
import time

from agentsoc.app_data import data_root, discover_sources
from agentsoc.exceptions import AgentSOCError
from agentsoc.store.eventdb import EventIndexStaleError, EventStoreError, build_index, check_current

INDEX_DIR = "event_index"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build event indexes.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true")
    group.add_argument("--source")
    parser.add_argument("--force", action="store_true", help="rebuild even if current")
    args = parser.parse_args(argv)
    root = data_root()
    sources = [s for s in discover_sources(root) if args.all or s.key == args.source]
    if not sources:
        print(f"Unknown source: {args.source}", file=sys.stderr)
        return 1
    failed = 0
    for source in sources:
        path = root / INDEX_DIR / f"{source.key}.sqlite"
        try:
            if not args.force:
                try:
                    check_current(path, source.dataset_dir)
                    print(f"{source.key}: current")
                    continue
                except (EventStoreError, EventIndexStaleError):
                    pass
            start = time.perf_counter()
            info = build_index(source.dataset_dir, path, source_key=source.key)
            print(f"{source.key}: {info.event_count:,} events in "
                  f"{time.perf_counter() - start:.1f} s")
        except AgentSOCError as exc:
            failed += 1
            print(f"{source.key}: not built ({exc})", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
