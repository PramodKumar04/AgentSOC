"""Ingest a LANL-format authentication file into a processed dataset.

Usage:
    python scripts/ingest_lanl.py INPUT --out DIR --label "TRUE PROVENANCE" [--source synthetic]
                                  [--limit N] [--skip N] [--base-time ISO] [--overwrite]
"""

import sys

from agentsoc.cli import ingest_main

if __name__ == "__main__":
    sys.exit(ingest_main())
