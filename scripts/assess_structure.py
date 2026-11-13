"""Validate detected incidents against observed authentication graphs (SSE).

Usage:
    python scripts/assess_structure.py DATASET_DIR --detection DETECTION_DIR [--overwrite]
"""

import sys

from agentsoc.cli import assess_structure_main

if __name__ == "__main__":
    sys.exit(assess_structure_main())
