"""Run authentication threat detection on verified processed datasets.

Usage:
    python scripts/detect.py DATASET_DIR [DATASET_DIR ...] --out DIR [--config FILE] [--overwrite]
"""

import sys

from agentsoc.cli import detect_main

if __name__ == "__main__":
    sys.exit(detect_main())
