"""Validate Phases 1-2 on windows of the real LANL 2015 authentication archive.

Usage:
    python scripts/validate_lanl.py --archive PATH/auth.txt.gz [--redteam PATH/redteam.txt.gz]
        --out data/processed/lanl_validation --run NAME:SKIP:LIMIT[:default|half_window] ...
"""

import sys

from agentsoc.evaluation.validate import main

if __name__ == "__main__":
    sys.exit(main())
