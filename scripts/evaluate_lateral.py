"""Generate the Target 1 result reports from actual runs.

Usage:
    python scripts/evaluate_lateral.py synthetic --work SCRATCH_DIR
    python scripts/evaluate_lateral.py lanl --redteam PATH/redteam.txt.gz
"""

import sys

from agentsoc.evaluation.lateral_report import main

if __name__ == "__main__":
    sys.exit(main())
