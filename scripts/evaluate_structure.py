"""Generate the Target 2 result reports from actual runs.

Usage:
    python scripts/evaluate_structure.py synthetic --work SCRATCH_DIR
    python scripts/evaluate_structure.py lanl --redteam PATH/redteam.txt.gz
"""

import sys

from agentsoc.evaluation.structural_report import main

if __name__ == "__main__":
    sys.exit(main())
