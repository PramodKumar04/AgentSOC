"""Generate the Target 3 result reports from actual runs.

Usage:
    python scripts/evaluate_risk.py synthetic --work SCRATCH_DIR
    python scripts/evaluate_risk.py lanl --redteam PATH/redteam.txt.gz
"""

import sys

from agentsoc.evaluation.risk_report import main

if __name__ == "__main__":
    sys.exit(main())
