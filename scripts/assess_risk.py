"""Score incidents with RSEM (needs a stored structural assessment).

Usage:
    python scripts/assess_risk.py --detection DETECTION_DIR [--config FILE] [--overwrite]
"""

import sys

from agentsoc.cli import assess_risk_main

if __name__ == "__main__":
    sys.exit(assess_risk_main())
