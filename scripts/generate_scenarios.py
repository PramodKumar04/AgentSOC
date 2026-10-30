"""Write the deterministic SYNTHETIC LANL-format scenario file.

Usage:
    python scripts/generate_scenarios.py --out data/samples/auth_scenarios_synthetic.txt
"""

import sys

from agentsoc.cli import generate_scenarios_main

if __name__ == "__main__":
    sys.exit(generate_scenarios_main())
