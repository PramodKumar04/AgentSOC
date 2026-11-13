"""Register labelled synthetic and LANL sources for the dashboard.

Usage:
    python scripts/prepare_demo_sources.py
"""

import sys

from agentsoc.demo_sources import prepare_demo_sources


def main() -> int:
    for item in prepare_demo_sources():
        print(f"{item.key}: {item.status}{f' ({item.detail})' if item.detail else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
