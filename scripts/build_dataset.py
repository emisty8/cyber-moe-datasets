"""Convenience wrapper for the packaged CLI."""

import sys

from cyber_moe_datasets.cli import main

if __name__ == "__main__":
    sys.argv.insert(1, "build")
    main()
