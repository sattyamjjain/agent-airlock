"""``python -m benchmarks.adaptive_redteam`` -> the session runner CLI."""

from __future__ import annotations

import sys

from .run_session import main

if __name__ == "__main__":
    sys.exit(main())
