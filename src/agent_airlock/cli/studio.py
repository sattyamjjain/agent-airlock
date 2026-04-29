"""``airlock studio`` CLI — local rehearsal sandbox (Feature C, v0.6.0+)."""

from __future__ import annotations

import argparse
import sys
import time

from ..studio import StudioApp, StudioState


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="airlock studio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)

    state = StudioState()
    app = StudioApp(state, host=args.host, port=args.port)
    httpd = app.serve()
    print(
        f"airlock studio serving on http://{args.host}:{args.port}",
        file=sys.stderr,
    )
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        httpd.shutdown()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["main"]
