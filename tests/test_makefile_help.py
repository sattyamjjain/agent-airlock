"""``make help`` must list every target the Makefile declares.

CLAUDE.md said "``make help`` lists every target" while three were missing from it —
``check-docs`` and both ``check-registry-parity`` targets — so reading the help never
showed the release-only gates existed. This pins the help text to the ``.PHONY``
declaration, and ``.PHONY`` to the rules the Makefile actually defines.
"""

from __future__ import annotations

import re
from pathlib import Path

MAKEFILE = Path(__file__).resolve().parents[1] / "Makefile"


def _phony_targets(text: str) -> set[str]:
    line = next(line for line in text.splitlines() if line.startswith(".PHONY:"))
    return set(line.split(":", 1)[1].split())


def _defined_targets(text: str) -> set[str]:
    return set(re.findall(r"^([a-zA-Z0-9_-]+):(?!=)", text, re.MULTILINE))


def _help_targets(text: str) -> set[str]:
    block = text.split("\nhelp:\n", 1)[1].split("\n\n", 1)[0]
    return set(re.findall(r'@echo "  ([a-z0-9-]+)\s', block))


class TestMakeHelp:
    def test_every_defined_target_is_declared_phony(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")

        assert _defined_targets(text) == _phony_targets(text)

    def test_help_lists_every_target_but_itself(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")

        missing = _phony_targets(text) - {"help"} - _help_targets(text)
        extra = _help_targets(text) - _phony_targets(text)
        assert not missing, f"make help omits: {sorted(missing)}"
        assert not extra, f"make help lists targets that do not exist: {sorted(extra)}"
