"""Matched-pair multi-harness prompt-injection benchmark.

Measures something the published literature does not cover: given the **same repository**
and the **same task**, with **one** realistic instruction planted in the README, which
coding harness acts on it — reported against its benign twin so the number is interpretable.

See ``RESULTS.md`` for the design, the results, and an explicit statement of what the
number does not show.
"""

from __future__ import annotations

from .fixture import ARMS, TASK_PROMPT, Arm, build_fixture
from .harnesses import HARNESSES, Harness, available_harnesses
from .report import render_results_md, render_summary
from .runner import CellResult, RunReport, run_matrix

__all__ = [
    "ARMS",
    "HARNESSES",
    "TASK_PROMPT",
    "Arm",
    "CellResult",
    "Harness",
    "RunReport",
    "available_harnesses",
    "build_fixture",
    "render_results_md",
    "render_summary",
    "run_matrix",
]
