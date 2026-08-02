"""CI guard: the README TEST-BADGE headline counts the WHOLE suite, honestly.

The badge is the "source of truth" the README points at, but the coverage run it
is generated from excludes two buckets — ``tests/benchmarks`` (``--ignore``) and
``docker``-marked tests (``-m 'not docker'``). Before v0.8.62 the headline silently
showed only the coverage-run count, so twelve real tests never entered the number.

This locks two invariants so that can't drift back (same spirit as
``tests/test_no_placeholder_cves.py`` — a structural claims-integrity guard):

1. the headline total equals the TRUE collected total (a fresh, unfiltered
   ``--collect-only`` in this same env), so the number cannot quietly shrink; and
2. the block is internally consistent and discloses both excluded buckets with
   their reasons (benchmarks are not correctness tests; docker needs a daemon).

The collect is ``--collect-only`` (no execution) and runs once — a bounded cost.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"

_BADGE_BLOCK_RE = re.compile(
    r"<!-- TEST-BADGE-START -->(?P<body>.*?)<!-- TEST-BADGE-END -->",
    re.DOTALL,
)


def _badge_body() -> str:
    block = _BADGE_BLOCK_RE.search(README.read_text(encoding="utf-8"))
    assert block, "README is missing the TEST-BADGE block"
    return block.group("body")


def _int(pattern: str, text: str, label: str) -> int:
    m = re.search(pattern, text)
    assert m, f"could not parse {label} from the TEST-BADGE block:\n{text}"
    return int(m.group(1).replace(",", ""))


def _true_total() -> int:
    """Collected test count with NO addopts filters — the whole suite, this env."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "--no-cov", "-o", "addopts="],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    m = re.search(r"(\d+)\s+tests collected", result.stdout)
    assert m, f"could not parse a collected count from pytest:\n{result.stdout[-2000:]}"
    return int(m.group(1))


def test_badge_total_equals_the_true_collected_total() -> None:
    body = _badge_body()
    headline_total = _int(r"\*\*Test suite:\*\*\s*([\d,]+)\s*tests", body, "headline total")
    true_total = _true_total()
    assert headline_total == true_total, (
        f"README badge headline says {headline_total:,} tests but a fresh unfiltered "
        f"collect finds {true_total:,}. Run `make test-badge` — the headline must count "
        "the whole suite, not just the coverage run."
    )


def test_badge_discloses_and_reconciles_the_excluded_buckets() -> None:
    body = _badge_body()
    total = _int(r"\*\*Test suite:\*\*\s*([\d,]+)\s*tests", body, "total")
    run = _int(r"runs\s+([\d,]+)\s+of", body, "coverage-run count")
    excluded = _int(r"the\s+(\d+)\s+excluded", body, "excluded count")
    benchmarks = _int(r"(\d+)\s+benchmark tests", body, "benchmark count")
    docker = _int(r"(\d+)\s+docker-marked", body, "docker count")

    assert excluded == benchmarks + docker, (
        f"badge note is inconsistent: {excluded} excluded != {benchmarks} benchmark + {docker} docker"
    )
    assert total == run + excluded, (
        f"badge note is inconsistent: total {total} != run {run} + excluded {excluded}"
    )
    # The reasons must travel with the counts — a bare number is what this guards against.
    assert "not correctness tests" in body, "badge dropped the benchmark-exclusion reason"
    assert "need a daemon" in body, "badge dropped the docker-exclusion reason"


def test_guard_would_catch_a_silently_shrunk_headline() -> None:
    # Models the pre-v0.8.62 drift the guards exist to catch: a headline equal to the
    # coverage-run count that claims nothing is excluded. Uses the same parse helpers,
    # proving they are live (mirrors test_no_placeholder_cves's guard-would-catch).
    dishonest = (
        "**Test suite:** 3,650 tests · runs 3,650 of 3,650; "
        "the 0 excluded are 0 benchmark tests and 0 docker-marked"
    )
    total = _int(r"\*\*Test suite:\*\*\s*([\d,]+)", dishonest, "total")
    run = _int(r"runs\s+([\d,]+)\s+of", dishonest, "run")
    excluded = _int(r"the\s+(\d+)\s+excluded", dishonest, "excluded")
    assert total == run and excluded == 0, (
        "synthetic dishonest badge should model total == run with 0 disclosed exclusions"
    )
