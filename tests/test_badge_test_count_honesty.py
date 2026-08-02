"""CI guard: the README TEST-BADGE headline discloses the WHOLE suite, honestly.

The badge is the "source of truth" the README points at, but the coverage run it
is generated from excludes two buckets — ``tests/benchmarks`` (``--ignore``) and
``docker``-marked tests (``-m 'not docker'``). Before v0.8.62 the headline silently
showed only the coverage-run count, so a dozen real tests never entered the number.

This locks the DISCLOSURE invariant so that cannot drift back — a *structural*
check, in the same spirit as ``tests/test_no_placeholder_cves.py`` (which asserts
shape, not a live re-verification):

1. the block reconciles — headline total == coverage-run count + excluded, and
   excluded == benchmark bucket + docker bucket; and
2. both excluded buckets are disclosed, with their reasons.

It deliberately does NOT re-count against a live ``pytest --collect-only``: the
absolute total is the badge script's job (regenerated from pytest on release) and
is genuinely environment-dependent — optional-extra tests gated by ``importorskip``
collect only where their extra is installed, so a live re-count differs between a
fat local env and CI's ``.[dev]``. What must never drift is the *disclosure*, and
that is what this guard pins.
"""

from __future__ import annotations

import re
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


def test_badge_discloses_and_reconciles_the_excluded_buckets() -> None:
    body = _badge_body()
    total = _int(r"\*\*Test suite:\*\*\s*([\d,]+)\s*tests", body, "total")
    run = _int(r"runs\s+([\d,]+)\s+of", body, "coverage-run count")
    excluded = _int(r"the\s+(\d+)\s+excluded", body, "excluded count")
    benchmarks = _int(r"(\d+)\s+benchmark tests", body, "benchmark count")
    docker = _int(r"(\d+)\s+docker-marked", body, "docker count")

    assert excluded == benchmarks + docker, (
        f"badge note is inconsistent: {excluded} excluded != "
        f"{benchmarks} benchmark + {docker} docker"
    )
    assert total == run + excluded, (
        f"badge note is inconsistent: total {total} != run {run} + excluded {excluded}"
    )
    # The reasons must travel with the counts — a bare number is what this guards against.
    assert "not correctness tests" in body, "badge dropped the benchmark-exclusion reason"
    assert "need a daemon" in body, "badge dropped the docker-exclusion reason"
    # A real suite excludes a non-zero number; a "0 excluded" headline is the drift.
    assert excluded > 0, "badge claims nothing is excluded from the coverage run — it is"


def test_guard_would_catch_a_silently_shrunk_headline() -> None:
    # Models the pre-v0.8.62 drift the guard exists to catch: a headline equal to the
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
