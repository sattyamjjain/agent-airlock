"""Regression tests for ``.claude-plugin/marketplace.json`` drift (v0.5.8+).

The same honesty-bug class that bit v0.5.2 / v0.5.4 / v0.5.7.1 — the
plugin marketplace listing claims numbers that drift the moment new
tests / CVE fixtures / presets land. This module locks the shape so
CI fails before the listing diverges.

Open issue #3 from the v0.5.8 daily prompt.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MARKETPLACE = REPO_ROOT / ".claude-plugin" / "marketplace.json"
PRESETS_FILE = REPO_ROOT / "src" / "agent_airlock" / "policy_presets.py"
CVE_FIXTURES = REPO_ROOT / "tests" / "cves" / "fixtures"


def _load_marketplace() -> dict:
    return json.loads(MARKETPLACE.read_text(encoding="utf-8"))


def test_marketplace_file_exists() -> None:
    assert MARKETPLACE.exists(), ".claude-plugin/marketplace.json missing — listing cannot ship"


def test_marketplace_parses_as_json() -> None:
    """Catches a corrupted marketplace.json before submission."""
    _load_marketplace()


def test_proof_points_present() -> None:
    """proof_points must list test count + CVE count + preset count."""
    data = _load_marketplace()
    listing = data.get("listing", {})
    proof = listing.get("proof_points", [])
    joined = " ".join(proof)
    # We don't pin exact numbers (they drift fast) but we DO require
    # the three claims to be structurally present.
    assert re.search(r"\d+\s*tests?", joined, re.IGNORECASE), (
        f"proof_points missing a 'NN tests' claim: {proof!r}"
    )
    assert re.search(r"\d+\s*CVE", joined, re.IGNORECASE), (
        f"proof_points missing a 'NN CVE' claim: {proof!r}"
    )
    assert re.search(r"\d+\s*polic(?:y|ies)|\d+\s*presets?", joined, re.IGNORECASE), (
        f"proof_points missing a preset/policy count: {proof!r}"
    )


def _claimed_cve_count() -> int:
    data = _load_marketplace()
    proof = " ".join(data.get("listing", {}).get("proof_points", []))
    m = re.search(r"(\d+)\s*CVE", proof, re.IGNORECASE)
    return int(m.group(1)) if m else 0


def _actual_cve_fixture_count() -> int:
    if not CVE_FIXTURES.is_dir():
        return 0
    # Count distinct CVE-named fixtures (skip composite/umbrella files
    # that don't pin a single CVE id in the filename).
    return sum(1 for f in CVE_FIXTURES.glob("cve_*.json") if f.is_file())


def test_cve_count_does_not_exceed_actual() -> None:
    """Marketplace must NOT over-claim CVE coverage.

    Allowed to under-claim during a release-prep window (the listing
    lags reality between bump and submit), but never over-claim.
    """
    claimed = _claimed_cve_count()
    actual = _actual_cve_fixture_count()
    assert claimed <= actual, (
        f"marketplace.json claims {claimed} CVEs but only {actual} CVE-named "
        f"fixtures live under {CVE_FIXTURES}. Honesty-bug class: update the "
        "listing or add the fixture."
    )


def _actual_preset_count() -> int:
    """Count preset factories in policy_presets.py."""
    if not PRESETS_FILE.is_file():
        return 0
    text = PRESETS_FILE.read_text(encoding="utf-8")
    # Match top-level def lines whose name ends in _defaults / _policy /
    # _check (the established preset-naming conventions).
    return len(
        re.findall(
            r"^def\s+\w+(?:_defaults|_policy|_check|_caps|_guard)\b",
            text,
            re.MULTILINE,
        )
    )


def test_preset_count_does_not_exceed_actual() -> None:
    data = _load_marketplace()
    proof = " ".join(data.get("listing", {}).get("proof_points", []))
    m = re.search(r"(\d+)\s*(?:polic(?:y|ies)|presets?)", proof, re.IGNORECASE)
    if not m:
        pytest.skip("no preset-count claim in proof_points")
    claimed = int(m.group(1))
    actual = _actual_preset_count()
    assert claimed <= actual, (
        f"marketplace.json claims {claimed} presets but only {actual} live in "
        f"policy_presets.py. Honesty-bug class."
    )
