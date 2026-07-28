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

import agent_airlock
from agent_airlock import policy_presets

REPO_ROOT = Path(__file__).resolve().parent.parent
MARKETPLACE = REPO_ROOT / ".claude-plugin" / "marketplace.json"
PLUGIN = REPO_ROOT / ".claude-plugin" / "plugin.json"
PRESETS_FILE = REPO_ROOT / "src" / "agent_airlock" / "policy_presets.py"
CVE_DIR = REPO_ROOT / "tests" / "cves"


def _load_marketplace() -> dict:
    return json.loads(MARKETPLACE.read_text(encoding="utf-8"))


def _load_plugin() -> dict:
    return json.loads(PLUGIN.read_text(encoding="utf-8"))


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


def _actual_cve_module_count() -> int:
    """Count CVE regression MODULES (``tests/cves/test_cve_*.py``).

    Was ``_actual_cve_fixture_count``, which globbed
    ``tests/cves/fixtures/cve_*.json`` — a strict subset that made an honest CVE
    claim un-publishable under the one-sided ``claimed <= actual`` guard. Each
    ``test_cve_*.py`` module reproduces a disclosed CVE / advisory pattern and
    asserts an airlock primitive blocks it, so it is the right denominator.
    """
    if not CVE_DIR.is_dir():
        return 0
    return sum(1 for f in CVE_DIR.glob("test_cve_*.py") if f.is_file())


def test_cve_count_is_honest() -> None:
    """Two-sided honesty gate on the CVE claim.

    ``claimed <= actual`` (never over-claim, as before) AND
    ``claimed >= 0.9 * actual`` (never silently under-claim by a wide margin). A
    stale 4x under-claim is the same honesty-bug class this module header names —
    the listing had been claiming 9 CVEs against 30 regression modules.
    """
    claimed = _claimed_cve_count()
    actual = _actual_cve_module_count()
    assert claimed <= actual, (
        f"marketplace over-claims CVEs: claims {claimed} but only {actual} CVE "
        f"regression modules (test_cve_*.py) live under {CVE_DIR}."
    )
    assert claimed >= 0.9 * actual, (
        f"marketplace under-claims CVEs: claims {claimed} against {actual} CVE "
        f"regression modules (>10% stale)."
    )


def _actual_preset_count() -> int:
    """The real registry size via the discovery API, not a regex.

    ``len(policy_presets.list_active())`` (policy_presets.py) is what discovery
    actually surfaces, so the count cannot drift from a hand-maintained regex that
    over- or under-matches ``def`` lines.
    """
    return len(policy_presets.list_active())


def test_preset_count_is_honest() -> None:
    """Two-sided honesty gate on the preset claim (see ``test_cve_count_is_honest``).

    The listing had been claiming 31 presets against a live registry of 61.
    """
    data = _load_marketplace()
    proof = " ".join(data.get("listing", {}).get("proof_points", []))
    m = re.search(r"(\d+)\s*(?:polic(?:y|ies)|presets?)", proof, re.IGNORECASE)
    assert m, f"proof_points missing a preset/policy count: {proof!r}"
    claimed = int(m.group(1))
    actual = _actual_preset_count()
    assert claimed <= actual, (
        f"marketplace over-claims presets: claims {claimed} but only {actual} live "
        f"in policy_presets.list_active()."
    )
    assert claimed >= 0.9 * actual, (
        f"marketplace under-claims presets: claims {claimed} against {actual} in "
        f"policy_presets.list_active() (>10% stale)."
    )


def test_plugin_version_matches_package() -> None:
    """The guard that would have caught the 0.5.0-vs-0.8.x drift months ago:
    plugin.json version must equal ``agent_airlock.__version__`` (single source of
    truth), so a version bump can never leave the published listing stale."""
    plugin = _load_plugin()
    assert plugin.get("version") == agent_airlock.__version__, (
        f"plugin.json version {plugin.get('version')!r} != "
        f"agent_airlock.__version__ {agent_airlock.__version__!r} — bump both together."
    )


def _self_describing_strings() -> list[str]:
    """Fields where the manifests describe agent-airlock ITSELF, not third parties."""
    plugin = _load_plugin()
    listing = _load_marketplace().get("listing", {})
    out: list[str] = []
    for key in ("summary", "description"):
        value = plugin.get(key)
        if isinstance(value, str):
            out.append(value)
    for key in ("keywords", "tags"):
        out.extend(str(x) for x in plugin.get(key, []))
    tagline = listing.get("tagline")
    if isinstance(tagline, str):
        out.append(tagline)
    for key in ("feature_bullets", "why_this_plugin"):
        out.extend(str(x) for x in listing.get(key, []))
    return out


def test_manifests_do_not_self_brand_as_firewall() -> None:
    """v0.8.55 dropped the 'firewall' self-branding (the term collides with what MCP
    gateways / WAFs do). The published manifests are the last surface that can
    silently reintroduce it. Referring to OTHER people's firewalls / gateways stays
    legal — this scans only agent-airlock's self-describing fields."""
    offenders = [s for s in _self_describing_strings() if "firewall" in s.lower()]
    assert not offenders, (
        f"manifest describes agent-airlock itself as a 'firewall' (dropped in v0.8.55): {offenders}"
    )
