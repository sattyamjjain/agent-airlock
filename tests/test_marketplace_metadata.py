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

# The two docs whose job is to publish a *real* vulnerability-reporting channel.
# `example.com` is RFC-2606-reserved and used legitimately for illustration all
# over the tree (PII-masking examples, placeholder URLs), so this guard is scoped
# to the reporting docs rather than the whole repo — see the test below.
SECURITY_DOCS = [REPO_ROOT / "SECURITY.md", REPO_ROOT / "docs" / "SECURITY.md"]


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


# tests/cves/ modules that are NOT tied to a specific disclosed CVE / advisory.
# Everything else in the directory reproduces one external disclosure; the Metis
# corpus is an internal block-rate regression, so it must not inflate a "CVE /
# advisory" count.
_NON_DISCLOSURE_CVE_MODULES = {"test_metis_inspired_corpus_2026_05_18"}


def _cve_regression_module_count() -> int:
    """Canonical count of CVE / advisory regression modules under ``tests/cves/``.

    The old counter globbed only ``test_cve_*.py`` (30), silently dropping the
    ``test_ghsa_*`` / ``test_ox_*`` modules and CVE regressions named after their
    subject rather than the ``test_cve_`` prefix (e.g.
    ``test_azure_mcp_cve_2026_32211``, ``test_vercel_contextai_oauth``). Every
    ``test_*.py`` in the directory reproduces a disclosed CVE / advisory and
    asserts an airlock primitive blocks it, EXCEPT the internal-corpus modules in
    ``_NON_DISCLOSURE_CVE_MODULES``. This is the single number every published
    surface (marketplace proof point, README ASI04) is fenced against.
    """
    if not CVE_DIR.is_dir():
        return 0
    return sum(
        1
        for f in CVE_DIR.glob("test_*.py")
        if f.is_file() and f.stem not in _NON_DISCLOSURE_CVE_MODULES
    )


def _readme_cve_count() -> int:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    m = re.search(r"(\d+)\s*CVE\s*/\s*advisory regression tests", text)
    return int(m.group(1)) if m else 0


def test_cve_count_is_honest() -> None:
    """One canonical CVE / advisory count, fenced across every published surface.

    The bug this replaces: three surfaces disagreed — README ASI04 said "11+ CVEs
    tracked", marketplace.json said "30 CVE regression tests", and the directory
    held 37 disclosed-CVE / advisory regression modules. The count is now derived
    programmatically (``_cve_regression_module_count``) and BOTH the marketplace
    proof point and the README ASI04 cell must carry exactly that number, so they
    cannot drift from each other or from the suite. Add a CVE regression module
    and this fails until both surfaces are bumped.
    """
    actual = _cve_regression_module_count()
    assert _claimed_cve_count() == actual, (
        f"marketplace CVE proof point ({_claimed_cve_count()}) != actual regression "
        f"modules ({actual}) under {CVE_DIR}. Update the proof point."
    )
    assert _readme_cve_count() == actual, (
        f"README ASI04 CVE count ({_readme_cve_count()}) != actual regression modules "
        f"({actual}). Say '{actual} CVE/advisory regression tests'."
    )


def _pyproject_fail_under() -> int:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r"fail_under\s*=\s*(\d+)", text)
    assert m, "pyproject.toml has no [tool.coverage.report] fail_under"
    return int(m.group(1))


def _ci_cov_fail_under() -> int:
    text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    m = re.search(r"--cov-fail-under=(\d+)", text)
    assert m, "ci.yml no longer passes --cov-fail-under"
    return int(m.group(1))


def _marketplace_claimed_floor() -> int:
    proof = " ".join(_load_marketplace().get("listing", {}).get("proof_points", []))
    m = re.search(r"floor\s*(\d+)\s*%", proof)
    return int(m.group(1)) if m else 0


def test_coverage_floor_is_consistent() -> None:
    """The published 'CI-enforced floor' must equal what CI actually enforces.

    Two floors disagreed: ``[tool.coverage.report] fail_under = 82`` (the intended
    floor from the v0.5.4 honesty sweep, applied locally) but ci.yml passed
    ``--cov-fail-under=80`` on the command line, which overrides the config for
    the CI run — so CI enforced 80 while the config claimed 82, and the
    marketplace repeated the stale 80. This binds all three: the pytest override
    in CI, the coverage config, and the marketplace 'floor NN%' proof point must
    be the same number.
    """
    ci = _ci_cov_fail_under()
    cfg = _pyproject_fail_under()
    claimed = _marketplace_claimed_floor()
    assert ci == cfg == claimed, (
        f"coverage floor disagreement: ci.yml --cov-fail-under={ci}, "
        f"pyproject fail_under={cfg}, marketplace proof point floor={claimed}%. "
        "All three must match (the CLI --cov-fail-under overrides the config, so it "
        "is the number CI truly enforces)."
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


def test_security_docs_publish_no_example_com_contact() -> None:
    """SECURITY.md / docs/SECURITY.md must give a *real* reporting channel.

    A fake ``example.com`` contact actually shipped: through v0.8.57 the security
    address was ``sattyamjain@example.com`` — an RFC-2606 reserved domain that
    nobody reads, so a responsibly-disclosed vulnerability would have bounced.
    This locks the reporting docs against that regression. It is scoped to those
    two files on purpose: ``example.com`` is legitimate illustration elsewhere in
    the tree (sanitizer/PII examples, placeholder URLs), so a repo-wide ban would
    flag ~30 correct uses. The reporting docs are the only surface where an
    ``example.com`` string is a bug rather than an example.
    """
    offenders: list[str] = []
    for doc in SECURITY_DOCS:
        if not doc.is_file():
            continue
        for lineno, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            if "example.com" in line:
                offenders.append(f"{doc.relative_to(REPO_ROOT)}:{lineno}: {line.strip()}")
    assert not offenders, (
        "fake example.com contact in a security-reporting doc — replace with the real "
        "channel (GitHub Security Advisories / maintainer email):\n" + "\n".join(offenders)
    )


def _exported_zero_arg_preset_factories() -> list[str]:
    """``__all__`` names that are module-level factories callable with no args.

    This is the set every enumeration surface (``airlock graph``, the OWASP
    coverage matrix) is *supposed* to see. Classes (``PresetMeta``,
    ``*Blocked``/``*Error``), eagerly-built default instances (``UPPER_SNAKE``),
    and check predicates that demand positional args (``*_check``,
    ``is_destructive_tool``) are excluded — they are not zero-arg factories.
    ``list_active`` itself is excluded.
    """
    import inspect

    out: list[str] = []
    for name in policy_presets.__all__:
        if name == "list_active":
            continue
        obj = getattr(policy_presets, name, None)
        if not inspect.isfunction(obj):
            continue
        try:
            sig = inspect.signature(obj)
        except (TypeError, ValueError):
            continue
        has_required_positional = any(
            p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
            and p.default is inspect.Parameter.empty
            for p in sig.parameters.values()
        )
        if has_required_positional:
            continue
        out.append(name)
    return out


def test_all_exported_zero_arg_presets_are_registered() -> None:
    """Every ``__all__``-exported zero-arg preset factory must appear in
    ``list_active()``.

    v0.8.57 shipped a ``list_active`` that discovered presets by a name-suffix
    heuristic (admit ``*_policy`` / ``*_defaults`` / ``*_caps`` / ``*_2026_04``).
    Ten shipped, exported presets with off-pattern names — ``lan_unauth_mcp_guard``,
    ``apply_india_dpdp_2023``, ``mobile_mcp_intent_guard_2026_05``,
    ``oauth_state_injection_guard``, ``high_value_action_deny_by_default``, and
    five CVE presets — were silently dropped from ``airlock graph`` and the OWASP
    matrix despite the function calling itself the 'single source of truth'.

    ``list_active`` is now backed by an explicit ``@preset`` registry, so this
    guard binds the public surface to the enumerated surface: add a preset to
    ``__all__`` without ``@preset`` and this fails, rather than the preset
    quietly disappearing from every enumeration.
    """
    exported = set(_exported_zero_arg_preset_factories())
    active = {m.factory_name for m in policy_presets.list_active()}
    missing = sorted(exported - active)
    assert not missing, (
        f"{len(missing)} __all__-exported zero-arg preset factories are not in "
        f"list_active() — decorate them with @preset:\n" + "\n".join(missing)
    )
