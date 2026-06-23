"""CI guard: the preset registry must cite only real-shaped CVE ids.

Scans ``policy_presets.py`` (and the canonical ``cves=`` tuples it exposes) for
every ``CVE-…`` identifier and fails if any matches a placeholder / reserved /
example pattern (``99999``, ``00000``, ``XXXX``, ``YYYY``, ``12345`` …) or does
not match the canonical NVD id shape ``CVE-<year>-<digits>``.

This does NOT (and cannot, offline) assert each id resolves on nvd.nist.gov —
that needs network and is not a deterministic unit test. It enforces the
structural invariant that catches the failure this guard exists for: a
placeholder id slipping into the per-CVE regression suite.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_PRESETS = Path(__file__).resolve().parents[1] / "src" / "agent_airlock" / "policy_presets.py"

# Canonical NVD id shape: CVE-YYYY-NNNN (4+ digit sequence).
_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}")
# Anything CVE-shaped at all, so we also catch non-numeric stubs (CVE-XXXX-...).
_CVE_LOOSE_RE = re.compile(r"CVE-[0-9A-Za-z]+-[0-9A-Za-z]+")

# Placeholder / reserved / example sequence-number patterns that must never
# appear as a CVE sequence number in the registry.
_PLACEHOLDER_SEQS = {"99999", "999999", "00000", "0000", "12345", "11111"}
_PLACEHOLDER_TOKENS = ("XXXX", "YYYY", "NNNN", "XXX")


def _registry_source() -> str:
    return _PRESETS.read_text(encoding="utf-8")


def test_presets_file_exists() -> None:
    assert _PRESETS.is_file(), f"preset registry not found at {_PRESETS}"


def test_no_nonnumeric_placeholder_cve_ids() -> None:
    src = _registry_source()
    for token in _PLACEHOLDER_TOKENS:
        bad = re.findall(rf"CVE-[^\s`'\"]*{token}[^\s`'\"]*", src)
        assert not bad, f"non-numeric placeholder CVE id(s) in preset registry: {bad}"


def test_no_placeholder_sequence_numbers() -> None:
    src = _registry_source()
    offenders = [cve for cve in _CVE_RE.findall(src) if cve.split("-")[-1] in _PLACEHOLDER_SEQS]
    assert not offenders, f"placeholder-sequence CVE id(s) in preset registry: {offenders}"


def test_every_cve_id_matches_canonical_shape() -> None:
    src = _registry_source()
    loose = set(_CVE_LOOSE_RE.findall(src))
    canonical = set(_CVE_RE.findall(src))
    malformed = sorted(loose - canonical)
    assert not malformed, f"CVE id(s) not matching canonical CVE-YYYY-NNNN shape: {malformed}"


def test_registry_actually_cites_real_cves() -> None:
    # Sanity: the scan finds the known-real anchors, so the guard is not a no-op
    # against an empty match set.
    src = _registry_source()
    found = set(_CVE_RE.findall(src))
    for known_real in ("CVE-2025-59528", "CVE-2026-30615", "CVE-2026-25592", "CVE-2026-26030"):
        assert known_real in found, f"expected real anchor CVE {known_real} missing from registry"


@pytest.mark.parametrize("placeholder", ["CVE-2026-99999", "CVE-XXXX-0000", "CVE-2026-00000"])
def test_guard_would_catch_a_placeholder(placeholder: str) -> None:
    # The guard's own detectors fire on a synthetic placeholder — proves the
    # patterns are live, not silently passing.
    seq = placeholder.split("-")[-1]
    caught = (
        seq in _PLACEHOLDER_SEQS
        or any(tok in placeholder for tok in _PLACEHOLDER_TOKENS)
        or not _CVE_RE.fullmatch(placeholder)
    )
    assert caught, f"guard failed to flag placeholder {placeholder}"
