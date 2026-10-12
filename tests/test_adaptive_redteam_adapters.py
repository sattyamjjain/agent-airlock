"""Every registered adapter is wired to a real refusal and a real admit.

For all 41 adapters (38 bypass targets + 3 value-gate), the known-blocked shape
must classify as ``hard_block`` and the benign control as ``benign_pass``. This is
what proves the campaign actually drives each guard — not a stub.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
for _p in (str(_ROOT / "src"), str(_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from benchmarks.adaptive_redteam.adapters import (  # noqa: E402
    BYPASS_TARGETS,
    VALUE_GATE_TARGETS,
    all_adapter_names,
    get_adapter,
    get_registry,
    seed_count,
)
from benchmarks.adaptive_redteam.oracle import Intent, Outcome, classify  # noqa: E402

_NAMES = all_adapter_names()


def test_registry_covers_all_38_bypass_targets() -> None:
    assert len(BYPASS_TARGETS) == 38
    assert len(set(BYPASS_TARGETS)) == 38
    registry = get_registry()
    for name in BYPASS_TARGETS:
        assert name in registry, f"missing bypass target {name!r}"
    for name in VALUE_GATE_TARGETS:
        assert name in registry, f"missing value-gate adapter {name!r}"
    assert len(registry) == 41


def test_mode_counts() -> None:
    registry = get_registry()
    modes = {"A": 0, "B": 0, "C": 0}
    for ad in registry.values():
        modes[ad.mode] += 1
    assert modes == {"A": 3, "B": 2, "C": 36}


@pytest.mark.parametrize("name", _NAMES)
def test_known_blocked_is_hard_block(name: str) -> None:
    adapter = get_adapter(name)
    candidate = adapter.known_blocked(0)
    canary = adapter.run(candidate)
    outcome = classify(candidate, canary, Intent.ATTACK)
    assert outcome is Outcome.HARD_BLOCK, (
        f"{name}: expected hard_block, got {outcome.value} "
        f"(response={canary.response!r}, raised={canary.raised!r})"
    )


@pytest.mark.parametrize("name", _NAMES)
def test_benign_control_is_benign_pass(name: str) -> None:
    adapter = get_adapter(name)
    candidate = adapter.benign_control(0)
    canary = adapter.run(candidate)
    outcome = classify(candidate, canary, candidate.intent)
    assert outcome is Outcome.BENIGN_PASS, (
        f"{name}: expected benign_pass, got {outcome.value} "
        f"(response={canary.response!r}, raised={canary.raised!r})"
    )


@pytest.mark.parametrize("name", _NAMES)
def test_adapter_declares_a_forbidden_effect(name: str) -> None:
    fe = get_adapter(name).intent()
    assert fe.sink, f"{name}: ForbiddenEffect.sink is empty"


def test_seed_counts_follow_the_plan() -> None:
    # High-surface value/RCE/SSRF/path/spawn guards get 10; low-surface 5.
    assert seed_count("ssrf_egress_guard") == 10
    assert seed_count("eval_rce_guard") == 10
    assert seed_count("deserialization_guard") == 10
    assert seed_count("filesystem") == 10
    assert seed_count("oauth_state_entropy_guard") == 5
    assert seed_count("sampling_guard") == 5
