"""A lockfile hash must be the same in every process, or the lockfile is decorative.

Through v0.8.85 ``airlock pack lock --verify`` failed on **all three packs that ship in
the box**, verified 2026-09-04. Two distinct causes, both here as regressions:

1. ``_canonicalise`` fell through to ``repr(value)`` for any type it did not know, and a
   function's ``repr`` embeds its memory address. ``archived_mcp_server_advisory_defaults``
   puts a closure under ``check``, so its SHA-256 differed in every process — the lockfile
   verified green in the run that wrote it and red in every run afterwards.
2. The CLI coerced every composed preset with ``dict(data)``. ``stdio_guard_ox_defaults``
   yields a ``StdioGuardConfig`` dataclass, so ``airlock pack lock`` crashed outright on
   ``claude-code-ci``.

The second is the louder bug and the first is the more dangerous one: a control that
reports drift on an unchanged bundle gets switched off, and a control that reports no
drift on a changed one was never a control.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from agent_airlock.pack.lock import (
    LockfileDriftError,
    UnstableHashError,
    build_lock,
    hash_preset,
    verify_lock,
)

PACKS = Path(__file__).resolve().parents[2] / "src" / "agent_airlock" / "packs"


def _preset_with_closure(block: set[str]) -> dict[str, object]:
    """A preset shaped like the real guard factories: config plus a closure over it."""
    allow_set: frozenset[str] = frozenset()

    def check(name: str) -> bool:
        return name in block or name in allow_set

    return {"block_list": sorted(block), "check": check}


class TestCallableHashIsProcessStable:
    """The bug that made every shipped pack fail its own verification."""

    def test_two_closures_from_the_same_factory_hash_alike(self) -> None:
        """Same configuration, different function object — not drift."""
        assert hash_preset(_preset_with_closure({"rm"})) == hash_preset(
            _preset_with_closure({"rm"})
        )

    def test_the_digest_does_not_contain_an_address(self) -> None:
        """The direct witness: before the fix the canonical form carried ``at 0x...``."""
        import json

        from agent_airlock.pack.lock import _canonicalise

        blob = json.dumps(_canonicalise(_preset_with_closure({"rm"})), sort_keys=True)
        assert " at 0x" not in blob, blob

    def test_it_is_stable_across_real_processes(self) -> None:
        """The in-process test would pass on address reuse; this one cannot."""
        code = (
            "from agent_airlock.pack.lock import hash_preset\n"
            "def f():\n"
            "    cfg = {'a': 1}\n"
            "    def check(x):\n"
            "        return x in cfg\n"
            "    return {'cfg': cfg, 'check': check}\n"
            "print(hash_preset(f()))\n"
        )
        runs = {
            subprocess.run(
                [sys.executable, "-c", code], capture_output=True, text=True, check=True
            ).stdout.strip()
            for _ in range(3)
        }
        assert len(runs) == 1, f"hash differed across processes: {runs}"


class TestDriftIsStillDetected:
    """Making the hash stable must not make it blind — that trade is the real risk."""

    def test_different_captured_config_is_drift(self) -> None:
        """Hashing a callable by name alone would collide here. That is a false negative."""
        lock = build_lock({"p": _preset_with_closure({"rm"})}, airlock_version="0.8.86")
        with pytest.raises(LockfileDriftError):
            verify_lock(lock, {"p": _preset_with_closure({"rm", "curl"})})

    def test_unchanged_config_is_not_drift(self) -> None:
        lock = build_lock({"p": _preset_with_closure({"rm"})}, airlock_version="0.8.86")
        verify_lock(lock, {"p": _preset_with_closure({"rm"})})

    def test_a_plain_value_change_is_still_drift(self) -> None:
        lock = build_lock({"p": {"block": ["rm"]}}, airlock_version="0.8.86")
        with pytest.raises(LockfileDriftError):
            verify_lock(lock, {"p": {"block": ["rm", "curl"]}})


class TestUnhashableValuesFailLoudly:
    """Refusing beats a digest that can never verify."""

    def test_an_address_bearing_repr_is_refused(self) -> None:
        class Opaque:
            pass

        with pytest.raises(UnstableHashError, match="memory address"):
            hash_preset({"x": Opaque()})

    def test_the_error_names_the_preset(self) -> None:
        class Opaque:
            pass

        with pytest.raises(UnstableHashError, match="my_preset"):
            hash_preset({"x": Opaque()}, preset_id="my_preset")

    def test_a_reference_cycle_is_refused_not_hung(self) -> None:
        cyclic: dict[str, object] = {}
        cyclic["self"] = cyclic
        with pytest.raises(UnstableHashError):
            hash_preset(cyclic)

    def test_a_stable_repr_still_hashes(self) -> None:
        """Only address-bearing reprs are refused; a custom __repr__ is fine."""

        class Stable:
            def __repr__(self) -> str:
                return "Stable()"

        assert hash_preset({"x": Stable()}) == hash_preset({"x": Stable()})


class TestEveryShippedPackRoundTrips:
    """The end-to-end claim: generate then verify, on the packs users actually get."""

    @pytest.mark.parametrize("pack", ["claude-code-ci", "copilot-agent-ci", "gemini-cli-ci"])
    def test_lock_then_verify_passes(self, pack: str, tmp_path: Path) -> None:
        from agent_airlock.pack import PackInstaller, load_manifest

        installed = PackInstaller().install(load_manifest(PACKS / pack / "manifest.yaml"))
        data = dict(installed.composed)
        lock = build_lock(data, airlock_version="0.8.86")
        assert lock.entries, f"{pack} produced an empty lockfile"
        # A second install is a fresh set of closure objects, as a later process would see.
        reinstalled = PackInstaller().install(load_manifest(PACKS / pack / "manifest.yaml"))
        verify_lock(lock, dict(reinstalled.composed))

    def test_a_dataclass_preset_does_not_crash_the_hash(self) -> None:
        """``stdio_guard_ox_defaults`` yields StdioGuardConfig; ``dict()`` used to raise."""
        from agent_airlock.pack import PackInstaller, load_manifest

        installed = PackInstaller().install(
            load_manifest(PACKS / "claude-code-ci" / "manifest.yaml")
        )
        non_mappings = [p for p, v in installed.composed.items() if not isinstance(v, dict)]
        assert non_mappings, "fixture drifted: expected at least one dataclass preset"
        for preset_id in non_mappings:
            assert hash_preset(installed.composed[preset_id], preset_id=preset_id)
