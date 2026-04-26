"""Benchmark: manifest-only-mode HMAC verify per launch (v0.5.7+).

The OX-disclosure response (Task 2) introduced manifest-only mode, in
which every spawn re-verifies the registered manifest's HMAC signature.
That's a single ``hmac.new(...).hexdigest()`` over a sub-1-KB payload
plus a constant-time compare — but the **claim** that the cost is
negligible has to be locked into CI before v0.5.7's manifest-mode
latency story is verifiable.

Run with::

    pytest tests/benchmarks/test_bench_manifest_mode.py --benchmark-only

The number to watch on `make bench`: the median of
``test_manifest_resolve_p50_under_50us`` should stay below 50 µs on a
2024-class developer laptop. If it crosses 100 µs, the manifest-mode
spawn path is regressing — open issue #4 follow-up.
"""

from __future__ import annotations

from agent_airlock.mcp_spec.manifest_only_mode import (
    ManifestRegistry,
    StdioManifest,
)

# Same fixture key the unit tests use — never used in production.
TEST_KEY = b"test-fixture-key-0123456789abcdef"


def _build_registry_with_n(n: int) -> tuple[ManifestRegistry, list[str]]:
    registry = ManifestRegistry()
    ids: list[str] = []
    for i in range(n):
        manifest = StdioManifest(
            manifest_id=f"manifest-{i}",
            command=("uvx", f"mcp-server-{i}"),
            env_allowlist=frozenset({"PATH", "HOME"}),
            cwd=None,
            signer="bench",
        )
        registry.register(manifest, TEST_KEY)
        ids.append(manifest.manifest_id)
    return registry, ids


def test_manifest_resolve_p50_under_50us(benchmark) -> None:
    """A single resolve+verify on a 100-entry registry must stay under 50 µs (median).

    100 entries is well above realistic deployment counts (typical
    integration registers single-digit manifests). The benchmark is
    therefore a *ceiling* number, not a realistic load.
    """
    registry, ids = _build_registry_with_n(100)
    target = ids[len(ids) // 2]

    def _resolve() -> StdioManifest:
        return registry.resolve(target, TEST_KEY)

    benchmark(_resolve)


def test_manifest_register_p50_under_100us(benchmark) -> None:
    """Registration cost (HMAC sign + sha256 + dict insert) must stay under 100 µs."""
    manifest = StdioManifest(
        manifest_id="bench-register",
        command=("uvx", "mcp-server-everything"),
        env_allowlist=frozenset({"PATH", "HOME"}),
        cwd=None,
        signer="bench",
    )

    def _register_fresh() -> None:
        ManifestRegistry().register(manifest, TEST_KEY)

    benchmark(_register_fresh)
