"""Tests for the v0.5.7 manifest-only STDIO execution mode.

Primary sources (cited per v0.5.1+ convention):
- OX Security 2026-04-15 deep dive
- Cloudflare enterprise MCP reference architecture (2026-04-22):
  https://blog.cloudflare.com/enterprise-mcp/
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agent_airlock import (
    ManifestNotRegisteredError,
    ManifestRegistry,
    ManifestRuntimeOverrideAttempted,
    ManifestSignatureError,
    ManifestSigningKeyError,
    SecurityPolicy,
    StdioManifest,
    launch_from_manifest,
)
from agent_airlock.exceptions import AirlockError
from agent_airlock.mcp_spec.manifest_only_mode import (
    _hmac_sign,
    _load_signing_key,
)

# Test signing key — exactly 32 chars, never used in production.
TEST_KEY = b"test-fixture-key-0123456789abcdef"


def _make_manifest(manifest_id: str = "local-fs") -> StdioManifest:
    return StdioManifest(
        manifest_id=manifest_id,
        command=("uvx", "mcp-server-everything"),
        env_allowlist=frozenset({"PATH", "HOME"}),
        cwd=None,
        signer="sre-team",
    )


class TestRoundTrip:
    """register + resolve must yield the same manifest with a stable signature."""

    def test_register_then_resolve(self) -> None:
        registry = ManifestRegistry()
        signed = registry.register(_make_manifest(), TEST_KEY)
        assert signed.sha256, "registry must populate sha256"
        resolved = registry.resolve("local-fs", TEST_KEY)
        assert resolved.command == ("uvx", "mcp-server-everything")
        assert resolved.signer == "sre-team"

    def test_unregistered_id_raises(self) -> None:
        registry = ManifestRegistry()
        with pytest.raises(ManifestNotRegisteredError):
            registry.resolve("nope", TEST_KEY)


class TestSignature:
    """Tampering with the registry table must be detected at resolve time."""

    def test_tampered_signature_raises(self) -> None:
        registry = ManifestRegistry()
        registry.register(_make_manifest(), TEST_KEY)
        # Reach into the private store and corrupt the signature.
        manifest, _ = registry._entries["local-fs"]
        registry._entries["local-fs"] = (manifest, "00" * 32)
        with pytest.raises(ManifestSignatureError):
            registry.resolve("local-fs", TEST_KEY)

    def test_resolve_with_wrong_key_raises(self) -> None:
        registry = ManifestRegistry()
        registry.register(_make_manifest(), TEST_KEY)
        wrong_key = b"another-test-key-0123456789abcdef"
        with pytest.raises(ManifestSignatureError):
            registry.resolve("local-fs", wrong_key)


class TestRuntimeOverrideRejection:
    """Runtime callers cannot pass argv / cwd / command — that's the whole point."""

    def test_extra_kwarg_rejected(self) -> None:
        registry = ManifestRegistry()
        registry.register(_make_manifest(), TEST_KEY)
        popen_factory = MagicMock()
        with pytest.raises(ManifestRuntimeOverrideAttempted):
            launch_from_manifest(
                "local-fs",
                registry,
                signing_key=TEST_KEY,
                _popen_factory=popen_factory,
                command=["evil"],  # type: ignore[arg-type]
            )
        popen_factory.assert_not_called()

    def test_cwd_outside_allowed_prefix_rejected(self) -> None:
        registry = ManifestRegistry()
        manifest = StdioManifest(
            manifest_id="needs-cwd",
            command=("uvx", "x"),
            env_allowlist=frozenset(),
            cwd="/etc/secrets",
            signer="sre",
        )
        registry.register(manifest, TEST_KEY)
        with pytest.raises(ManifestRuntimeOverrideAttempted, match="not under"):
            launch_from_manifest(
                "needs-cwd",
                registry,
                signing_key=TEST_KEY,
                allowed_cwd_prefixes=("/var/repos/",),
                _popen_factory=MagicMock(),
            )

    def test_relative_cwd_rejected(self) -> None:
        registry = ManifestRegistry()
        manifest = StdioManifest(
            manifest_id="rel-cwd",
            command=("uvx", "x"),
            env_allowlist=frozenset(),
            cwd="./relative/bad",
            signer="sre",
        )
        registry.register(manifest, TEST_KEY)
        with pytest.raises(ManifestRuntimeOverrideAttempted, match="not absolute"):
            launch_from_manifest(
                "rel-cwd",
                registry,
                signing_key=TEST_KEY,
                _popen_factory=MagicMock(),
            )


class TestEnvAllowlist:
    """Only env vars in the manifest's allowlist are forwarded."""

    def test_env_outside_allowlist_dropped(self) -> None:
        registry = ManifestRegistry()
        registry.register(_make_manifest(), TEST_KEY)
        popen_factory = MagicMock()
        launch_from_manifest(
            "local-fs",
            registry,
            runtime_env={
                "PATH": "/usr/bin",
                "SECRET": "leak",  # not in manifest's allowlist
                "HOME": "/home/user",
            },
            signing_key=TEST_KEY,
            _popen_factory=popen_factory,
        )
        kwargs = popen_factory.call_args.kwargs
        env = kwargs["env"]
        assert env == {"PATH": "/usr/bin", "HOME": "/home/user"}
        assert "SECRET" not in env


class TestRegistryIsolation:
    """Two registries are independent — no cross-tenant leak."""

    def test_two_registries_isolated(self) -> None:
        a = ManifestRegistry()
        b = ManifestRegistry()
        a.register(_make_manifest("only-in-a"), TEST_KEY)
        with pytest.raises(ManifestNotRegisteredError):
            b.resolve("only-in-a", TEST_KEY)


class TestSigningKeyLength:
    """Short keys are rejected at register time."""

    def test_short_register_key_raises(self) -> None:
        registry = ManifestRegistry()
        short = b"too-short"
        with pytest.raises(ManifestSigningKeyError):
            registry.register(_make_manifest(), short)

    def test_short_env_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AIRLOCK_MANIFEST_SIGNING_KEY", "short")
        with pytest.raises(ManifestSigningKeyError):
            _load_signing_key()

    def test_env_key_loads_when_long_enough(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AIRLOCK_MANIFEST_SIGNING_KEY", "x" * 32)
        loaded = _load_signing_key()
        assert loaded == b"x" * 32


class TestPolicyStdioMode:
    """SecurityPolicy gains a new ``stdio_mode`` field; default keeps v0.5.1
    behaviour."""

    def test_default_is_allowlist(self) -> None:
        p = SecurityPolicy()
        assert p.stdio_mode == "allowlist"

    def test_manifest_only_mode_settable(self) -> None:
        p = SecurityPolicy(stdio_mode="manifest_only")
        assert p.stdio_mode == "manifest_only"


class TestLaunchHappyPath:
    """A clean launch returns whatever Popen returned, with the manifest's argv."""

    def test_launch_passes_manifest_command(self) -> None:
        registry = ManifestRegistry()
        registry.register(_make_manifest(), TEST_KEY)
        popen_factory = MagicMock()
        popen_factory.return_value = "popen-handle"
        result = launch_from_manifest(
            "local-fs",
            registry,
            runtime_env={"PATH": "/usr/bin"},
            signing_key=TEST_KEY,
            _popen_factory=popen_factory,
        )
        assert result == "popen-handle"
        args = popen_factory.call_args.args
        assert args[0] == ["uvx", "mcp-server-everything"]


class TestErrorHierarchy:
    @pytest.mark.parametrize(
        "err",
        [
            ManifestNotRegisteredError,
            ManifestSignatureError,
            ManifestRuntimeOverrideAttempted,
            ManifestSigningKeyError,
        ],
    )
    def test_subclasses_airlock_error(self, err: type[Exception]) -> None:
        assert issubclass(err, AirlockError)


class TestSignatureDeterminism:
    """The HMAC signature is deterministic for a given (manifest, key) pair."""

    def test_two_signs_match(self) -> None:
        manifest = _make_manifest()
        sig_a = _hmac_sign(TEST_KEY, manifest)
        sig_b = _hmac_sign(TEST_KEY, manifest)
        assert sig_a == sig_b
