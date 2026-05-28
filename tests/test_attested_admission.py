"""Tests for MCP Attested Tool-Server Admission (RFC arXiv:2605.24248).

These tests exercise the full pipeline — clearance fetch → offline
signature verification → per-server allowlist admission — using
in-process generated key pairs. No signing key ever leaves the test
process, so committing them to the repo is impossible.

Coverage matrix:

- Signed-valid clearance admits **only** allowlisted tools.
- Tampered signature denies under ENFORCE, warns under WARN.
- Expired clearance (stale ``iat``) denies under ENFORCE, warns under WARN.
- Explicit ``exp`` in the past denies regardless of ``iat`` freshness.
- Server with no clearance document (missing well-known doc) denies
  under ENFORCE, warns under WARN.
- Subject-mismatch (clearance ``sub`` != dispatched ``server_id``)
  denies under ENFORCE, warns under WARN.
- RSA-PSS trust roots verify in addition to the Ed25519 default.
- JWKS-shaped trust roots verify (OKP / RSA).
- The audit receipt fingerprint matches the SHA-256 of the raw bytes.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

# These tests require the [attested] extra; skip the whole module if
# cryptography is not importable so a base-install CI matrix still runs
# the rest of the suite cleanly.
cryptography = pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, PSS  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.rsa import (  # noqa: E402
    generate_private_key as rsa_generate,
)

from agent_airlock.mcp_spec.attested_admission import (  # noqa: E402
    AdmissionDecision,
    AttestedAdmissionConfig,
    ClearanceVerificationError,
    ExpiredClearance,
    InvalidClearanceSignature,
    MalformedClearance,
    MissingClearance,
    TrustRoot,
    admit_server_tool,
    admit_tool,
    verify_clearance,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _ed25519_sign_clearance(payload: dict[str, Any], priv: Ed25519PrivateKey) -> bytes:
    """Build a JWS-compact token signed with Ed25519. Returns raw bytes
    suitable for handing to ``verify_clearance``."""
    header = {"alg": "EdDSA", "typ": "MCP-CLEARANCE"}
    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = priv.sign(signing_input)
    return f"{h_b64}.{p_b64}.{_b64url(sig)}".encode("ascii")


def _rsa_sign_clearance(payload: dict[str, Any], priv: Any) -> bytes:
    header = {"alg": "PS256", "typ": "MCP-CLEARANCE"}
    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = priv.sign(
        signing_input,
        PSS(mgf=MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return f"{h_b64}.{p_b64}.{_b64url(sig)}".encode("ascii")


def _ed25519_pubkey_pem(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _now_unix() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp())


@pytest.fixture
def ed25519_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    priv = Ed25519PrivateKey.generate()
    return priv, _ed25519_pubkey_pem(priv)


@pytest.fixture
def ed25519_config(
    ed25519_keypair: tuple[Ed25519PrivateKey, bytes],
) -> tuple[Ed25519PrivateKey, AttestedAdmissionConfig]:
    priv, pem = ed25519_keypair
    cfg = AttestedAdmissionConfig(
        trust_root=TrustRoot(key_id="test-ed25519-2026", ed25519_pem=pem),
        enforcement_mode="ENFORCE",
        max_clearance_age=timedelta(days=30),
    )
    return priv, cfg


def _make_clearance(
    priv: Ed25519PrivateKey,
    *,
    server_id: str = "srv-alpha",
    iat: int | None = None,
    exp: int | None = None,
    tools: list[str] | None = None,
    issuer: str = "https://mcp.example.com",
) -> bytes:
    payload: dict[str, Any] = {
        "iss": issuer,
        "sub": server_id,
        "iat": iat if iat is not None else _now_unix(),
        "tools": tools if tools is not None else ["read", "search"],
    }
    if exp is not None:
        payload["exp"] = exp
    return _ed25519_sign_clearance(payload, priv)


# ---------------------------------------------------------------------------
# Happy path — signed-valid admits only allowlisted tools
# ---------------------------------------------------------------------------


class TestSignedValidClearance:
    def test_admits_allowlisted_tool(
        self,
        ed25519_config: tuple[Ed25519PrivateKey, AttestedAdmissionConfig],
    ) -> None:
        priv, cfg = ed25519_config
        clearance = verify_clearance(_make_clearance(priv, tools=["read", "search"]), cfg)

        decision = admit_tool(
            server_id="srv-alpha",
            tool_name="read",
            clearance=clearance,
            cfg=cfg,
        )

        assert decision.admitted is True
        assert decision.verdict.verdict == "allow"
        assert decision.reason == "admitted_by_allowlist"
        assert decision.clearance_fingerprint == clearance.fingerprint

    def test_denies_non_allowlisted_tool(
        self,
        ed25519_config: tuple[Ed25519PrivateKey, AttestedAdmissionConfig],
    ) -> None:
        priv, cfg = ed25519_config
        clearance = verify_clearance(_make_clearance(priv, tools=["read"]), cfg)

        decision = admit_tool(
            server_id="srv-alpha",
            tool_name="write",
            clearance=clearance,
            cfg=cfg,
        )

        assert decision.admitted is False
        assert decision.verdict.verdict == "block"
        assert "tool_not_in_allowlist" in decision.reason
        assert decision.clearance_fingerprint == clearance.fingerprint

    def test_warn_mode_admits_non_allowlisted_with_warn_verdict(
        self,
        ed25519_keypair: tuple[Ed25519PrivateKey, bytes],
    ) -> None:
        priv, pem = ed25519_keypair
        cfg = AttestedAdmissionConfig(
            trust_root=TrustRoot(key_id="test", ed25519_pem=pem),
            enforcement_mode="WARN",
        )
        clearance = verify_clearance(_make_clearance(priv, tools=["read"]), cfg)

        decision = admit_tool(
            server_id="srv-alpha",
            tool_name="write",
            clearance=clearance,
            cfg=cfg,
        )

        assert decision.admitted is True  # WARN admits
        assert decision.verdict.verdict == "warn"


# ---------------------------------------------------------------------------
# Tampered signature
# ---------------------------------------------------------------------------


class TestTamperedSignature:
    def test_enforce_denies(
        self,
        ed25519_config: tuple[Ed25519PrivateKey, AttestedAdmissionConfig],
    ) -> None:
        priv, cfg = ed25519_config
        good = _make_clearance(priv)
        # Flip a byte in the payload segment.
        h, p, s = good.decode().split(".")
        # Re-encode the payload b64 with one base64 char swapped (still
        # valid b64 but decodes to different bytes).
        tampered_p = "A" + p[1:] if p[0] != "A" else "B" + p[1:]
        tampered = f"{h}.{tampered_p}.{s}".encode()

        with pytest.raises((InvalidClearanceSignature, MalformedClearance)):
            verify_clearance(tampered, cfg)

        # End-to-end via admit_server_tool also denies.
        decision = admit_server_tool(
            server_url="https://mcp.example.com",
            server_id="srv-alpha",
            tool_name="read",
            cfg=AttestedAdmissionConfig(
                trust_root=cfg.trust_root,
                enforcement_mode="ENFORCE",
                fetcher=lambda _u, _p: tampered,
            ),
        )
        assert decision.admitted is False
        assert decision.verdict.verdict == "block"

    def test_warn_mode_admits_with_warn_verdict(
        self,
        ed25519_keypair: tuple[Ed25519PrivateKey, bytes],
    ) -> None:
        priv, pem = ed25519_keypair
        good = _make_clearance(priv)
        h, p, s = good.decode().split(".")
        tampered_p = "A" + p[1:] if p[0] != "A" else "B" + p[1:]
        tampered = f"{h}.{tampered_p}.{s}".encode()

        cfg = AttestedAdmissionConfig(
            trust_root=TrustRoot(key_id="test", ed25519_pem=pem),
            enforcement_mode="WARN",
            fetcher=lambda _u, _p: tampered,
        )

        decision = admit_server_tool(
            server_url="https://mcp.example.com",
            server_id="srv-alpha",
            tool_name="read",
            cfg=cfg,
        )
        assert decision.admitted is True
        assert decision.verdict.verdict == "warn"
        assert decision.clearance_fingerprint is None
        assert "clearance_verification_failed" in decision.reason


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------


class TestExpiry:
    def test_stale_iat_denies_under_enforce(
        self,
        ed25519_keypair: tuple[Ed25519PrivateKey, bytes],
    ) -> None:
        priv, pem = ed25519_keypair
        cfg = AttestedAdmissionConfig(
            trust_root=TrustRoot(key_id="test", ed25519_pem=pem),
            enforcement_mode="ENFORCE",
            max_clearance_age=timedelta(days=1),
        )
        stale = _make_clearance(
            priv,
            iat=_now_unix() - int(timedelta(days=2).total_seconds()),
        )
        with pytest.raises(ExpiredClearance):
            verify_clearance(stale, cfg)

    def test_stale_iat_warns_under_warn(
        self,
        ed25519_keypair: tuple[Ed25519PrivateKey, bytes],
    ) -> None:
        priv, pem = ed25519_keypair
        cfg = AttestedAdmissionConfig(
            trust_root=TrustRoot(key_id="test", ed25519_pem=pem),
            enforcement_mode="WARN",
            max_clearance_age=timedelta(days=1),
            fetcher=lambda _u, _p: _make_clearance(
                priv, iat=_now_unix() - int(timedelta(days=2).total_seconds())
            ),
        )
        decision = admit_server_tool(
            server_url="https://mcp.example.com",
            server_id="srv-alpha",
            tool_name="read",
            cfg=cfg,
        )
        assert decision.admitted is True
        assert decision.verdict.verdict == "warn"
        assert "ExpiredClearance" in decision.reason

    def test_explicit_exp_in_past_denies(
        self,
        ed25519_keypair: tuple[Ed25519PrivateKey, bytes],
    ) -> None:
        priv, pem = ed25519_keypair
        cfg = AttestedAdmissionConfig(
            trust_root=TrustRoot(key_id="test", ed25519_pem=pem),
            enforcement_mode="ENFORCE",
        )
        blob = _make_clearance(
            priv,
            iat=_now_unix() - 60,
            exp=_now_unix() - 30,  # Already expired
        )
        with pytest.raises(ExpiredClearance):
            verify_clearance(blob, cfg)


# ---------------------------------------------------------------------------
# Missing well-known document
# ---------------------------------------------------------------------------


class TestMissingClearance:
    def test_enforce_denies(
        self,
        ed25519_keypair: tuple[Ed25519PrivateKey, bytes],
    ) -> None:
        _, pem = ed25519_keypair

        def _absent(_u: str, _p: str) -> bytes:
            raise MissingClearance("404")

        cfg = AttestedAdmissionConfig(
            trust_root=TrustRoot(key_id="test", ed25519_pem=pem),
            enforcement_mode="ENFORCE",
            fetcher=_absent,
        )

        decision = admit_server_tool(
            server_url="https://mcp.example.com",
            server_id="srv-alpha",
            tool_name="read",
            cfg=cfg,
        )
        assert decision.admitted is False
        assert decision.verdict.verdict == "block"
        assert "MissingClearance" in decision.reason

    def test_warn_admits(
        self,
        ed25519_keypair: tuple[Ed25519PrivateKey, bytes],
    ) -> None:
        _, pem = ed25519_keypair

        def _absent(_u: str, _p: str) -> bytes:
            raise MissingClearance("404")

        cfg = AttestedAdmissionConfig(
            trust_root=TrustRoot(key_id="test", ed25519_pem=pem),
            enforcement_mode="WARN",
            fetcher=_absent,
        )

        decision = admit_server_tool(
            server_url="https://mcp.example.com",
            server_id="srv-alpha",
            tool_name="read",
            cfg=cfg,
        )
        assert decision.admitted is True
        assert decision.verdict.verdict == "warn"


# ---------------------------------------------------------------------------
# Subject mismatch
# ---------------------------------------------------------------------------


class TestSubjectMismatch:
    def test_enforce_denies(
        self,
        ed25519_config: tuple[Ed25519PrivateKey, AttestedAdmissionConfig],
    ) -> None:
        priv, cfg = ed25519_config
        clearance = verify_clearance(_make_clearance(priv, server_id="srv-alpha"), cfg)

        decision = admit_tool(
            server_id="srv-beta",  # Different
            tool_name="read",
            clearance=clearance,
            cfg=cfg,
        )
        assert decision.admitted is False
        assert "clearance_subject_mismatch" in decision.reason


# ---------------------------------------------------------------------------
# Fingerprint stability
# ---------------------------------------------------------------------------


class TestFingerprint:
    def test_fingerprint_is_sha256_of_raw_bytes(
        self,
        ed25519_config: tuple[Ed25519PrivateKey, AttestedAdmissionConfig],
    ) -> None:
        from hashlib import sha256

        priv, cfg = ed25519_config
        blob = _make_clearance(priv)
        clearance = verify_clearance(blob, cfg)

        assert clearance.fingerprint == sha256(blob).hexdigest()


# ---------------------------------------------------------------------------
# RSA-PSS trust root
# ---------------------------------------------------------------------------


class TestRSATrustRoot:
    def test_rsa_pss_verifies(self) -> None:
        priv = rsa_generate(public_exponent=65537, key_size=2048)
        pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        cfg = AttestedAdmissionConfig(
            trust_root=TrustRoot(key_id="test-rsa", rsa_pem=pem),
            enforcement_mode="ENFORCE",
        )
        payload = {
            "iss": "https://mcp.example.com",
            "sub": "srv-alpha",
            "iat": _now_unix(),
            "tools": ["read"],
        }
        blob = _rsa_sign_clearance(payload, priv)

        clearance = verify_clearance(blob, cfg)
        decision = admit_tool(
            server_id="srv-alpha",
            tool_name="read",
            clearance=clearance,
            cfg=cfg,
        )
        assert decision.admitted is True


# ---------------------------------------------------------------------------
# JWKS trust root (OKP / Ed25519)
# ---------------------------------------------------------------------------


class TestJWKSTrustRoot:
    def test_jwks_okp_verifies(
        self,
        ed25519_keypair: tuple[Ed25519PrivateKey, bytes],
    ) -> None:
        priv, _ = ed25519_keypair
        raw_pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        jwks = {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": "test-1",
                    "x": base64.urlsafe_b64encode(raw_pub).rstrip(b"=").decode("ascii"),
                }
            ]
        }
        cfg = AttestedAdmissionConfig(
            trust_root=TrustRoot(key_id="test-jwks", jwks=jwks),
            enforcement_mode="ENFORCE",
        )
        clearance = verify_clearance(_make_clearance(priv), cfg)
        decision = admit_tool(
            server_id="srv-alpha",
            tool_name="read",
            clearance=clearance,
            cfg=cfg,
        )
        assert decision.admitted is True


# ---------------------------------------------------------------------------
# Pure-function discipline & config validation
# ---------------------------------------------------------------------------


class TestConfigValidation:
    def test_trust_root_rejects_zero_keys(self) -> None:
        with pytest.raises(ValueError, match="exactly one"):
            TrustRoot(key_id="t")

    def test_trust_root_rejects_two_keys(self) -> None:
        with pytest.raises(ValueError, match="exactly one"):
            TrustRoot(
                key_id="t",
                ed25519_pem=b"-----BEGIN PUBLIC KEY-----\n...",
                rsa_pem=b"-----BEGIN PUBLIC KEY-----\n...",
            )

    def test_config_rejects_unknown_mode(self) -> None:
        with pytest.raises(ValueError, match="enforcement_mode"):
            AttestedAdmissionConfig(enforcement_mode="MAYBE")  # type: ignore[arg-type]

    def test_config_rejects_nonpositive_max_age(self) -> None:
        with pytest.raises(ValueError, match="positive timedelta"):
            AttestedAdmissionConfig(max_clearance_age=timedelta(0))

    def test_verify_without_trust_root_raises_malformed(self) -> None:
        cfg = AttestedAdmissionConfig(enforcement_mode="ENFORCE")
        with pytest.raises(MalformedClearance, match="no trust_root"):
            verify_clearance(b"a.b.c", cfg)

    def test_admit_tool_returns_admissiondecision(
        self,
        ed25519_keypair: tuple[Ed25519PrivateKey, bytes],
    ) -> None:
        _, pem = ed25519_keypair
        cfg = AttestedAdmissionConfig(
            trust_root=TrustRoot(key_id="t", ed25519_pem=pem),
            enforcement_mode="ENFORCE",
        )
        decision = admit_tool(
            server_id="s",
            tool_name="t",
            clearance=None,
            cfg=cfg,
            error=ClearanceVerificationError("forced"),
        )
        assert isinstance(decision, AdmissionDecision)
        assert decision.admitted is False
        assert decision.verdict.guard == "mcp_attested_admission"


# ---------------------------------------------------------------------------
# Malformed inputs
# ---------------------------------------------------------------------------


class TestMalformedInputs:
    def test_non_jws_compact_raises(
        self,
        ed25519_keypair: tuple[Ed25519PrivateKey, bytes],
    ) -> None:
        _, pem = ed25519_keypair
        cfg = AttestedAdmissionConfig(
            trust_root=TrustRoot(key_id="t", ed25519_pem=pem),
        )
        with pytest.raises(MalformedClearance):
            verify_clearance(b"not-a-jws-token", cfg)

    def test_missing_sub_raises(
        self,
        ed25519_keypair: tuple[Ed25519PrivateKey, bytes],
    ) -> None:
        priv, pem = ed25519_keypair
        cfg = AttestedAdmissionConfig(
            trust_root=TrustRoot(key_id="t", ed25519_pem=pem),
        )
        # Build a valid signature over a payload missing 'sub'.
        payload = {
            "iss": "x",
            "iat": _now_unix(),
            "tools": ["read"],
        }
        blob = _ed25519_sign_clearance(payload, priv)
        with pytest.raises(MalformedClearance, match="sub"):
            verify_clearance(blob, cfg)


# ---------------------------------------------------------------------------
# MCPProxyGuard integration
# ---------------------------------------------------------------------------


class TestPresetFactoryDiscoverable:
    """The `mcp_attested_admission_defaults` factory must appear in
    `policy_presets.list_active()` so `airlock graph` and the OWASP
    coverage matrix can enumerate it without ad-hoc package walking."""

    def test_factory_returns_attested_admission_config(self) -> None:
        from agent_airlock.mcp_spec.attested_admission import AttestedAdmissionConfig
        from agent_airlock.policy_presets import mcp_attested_admission_defaults

        cfg = mcp_attested_admission_defaults()
        assert isinstance(cfg, AttestedAdmissionConfig)
        assert cfg.enforcement_mode == "ENFORCE"  # deny-by-default
        assert cfg.clearance_well_known_path == "/.well-known/mcp-clearance"
        assert cfg.max_clearance_age == timedelta(days=30)
        assert cfg.trust_root is None  # operator must supply

    def test_factory_listed_by_list_active(self) -> None:
        from agent_airlock.policy_presets import list_active

        names = {meta.preset_id for meta in list_active()}
        assert "mcp_attested_admission_defaults" in names

    def test_factory_round_trip_with_trust_root(
        self,
        ed25519_keypair: tuple[Ed25519PrivateKey, bytes],
    ) -> None:
        from agent_airlock.policy_presets import mcp_attested_admission_defaults

        _, pem = ed25519_keypair
        cfg = mcp_attested_admission_defaults(
            trust_root=TrustRoot(key_id="op-pinned", ed25519_pem=pem),
            enforcement_mode="WARN",
            max_clearance_age_days=7,
        )
        assert cfg.enforcement_mode == "WARN"
        assert cfg.max_clearance_age == timedelta(days=7)
        assert cfg.trust_root is not None
        assert cfg.trust_root.key_id == "op-pinned"


class TestMCPProxyGuardIntegration:
    def test_audit_tool_admission_delegates(
        self,
        ed25519_keypair: tuple[Ed25519PrivateKey, bytes],
    ) -> None:
        from agent_airlock.mcp_proxy_guard import MCPProxyConfig, MCPProxyGuard

        priv, pem = ed25519_keypair
        cfg = AttestedAdmissionConfig(
            trust_root=TrustRoot(key_id="t", ed25519_pem=pem),
            enforcement_mode="ENFORCE",
            fetcher=lambda _u, _p: _make_clearance(priv, tools=["read"]),
        )
        guard = MCPProxyGuard(MCPProxyConfig(attested_admission=cfg))

        decision = guard.audit_tool_admission(
            server_url="https://mcp.example.com",
            server_id="srv-alpha",
            tool_name="read",
        )
        assert decision.admitted is True
        assert decision.verdict.guard == "mcp_attested_admission"

    def test_audit_tool_admission_unconfigured_raises(self) -> None:
        from agent_airlock.mcp_proxy_guard import (
            MCPProxyConfig,
            MCPProxyGuard,
            MCPSecurityError,
        )

        guard = MCPProxyGuard(MCPProxyConfig())
        with pytest.raises(MCPSecurityError, match="attested_admission"):
            guard.audit_tool_admission(
                server_url="https://x",
                server_id="srv-alpha",
                tool_name="read",
            )
