"""MCP Attested Tool-Server Admission (RFC arXiv:2605.24248).

Implements the three additive mechanisms described in Metere (May 2026):

1. **Offline-signed clearance assertion** — server publishes a JWS-compact
   token at a well-known URI (default ``/.well-known/mcp-clearance``); the
   host verifies the signature against a **pinned trust root** before any
   tool dispatch. The trust root is supplied by the operator and is never
   network-fetched on the hot path.
2. **Deny-by-default per-server tool allowlist** — admitting a server is
   not the same as trusting its every tool. The verified clearance carries
   an explicit list of tool names the host will permit; everything else
   is denied.
3. **Flavor-gated enforcement** — ``WARN`` (log only, admit) vs ``ENFORCE``
   (hard deny on missing / invalid / expired clearance).

Every admission decision is emitted as an
:class:`agent_airlock.attest.ReceiptVerdict` on the
``guard="mcp_attested_admission"`` channel, so the existing
``airlock attest`` DSSE pipeline picks the verdicts up unchanged — this
module does **not** invent a new log.

Failure model: **fail closed.** If ``enforcement_mode == ENFORCE`` and the
clearance is absent, malformed, has an invalid signature, or is stale beyond
``max_clearance_age`` (or has a past ``exp``), the admission is denied.
``WARN`` mode emits the same verdict tagged ``"warn"`` and admits.

This module requires the ``[attested]`` extra
(``pip install agent-airlock[attested]``) for the offline asymmetric
verifier (Ed25519 / RSA-PSS over JWS-compact via ``cryptography``). The
crypto bindings are imported lazily inside :func:`verify_clearance` so the
base install stays zero-runtime-dep.

References
----------
- Metere, A. *Attested Tool-Server Admission: A Security Extension to the
  Model Context Protocol.* arXiv:2605.24248 (2026).
  https://arxiv.org/abs/2605.24248
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any, Literal

import structlog

from ..attest.receipt import ReceiptVerdict, ReceiptVerdictKind
from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.attested_admission")


EnforcementMode = Literal["WARN", "ENFORCE"]
"""Flavor gate from the RFC. ``ENFORCE`` denies on missing/invalid/expired
clearance; ``WARN`` admits with a logged warning."""


DEFAULT_WELL_KNOWN_PATH = "/.well-known/mcp-clearance"
DEFAULT_MAX_AGE = timedelta(days=30)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ClearanceVerificationError(AirlockError):
    """Base for any clearance-verification failure."""


class MissingClearance(ClearanceVerificationError):
    """Server returned no document at the well-known URI."""


class InvalidClearanceSignature(ClearanceVerificationError):
    """The offline signature failed verification against the pinned trust root."""


class ExpiredClearance(ClearanceVerificationError):
    """The clearance ``iat`` is older than ``max_clearance_age``, or
    ``exp`` is in the past."""


class MalformedClearance(ClearanceVerificationError):
    """The clearance document failed schema validation."""


class ToolNotAdmitted(ClearanceVerificationError):
    """The tool name is not in the verified per-server allowlist.

    Reserved for callers that prefer to raise on deny rather than read
    :attr:`AdmissionDecision.admitted` — :func:`admit_tool` itself returns
    a decision and never raises this.
    """


# ---------------------------------------------------------------------------
# Config + result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustRoot:
    """Pinned public-key material used to verify clearance signatures.

    Exactly one of ``ed25519_pem`` / ``rsa_pem`` / ``jwks`` must be set.
    Network resolution of trust roots is **not** supported — the entire
    point of a pinned root is that it cannot be substituted at runtime.

    Attributes:
        key_id: Operator-chosen identifier for this trust root. Recorded
            in audit verdicts so reviewers can correlate a verified
            decision to the key that signed it.
        ed25519_pem: PEM-encoded Ed25519 public key
            (PKCS#8 SubjectPublicKeyInfo).
        rsa_pem: PEM-encoded RSA public key
            (PKCS#8 SubjectPublicKeyInfo).
        jwks: A JWKS-shaped mapping (``{"keys": [...]}``). The first key
            entry is used. Supported ``kty`` values: ``OKP`` (Ed25519) and
            ``RSA``.
    """

    key_id: str
    ed25519_pem: bytes | None = None
    rsa_pem: bytes | None = None
    jwks: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        chosen = sum(1 for x in (self.ed25519_pem, self.rsa_pem, self.jwks) if x is not None)
        if chosen != 1:
            raise ValueError("TrustRoot: exactly one of ed25519_pem, rsa_pem, jwks must be set")


@dataclass(frozen=True)
class AttestedAdmissionConfig:
    """Operator-facing configuration for the attested-admission preset.

    Construct one per host process and pin it for the lifetime of that
    process — rotating trust roots at runtime is a deliberate operation
    that should re-construct this object.

    Attributes:
        trust_root: Pinned public-key material (PEM or JWKS). Required
            for any actual verification call; can be left ``None`` only on
            placeholder configs.
        clearance_well_known_path: URI path the host fetches relative to
            each MCP server's origin. Defaults to
            ``/.well-known/mcp-clearance``.
        enforcement_mode: ``ENFORCE`` (deny on missing/invalid/expired)
            or ``WARN`` (log only, admit).
        max_clearance_age: Clearance is considered fresh iff
            ``now() - iat <= max_clearance_age``.
        fetcher: Optional callable ``(server_url, path) -> bytes`` that
            injects a custom transport — used by tests and air-gapped
            operators who load clearances from disk. Falls back to the
            stdlib HTTPS fetcher when ``None``.
        clock: Optional ``() -> datetime`` for deterministic tests.
            Falls back to ``datetime.now(timezone.utc)``.
    """

    trust_root: TrustRoot | None = None
    clearance_well_known_path: str = DEFAULT_WELL_KNOWN_PATH
    enforcement_mode: EnforcementMode = "ENFORCE"
    max_clearance_age: timedelta = DEFAULT_MAX_AGE
    fetcher: Callable[[str, str], bytes] | None = None
    clock: Callable[[], datetime] | None = None

    def __post_init__(self) -> None:
        if self.enforcement_mode not in ("WARN", "ENFORCE"):
            raise ValueError(
                f"enforcement_mode must be 'WARN' or 'ENFORCE'; got {self.enforcement_mode!r}"
            )
        if self.max_clearance_age <= timedelta(0):
            raise ValueError("max_clearance_age must be a positive timedelta")


@dataclass(frozen=True)
class AdmittedClearance:
    """Output of :func:`verify_clearance` — a parsed + verified clearance.

    Attributes:
        server_id: The ``sub`` claim from the verified payload.
        issuer: The ``iss`` claim.
        iat: Parsed issued-at as a UTC :class:`datetime`.
        exp: Parsed expiry, or ``None`` if the clearance carried no ``exp``.
        allowed_tools: The verified per-server tool allowlist.
        fingerprint: SHA-256 hex of the raw clearance bytes. Recorded in
            every verdict so an auditor can correlate a decision to the
            exact bytes that produced it.
        raw: The full decoded payload, retained for debugging.
    """

    server_id: str
    issuer: str
    iat: datetime
    exp: datetime | None
    allowed_tools: frozenset[str]
    fingerprint: str
    raw: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AdmissionDecision:
    """Result of admitting one tool against a verified clearance."""

    admitted: bool
    server_id: str
    tool_name: str
    reason: str
    clearance_fingerprint: str | None
    verdict: ReceiptVerdict

    def as_log_fields(self) -> dict[str, Any]:
        """Return a flat dict suitable for structlog ``logger.info(**fields)``."""
        return {
            "guard": "mcp_attested_admission",
            "admitted": self.admitted,
            "server_id": self.server_id,
            "tool_name": self.tool_name,
            "reason": self.reason,
            "clearance_fingerprint": self.clearance_fingerprint,
        }


# ---------------------------------------------------------------------------
# Fetcher (stdlib only)
# ---------------------------------------------------------------------------


def _default_fetcher(server_url: str, path: str) -> bytes:
    """Fetch the clearance document from ``{server_url}{path}`` over HTTPS.

    Stdlib-only — uses :mod:`urllib.request`. Operators who need a custom
    transport (mTLS, IPC, on-disk) inject a ``fetcher`` callable on
    :class:`AttestedAdmissionConfig` instead.

    Raises:
        MissingClearance: 404/410 or any connection error.
    """
    url = server_url.rstrip("/") + path
    try:
        # URL is operator-pinned via AttestedAdmissionConfig at config
        # time (operator supplies the MCP server origin + well-known
        # path), not arbitrary user input — the scheme allowlist is the
        # operator's responsibility to configure. Bandit B310 / ruff S310
        # are both false-positives here.
        with urllib.request.urlopen(url, timeout=5.0) as resp:  # noqa: S310  # nosec B310 - operator-pinned URL, not user input
            return resp.read()  # type: ignore[no-any-return]
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 410):
            raise MissingClearance(f"server {server_url} has no clearance document") from exc
        raise MissingClearance(f"clearance fetch failed: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise MissingClearance(f"clearance fetch failed: {exc.reason}") from exc


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _fingerprint(blob: bytes) -> str:
    """SHA-256 hex of the raw clearance bytes."""
    return sha256(blob).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _load_pubkey(trust_root: TrustRoot) -> Any:
    """Lazily import ``cryptography`` and return a verifying-key object.

    Raises:
        RuntimeError: ``cryptography`` is not installed. Operators must
            ``pip install agent-airlock[attested]``.
    """
    try:
        from cryptography.hazmat.primitives.serialization import (
            load_pem_public_key,
        )
    except ImportError as exc:  # pragma: no cover - env-level guard
        raise RuntimeError(
            "agent-airlock[attested] extra not installed; run "
            "`pip install agent-airlock[attested]` to enable MCP "
            "attested-admission signature verification"
        ) from exc

    if trust_root.ed25519_pem is not None:
        return load_pem_public_key(trust_root.ed25519_pem)
    if trust_root.rsa_pem is not None:
        return load_pem_public_key(trust_root.rsa_pem)

    # JWKS path — pick the first key and decode it into a cryptography
    # public-key object.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

    assert trust_root.jwks is not None  # noqa: S101  # nosec B101 - guarded by TrustRoot.__post_init__ (exactly one of three key fields is non-None)
    key_entries = trust_root.jwks.get("keys") or []
    if not key_entries:
        raise ValueError("JWKS trust root has no keys")
    jwk = key_entries[0]
    kty = jwk.get("kty")
    if kty == "OKP":
        return Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))
    if kty == "RSA":
        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        return RSAPublicNumbers(e=e, n=n).public_key()
    raise ValueError(f"unsupported JWKS key type: {kty!r}")


def _verify_signature(public_key: Any, signed_bytes: bytes, signature: bytes) -> None:
    """Verify a JWS-style signature using the loaded public key.

    Ed25519: plain ``public_key.verify(sig, msg)``.
    RSA: PSS with MGF1-SHA256 and ``salt_length=PSS.MAX_LENGTH`` — matches
    the JOSE ``PS256`` profile.

    Raises:
        InvalidClearanceSignature: signature does not validate.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.asymmetric.padding import MGF1, PSS
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    except ImportError as exc:  # pragma: no cover - env-level guard
        raise RuntimeError("agent-airlock[attested] extra not installed") from exc

    try:
        if isinstance(public_key, Ed25519PublicKey):
            public_key.verify(signature, signed_bytes)
        elif isinstance(public_key, RSAPublicKey):
            public_key.verify(
                signature,
                signed_bytes,
                PSS(mgf=MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        else:
            raise ValueError(f"unsupported public key type: {type(public_key).__name__}")
    except InvalidSignature as exc:
        raise InvalidClearanceSignature("clearance signature did not verify") from exc


def verify_clearance(
    blob: bytes,
    cfg: AttestedAdmissionConfig,
) -> AdmittedClearance:
    """Parse + verify a JWS-compact clearance document.

    Expected payload shape (JSON, base64url-encoded as the JWS body)::

        {
          "iss": "https://mcp.example.com",
          "sub": "<server-id>",
          "iat": <unix-ts>,
          "exp": <unix-ts>,          # optional
          "tools": ["read", "search"]
        }

    Args:
        blob: Raw bytes returned by the fetcher. Must be a JWS-compact
            token (``header.payload.signature``, base64url segments).
        cfg: Configuration carrying the pinned trust root + max age.

    Raises:
        MalformedClearance: bad encoding / missing required claims /
            no trust root configured.
        InvalidClearanceSignature: signature did not verify.
        ExpiredClearance: clearance is older than ``max_clearance_age``,
            or ``exp`` is in the past.
    """
    if cfg.trust_root is None:
        raise MalformedClearance(
            "AttestedAdmissionConfig has no trust_root; cannot verify clearance"
        )

    try:
        text = blob.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise MalformedClearance("clearance bytes are not valid UTF-8") from exc
    parts = text.split(".")
    if len(parts) != 3:
        raise MalformedClearance("clearance is not a JWS compact token")
    header_b64, payload_b64, sig_b64 = parts

    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(sig_b64)
    except (ValueError, json.JSONDecodeError) as exc:
        raise MalformedClearance(f"clearance encoding invalid: {exc}") from exc

    if not isinstance(header, dict):
        raise MalformedClearance("clearance header is not a JSON object")
    if not isinstance(payload, dict):
        raise MalformedClearance("clearance payload is not a JSON object")

    public_key = _load_pubkey(cfg.trust_root)
    signed = f"{header_b64}.{payload_b64}".encode("ascii")
    _verify_signature(public_key, signed, signature)

    # Schema checks (post-signature so an attacker can't probe schema by
    # crafting unsigned payloads).
    sub = payload.get("sub")
    iss = payload.get("iss")
    iat = payload.get("iat")
    tools = payload.get("tools")
    if not isinstance(sub, str) or not sub:
        raise MalformedClearance("clearance missing string 'sub'")
    if not isinstance(iss, str) or not iss:
        raise MalformedClearance("clearance missing string 'iss'")
    if not isinstance(iat, (int, float)):
        raise MalformedClearance("clearance missing numeric 'iat'")
    if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
        raise MalformedClearance("clearance 'tools' must be a list of strings")

    now = (cfg.clock or _utcnow)()
    iat_dt = datetime.fromtimestamp(float(iat), tz=timezone.utc)
    if (now - iat_dt) > cfg.max_clearance_age:
        raise ExpiredClearance(
            f"clearance issued at {iat_dt.isoformat()} is older than "
            f"max_clearance_age={cfg.max_clearance_age}"
        )
    exp_val = payload.get("exp")
    exp_dt: datetime | None = None
    if isinstance(exp_val, (int, float)):
        exp_dt = datetime.fromtimestamp(float(exp_val), tz=timezone.utc)
        if exp_dt < now:
            raise ExpiredClearance(f"clearance expired at {exp_dt.isoformat()}")

    return AdmittedClearance(
        server_id=sub,
        issuer=iss,
        iat=iat_dt,
        exp=exp_dt,
        allowed_tools=frozenset(tools),
        fingerprint=_fingerprint(blob),
        raw=payload,
    )


# ---------------------------------------------------------------------------
# Admission
# ---------------------------------------------------------------------------


def _verdict(
    *,
    admitted: bool,
    server_id: str,
    tool_name: str,
    reason: str,
    fingerprint: str | None,
    warn: bool,
) -> ReceiptVerdict:
    """Build the per-decision :class:`ReceiptVerdict`.

    ``warn`` is true only when the config is in WARN mode AND the
    decision would otherwise have been a deny — that's the only case in
    which the verdict kind differs from a plain allow/block.
    """
    kind: ReceiptVerdictKind = "warn" if warn else ("allow" if admitted else "block")
    return ReceiptVerdict(
        guard="mcp_attested_admission",
        verdict=kind,
        tool_name=f"{server_id}:{tool_name}",
        detail=f"reason={reason}; clearance_fp={fingerprint or '<none>'}",
    )


def admit_tool(
    *,
    server_id: str,
    tool_name: str,
    clearance: AdmittedClearance | None,
    cfg: AttestedAdmissionConfig,
    error: ClearanceVerificationError | None = None,
) -> AdmissionDecision:
    """Decide whether ``tool_name`` from ``server_id`` may run.

    Pure function — no I/O, no audit emission. Callers (e.g.
    ``MCPProxyGuard``) are responsible for logging the returned
    :attr:`AdmissionDecision.verdict` through the existing audit / attest
    pipeline.

    Args:
        server_id: The MCP server identity the host is dispatching to.
            Compared to the verified clearance's ``sub`` claim.
        tool_name: The MCP tool being invoked.
        clearance: The result of :func:`verify_clearance`, or ``None`` if
            verification failed.
        cfg: The runtime config (used for ``enforcement_mode``).
        error: If ``clearance`` is ``None``, the verification error that
            explains why; used to build the deny reason. Ignored when
            ``clearance`` is not ``None``.

    Returns:
        :class:`AdmissionDecision` — ``admitted`` is True iff the
        clearance verified and the tool is in the allowlist, OR the
        config is in ``WARN`` mode.
    """
    warn_mode = cfg.enforcement_mode == "WARN"

    if clearance is None:
        reason = (
            f"clearance_verification_failed: {type(error).__name__}: {error}"
            if error is not None
            else "clearance_unavailable"
        )
        admitted = warn_mode  # WARN admits, ENFORCE denies
        return AdmissionDecision(
            admitted=admitted,
            server_id=server_id,
            tool_name=tool_name,
            reason=reason,
            clearance_fingerprint=None,
            verdict=_verdict(
                admitted=admitted,
                server_id=server_id,
                tool_name=tool_name,
                reason=reason,
                fingerprint=None,
                warn=warn_mode,  # the "would-have-denied" case
            ),
        )

    if clearance.server_id != server_id:
        reason = (
            f"clearance_subject_mismatch: clearance sub={clearance.server_id!r} "
            f"!= dispatched server_id={server_id!r}"
        )
        admitted = warn_mode
        return AdmissionDecision(
            admitted=admitted,
            server_id=server_id,
            tool_name=tool_name,
            reason=reason,
            clearance_fingerprint=clearance.fingerprint,
            verdict=_verdict(
                admitted=admitted,
                server_id=server_id,
                tool_name=tool_name,
                reason=reason,
                fingerprint=clearance.fingerprint,
                warn=warn_mode,
            ),
        )

    if tool_name not in clearance.allowed_tools:
        reason = f"tool_not_in_allowlist: {tool_name!r} not in {sorted(clearance.allowed_tools)!r}"
        admitted = warn_mode
        return AdmissionDecision(
            admitted=admitted,
            server_id=server_id,
            tool_name=tool_name,
            reason=reason,
            clearance_fingerprint=clearance.fingerprint,
            verdict=_verdict(
                admitted=admitted,
                server_id=server_id,
                tool_name=tool_name,
                reason=reason,
                fingerprint=clearance.fingerprint,
                warn=warn_mode,
            ),
        )

    # Happy path — admitted by the verified allowlist.
    return AdmissionDecision(
        admitted=True,
        server_id=server_id,
        tool_name=tool_name,
        reason="admitted_by_allowlist",
        clearance_fingerprint=clearance.fingerprint,
        verdict=_verdict(
            admitted=True,
            server_id=server_id,
            tool_name=tool_name,
            reason="admitted_by_allowlist",
            fingerprint=clearance.fingerprint,
            warn=False,
        ),
    )


def admit_server_tool(
    *,
    server_url: str,
    server_id: str,
    tool_name: str,
    cfg: AttestedAdmissionConfig,
) -> AdmissionDecision:
    """High-level orchestrator: fetch → verify → admit.

    Convenience wrapper that runs the full pipeline against a config. On
    any verification error, falls through to :func:`admit_tool` with
    ``clearance=None`` so the WARN/ENFORCE gate still fires.

    Args:
        server_url: Origin to fetch the clearance from (e.g.
            ``"https://mcp.example.com"``).
        server_id: Expected ``sub`` claim — usually a stable server identity.
        tool_name: MCP tool being invoked.
        cfg: Operator-pinned configuration.
    """
    fetcher = cfg.fetcher or _default_fetcher
    err: ClearanceVerificationError | None = None
    clearance: AdmittedClearance | None = None
    try:
        blob = fetcher(server_url, cfg.clearance_well_known_path)
        clearance = verify_clearance(blob, cfg)
    except ClearanceVerificationError as exc:
        err = exc
        logger.warning(
            "attested_admission.verification_failed",
            server_url=server_url,
            server_id=server_id,
            error_type=type(exc).__name__,
            error=str(exc),
            mode=cfg.enforcement_mode,
        )

    decision = admit_tool(
        server_id=server_id,
        tool_name=tool_name,
        clearance=clearance,
        cfg=cfg,
        error=err,
    )
    logger.info(
        "attested_admission.decision",
        mode=cfg.enforcement_mode,
        **decision.as_log_fields(),
    )
    return decision


__all__ = [
    "DEFAULT_MAX_AGE",
    "DEFAULT_WELL_KNOWN_PATH",
    "AdmissionDecision",
    "AdmittedClearance",
    "AttestedAdmissionConfig",
    "ClearanceVerificationError",
    "EnforcementMode",
    "ExpiredClearance",
    "InvalidClearanceSignature",
    "MalformedClearance",
    "MissingClearance",
    "ToolNotAdmitted",
    "TrustRoot",
    "admit_server_tool",
    "admit_tool",
    "verify_clearance",
]
