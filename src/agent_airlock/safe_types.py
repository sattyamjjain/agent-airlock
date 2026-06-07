"""Safe types for Agent-Airlock (V0.4.0).

Provides built-in types that validate paths and URLs at the type level,
preventing directory traversal, secret access, and data exfiltration.

These types integrate with Pydantic validation and can be used directly
in function signatures of Airlock-protected tools.

Usage:
    from agent_airlock import SafePath, SafeURL

    @Airlock()
    def read_config(path: SafePath) -> str:
        return Path(path).read_text()

    @Airlock()
    def fetch_data(url: SafeURL) -> str:
        return requests.get(url).text

The validators reject:
    - Directory traversal (../)
    - Home directory access (~)
    - Secret files (.env, .ssh, *.pem, *.key)
    - System files (/etc/passwd, /etc/shadow)
    - Metadata URLs (AWS/GCP)
    - File URLs (file://)
    - Private/link-local IPs
"""

from __future__ import annotations

import base64
import binascii
import enum
import fnmatch
import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlparse

import structlog
from pydantic import AfterValidator

logger = structlog.get_logger("agent-airlock.safe_types")


# Default deny patterns for paths (can be customized)
DEFAULT_PATH_DENY_PATTERNS = [
    # Home directory
    "~",
    "~/*",
    # Parent traversal
    "..",
    "*/..*",
    "../*",
    "*/../*",
    # Environment and secrets
    ".env",
    "*.env",
    "*/.env",
    ".env.*",
    # SSH keys
    ".ssh",
    ".ssh/*",
    "*/.ssh/*",
    "*.ssh/*",
    # Git directory
    ".git",
    ".git/*",
    "*/.git/*",
    # Certificate and key files
    "*.pem",
    "*.key",
    "*.crt",
    "*.p12",
    "*.pfx",
    # AWS credentials
    ".aws",
    ".aws/*",
    "*/.aws/*",
    "credentials",
    # Docker secrets
    ".docker",
    ".docker/*",
    # System files
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/sudoers",
    "/proc/*",
    "/sys/*",
    # macOS/Windows secrets
    "*.keychain",
    "*.keychain-db",
    "ntds.dit",
    "SAM",
    "SYSTEM",
]


# URLs that should be blocked
BLOCKED_HOSTS = [
    # AWS metadata
    "169.254.169.254",
    "fd00:ec2::254",
    # GCP metadata
    "metadata.google.internal",
    "169.254.169.253",
    # Azure metadata
    "169.254.169.253",
    # Link-local
    "169.254.0.0/16",
]


class SafePathValidationError(ValueError):
    """Raised when a path fails safety validation."""

    def __init__(self, message: str, path: str, pattern: str | None = None) -> None:
        self.path = path
        self.pattern = pattern
        super().__init__(message)


class SafeURLValidationError(ValueError):
    """Raised when a URL fails safety validation."""

    def __init__(self, message: str, url: str, reason: str | None = None) -> None:
        self.url = url
        self.reason = reason
        super().__init__(message)


class SafePathValidator:
    """Validates paths are safe (no traversal, no secrets).

    This validator rejects paths that:
    - Contain parent traversal (..)
    - Access the home directory (~)
    - Match deny patterns (secrets, configs, etc.)
    - Are absolute paths (when not allowed)
    - Escape the root directory (when specified)

    Examples:
        # Basic validation
        validator = SafePathValidator()
        safe_path = validator("/app/data/file.txt")  # OK
        validator("~/.ssh/id_rsa")  # Raises SafePathValidationError

        # With root directory jail
        validator = SafePathValidator(root_dir=Path("/app/data"))
        validator("/app/data/subdir/file.txt")  # OK
        validator("/etc/passwd")  # Raises SafePathValidationError

        # Custom deny patterns
        validator = SafePathValidator(deny_patterns=["*.log", "*.tmp"])
    """

    def __init__(
        self,
        root_dir: Path | None = None,
        deny_patterns: list[str] | None = None,
        allow_absolute: bool = True,
        extra_deny_patterns: list[str] | None = None,
    ) -> None:
        """Initialize the path validator.

        Args:
            root_dir: If specified, paths must resolve within this directory.
            deny_patterns: Patterns to deny. Defaults to DEFAULT_PATH_DENY_PATTERNS.
                          Set to [] to disable default patterns.
            allow_absolute: Whether to allow absolute paths.
            extra_deny_patterns: Additional patterns to deny (appended to defaults).
        """
        self.root_dir = root_dir.resolve() if root_dir else None
        self.deny_patterns = (
            deny_patterns if deny_patterns is not None else DEFAULT_PATH_DENY_PATTERNS.copy()
        )
        if extra_deny_patterns:
            self.deny_patterns.extend(extra_deny_patterns)
        self.allow_absolute = allow_absolute

    def __call__(self, value: str | Path) -> Path:
        """Validate and return safe path.

        Args:
            value: Path to validate.

        Returns:
            Validated Path object.

        Raises:
            SafePathValidationError: If the path is unsafe.
        """
        path_str = str(value)
        path = Path(value)

        # Check for parent traversal in the string (before resolution)
        if ".." in path_str:
            raise SafePathValidationError(
                f"Path contains parent traversal: {path_str}",
                path=path_str,
                pattern="..",
            )

        # Check for home directory
        if path_str.startswith("~"):
            raise SafePathValidationError(
                f"Home directory access not allowed: {path_str}",
                path=path_str,
                pattern="~",
            )

        # Check absolute path
        if not self.allow_absolute and path.is_absolute():
            raise SafePathValidationError(
                f"Absolute paths not allowed: {path_str}",
                path=path_str,
            )

        # Check against deny patterns
        for pattern in self.deny_patterns:
            if self._matches_pattern(path_str, pattern):
                raise SafePathValidationError(
                    f"Path matches denied pattern '{pattern}': {path_str}",
                    path=path_str,
                    pattern=pattern,
                )

        # Check within root if specified
        if self.root_dir is not None:
            try:
                if path.is_absolute():
                    resolved = path.resolve()
                else:
                    resolved = (self.root_dir / path).resolve()

                # Use os.path.commonpath for CVE-resistant traversal check
                import os

                try:
                    common = os.path.commonpath([str(resolved), str(self.root_dir)])
                    if common != str(self.root_dir):
                        raise SafePathValidationError(
                            f"Path escapes root directory {self.root_dir}: {path_str}",
                            path=path_str,
                        )
                except ValueError:
                    # Different drives on Windows
                    raise SafePathValidationError(
                        f"Path escapes root directory {self.root_dir}: {path_str}",
                        path=path_str,
                    ) from None
            except OSError as e:
                raise SafePathValidationError(
                    f"Path resolution failed: {e}",
                    path=path_str,
                ) from e

        return path

    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches a deny pattern."""
        # Normalize path separators
        path_normalized = path.replace("\\", "/")
        pattern_normalized = pattern.replace("\\", "/")

        # Check exact match
        if path_normalized == pattern_normalized:
            return True

        # Check if path ends with the pattern
        if path_normalized.endswith("/" + pattern_normalized):
            return True

        # Check filename match
        filename = Path(path_normalized).name
        if fnmatch.fnmatch(filename, pattern_normalized):
            return True

        # Check full path match with glob
        if fnmatch.fnmatch(path_normalized, pattern_normalized):
            return True

        return False


class SafeURLValidator:
    """Validates URLs are safe (no file://, no metadata, no private IPs).

    This validator rejects URLs that:
    - Use file:// scheme
    - Point to cloud metadata endpoints
    - Point to private/link-local IPs
    - Use non-allowed schemes
    - Point to non-allowed hosts

    Examples:
        # Basic validation
        validator = SafeURLValidator()
        safe_url = validator("https://api.example.com/data")  # OK
        validator("file:///etc/passwd")  # Raises SafeURLValidationError
        validator("http://169.254.169.254/latest/meta-data/")  # Raises

        # With host allowlist
        validator = SafeURLValidator(allowed_hosts=["api.company.com"])
        validator("https://api.company.com/data")  # OK
        validator("https://evil.com/data")  # Raises SafeURLValidationError
    """

    def __init__(
        self,
        allowed_schemes: list[str] | None = None,
        allowed_hosts: list[str] | None = None,
        block_private_ips: bool = True,
        block_metadata_urls: bool = True,
        extra_blocked_hosts: list[str] | None = None,
    ) -> None:
        """Initialize the URL validator.

        Args:
            allowed_schemes: Allowed URL schemes. Defaults to ["https"].
            allowed_hosts: If specified, only these hosts are allowed.
            block_private_ips: Block private/link-local IP addresses.
            block_metadata_urls: Block cloud metadata endpoints.
            extra_blocked_hosts: Additional hosts to block.
        """
        self.allowed_schemes = allowed_schemes or ["https"]
        self.allowed_hosts = allowed_hosts
        self.block_private_ips = block_private_ips
        self.block_metadata_urls = block_metadata_urls
        self.blocked_hosts = BLOCKED_HOSTS.copy()
        if extra_blocked_hosts:
            self.blocked_hosts.extend(extra_blocked_hosts)

    def __call__(self, value: str) -> str:
        """Validate and return safe URL.

        Args:
            value: URL to validate.

        Returns:
            Validated URL string.

        Raises:
            SafeURLValidationError: If the URL is unsafe.
        """
        try:
            parsed = urlparse(value)
        except Exception as e:
            raise SafeURLValidationError(
                f"Invalid URL: {e}",
                url=value,
                reason="parse_error",
            ) from e

        # Check scheme
        if parsed.scheme not in self.allowed_schemes:
            raise SafeURLValidationError(
                f"URL scheme '{parsed.scheme}' not allowed. Allowed: {self.allowed_schemes}",
                url=value,
                reason="invalid_scheme",
            )

        # Check for file:// scheme explicitly
        if parsed.scheme == "file":
            raise SafeURLValidationError(
                "file:// URLs are not allowed",
                url=value,
                reason="file_scheme",
            )

        hostname = parsed.hostname
        if not hostname:
            raise SafeURLValidationError(
                "URL must have a hostname",
                url=value,
                reason="missing_hostname",
            )

        # Check host allowlist
        if self.allowed_hosts is not None and hostname not in self.allowed_hosts:
            raise SafeURLValidationError(
                f"Host '{hostname}' not in allowed list: {self.allowed_hosts}",
                url=value,
                reason="host_not_allowed",
            )

        # Check blocked hosts
        if self.block_metadata_urls:
            for blocked in self.blocked_hosts:
                if hostname == blocked or hostname.endswith("." + blocked):
                    raise SafeURLValidationError(
                        f"URL points to blocked host: {hostname}",
                        url=value,
                        reason="metadata_url",
                    )

        # Check private IPs. NOTE: ``SafeURLValidationError`` is a
        # ``ValueError`` subclass, so the IP-parse step is isolated to
        # its own try/except — otherwise an ``except ValueError`` would
        # silently swallow our own raise (CVE-2026-35394 regression
        # corpus surfaced this — ``block_private_ips=True`` was a no-op
        # for 10.x / 172.16-31.x / 192.168.x addresses).
        if self.block_private_ips:
            try:
                ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(
                    hostname
                )
            except ValueError:
                ip = None  # Not an IP literal — fine, fall through to host checks
            if ip is not None and (ip.is_private or ip.is_loopback or ip.is_link_local):
                raise SafeURLValidationError(
                    f"URL points to private/loopback/link-local IP: {hostname}",
                    url=value,
                    reason="private_ip",
                )

            # Check for localhost aliases
            if hostname in ["localhost", "127.0.0.1", "::1", "0.0.0.0"]:  # nosec B104 - checking not binding
                raise SafeURLValidationError(
                    f"URL points to localhost: {hostname}",
                    url=value,
                    reason="localhost",
                )

        return value


# Pre-configured validators
_default_path_validator = SafePathValidator()
_strict_path_validator = SafePathValidator(allow_absolute=False)
_tmp_path_validator = SafePathValidator(root_dir=Path("/tmp/airlock"))  # nosec B108 - intentional
_default_url_validator = SafeURLValidator()
_http_url_validator = SafeURLValidator(allowed_schemes=["http", "https"])


def validate_safe_path(value: str | Path) -> Path:
    """Default path validator using DEFAULT_PATH_DENY_PATTERNS."""
    return _default_path_validator(value)


def validate_safe_path_strict(value: str | Path) -> Path:
    """Strict path validator that rejects absolute paths."""
    return _strict_path_validator(value)


def validate_safe_path_in_tmp(value: str | Path) -> Path:
    """Path validator that requires paths within /tmp/airlock."""
    return _tmp_path_validator(value)


def validate_safe_url(value: str) -> str:
    """Default URL validator (HTTPS only)."""
    return _default_url_validator(value)


def validate_safe_url_allow_http(value: str) -> str:
    """URL validator that allows both HTTP and HTTPS."""
    return _http_url_validator(value)


# Type aliases using Pydantic's Annotated pattern
SafePath = Annotated[Path, AfterValidator(validate_safe_path)]
"""Safe path type that validates against common attack patterns.

Rejects: traversal (..), home (~), .env, .ssh, *.pem, /etc/passwd, etc.
"""

SafePathStrict = Annotated[Path, AfterValidator(validate_safe_path_strict)]
"""Strict safe path that also rejects absolute paths."""

SafePathInTmp = Annotated[Path, AfterValidator(validate_safe_path_in_tmp)]
"""Safe path that must be within /tmp/airlock."""

SafeURL = Annotated[str, AfterValidator(validate_safe_url)]
"""Safe URL type that validates against exfiltration patterns.

Rejects: file://, metadata URLs, private IPs, localhost.
Only allows HTTPS.
"""

SafeURLAllowHttp = Annotated[str, AfterValidator(validate_safe_url_allow_http)]
"""Safe URL type that allows both HTTP and HTTPS."""


# Factory functions for custom validators
def create_safe_path_type(
    root_dir: Path | None = None,
    deny_patterns: list[str] | None = None,
    allow_absolute: bool = True,
    extra_deny_patterns: list[str] | None = None,
) -> Any:
    """Create a custom SafePath type with specific validation rules.

    Args:
        root_dir: If specified, paths must resolve within this directory.
        deny_patterns: Patterns to deny. Defaults to DEFAULT_PATH_DENY_PATTERNS.
        allow_absolute: Whether to allow absolute paths.
        extra_deny_patterns: Additional patterns to deny.

    Returns:
        An Annotated type that can be used in function signatures.

    Examples:
        # Create a type for paths within /app/data
        AppDataPath = create_safe_path_type(root_dir=Path("/app/data"))

        @Airlock()
        def read_data(path: AppDataPath) -> str:
            return Path(path).read_text()
    """
    validator = SafePathValidator(
        root_dir=root_dir,
        deny_patterns=deny_patterns,
        allow_absolute=allow_absolute,
        extra_deny_patterns=extra_deny_patterns,
    )
    return Annotated[Path, AfterValidator(validator)]


def create_safe_url_type(
    allowed_schemes: list[str] | None = None,
    allowed_hosts: list[str] | None = None,
    block_private_ips: bool = True,
    block_metadata_urls: bool = True,
    extra_blocked_hosts: list[str] | None = None,
) -> Any:
    """Create a custom SafeURL type with specific validation rules.

    Args:
        allowed_schemes: Allowed URL schemes.
        allowed_hosts: If specified, only these hosts are allowed.
        block_private_ips: Block private/link-local IP addresses.
        block_metadata_urls: Block cloud metadata endpoints.
        extra_blocked_hosts: Additional hosts to block.

    Returns:
        An Annotated type that can be used in function signatures.

    Examples:
        # Create a type for API URLs only
        ApiURL = create_safe_url_type(allowed_hosts=["api.company.com", "api.partner.com"])

        @Airlock()
        def call_api(url: ApiURL) -> str:
            return requests.get(url).text
    """
    validator = SafeURLValidator(
        allowed_schemes=allowed_schemes,
        allowed_hosts=allowed_hosts,
        block_private_ips=block_private_ips,
        block_metadata_urls=block_metadata_urls,
        extra_blocked_hosts=extra_blocked_hosts,
    )
    return Annotated[str, AfterValidator(validator)]


# ---------------------------------------------------------------------------
# Unsafe-deserialization guard (V0.8.19+, CVE-2026-25874 anchor).
# ---------------------------------------------------------------------------
#
# CVE-2026-25874 (HuggingFace LeRobot, CVSS 9.3): the async-inference
# PolicyServer / robot-client `pickle.loads()` untrusted payloads received
# over an *unauthenticated, non-TLS* gRPC channel — an unauthenticated,
# network-reachable attacker reaches arbitrary code execution by sending a
# crafted pickle blob. The exploit class is NOT LeRobot-specific: any tool
# that deserializes a network-received payload with pickle / marshal /
# shelve / dill / jsonpickle is exposed. This guard is the reusable,
# CVE-agnostic primitive; `policy_presets.lerobot_cve_2026_25874_defaults`
# is the per-CVE projection.
#
# Where it sits: this is a *content* gate on the call's argument VALUES,
# composed above ghost-arg stripping + Pydantic type-validation. It looks
# for serialized-object payloads in the args and fails closed.
#
# Primary sources (retrieved 2026-06-07):
#   https://www.sentinelone.com/vulnerability-database/cve-2026-25874/
#   https://labs.cloudsecurityalliance.org/research/csa-research-note-lerobot-cve-2026-25874-unauth-rce-20260429/


# Default serializer-marker substrings flagged inside *string* args. These
# are the function/module tokens an injected payload or a mis-wired tool
# uses to reach a deserialization sink. Kept lowercase; matching is
# case-insensitive.
DEFAULT_DESERIALIZATION_MARKERS: frozenset[str] = frozenset(
    {
        "pickle.loads",
        "cpickle.loads",
        "_pickle.loads",
        "pickle.load",
        "__reduce__",
        "__reduce_ex__",
        "marshal.loads",
        "marshal.load",
        "shelve.open",
        "dill.loads",
        "dill.load",
        "jsonpickle.decode",
        "yaml.unsafe_load",
        "yaml.load(",  # bare yaml.load without SafeLoader is the unsafe form
    }
)

# Pickle PROTO opcode is 0x80 followed by a protocol byte. Protocols 0-5
# exist as of CPython 3.13; we accept 0x00-0x05 as the trailing byte to
# stay forward-compatible without matching arbitrary 0x80-prefixed data.
_PICKLE_PROTO_OPCODE = 0x80
_MAX_PICKLE_PROTOCOL = 5

# Minimum length before a string is even considered as candidate base64
# pickle. Below this, false-positive risk outweighs signal.
_MIN_B64_PICKLE_LEN = 8


class UnsafeDeserializationVerdict(str, enum.Enum):
    """Stable reason codes for :class:`UnsafeDeserializationDecision`."""

    ALLOW = "allow"
    DENY_PICKLE_MAGIC = "deny_pickle_magic"
    DENY_BASE64_PICKLE = "deny_base64_pickle"
    DENY_SERIALIZER_MARKER = "deny_serializer_marker"
    DENY_UNAUTHENTICATED_TRANSPORT = "deny_unauthenticated_transport"


@dataclass(frozen=True)
class UnsafeDeserializationDecision:
    """Outcome of a single :meth:`UnsafeDeserializationGuard.evaluate` call.

    Mirrors the v0.7.x / v0.8.x guard decision family — every guard
    exposes ``allowed: bool`` so integrators can chain on one
    short-circuit predicate.

    Attributes:
        allowed: True iff no unsafe-deserialization shape was found.
        verdict: A stable :class:`UnsafeDeserializationVerdict` value.
        detail: Free-form human-readable explanation.
        matched_field: The argument name that tripped the guard, or
            ``None`` when ``allowed=True``.
        matched_pattern: The concrete signal that fired (a marker
            token, ``"pickle-magic"``, ``"base64-pickle"``, or the
            transport reason), or ``None`` when allowed.
        fix_hints: LLM-actionable remediation hints. Carries the
            advisory / CVE reference when the guard was constructed
            with one.
    """

    allowed: bool
    verdict: UnsafeDeserializationVerdict
    detail: str
    matched_field: str | None = None
    matched_pattern: str | None = None
    fix_hints: list[str] = field(default_factory=list)


class UnsafeDeserializationGuard:
    """Fail-closed content gate on serialized-object payloads in tool args.

    Detects, across the call's argument values:

    1. **Pickle magic bytes** — a ``bytes`` / ``bytearray`` value whose
       first byte is the pickle ``PROTO`` opcode (``0x80``) followed by a
       known protocol byte (0-5).
    2. **Base64-encoded pickle** — a ``str`` value that decodes to a
       byte string carrying the same pickle magic.
    3. **Serializer marker tokens** — a ``str`` value containing a
       deserialization sink token (``pickle.loads``, ``marshal.loads``,
       ``dill.loads``, ``jsonpickle.decode``, ``yaml.unsafe_load``, ...).
    4. **Serialized-object args over an unauthenticated channel** — when
       ``require_authenticated_transport=True``, any ``bytes`` /
       ``bytearray`` arg (a serialized-object payload by type) is denied
       unless the call's declared transport metadata asserts both an
       authenticated channel and TLS. This is the airgap pairing for
       CVE-2026-25874, whose root cause was pickle over an
       *unauthenticated, non-TLS* gRPC channel.

    The guard never deserializes anything — it inspects magic bytes and
    string tokens only. No ``pickle`` / ``marshal`` / ``dill`` import
    occurs (it carries no execution risk itself).

    Args:
        require_authenticated_transport: When True, a serialized-object
            (bytes) arg requires the call to declare an authenticated +
            TLS transport (see ``transport_metadata_key``).
        transport_metadata_key: The argument name carrying transport
            metadata. The value may be a mapping with truthy
            ``authenticated`` (or ``auth``) AND ``tls`` (or ``encrypted``)
            keys, or an object exposing those attributes.
        extra_markers: Additional serializer marker substrings to flag,
            merged with :data:`DEFAULT_DESERIALIZATION_MARKERS`.
        advisory: Optional advisory / CVE identifier (e.g.
            ``"CVE-2026-25874"``) surfaced in every deny ``fix_hints``.
        advisory_url: Optional primary-source URL surfaced alongside.

    Raises:
        TypeError: ``extra_markers`` is not a frozenset / set.
    """

    def __init__(
        self,
        *,
        require_authenticated_transport: bool = False,
        transport_metadata_key: str = "transport",
        extra_markers: frozenset[str] | set[str] | None = None,
        advisory: str | None = None,
        advisory_url: str | None = None,
    ) -> None:
        if extra_markers is None:
            extra_markers = frozenset()
        if not isinstance(extra_markers, (frozenset, set)):
            raise TypeError(
                f"extra_markers must be a set/frozenset of str; got {type(extra_markers).__name__}"
            )
        self._require_auth = require_authenticated_transport
        self._transport_key = transport_metadata_key
        self._markers = frozenset(m.lower() for m in DEFAULT_DESERIALIZATION_MARKERS) | frozenset(
            m.lower() for m in extra_markers
        )
        self._advisory = advisory
        self._advisory_url = advisory_url

    def evaluate(self, args: Mapping[str, Any] | None) -> UnsafeDeserializationDecision:
        """Decide whether the call args carry an unsafe-deserialization shape.

        Args:
            args: The tool call's argument mapping. ``None`` = no payload
                = allow.

        Returns:
            :class:`UnsafeDeserializationDecision`. Callers map
            ``allowed=False`` to a refusal at the Airlock decorator
            boundary.
        """
        if not args:
            return self._allow()

        transport_ok = self._transport_authenticated(args)

        for field_name, value in args.items():
            if field_name == self._transport_key:
                continue

            # 1) Raw pickle magic bytes.
            if isinstance(value, (bytes, bytearray)):
                if self._is_pickle_magic(value):
                    return self._deny(
                        UnsafeDeserializationVerdict.DENY_PICKLE_MAGIC,
                        field_name,
                        "pickle-magic",
                        f"argument {field_name!r} carries pickle magic bytes "
                        f"(0x80 PROTO opcode) — an unsafe-deserialization payload",
                    )
                # 4) A serialized-object (bytes) arg over an unauthenticated
                #    channel is denied even when its content is not a
                #    recognised pickle (defence-in-depth for the airgap).
                if self._require_auth and not transport_ok:
                    return self._deny(
                        UnsafeDeserializationVerdict.DENY_UNAUTHENTICATED_TRANSPORT,
                        field_name,
                        "unauthenticated-transport",
                        f"argument {field_name!r} is a serialized-object (bytes) "
                        f"payload but the call did not declare an authenticated + "
                        f"TLS transport in {self._transport_key!r}",
                    )
                continue

            # 2) + 3) String-valued args: base64 pickle, then marker tokens.
            if isinstance(value, str):
                if self._is_base64_pickle(value):
                    return self._deny(
                        UnsafeDeserializationVerdict.DENY_BASE64_PICKLE,
                        field_name,
                        "base64-pickle",
                        f"argument {field_name!r} is base64 that decodes to a "
                        f"pickle payload (0x80 PROTO opcode)",
                    )
                marker = self._find_marker(value)
                if marker is not None:
                    return self._deny(
                        UnsafeDeserializationVerdict.DENY_SERIALIZER_MARKER,
                        field_name,
                        marker,
                        f"argument {field_name!r} contains deserialization sink token {marker!r}",
                    )

        return self._allow()

    # -- internal helpers --------------------------------------------------

    def _allow(self) -> UnsafeDeserializationDecision:
        return UnsafeDeserializationDecision(
            allowed=True,
            verdict=UnsafeDeserializationVerdict.ALLOW,
            detail="no unsafe-deserialization shape found in args",
        )

    def _deny(
        self,
        verdict: UnsafeDeserializationVerdict,
        field_name: str,
        pattern: str,
        detail: str,
    ) -> UnsafeDeserializationDecision:
        logger.warning(
            "unsafe_deserialization_blocked",
            verdict=verdict.value,
            field=field_name,
            pattern=pattern,
            advisory=self._advisory,
        )
        hints: list[str] = []
        if self._advisory:
            hints.append(
                f"Blocked unsafe-deserialization payload ({self._advisory}). "
                f"Do not pass pickle/marshal/dill/jsonpickle payloads to this tool."
            )
        else:
            hints.append(
                "Blocked unsafe-deserialization payload. Do not pass "
                "pickle/marshal/dill/jsonpickle payloads to this tool."
            )
        hints.append(
            "Use a safe, schema-validated format (JSON / Pydantic model) instead "
            "of an opaque serialized object."
        )
        if verdict is UnsafeDeserializationVerdict.DENY_UNAUTHENTICATED_TRANSPORT:
            hints.append(
                f"Declare an authenticated + TLS transport in the "
                f"{self._transport_key!r} argument before sending serialized objects."
            )
        if self._advisory_url:
            hints.append(f"See: {self._advisory_url}")
        return UnsafeDeserializationDecision(
            allowed=False,
            verdict=verdict,
            detail=detail,
            matched_field=field_name,
            matched_pattern=pattern,
            fix_hints=hints,
        )

    @staticmethod
    def _is_pickle_magic(value: bytes | bytearray) -> bool:
        """True iff ``value`` starts with the pickle PROTO opcode + valid protocol."""
        if len(value) < 2:
            return False
        return value[0] == _PICKLE_PROTO_OPCODE and value[1] <= _MAX_PICKLE_PROTOCOL

    def _is_base64_pickle(self, value: str) -> bool:
        """True iff ``value`` is base64 that decodes to a pickle-magic byte string."""
        candidate = value.strip()
        if len(candidate) < _MIN_B64_PICKLE_LEN or len(candidate) % 4 != 0:
            return False
        # Fast pre-filter: base64 of a leading 0x80 byte always starts "gA".
        if not candidate.startswith("gA"):
            return False
        try:
            decoded = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            return False
        return self._is_pickle_magic(decoded)

    def _find_marker(self, value: str) -> str | None:
        lowered = value.lower()
        for marker in self._markers:
            if marker in lowered:
                return marker
        return None

    def _transport_authenticated(self, args: Mapping[str, Any]) -> bool:
        """True iff the call declares an authenticated + TLS transport.

        Accepts the transport metadata as a mapping (truthy
        ``authenticated``/``auth`` AND ``tls``/``encrypted`` keys) or as an
        object exposing the same as attributes.
        """
        meta = args.get(self._transport_key)
        if meta is None:
            return False

        def _get(key: str) -> Any:
            if isinstance(meta, Mapping):
                return meta.get(key)
            return getattr(meta, key, None)

        authenticated = bool(_get("authenticated") or _get("auth"))
        tls = bool(_get("tls") or _get("encrypted"))
        return authenticated and tls
