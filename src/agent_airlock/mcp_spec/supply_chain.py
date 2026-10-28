"""OX MCP supply-chain dossier micro-checks (v0.5.3+).

On 2026-04-20 OX Security published "Mother of All AI Supply Chains"
— 10+ coordinated MCP-ecosystem CVEs disclosed in a single report.
Anthropic publicly declined to patch four of the six Claude Desktop
tool-definition tampering CVEs, citing "defense-in-depth is the
caller's job." This module ships the caller's side of that
defense-in-depth.

Three new runtime checks cover the three CVE classes not yet covered
by existing presets:

1. **Tool-definition tamper resistance** — digest each registered tool
   manifest at first-register, re-verify before each call. Covers
   CVE-2026-30615/30617/30618/30623/30624/30625 (Claude Desktop).
2. **MCP Bridge SSRF** — refuse tool ``target_url`` values that resolve
   to RFC1918, link-local, loopback, or carrier-grade NAT ranges.
   Covers CVE-2026-26015 (OpenAI MCP Bridge).
3. **LlamaIndex deserialization guard** — reject tool responses whose
   ``Content-Type`` is a known-unsafe serialization format. Covers
   CVE-2026-33224.

References
----------
- OX dossier:  https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20
- The Hacker News:  https://thehackernews.com/2026/04/ox-security-mcp-dossier.html
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from .._log import structlog
from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.supply_chain")


# -----------------------------------------------------------------------------
# Tool-definition tamper resistance — CVE-2026-30615/30617/30618/30623/30624/30625
# -----------------------------------------------------------------------------


class ToolDefinitionTamperedError(AirlockError):
    """Raised when a tool manifest digest does not match the digest
    recorded at first-registration."""

    def __init__(self, *, tool_name: str, expected: str, actual: str) -> None:
        self.tool_name = tool_name
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"tool {tool_name!r} manifest has been tampered with: "
            f"expected sha256={expected}, got {actual}"
        )


class ToolManifestUnreadable(AirlockError):
    """Raised when a tool manifest has no canonical JSON form to digest (fail-closed).

    A manifest that is not a mapping, holds a value JSON cannot encode, keys of mixed
    types (``sort_keys`` cannot order them) or itself has no digest, so it can be
    neither registered nor verified. Until 0.10.28 these escaped as a bare
    ``TypeError`` / ``ValueError`` from ``json.dumps``.
    """

    def __init__(self, *, reason: str) -> None:
        self.reason = reason
        super().__init__(f"tool manifest cannot be digested: {reason}")


def _canonicalize_manifest(manifest: dict[str, Any]) -> bytes:
    """Deterministic JSON serialization for stable digesting.

    Raises:
        ToolManifestUnreadable: the manifest has no canonical JSON form.
    """
    if not isinstance(manifest, Mapping):
        raise ToolManifestUnreadable(reason="manifest is not a mapping")
    try:
        return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ToolManifestUnreadable(reason=str(exc)) from exc


def compute_tool_manifest_digest(manifest: dict[str, Any]) -> str:
    """Return the canonical SHA-256 hex digest of ``manifest``.

    Raises:
        ToolManifestUnreadable: the manifest has no canonical JSON form.
    """
    return hashlib.sha256(_canonicalize_manifest(manifest)).hexdigest()


@dataclass
class ToolDefinitionRegistry:
    """At-registration digest store used by :func:`verify_tool_manifest`.

    Usage::

        reg = ToolDefinitionRegistry()
        reg.register("read_file", {"params": {...}, "handler": "..."})
        # later, on every call:
        reg.verify("read_file", current_manifest)
        # Raises ToolDefinitionTamperedError on mismatch.
    """

    digests: dict[str, str] = field(default_factory=dict)

    def register(self, tool_name: str, manifest: dict[str, Any]) -> str:
        digest = compute_tool_manifest_digest(manifest)
        self.digests[tool_name] = digest
        return digest

    def verify(self, tool_name: str, manifest: dict[str, Any]) -> None:
        expected = self.digests.get(tool_name)
        if expected is None:
            # Unknown tool — first sighting. Auto-register so the
            # second call will verify. TOFU semantics match OWASP MCP
            # guidance: refuse changes after first trust.
            self.register(tool_name, manifest)
            return
        actual = compute_tool_manifest_digest(manifest)
        if actual != expected:
            raise ToolDefinitionTamperedError(tool_name=tool_name, expected=expected, actual=actual)


# -----------------------------------------------------------------------------
# MCP Bridge SSRF — CVE-2026-26015
# -----------------------------------------------------------------------------


class MCPBridgeSSRFBlocked(AirlockError):
    """Raised when a tool ``target_url`` resolves to a private / internal
    network range not on the explicit allow-list."""

    def __init__(self, *, target_url: str, resolved: str, reason: str) -> None:
        self.target_url = target_url
        self.resolved = resolved
        self.reason = reason
        super().__init__(f"MCP bridge SSRF blocked: {target_url!r} → {resolved} ({reason})")


#: Advisory the delegated SSRF guard names in its deny hints.
_BRIDGE_ADVISORY = "CVE-2026-26015"

#: Cloud-metadata host names refused outright, before any DNS lookup.
_METADATA_HOSTNAMES = frozenset({"metadata", "metadata.google.internal", "169.254.169.254"})

#: Carrier-grade NAT (RFC 6598). Python's ``ipaddress`` calls it neither private nor
#: reserved, so ``SSRFEgressGuard`` admits it; the bridge has refused it since v0.5.3 and
#: still does, on top of the guard's own ranges.
_CARRIER_GRADE_NAT = ipaddress.ip_network("100.64.0.0/10")


class _RecordingResolver:
    """An ``SSRFEgressGuard`` resolver that keeps every address it resolved.

    Every failure is an ``OSError``, which the guard turns into a fail-closed
    ``deny_unresolvable``: a host name the IDNA codec cannot encode raises
    ``UnicodeError`` (a ``ValueError``) out of ``getaddrinfo``, and a lookup that
    returns no address is no answer at all.
    """

    def __init__(self) -> None:
        self.addresses: list[str] = []

    def __call__(self, host: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(host, None)
        except ValueError as exc:
            raise OSError(f"host {host!r} cannot be resolved: {exc}") from exc
        addresses = [str(info[4][0]).split("%", 1)[0] for info in infos]
        if not addresses:
            raise OSError(f"host {host!r} resolved to no address")
        self.addresses.extend(addresses)
        return addresses


def _in_carrier_grade_nat(address: str) -> bool:
    """Whether ``address`` (or the IPv4 address an IPv6 form maps) is in 100.64.0.0/10."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped in _CARRIER_GRADE_NAT
    return ip in _CARRIER_GRADE_NAT


def _bridge_host(target_url: object) -> str:
    """The host ``target_url`` names, or the bridge's refusal when it names none.

    Raises:
        MCPBridgeSSRFBlocked: The URL is not a ``str``, cannot be parsed, or has no host.
    """
    if not isinstance(target_url, str):
        raise MCPBridgeSSRFBlocked(
            target_url=repr(target_url),
            resolved="<unreadable>",
            reason=f"target_url is a {type(target_url).__name__}, not a str",
        )
    try:
        host = urlparse(target_url).hostname
    except ValueError as exc:
        raise MCPBridgeSSRFBlocked(
            target_url=target_url, resolved="<unparseable>", reason=f"malformed URL: {exc}"
        ) from exc
    if not host:
        raise MCPBridgeSSRFBlocked(
            target_url=target_url,
            resolved="<unparseable>",
            reason="no hostname in URL",
        )
    return host


def check_mcp_bridge_target(
    target_url: str,
    allowed_hosts: frozenset[str] = frozenset(),
) -> None:
    """Refuse ``target_url`` if it resolves to a private / internal range.

    The address decision is
    :meth:`agent_airlock.ssrf_egress_guard.SSRFEgressGuard.check_url`: it refuses a
    parser-differential authority, decodes every spelling of an IP literal (``0.0.0.0``,
    ``[::]``, IPv4-mapped and NAT64 IPv6, hex / decimal / octal / short IPv4) and checks
    every address a host name resolves to. Until 0.10.28 a hand-rolled range list here
    admitted ``0.0.0.0``, ``[::ffff:127.0.0.1]``, ``[::]`` and NAT64. The bridge adds two
    refusals of its own: the cloud-metadata host names, before any lookup, and
    carrier-grade NAT (100.64.0.0/10), which the guard admits.

    Args:
        target_url: The URL a tool wants to fetch. Anything but a ``str`` is refused.
        allowed_hosts: Explicit allow-list (host names or IPs, case-insensitive). A
            match on the written host, or on an address it resolves to, bypasses the
            range checks — use sparingly. A parser-differential authority is refused
            even for an allow-listed host.

    Raises:
        MCPBridgeSSRFBlocked: If the URL is not a string or cannot be parsed, has no
            host, names a cloud-metadata host, or resolves to any forbidden range and
            is not on ``allowed_hosts``.
        TypeError: ``allowed_hosts`` is a bare ``str`` / ``bytes`` or holds a non-string.
    """
    from ..ssrf_egress_guard import SSRFEgressGuard, SSRFEgressVerdict

    if isinstance(allowed_hosts, (str, bytes)) or not all(
        isinstance(name, str) for name in allowed_hosts
    ):
        raise TypeError(f"allowed_hosts must be a collection of host strings: {allowed_hosts!r}")
    host = _bridge_host(target_url).lower()
    allowed = {name.strip().lower() for name in allowed_hosts}
    if host in _METADATA_HOSTNAMES and host not in allowed:
        raise MCPBridgeSSRFBlocked(
            target_url=target_url,
            resolved=host,
            reason="cloud metadata endpoint (canonical SSRF target)",
        )

    resolver = _RecordingResolver()
    decision = SSRFEgressGuard(
        allow_internal_hosts=allowed, resolver=resolver, advisory=_BRIDGE_ADVISORY
    ).check_url(target_url)
    if not decision.allowed:
        raise MCPBridgeSSRFBlocked(
            target_url=target_url,
            resolved=decision.resolved_ip or decision.host or "<unparseable>",
            reason=decision.explain[0] if decision.explain else decision.verdict.value,
        )
    if decision.verdict is SSRFEgressVerdict.ALLOW_HOST_ALLOWLISTED:
        return
    for address in [decision.resolved_ip] if decision.resolved_ip else resolver.addresses:
        if address.lower() not in allowed and _in_carrier_grade_nat(address):
            raise MCPBridgeSSRFBlocked(
                target_url=target_url,
                resolved=address,
                reason="carrier-grade NAT (100.64.0.0/10)",
            )


# -----------------------------------------------------------------------------
# LlamaIndex deserialization guard — CVE-2026-33224
# -----------------------------------------------------------------------------


class UnsafeDeserializationError(AirlockError):
    """Raised when a tool response carries an unsafe serialization format."""

    def __init__(self, *, content_type: str, tool_name: str = "<unknown>") -> None:
        self.content_type = content_type
        self.tool_name = tool_name
        super().__init__(
            f"tool {tool_name!r} returned unsafe content-type "
            f"{content_type!r} — refusing to deserialize "
            "(CVE-2026-33224 class)"
        )


_UNSAFE_CONTENT_TYPES: frozenset[str] = frozenset(
    {
        "application/x-python-pickle",
        "application/x-pickle",
        "application/octet-stream",
        "application/x-java-serialized-object",
        "application/vnd.msgpack",
    }
)


def _declared_content_types(content_type: object) -> list[str] | None:
    """Every media type the response declares, or ``None`` when none can be read.

    A ``str`` declares one; ``bytes`` are header octets and must be ASCII, as a media
    type is (a non-ASCII byte that a client dropped while decoding could rejoin a
    denied type the check never saw, and this is a deny-list); a list or tuple is
    every ``Content-Type`` value the response carried, each a ``str`` or ``bytes``.
    Anything else (``None``, a number, an empty list, an item of another type)
    declares nothing the check can read.
    """
    items = content_type if isinstance(content_type, (list, tuple)) else [content_type]
    declared: list[str] = []
    for item in items:
        if isinstance(item, (bytes, bytearray)):
            try:
                item = bytes(item).decode("ascii")
            except UnicodeDecodeError:
                return None
        if not isinstance(item, str):
            return None
        declared.append(item)
    return declared or None


def check_tool_response_content_type(
    content_type: str | bytes | list[str | bytes] | tuple[str | bytes, ...],
    tool_name: str = "<unknown>",
    allowed_content_types: frozenset[str] = frozenset(),
) -> None:
    """Refuse responses whose ``Content-Type`` is a known-unsafe format.

    Args:
        content_type: The ``Content-Type`` header from the MCP tool response:
            a ``str``, ASCII header ``bytes``, or a list / tuple of every value
            the response carried, each of which must pass. A value it cannot
            read (``None``, a number, an empty list, non-ASCII bytes) is
            refused: until v0.10.28 a list raised ``AttributeError`` and
            ``bytes`` a ``TypeError`` instead of the refusal.
        tool_name: The tool that returned it (for error context).
        allowed_content_types: Caller-supplied allow-list. A match
            here bypasses the unsafe-list check. Use when you have an
            explicit schema + deserializer.

    Raises:
        UnsafeDeserializationError: On a match against the unsafe
            default list, absent an explicit allow-list override, or on a
            ``content_type`` it cannot read.
    """
    declared = _declared_content_types(content_type)
    if declared is None:
        raise UnsafeDeserializationError(
            content_type=f"<unreadable {type(content_type).__name__}>",
            tool_name=tool_name,
        )
    for value in declared:
        # Strip parameters: "application/x-python-pickle; charset=utf-8"
        primary = value.split(";", 1)[0].strip().lower()
        if primary in allowed_content_types:
            continue
        if primary in _UNSAFE_CONTENT_TYPES:
            raise UnsafeDeserializationError(
                content_type=value,
                tool_name=tool_name,
            )


__all__ = [
    "MCPBridgeSSRFBlocked",
    "ToolDefinitionRegistry",
    "ToolDefinitionTamperedError",
    "ToolManifestUnreadable",
    "UnsafeDeserializationError",
    "check_mcp_bridge_target",
    "check_tool_response_content_type",
    "compute_tool_manifest_digest",
]
