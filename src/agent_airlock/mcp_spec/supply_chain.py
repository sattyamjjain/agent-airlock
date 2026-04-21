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
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import structlog

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


def _canonicalize_manifest(manifest: dict[str, Any]) -> bytes:
    """Deterministic JSON serialization for stable digesting."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_tool_manifest_digest(manifest: dict[str, Any]) -> str:
    """Return the canonical SHA-256 hex digest of ``manifest``."""
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


_PRIVATE_BLOCK_REASONS: tuple[tuple[str, str], ...] = (
    ("127.0.0.0/8", "loopback"),
    ("10.0.0.0/8", "RFC1918 private (10/8)"),
    ("172.16.0.0/12", "RFC1918 private (172.16/12)"),
    ("192.168.0.0/16", "RFC1918 private (192.168/16)"),
    ("169.254.0.0/16", "link-local / AWS IMDS"),
    ("100.64.0.0/10", "carrier-grade NAT"),
    ("::1/128", "IPv6 loopback"),
    ("fc00::/7", "IPv6 unique-local"),
    ("fe80::/10", "IPv6 link-local"),
)

_PRIVATE_NETS = [(ipaddress.ip_network(n), r) for n, r in _PRIVATE_BLOCK_REASONS]


def check_mcp_bridge_target(
    target_url: str,
    allowed_hosts: frozenset[str] = frozenset(),
) -> None:
    """Refuse ``target_url`` if it resolves to a private / internal range.

    Args:
        target_url: The URL a tool wants to fetch.
        allowed_hosts: Explicit allow-list (hostnames). A match on
            hostname bypasses IP-range checks — use sparingly.

    Raises:
        MCPBridgeSSRFBlocked: If the URL's hostname resolves to any
            forbidden IP range and is not on ``allowed_hosts``.
    """
    parsed = urlparse(target_url)
    host = parsed.hostname
    if not host:
        raise MCPBridgeSSRFBlocked(
            target_url=target_url,
            resolved="<unparseable>",
            reason="no hostname in URL",
        )
    if host in allowed_hosts:
        return

    # Refuse bare metadata hostnames outright — no DNS needed.
    if host.lower() in {"metadata", "metadata.google.internal", "169.254.169.254"}:
        raise MCPBridgeSSRFBlocked(
            target_url=target_url,
            resolved=host,
            reason="cloud metadata endpoint (canonical SSRF target)",
        )

    # Resolve every A/AAAA record; any one hitting a private range = reject.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise MCPBridgeSSRFBlocked(
            target_url=target_url,
            resolved=host,
            reason=f"DNS resolution failed: {exc}",
        ) from exc

    for info in infos:
        ip_str = str(info[4][0])
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        for net, reason in _PRIVATE_NETS:
            if ip in net:
                raise MCPBridgeSSRFBlocked(
                    target_url=target_url,
                    resolved=ip_str,
                    reason=reason,
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


def check_tool_response_content_type(
    content_type: str,
    tool_name: str = "<unknown>",
    allowed_content_types: frozenset[str] = frozenset(),
) -> None:
    """Refuse responses whose ``Content-Type`` is a known-unsafe format.

    Args:
        content_type: The ``Content-Type`` header from the MCP tool response.
        tool_name: The tool that returned it (for error context).
        allowed_content_types: Caller-supplied allow-list. A match
            here bypasses the unsafe-list check. Use when you have an
            explicit schema + deserializer.

    Raises:
        UnsafeDeserializationError: On a match against the unsafe
            default list, absent an explicit allow-list override.
    """
    # Strip parameters: "application/x-python-pickle; charset=utf-8"
    primary = content_type.split(";", 1)[0].strip().lower()
    if primary in allowed_content_types:
        return
    if primary in _UNSAFE_CONTENT_TYPES:
        raise UnsafeDeserializationError(
            content_type=content_type,
            tool_name=tool_name,
        )


__all__ = [
    "MCPBridgeSSRFBlocked",
    "ToolDefinitionRegistry",
    "ToolDefinitionTamperedError",
    "UnsafeDeserializationError",
    "check_mcp_bridge_target",
    "check_tool_response_content_type",
    "compute_tool_manifest_digest",
]
