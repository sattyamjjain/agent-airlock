"""SSRF egress guard — deny-by-default outbound-target validation (v0.8.29+).

CVE-2026-47390 (CWE-918, SSRF-protection bypass): an agent egress filter that
validates the *literal hostname string* of an outbound URL — rather than the
**resolved IP** — is trivially bypassed. A target can encode loopback /
link-local / cloud-metadata addresses in a form the naive check does not
recognise but the OS resolver / HTTP client happily connects to:

- IPv4 loopback in alternate encodings: ``127.1``, decimal ``2130706433``,
  octal ``0177.0.0.1``, hex ``0x7f000001`` — all of which
  ``ipaddress.ip_address`` *rejects* (so a string allow/deny check waves them
  through) but ``socket.inet_aton`` (and therefore ``curl`` / ``requests`` /
  the kernel) resolves straight back to ``127.0.0.1``.
- IPv6 loopback / IPv4-mapped: ``::1``, ``[::1]``, ``::ffff:127.0.0.1``,
  ``0:0:0:0:0:0:0:1``.
- Link-local + cloud metadata: ``169.254.0.0/16`` (incl. the AWS/GCP/Azure
  IMDS address ``169.254.169.254``), ``fd00::/8``, ``fe80::/10``.
- DNS rebinding: a public-looking hostname whose A/AAAA record points at an
  internal address. The literal string is innocuous; only the **resolved IP**
  reveals the target.

This guard closes the class. It DENIES by default and FAILS CLOSED: every
candidate target is reduced to its canonical IP(s) — decoding the alternate
encodings above and **resolving hostnames via DNS at check time** (so a
rebind that flips a record to loopback is caught at connect time, not just at
parse time) — and any IP in a loopback / link-local / metadata / unspecified
range, or an RFC1918 private range not on the operator allow-list, is refused
*before* the fetch executes. A hostname that cannot be resolved is refused
(fail-closed) unless the operator opts out.

Composition
-----------
Reuses :func:`agent_airlock.network.is_blocked_ipv6_range` (the CVE-2026-41361
IPv6 range set: IPv4-mapped, NAT64, 6to4, ULA, documentation) so the IPv6
coverage stays single-sourced. Adds the alternate-encoding IPv4 decoder and
DNS resolution that the existing `SafeURLValidator` / `EndpointPolicy`
string-level checks do not perform.

Primary source:
  https://www.cve.org/CVERecord?id=CVE-2026-47390
  https://cwe.mitre.org/data/definitions/918.html
"""

from __future__ import annotations

import enum
import ipaddress
import socket
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from urllib.parse import urlparse

import structlog

from .exceptions import AirlockError
from .network import is_blocked_ipv6_range

logger = structlog.get_logger("agent-airlock.ssrf_egress_guard")

# A resolver maps a hostname to a list of IP strings. Injected for testing /
# to defeat-test DNS rebinding deterministically; defaults to the system
# resolver via :func:`_default_resolver`.
Resolver = Callable[[str], list[str]]

# Cloud-metadata addresses, called out for a precise explain trace (they are
# already inside 169.254.0.0/16 link-local, so they deny regardless).
_METADATA_IPS = frozenset({"169.254.169.254", "169.254.169.253"})

_IPv4 = ipaddress.IPv4Address
_IPv6 = ipaddress.IPv6Address


class SSRFEgressVerdict(str, enum.Enum):
    """Stable reason codes for :class:`SSRFEgressDecision`."""

    ALLOW = "allow"
    ALLOW_HOST_ALLOWLISTED = "allow_host_allowlisted"
    DENY_LOOPBACK = "deny_loopback"
    DENY_LINK_LOCAL = "deny_link_local"
    DENY_METADATA = "deny_metadata"
    DENY_UNSPECIFIED = "deny_unspecified"
    DENY_PRIVATE = "deny_private_rfc1918"
    DENY_IPV6_INTERNAL = "deny_ipv6_internal"
    DENY_UNRESOLVABLE = "deny_unresolvable"
    DENY_NO_HOST = "deny_no_host"


@dataclass(frozen=True)
class SSRFEgressDecision:
    """Outcome of a single :meth:`SSRFEgressGuard.check_url` call.

    Mirrors the v0.7.x / v0.8.x guard decision family — exposes
    ``allowed: bool`` for chain-friendly composition.

    Attributes:
        allowed: True iff the target is safe to fetch. False = fail-closed.
        verdict: A stable :class:`SSRFEgressVerdict` value.
        host: The literal host extracted from the URL (as written).
        resolved_ip: The canonical IP the host reduced to that tripped the
            rule (``None`` when allowed or no host).
        encoding: How ``host`` encoded that IP (``"hex_ipv4"`` /
            ``"decimal_ipv4"`` / ``"octal_ipv4"`` / ``"short_ipv4"`` /
            ``"canonical"`` / ``"dns"``), or ``None``.
        explain: A 3-line audit trace (rule / resolved IP / encoding) on a
            denial — so every deny is explainable.
        fix_hints: Operator/LLM-actionable remediation hints.
    """

    allowed: bool
    verdict: SSRFEgressVerdict
    host: str | None = None
    resolved_ip: str | None = None
    encoding: str | None = None
    explain: list[str] = field(default_factory=list)
    fix_hints: list[str] = field(default_factory=list)


class SSRFEgressBlocked(AirlockError):
    """Raised on a denied outbound target (fail-closed).

    Carries the :class:`SSRFEgressDecision` and exposes ``explain`` +
    ``fix_hints`` so an upstream airlock layer can audit and self-heal.

    Attributes:
        decision: The decision that triggered the refusal.
        explain: The 3-line audit trace.
        fix_hints: Operator/LLM-actionable remediation hints.
    """

    def __init__(self, decision: SSRFEgressDecision) -> None:
        self.decision = decision
        self.explain = decision.explain
        self.fix_hints = decision.fix_hints
        detail = decision.explain[0] if decision.explain else "SSRF egress denied"
        super().__init__(detail)


def _default_resolver(host: str) -> list[str]:
    """Resolve ``host`` to its A/AAAA addresses via the system resolver."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    out: list[str] = []
    for info in infos:
        addr = info[4][0]
        if isinstance(addr, str):
            # Strip any IPv6 scope id (``fe80::1%en0`` -> ``fe80::1``).
            out.append(addr.split("%", 1)[0])
    return out


def _classify_ipv4_encoding(host: str) -> str:
    """Label how an alternate-encoding IPv4 literal was written (for the trace)."""
    h = host.lower()
    if "0x" in h:
        return "hex_ipv4"
    if "." not in h and h.isdigit():
        return "decimal_ipv4"
    octets = h.split(".")
    if any(len(o) > 1 and o.startswith("0") and o.isdigit() for o in octets):
        return "octal_ipv4"
    if h.count(".") < 3:
        return "short_ipv4"
    return "alt_ipv4"


def _decode_literal_ip(host: str) -> tuple[_IPv4 | _IPv6, str] | None:
    """Decode ``host`` to a canonical IP + encoding label, or ``None`` if it is a name.

    Tries canonical parsing first (``ipaddress``), then the lenient
    ``socket.inet_aton`` path that accepts the hex / octal / decimal / short
    IPv4 forms an HTTP client would connect to but ``ipaddress`` rejects.
    """
    stripped = host.strip().strip("[]")
    try:
        return ipaddress.ip_address(stripped), "canonical"
    except ValueError:
        pass
    # Alternate IPv4 encodings: inet_aton mirrors what curl / the kernel do.
    try:
        packed = socket.inet_aton(stripped)
    except OSError:
        return None
    return ipaddress.IPv4Address(packed), _classify_ipv4_encoding(stripped)


def _blocked_reason(ip: _IPv4 | _IPv6) -> tuple[SSRFEgressVerdict, str] | None:
    """Classify ``ip`` against the blocked egress ranges; ``None`` if public."""
    if str(ip) in _METADATA_IPS:
        return SSRFEgressVerdict.DENY_METADATA, "cloud metadata (IMDS) address"
    if ip.is_loopback:
        return SSRFEgressVerdict.DENY_LOOPBACK, "loopback (127.0.0.0/8 or ::1)"
    if ip.is_link_local:
        return SSRFEgressVerdict.DENY_LINK_LOCAL, "link-local (169.254.0.0/16 or fe80::/10)"
    if ip.is_unspecified:
        return SSRFEgressVerdict.DENY_UNSPECIFIED, "unspecified (0.0.0.0 or ::)"
    if isinstance(ip, ipaddress.IPv6Address) and is_blocked_ipv6_range(str(ip)):
        return SSRFEgressVerdict.DENY_IPV6_INTERNAL, "internal IPv6 (ULA / mapped / NAT64 / 6to4)"
    if ip.is_private:
        return SSRFEgressVerdict.DENY_PRIVATE, "RFC1918 private (10/8, 172.16/12, 192.168/16)"
    return None


# URL-ish argument detection for the recursive arg scan.
_URL_SCHEMES = ("http://", "https://", "ws://", "wss://", "ftp://", "gopher://")


class SSRFEgressGuard:
    """Deny-by-default egress guard for the SSRF-protection-bypass class.

    Runs on every tool-call argument that resolves to a URL/host. Decodes
    alternate-encoding IP literals, resolves hostnames to their IP(s), and
    refuses any target in a loopback / link-local / metadata / unspecified
    range or an RFC1918 private range not on ``allow_internal_hosts`` —
    BEFORE the fetch executes.

    Args:
        allow_internal_hosts: Hosts (literal hostname or IP string,
            case-insensitive) that legitimate internal tools may reach. A
            target whose written host OR any resolved IP is on this list is
            allowed. Empty (default) allows no internal target.
        resolver: Hostname → list-of-IP-strings resolver. Defaults to the
            system resolver. Inject a stub to test DNS-rebinding handling.
        deny_on_resolution_failure: When True (default), a hostname that
            cannot be resolved is refused (fail-closed). Set False to allow
            unresolvable hosts through to the client's own error handling.
        advisory: Advisory / CVE id surfaced in deny ``fix_hints``.

    Raises:
        TypeError: ``allow_internal_hosts`` is a bare ``str``.
    """

    def __init__(
        self,
        *,
        allow_internal_hosts: Iterable[str] | None = None,
        resolver: Resolver | None = None,
        deny_on_resolution_failure: bool = True,
        advisory: str | None = "CVE-2026-47390",
    ) -> None:
        if isinstance(allow_internal_hosts, str):
            raise TypeError(
                "allow_internal_hosts must be an iterable of str, not a bare str: "
                f"{allow_internal_hosts!r}"
            )
        self._allow_hosts: frozenset[str] = frozenset(
            h.strip().lower() for h in (allow_internal_hosts or ())
        )
        self._resolver = resolver or _default_resolver
        self._deny_on_resolution_failure = deny_on_resolution_failure
        self._advisory = advisory

    @property
    def allow_internal_hosts(self) -> frozenset[str]:
        """The normalized internal-host allow-list."""
        return self._allow_hosts

    def check_url(self, url: str) -> SSRFEgressDecision:
        """Decide whether ``url`` is a safe outbound target.

        Args:
            url: The candidate URL (or bare host) the tool would fetch.

        Returns:
            :class:`SSRFEgressDecision`. ``allowed=False`` maps to a refusal
            of the egress, with a 3-line ``explain`` trace.
        """
        host = self._extract_host(url)
        if not host:
            return SSRFEgressDecision(
                allowed=False,
                verdict=SSRFEgressVerdict.DENY_NO_HOST,
                host=None,
                explain=[
                    "rule=no_host: could not extract a host from the target",
                    f"target={url!r}",
                    "encoding=n/a",
                ],
                fix_hints=self._hints("Provide an explicit http(s) URL with a host."),
            )

        host_l = host.strip().lower()
        # Explicit operator escape hatch — the written host is trusted.
        if host_l in self._allow_hosts:
            return SSRFEgressDecision(
                allowed=True,
                verdict=SSRFEgressVerdict.ALLOW_HOST_ALLOWLISTED,
                host=host,
            )

        literal = _decode_literal_ip(host)
        if literal is not None:
            ip, encoding = literal
            return self._decide_ip(host, ip, encoding)

        # A hostname: resolve and evaluate EVERY resolved address (rebinding).
        return self._decide_hostname(host)

    def _decide_hostname(self, host: str) -> SSRFEgressDecision:
        try:
            addrs = self._resolver(host)
        except OSError as exc:
            if not self._deny_on_resolution_failure:
                return SSRFEgressDecision(allowed=True, verdict=SSRFEgressVerdict.ALLOW, host=host)
            return SSRFEgressDecision(
                allowed=False,
                verdict=SSRFEgressVerdict.DENY_UNRESOLVABLE,
                host=host,
                encoding="dns",
                explain=[
                    "rule=unresolvable: host did not resolve; failing closed",
                    f"resolved_ip=<none> (host {host!r}, error {exc})",
                    "encoding=dns",
                ],
                fix_hints=self._hints(
                    f"{host!r} could not be resolved; an SSRF guard refuses "
                    "unverifiable targets by default.",
                ),
            )
        for addr in addrs:
            # A resolved address is canonical, but a rebind could hand back an
            # alternate encoding too — decode defensively.
            decoded = _decode_literal_ip(addr)
            if decoded is None:
                continue
            ip, _enc = decoded
            if str(ip) in self._allow_hosts:
                continue
            blocked = _blocked_reason(ip)
            if blocked is not None:
                verdict, reason = blocked
                return self._deny(host, ip, "dns", verdict, reason)
        return SSRFEgressDecision(allowed=True, verdict=SSRFEgressVerdict.ALLOW, host=host)

    def _decide_ip(self, host: str, ip: _IPv4 | _IPv6, encoding: str) -> SSRFEgressDecision:
        if str(ip) in self._allow_hosts:
            return SSRFEgressDecision(
                allowed=True, verdict=SSRFEgressVerdict.ALLOW_HOST_ALLOWLISTED, host=host
            )
        blocked = _blocked_reason(ip)
        if blocked is None:
            return SSRFEgressDecision(
                allowed=True, verdict=SSRFEgressVerdict.ALLOW, host=host, resolved_ip=str(ip)
            )
        verdict, reason = blocked
        return self._deny(host, ip, encoding, verdict, reason)

    def check(self, args: Mapping[str, object] | str | None) -> SSRFEgressDecision:
        """Scan tool-call arguments for URL-shaped values and check each.

        Args:
            args: A single URL string, or a mapping of argument name → value
                (values may nest dicts / lists). ``None`` = nothing to check.

        Returns:
            The first denying :class:`SSRFEgressDecision`, else an allow.
        """
        if args is None:
            return SSRFEgressDecision(allowed=True, verdict=SSRFEgressVerdict.ALLOW)
        for candidate in _iter_url_candidates(args):
            decision = self.check_url(candidate)
            if not decision.allowed:
                return decision
        return SSRFEgressDecision(allowed=True, verdict=SSRFEgressVerdict.ALLOW)

    def enforce(self, url: str) -> None:
        """Raise :class:`SSRFEgressBlocked` if ``url`` is a denied target."""
        decision = self.check_url(url)
        if not decision.allowed:
            raise SSRFEgressBlocked(decision)

    # -- internals --------------------------------------------------------

    def _extract_host(self, url: str) -> str | None:
        url = url.strip()
        if "://" not in url and not url.startswith("//"):
            # Treat a bare host[:port][/path] as a host.
            url = "//" + url
        try:
            parsed = urlparse(url)
        except ValueError:
            return None
        return parsed.hostname

    def _deny(
        self,
        host: str,
        ip: _IPv4 | _IPv6,
        encoding: str,
        verdict: SSRFEgressVerdict,
        reason: str,
    ) -> SSRFEgressDecision:
        explain = [
            f"rule={verdict.value}: {reason} — egress denied",
            f"resolved_ip={ip} (from host {host!r})",
            f"encoding={encoding}",
        ]
        logger.warning(
            "ssrf_egress_blocked",
            verdict=verdict.value,
            host=host,
            resolved_ip=str(ip),
            encoding=encoding,
            advisory=self._advisory,
        )
        return SSRFEgressDecision(
            allowed=False,
            verdict=verdict,
            host=host,
            resolved_ip=str(ip),
            encoding=encoding,
            explain=explain,
            fix_hints=self._hints(
                f"Target host {host!r} resolves to {ip} ({reason}). Outbound "
                "requests to internal addresses are refused; add the host to "
                "allow_internal_hosts only if it is a legitimate internal tool.",
            ),
        )

    def _hints(self, *extra: str) -> list[str]:
        prefix = f"({self._advisory}) " if self._advisory else ""
        hints = [f"{prefix}{extra[0]}", *extra[1:]] if extra else []
        return hints


def _iter_url_candidates(value: object) -> list[str]:
    """Recursively collect URL-shaped string values from tool args."""
    out: list[str] = []

    def _walk(v: object) -> None:
        if isinstance(v, str):
            low = v.strip().lower()
            if any(low.startswith(s) for s in _URL_SCHEMES):
                out.append(v.strip())
        elif isinstance(v, Mapping):
            for sub in v.values():
                _walk(sub)
        elif isinstance(v, (list, tuple)):
            for item in v:
                _walk(item)

    _walk(value)
    return out


__all__ = [
    "Resolver",
    "SSRFEgressBlocked",
    "SSRFEgressDecision",
    "SSRFEgressGuard",
    "SSRFEgressVerdict",
]
