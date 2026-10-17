"""Regressions for genuine guard fail-opens found by adaptive red-team wave 3.

Wave 3 drives the 27 lower-surface inspection guards. Most of its mode-C adapters
have no independent reference detector (the ``StandaloneAdapter.reference`` default
is ``False`` since F17), so an admitted probe scores ``benign_pass`` — the harness
cannot auto-confirm a fail-open on them and each candidate is triaged by hand. The
finding below was confirmed against ground truth (the OS socket parser), not a
model's opinion, and is fixed in 0.10.25.

F18 ``bind_address_guard`` admitted every kernel-lenient spelling of ``0.0.0.0``.
``_is_public_bind`` checked a literal blocklist and a strict :mod:`ipaddress` parse,
but the socket layer's own IPv4 parser (``inet_aton``) also accepts octal, hex,
bare-integer and short-dotted forms — ``0``, ``0x0``, ``00.00.00.00``,
``000.000.000.000``, ``0x0.0x0.0x0.0x0``, ``0.0.0``, ``0.00.0.0`` — and a server
handed any of them binds to ``0.0.0.0`` on every NIC, the exact CVE-2026-23744
surface the guard exists to refuse. ``ipaddress`` rejects all of them, so the guard
let them straight through. ``_is_public_bind`` now adds an ``inet_aton`` layer: any
spelling the kernel maps to ``0.0.0.0`` is refused, while a real address
(``127.0.0.1``, ``2130706433`` → loopback, ``1`` → ``0.0.0.1``) still passes, so the
fix adds no false positives. The same parser-differential class as wave-1 F2
(authority) and wave-2 F3 (reserved IPv6).

The sibling ``lan_unauth_rce_guard`` was checked and needs no change: its
``_is_lan_bound`` treats an address ``ipaddress`` cannot parse as LAN-bound, so the
lenient spellings are blocked there already (fail-safe, not fail-open).
"""

from __future__ import annotations

import pytest

from agent_airlock.mcp_spec.bind_address_guard import (
    BindAddressGuardConfig,
    BindAddressPublicError,
    UnauthenticatedPublicBindError,
    validate_bind_address,
)
from agent_airlock.mcp_spec.lan_unauth_rce_guard import LANUnauthRCEGuard

# Every spelling below is one socket.inet_aton maps to 0.0.0.0 — an all-interfaces
# bind however it is written. They are the fail-open set F18 closes.
_ALL_INTERFACES_SPELLINGS = [
    "00.00.00.00",
    "000.000.000.000",
    "0x0.0x0.0x0.0x0",
    "0",
    "0x0",
    "0.0.0",
    "0.00.0.0",
    "0.0.0.0\t",
]

# These must keep passing: loopback and specific NICs, including the lenient
# spellings that resolve somewhere other than 0.0.0.0.
_LEGIT_BINDS = [
    "127.0.0.1",
    "127.0.0.2",
    "10.0.0.0",
    "192.168.1.5",
    "2130706433",  # decimal 127.0.0.1 — loopback, not all-interfaces
    "1",  # inet_aton -> 0.0.0.1
    "0.0.0.1",
    "::1",
    "fe80::1",
]


class TestBindAddressParserDifferential:
    @pytest.mark.parametrize("addr", _ALL_INTERFACES_SPELLINGS)
    def test_lenient_all_interfaces_spellings_are_refused(self, addr: str) -> None:
        cfg = BindAddressGuardConfig()  # allow_public_bind=False
        with pytest.raises((BindAddressPublicError, UnauthenticatedPublicBindError)):
            validate_bind_address(addr, cfg)

    @pytest.mark.parametrize("addr", _LEGIT_BINDS)
    def test_legit_addresses_still_admitted(self, addr: str) -> None:
        cfg = BindAddressGuardConfig()
        # Must not raise — these are loopback or a specific interface.
        validate_bind_address(addr, cfg)

    def test_known_literals_still_refused(self) -> None:
        cfg = BindAddressGuardConfig()
        for addr in ("0.0.0.0", "::", "[::]", "0:0:0:0:0:0:0:0"):
            with pytest.raises((BindAddressPublicError, UnauthenticatedPublicBindError)):
                validate_bind_address(addr, cfg)

    def test_lenient_public_bind_still_needs_auth_when_allowed(self) -> None:
        # allow_public_bind=True, auth_required=False is the exact CVE shape — it
        # must still be refused for a lenient spelling, not only the literal.
        cfg = BindAddressGuardConfig(allow_public_bind=True, auth_required=False)
        with pytest.raises(UnauthenticatedPublicBindError):
            validate_bind_address("0", cfg)
        # with auth asserted, an explicit public bind is allowed
        validate_bind_address(
            "0", BindAddressGuardConfig(allow_public_bind=True, auth_required=True)
        )


class TestLANUnauthSiblingIsFailSafe:
    @pytest.mark.parametrize("addr", ["0", "00.00.00.00", "0x0", "0.0.0.0"])
    def test_alt_notation_all_interfaces_without_auth_is_blocked(self, addr: str) -> None:
        guard = LANUnauthRCEGuard()  # default profile
        verdict = guard.inspect_server({"name": "s", "bind_address": addr, "auth_headers": {}})
        assert verdict.action == "block"

    def test_loopback_without_auth_is_allowed(self) -> None:
        guard = LANUnauthRCEGuard()
        verdict = guard.inspect_server(
            {"name": "s", "bind_address": "127.0.0.1", "auth_headers": {}}
        )
        assert verdict.action == "allow"
