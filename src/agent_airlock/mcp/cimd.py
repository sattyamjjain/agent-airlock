"""CIMD (Client ID Metadata Document) trust-anchor pinning.

The MCP ``2026-07-28`` revision replaces Dynamic Client Registration with **Client ID
Metadata Documents**: the ``client_id`` *is* an https URL, and the client's metadata
document is served from that URL **by the client itself**.

That relocates the trust anchor. Under DCR the authorization server held a registration
record it had issued and could not be edited behind its back. Under CIMD the record lives
on infrastructure the client controls, so "the document I approved" and "the document I am
about to act on" are two different things separated by an HTTP request. A client that was
benign at approval time can rewrite its own ``redirect_uris`` at any later moment, and a
naive implementation re-reads the document on every grant and silently follows it.

This module closes that gap by pinning:

* **Fetch-and-pin** (:meth:`CIMDGuard.approve`) — on first *explicit* approval, hash the
  canonicalised document, record the resolved origin, and persist both.
* **Freshness check at grant time** (:meth:`CIMDGuard.check`) — re-resolve on every
  subsequent grant and compare against the pin. On mismatch **deny by default** and name
  exactly which fields changed. A rotation is never auto-accepted: the caller must call
  :meth:`CIMDGuard.approve` again to move the pin.
* **Origin constraints** — non-https scheme, a host resolving to a private / loopback /
  link-local / metadata address, or a redirect that leaves the original origin are all
  refused before the body is trusted.
* **Revocation** — a document that 404s, or that no longer carries the required fields,
  moves the client to **denied**, not back to unknown. Falling back to "unknown" would let
  a disappearing document look like a first-time client to the next code path.

Deny-by-default throughout: a ``client_id`` with no pin is denied, not trusted-on-first-use.
The pin is only created by an explicit, attributed :meth:`CIMDGuard.approve` call.

The document hash is taken over a **canonical JSON serialisation** (sorted keys, tight
separators) so reformatting alone is not drift, while any semantic change is.

Hooked into the same grant path as the v0.8.70 capability-union boundary — see
:meth:`agent_airlock.capability_caps.engine.CapabilityCapEngine.grant_lease` — so a lease
grant has **one** decision point, not two.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from .._log import structlog
from ..exceptions import AirlockError
from ..ssrf_egress_guard import _blocked_reason, _decode_literal_ip, _default_resolver

__all__ = [
    "CIMD_REQUIRED_FIELDS",
    "CIMDDecision",
    "CIMDDocument",
    "CIMDFieldChange",
    "CIMDGuard",
    "CIMDPin",
    "CIMDPinState",
    "CIMDPinStore",
    "CIMDTrustAnchorError",
    "CIMDVerdict",
    "FetchResult",
    "InMemoryCIMDPinStore",
    "SQLiteCIMDPinStore",
    "cimd_trust_anchor_defaults",
]

logger = structlog.get_logger("agent-airlock.mcp.cimd")

#: Fields a CIMD document must carry to be usable as a trust anchor. ``client_id`` must also
#: equal the URL the document was fetched from (self-consistency); a document that names a
#: different client is not a metadata document for this client.
CIMD_REQUIRED_FIELDS: tuple[str, ...] = ("client_id", "client_name", "redirect_uris")

#: Cap on the document body we will read. A metadata document is small; anything larger is
#: either a mistake or an attempt to exhaust the fetching process.
MAX_DOCUMENT_BYTES = 256 * 1024


class CIMDVerdict(str, Enum):
    """Outcome of one CIMD trust-anchor evaluation."""

    OK = "ok"
    DENY_UNPINNED = "deny_unpinned"
    DENY_DRIFT = "deny_drift"
    DENY_REVOKED = "deny_revoked"
    DENY_MALFORMED = "deny_malformed"
    DENY_SCHEME = "deny_scheme"
    DENY_PRIVATE_ADDRESS = "deny_private_address"
    DENY_CROSS_ORIGIN_REDIRECT = "deny_cross_origin_redirect"
    DENY_FETCH_FAILED = "deny_fetch_failed"


class CIMDPinState(str, Enum):
    """Persistent state of a ``client_id`` in the pin store."""

    PINNED = "pinned"
    REVOKED = "revoked"


@dataclass(frozen=True)
class FetchResult:
    """One document fetch, including the redirect chain that produced it."""

    status: int
    body: str
    url_chain: tuple[str, ...]
    """Every URL visited, starting with the requested one and ending with the final one."""

    @property
    def final_url(self) -> str:
        return self.url_chain[-1] if self.url_chain else ""


@dataclass(frozen=True)
class CIMDDocument:
    """A parsed, canonicalised metadata document."""

    client_id: str
    origin: str
    sha256: str
    fields: Mapping[str, str]
    """Top-level fields, each canonically JSON-encoded, so a diff can name what moved."""


@dataclass(frozen=True)
class CIMDFieldChange:
    """One field that differs between the pin and the freshly-resolved document."""

    field: str
    pinned: str | None
    observed: str | None

    def describe(self) -> str:
        if self.pinned is None:
            return f"{self.field}: added ({self.observed})"
        if self.observed is None:
            return f"{self.field}: removed (was {self.pinned})"
        return f"{self.field}: {self.pinned} -> {self.observed}"


@dataclass(frozen=True)
class CIMDPin:
    """The recorded trust anchor for one ``client_id`` URL."""

    client_id: str
    document_sha256: str
    origin: str
    fields: Mapping[str, str]
    pinned_at: float
    approved_by: str
    state: CIMDPinState = CIMDPinState.PINNED


@dataclass(frozen=True)
class CIMDDecision:
    """Result of evaluating a ``client_id`` against its pin."""

    allowed: bool
    verdict: CIMDVerdict
    client_id: str
    reason: str
    changed_fields: tuple[CIMDFieldChange, ...] = ()
    pin: CIMDPin | None = None
    observed: CIMDDocument | None = None
    fix_hints: tuple[str, ...] = ()

    @property
    def audit_event(self) -> dict[str, Any]:
        """Structured, machine-readable description for the audit / decision log."""
        return {
            "event": "cimd.decision",
            "allowed": self.allowed,
            "verdict": self.verdict.value,
            "client_id": self.client_id,
            "reason": self.reason,
            "changed_fields": [change.field for change in self.changed_fields],
            "pinned_sha256": self.pin.document_sha256 if self.pin else None,
            "observed_sha256": self.observed.sha256 if self.observed else None,
        }


class CIMDTrustAnchorError(AirlockError):
    """Raised when a ``client_id``'s metadata document fails its trust-anchor check."""

    def __init__(self, decision: CIMDDecision) -> None:
        self.decision = decision
        self.verdict = decision.verdict
        self.client_id = decision.client_id
        self.changed_fields = decision.changed_fields
        self.audit_event = decision.audit_event
        self.fix_hints = decision.fix_hints
        super().__init__(decision.reason)


# ---------------------------------------------------------------------------
# Pin storage
# ---------------------------------------------------------------------------


class CIMDPinStore(Protocol):
    """Persistence for CIMD pins."""

    def get(self, client_id: str) -> CIMDPin | None: ...

    def put(self, pin: CIMDPin) -> None: ...

    def delete(self, client_id: str) -> bool: ...


class InMemoryCIMDPinStore:
    """Process-local pin store. Fine for tests; loses pins on restart."""

    def __init__(self) -> None:
        self._pins: dict[str, CIMDPin] = {}
        self._lock = threading.Lock()

    def get(self, client_id: str) -> CIMDPin | None:
        with self._lock:
            return self._pins.get(client_id)

    def put(self, pin: CIMDPin) -> None:
        with self._lock:
            self._pins[pin.client_id] = pin

    def delete(self, client_id: str) -> bool:
        with self._lock:
            return self._pins.pop(client_id, None) is not None


class SQLiteCIMDPinStore:
    """Durable pin store.

    Point this at the same database file as
    :class:`agent_airlock.capability_caps.store.SQLiteCapabilityLedgerStore` and the pins
    live alongside the lease ledger in one file, so a restart restores both together.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS cimd_pins (
        client_id TEXT PRIMARY KEY,
        document_sha256 TEXT NOT NULL,
        origin TEXT NOT NULL,
        fields_json TEXT NOT NULL,
        pinned_at REAL NOT NULL,
        approved_by TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('pinned','revoked'))
    );
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(self._SCHEMA)

    def get(self, client_id: str) -> CIMDPin | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT client_id, document_sha256, origin, fields_json, pinned_at, "
                "approved_by, state FROM cimd_pins WHERE client_id=?",
                (client_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return CIMDPin(
            client_id=row[0],
            document_sha256=row[1],
            origin=row[2],
            fields=json.loads(row[3]),
            pinned_at=row[4],
            approved_by=row[5],
            state=CIMDPinState(row[6]),
        )

    def put(self, pin: CIMDPin) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO cimd_pins (client_id, document_sha256, origin, fields_json, "
                "pinned_at, approved_by, state) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(client_id) DO UPDATE SET document_sha256=excluded.document_sha256, "
                "origin=excluded.origin, fields_json=excluded.fields_json, "
                "pinned_at=excluded.pinned_at, approved_by=excluded.approved_by, "
                "state=excluded.state",
                (
                    pin.client_id,
                    pin.document_sha256,
                    pin.origin,
                    json.dumps(dict(pin.fields), sort_keys=True),
                    pin.pinned_at,
                    pin.approved_by,
                    pin.state.value,
                ),
            )

    def delete(self, client_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM cimd_pins WHERE client_id=?", (client_id,))
            return cur.rowcount > 0

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

Fetcher = Callable[[str], FetchResult]
Resolver = Callable[[str], Sequence[str]]


class _RecordingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that records every hop so origins can be compared afterwards."""

    def __init__(self) -> None:
        super().__init__()
        self.chain: list[str] = []

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        self.chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _urllib_fetcher(url: str, *, timeout: float = 10.0) -> FetchResult:
    """Default fetcher. Records the redirect chain; never raises on 404."""
    handler = _RecordingRedirectHandler()
    opener = urllib.request.build_opener(handler)
    chain: list[str] = [url]
    try:
        with opener.open(url, timeout=timeout) as resp:  # noqa: S310 - scheme checked upstream
            body = resp.read(MAX_DOCUMENT_BYTES).decode("utf-8", errors="replace")
            chain.extend(handler.chain)
            return FetchResult(
                status=getattr(resp, "status", 200), body=body, url_chain=tuple(chain)
            )
    except urllib.error.HTTPError as exc:
        chain.extend(handler.chain)
        body = ""
        # Best-effort: an error response may have no readable body, which is fine — the
        # status code alone drives the revocation decision.
        with contextlib.suppress(Exception):  # pragma: no cover
            body = exc.read(MAX_DOCUMENT_BYTES).decode("utf-8", errors="replace")
        return FetchResult(status=exc.code, body=body, url_chain=tuple(chain))


def _origin_of(url: str) -> str:
    """Normalised ``scheme://host:port`` origin."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    port = parts.port
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return f"{parts.scheme}://{host}:{port}"


def _canonicalise(payload: Mapping[str, Any]) -> tuple[str, dict[str, str]]:
    """Canonical JSON + per-field canonical encodings, for hashing and field-level diffs."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    fields = {
        key: json.dumps(value, sort_keys=True, separators=(",", ":"))
        for key, value in payload.items()
    }
    return canonical, fields


def _resolution_invariant_error(client_id: str) -> CIMDDecision:
    """Fail-closed decision for the "resolve returned neither" case.

    :meth:`CIMDGuard.resolve` returns exactly one of ``(document, None)`` or ``(None, denial)``,
    so this is unreachable. It is written as a real branch rather than an ``assert`` because
    ``assert`` is stripped under ``python -O`` — a narrowing assertion in a security decision
    path would silently become no control flow at all in an optimised deployment.
    """
    return CIMDDecision(
        allowed=False,
        verdict=CIMDVerdict.DENY_FETCH_FAILED,
        client_id=client_id,
        reason=(
            "internal: CIMD resolution returned neither a document nor a denial; failing closed"
        ),
        fix_hints=("This is a bug in agent-airlock — please report it.",),
    )


def _diff_fields(
    pinned: Mapping[str, str], observed: Mapping[str, str]
) -> tuple[CIMDFieldChange, ...]:
    """Every field that differs, named. Sorted so the reason string is deterministic."""
    changes: list[CIMDFieldChange] = []
    for key in sorted(set(pinned) | set(observed)):
        before = pinned.get(key)
        after = observed.get(key)
        if before != after:
            changes.append(CIMDFieldChange(field=key, pinned=before, observed=after))
    return tuple(changes)


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------


@dataclass
class CIMDGuard:
    """Pins a ``client_id`` URL's metadata document and denies on drift.

    Args:
        store: pin persistence. Defaults to an in-memory store.
        fetcher: document fetcher. Injected in tests; defaults to urllib.
        resolver: hostname resolver used for the private-address check.
        required_fields: fields the document must carry to be usable.
        allow_private_addresses: escape hatch for a private-network deployment where the
            client metadata really is served from an internal host. Off by default, and the
            caller owns the consequences.
    """

    store: CIMDPinStore = field(default_factory=InMemoryCIMDPinStore)
    fetcher: Fetcher = _urllib_fetcher
    resolver: Resolver = _default_resolver
    required_fields: tuple[str, ...] = CIMD_REQUIRED_FIELDS
    allow_private_addresses: bool = False

    # -- origin constraints (c) ------------------------------------------------

    def _check_origin(self, client_id: str) -> CIMDDecision | None:
        """Scheme + resolved-address checks. ``None`` means the URL is acceptable."""
        parts = urlsplit(client_id)
        if parts.scheme != "https":
            return CIMDDecision(
                allowed=False,
                verdict=CIMDVerdict.DENY_SCHEME,
                client_id=client_id,
                reason=(
                    f"client_id {client_id!r} uses scheme {parts.scheme or '(none)'!r}; "
                    "a CIMD client_id must be an https URL"
                ),
                fix_hints=("Serve the client metadata document over https.",),
            )
        host = parts.hostname
        if not host:
            return CIMDDecision(
                allowed=False,
                verdict=CIMDVerdict.DENY_SCHEME,
                client_id=client_id,
                reason=f"client_id {client_id!r} has no host component",
                fix_hints=("Use an absolute https URL as the client_id.",),
            )
        if self.allow_private_addresses:
            return None
        return self._check_host_addresses(client_id, host)

    def _check_host_addresses(self, client_id: str, host: str) -> CIMDDecision | None:
        """Deny a host that is, or resolves to, a non-public address."""
        literal = _decode_literal_ip(host)
        if literal is not None:
            blocked = _blocked_reason(literal[0])
            if blocked is not None:
                return self._private_address_denial(client_id, host, str(literal[0]), blocked[1])
            return None
        try:
            addresses = self.resolver(host)
        except Exception as exc:
            return CIMDDecision(
                allowed=False,
                verdict=CIMDVerdict.DENY_FETCH_FAILED,
                client_id=client_id,
                reason=f"could not resolve client_id host {host!r}: {exc}",
                fix_hints=("Confirm the client_id host is publicly resolvable.",),
            )
        for address in addresses:
            decoded = _decode_literal_ip(address)
            if decoded is None:
                continue
            blocked = _blocked_reason(decoded[0])
            if blocked is not None:
                return self._private_address_denial(client_id, host, address, blocked[1])
        return None

    @staticmethod
    def _private_address_denial(
        client_id: str, host: str, address: str, detail: str
    ) -> CIMDDecision:
        return CIMDDecision(
            allowed=False,
            verdict=CIMDVerdict.DENY_PRIVATE_ADDRESS,
            client_id=client_id,
            reason=(
                f"client_id host {host!r} resolves to {address} which is {detail}; "
                "a CIMD trust anchor must be publicly reachable"
            ),
            fix_hints=(
                "Host the metadata document on a public origin.",
                "Set allow_private_addresses=True only for a deliberate internal deployment.",
            ),
        )

    def _check_redirects(self, client_id: str, result: FetchResult) -> CIMDDecision | None:
        """Every hop must stay on the original origin."""
        origin = _origin_of(client_id)
        for hop in result.url_chain:
            if _origin_of(hop) != origin:
                return CIMDDecision(
                    allowed=False,
                    verdict=CIMDVerdict.DENY_CROSS_ORIGIN_REDIRECT,
                    client_id=client_id,
                    reason=(
                        f"client_id {client_id!r} redirected off-origin to {hop!r} "
                        f"({_origin_of(hop)} != {origin}); the metadata document must be "
                        "served by the client_id origin itself"
                    ),
                    fix_hints=("Serve the document directly from the client_id URL.",),
                )
        return None

    # -- resolution ------------------------------------------------------------

    def resolve(self, client_id: str) -> tuple[CIMDDocument | None, CIMDDecision | None]:
        """Fetch + validate a document. Returns ``(document, None)`` or ``(None, denial)``."""
        origin_denial = self._check_origin(client_id)
        if origin_denial is not None:
            return None, origin_denial

        try:
            result = self.fetcher(client_id)
        except Exception as exc:
            return None, CIMDDecision(
                allowed=False,
                verdict=CIMDVerdict.DENY_FETCH_FAILED,
                client_id=client_id,
                reason=f"fetching client_id document failed: {exc}",
                fix_hints=("Confirm the metadata document is reachable.",),
            )

        redirect_denial = self._check_redirects(client_id, result)
        if redirect_denial is not None:
            return None, redirect_denial

        # (d) A document that has gone away revokes the client; it does not become unknown.
        if result.status == 404 or result.status == 410:
            return None, CIMDDecision(
                allowed=False,
                verdict=CIMDVerdict.DENY_REVOKED,
                client_id=client_id,
                reason=(
                    f"client_id document returned HTTP {result.status}; the trust anchor is "
                    "gone and the client is revoked"
                ),
                fix_hints=("Restore the document, then re-approve the client_id explicitly.",),
            )
        if result.status >= 400:
            return None, CIMDDecision(
                allowed=False,
                verdict=CIMDVerdict.DENY_FETCH_FAILED,
                client_id=client_id,
                reason=f"client_id document returned HTTP {result.status}",
                fix_hints=("Confirm the metadata document is served successfully.",),
            )

        try:
            payload = json.loads(result.body)
        except json.JSONDecodeError as exc:
            return None, CIMDDecision(
                allowed=False,
                verdict=CIMDVerdict.DENY_MALFORMED,
                client_id=client_id,
                reason=f"client_id document is not valid JSON: {exc}",
                fix_hints=("Serve a JSON client metadata document.",),
            )
        if not isinstance(payload, dict):
            return None, CIMDDecision(
                allowed=False,
                verdict=CIMDVerdict.DENY_MALFORMED,
                client_id=client_id,
                reason="client_id document must be a JSON object",
                fix_hints=("Serve a JSON object, not an array or scalar.",),
            )

        missing = [name for name in self.required_fields if name not in payload]
        if missing:
            return None, CIMDDecision(
                allowed=False,
                verdict=CIMDVerdict.DENY_MALFORMED,
                client_id=client_id,
                reason=(
                    f"client_id document is missing required field(s): {', '.join(sorted(missing))}"
                ),
                fix_hints=(f"Include {', '.join(self.required_fields)} in the document.",),
            )

        declared = payload.get("client_id")
        if declared != client_id:
            return None, CIMDDecision(
                allowed=False,
                verdict=CIMDVerdict.DENY_MALFORMED,
                client_id=client_id,
                reason=(
                    f"client_id document declares client_id={declared!r}, which does not match "
                    f"the URL it was served from ({client_id!r})"
                ),
                fix_hints=("Set client_id in the document to its own URL.",),
            )

        canonical, fields = _canonicalise(payload)
        document = CIMDDocument(
            client_id=client_id,
            origin=_origin_of(client_id),
            sha256=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            fields=fields,
        )
        return document, None

    # -- (a) fetch-and-pin ------------------------------------------------------

    def approve(self, client_id: str, *, approved_by: str) -> CIMDDecision:
        """Explicitly approve a ``client_id`` and pin its document.

        This is the **only** way a pin is created or moved. It is also the re-approval path
        out of :attr:`CIMDVerdict.DENY_DRIFT` and out of a revoked state.

        Raises:
            CIMDTrustAnchorError: if the document cannot be fetched or validated.
        """
        document, denial = self.resolve(client_id)
        if denial is not None:
            logger.warning(
                "cimd_approve_denied",
                client_id=client_id,
                verdict=denial.verdict.value,
                approved_by=approved_by,
            )
            raise CIMDTrustAnchorError(denial)
        if document is None:  # pragma: no cover - resolve() returns exactly one of the two
            raise CIMDTrustAnchorError(_resolution_invariant_error(client_id))

        previous = self.store.get(client_id)
        pin = CIMDPin(
            client_id=client_id,
            document_sha256=document.sha256,
            origin=document.origin,
            fields=dict(document.fields),
            pinned_at=time.time(),
            approved_by=approved_by,
            state=CIMDPinState.PINNED,
        )
        self.store.put(pin)

        rotated = previous is not None and previous.document_sha256 != document.sha256
        logger.warning(
            "cimd_pin_recorded",
            client_id=client_id,
            sha256=document.sha256,
            origin=document.origin,
            approved_by=approved_by,
            rotated=rotated,
            recovered_from_revoked=(
                previous is not None and previous.state is CIMDPinState.REVOKED
            ),
        )
        return CIMDDecision(
            allowed=True,
            verdict=CIMDVerdict.OK,
            client_id=client_id,
            reason=(
                f"client_id {client_id!r} pinned at {document.sha256[:16]} by {approved_by!r}"
                + (" (rotation approved)" if rotated else "")
            ),
            pin=pin,
            observed=document,
        )

    # -- (b) freshness check + (d) revocation ----------------------------------

    def check(self, client_id: str) -> CIMDDecision:
        """Re-resolve ``client_id`` and compare against its pin. Deny-by-default."""
        pin = self.store.get(client_id)
        if pin is None:
            return CIMDDecision(
                allowed=False,
                verdict=CIMDVerdict.DENY_UNPINNED,
                client_id=client_id,
                reason=(
                    f"client_id {client_id!r} has no pinned metadata document; "
                    "denied by default (no trust on first use)"
                ),
                fix_hints=("Call CIMDGuard.approve(client_id, approved_by=...) to pin it.",),
            )

        if pin.state is CIMDPinState.REVOKED:
            return CIMDDecision(
                allowed=False,
                verdict=CIMDVerdict.DENY_REVOKED,
                client_id=client_id,
                reason=f"client_id {client_id!r} is revoked; explicit re-approval is required",
                pin=pin,
                fix_hints=("Re-approve explicitly once the document is trustworthy again.",),
            )

        document, denial = self.resolve(client_id)
        if denial is not None:
            # (d) A gone/malformed document is sticky: persist the revocation so the next
            # caller sees "revoked", never "unknown".
            if denial.verdict in (CIMDVerdict.DENY_REVOKED, CIMDVerdict.DENY_MALFORMED):
                self.store.put(
                    CIMDPin(
                        client_id=pin.client_id,
                        document_sha256=pin.document_sha256,
                        origin=pin.origin,
                        fields=pin.fields,
                        pinned_at=pin.pinned_at,
                        approved_by=pin.approved_by,
                        state=CIMDPinState.REVOKED,
                    )
                )
                logger.warning(
                    "cimd_revoked",
                    client_id=client_id,
                    verdict=denial.verdict.value,
                    reason=denial.reason,
                )
            return CIMDDecision(
                allowed=False,
                verdict=denial.verdict,
                client_id=client_id,
                reason=denial.reason,
                pin=pin,
                fix_hints=denial.fix_hints,
            )
        if document is None:  # pragma: no cover - resolve() returns exactly one of the two
            return _resolution_invariant_error(client_id)

        if document.sha256 == pin.document_sha256:
            return CIMDDecision(
                allowed=True,
                verdict=CIMDVerdict.OK,
                client_id=client_id,
                reason=f"client_id {client_id!r} matches its pin",
                pin=pin,
                observed=document,
            )

        changes = _diff_fields(pin.fields, document.fields)
        named = "; ".join(change.describe() for change in changes) or "document bytes changed"
        logger.warning(
            "cimd_drift_denied",
            client_id=client_id,
            pinned_sha256=pin.document_sha256,
            observed_sha256=document.sha256,
            changed_fields=[change.field for change in changes],
        )
        return CIMDDecision(
            allowed=False,
            verdict=CIMDVerdict.DENY_DRIFT,
            client_id=client_id,
            reason=(
                f"client_id {client_id!r} metadata document changed since it was pinned "
                f"({pin.document_sha256[:16]} -> {document.sha256[:16]}): {named} — denied by "
                "default; a rotation is never auto-accepted"
            ),
            changed_fields=changes,
            pin=pin,
            observed=document,
            fix_hints=(
                "Review the changed fields above.",
                "If the rotation is legitimate, call approve() again to move the pin.",
            ),
        )

    def check_or_raise(self, client_id: str) -> CIMDDecision:
        """:meth:`check`, raising :class:`CIMDTrustAnchorError` on denial."""
        decision = self.check(client_id)
        if not decision.allowed:
            raise CIMDTrustAnchorError(decision)
        return decision

    def revoke(self, client_id: str, *, reason: str = "manual revocation") -> bool:
        """Move a pinned ``client_id`` to revoked. Returns False if it was never pinned."""
        pin = self.store.get(client_id)
        if pin is None:
            return False
        self.store.put(
            CIMDPin(
                client_id=pin.client_id,
                document_sha256=pin.document_sha256,
                origin=pin.origin,
                fields=pin.fields,
                pinned_at=pin.pinned_at,
                approved_by=pin.approved_by,
                state=CIMDPinState.REVOKED,
            )
        )
        logger.warning("cimd_revoked", client_id=client_id, reason=reason)
        return True


def cimd_trust_anchor_defaults(
    *,
    store: CIMDPinStore | None = None,
    fetcher: Fetcher | None = None,
    resolver: Resolver | None = None,
    allow_private_addresses: bool = False,
) -> CIMDGuard:
    """Construct a :class:`CIMDGuard` with the deny-by-default posture.

    Matches the ``*_defaults()`` convention used by the other guards in this package.
    """
    guard = CIMDGuard(
        store=store if store is not None else InMemoryCIMDPinStore(),
        required_fields=CIMD_REQUIRED_FIELDS,
        allow_private_addresses=allow_private_addresses,
    )
    if fetcher is not None:
        guard.fetcher = fetcher
    if resolver is not None:
        guard.resolver = resolver
    return guard
