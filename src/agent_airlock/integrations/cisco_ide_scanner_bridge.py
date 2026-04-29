"""Bridge to Cisco IDE Security Scanner (v0.5.9+).

Cisco co-launched its IDE Security Scanner on 2026-04-21 with a
hosted scanning endpoint. The bridge plugs the Cisco endpoint into
airlock's pluggable scanner registry so the VS Code policy-lens can
surface Cisco findings inline alongside airlock's own.

Privacy posture
----------------

* Bridge is **opt-in**. ``is_configured()`` returns ``False`` until
  the operator sets ``AIRLOCK_CISCO_SCANNER_API_BASE`` and either
  ``AIRLOCK_CISCO_SCANNER_API_KEY`` or supplies the same values via
  the constructor.
* Zero PII / source content leaves the workstation when the bridge
  is unconfigured.
* Even when configured, the lens UI must obtain explicit per-file
  user consent — the bridge ships the protocol, not a policy.
* Cisco's hosted API contract was not yet public at v0.5.9 ship
  time. The bridge therefore defaults to a 410 ("configure when API
  published") response, and is one drop-in replacement away from
  going live when the contract stabilises.

Reference
---------
* Cisco IDE Security Scanner co-launch (2026-04-21):
  https://blogs.cisco.com/security/ide-security-scanner-launch-2026-04
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import structlog

from .scanners import Finding

logger = structlog.get_logger("agent-airlock.integrations.cisco_ide_scanner_bridge")

DEFAULT_NAME: str = "cisco-ide-scanner"
DEFAULT_TIMEOUT_S: float = 10.0


class CiscoIDEScannerBridge:
    """Pluggable bridge to the Cisco IDE Security Scanner endpoint."""

    name: str = DEFAULT_NAME

    def __init__(
        self,
        *,
        api_base: str | None = None,
        api_key: str | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        http_post: Callable[..., Any] | None = None,
    ) -> None:
        self._api_base = api_base or os.environ.get(
            "AIRLOCK_CISCO_SCANNER_API_BASE", ""
        )
        self._api_key = api_key or os.environ.get(
            "AIRLOCK_CISCO_SCANNER_API_KEY", ""
        )
        self._timeout_s = timeout_s
        self._http_post = http_post  # injected for tests

    # ------------------------------------------------------------------
    # Scanner protocol
    # ------------------------------------------------------------------

    def is_configured(self) -> bool:
        return bool(self._api_base and self._api_key)

    def scan_file(
        self,
        path: Path | str,
        source: str | None = None,
    ) -> list[Finding]:
        """Submit ``path`` to the Cisco endpoint, return the findings.

        With the bridge unconfigured, returns an empty list — the
        operator gets exactly zero behaviour change unless they
        explicitly enable it.
        """
        if not self.is_configured():
            logger.debug("cisco_scanner_unconfigured", path=str(path))
            return []

        path = Path(path)
        if source is None:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.warning(
                    "cisco_scanner_read_failed", path=str(path), error=str(exc)
                )
                return []

        payload = {
            "filename": path.name,
            "source": source,
        }
        try:
            raw = self._post(payload)
        except Exception as exc:  # network / decode failure
            logger.warning(
                "cisco_scanner_request_failed",
                path=str(path),
                error=str(exc),
            )
            return []

        findings: list[Finding] = []
        for entry in raw.get("findings", []):
            if not isinstance(entry, dict):
                continue
            findings.append(
                Finding(
                    scanner_id=self.name,
                    rule_id=str(entry.get("rule_id", "unknown")),
                    severity=str(entry.get("severity", "low")),
                    message=str(entry.get("message", "")),
                    file_path=str(path),
                    line=int(entry.get("line", 0) or 0),
                    column=int(entry.get("column", 0) or 0),
                    metadata=dict(entry.get("metadata", {})),
                )
            )
        return findings

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        """POST to the Cisco endpoint.

        Until the API contract is public, returns a stub
        ``410 / configure-when-published`` response. Tests inject a
        callable via ``http_post=`` to bypass the network entirely.
        """
        if self._http_post is not None:
            base = (self._api_base or "").rstrip("/")
            response = self._http_post(
                f"{base}/scan",
                json=payload,
                headers=self._headers(),
                timeout=self._timeout_s,
            )
            return dict(response) if response else {}

        # Real-network code path is intentionally a placeholder until
        # Cisco publishes the contract. Implementations should replace
        # this with a ``urllib.request`` call (no new runtime dep) or
        # an injected ``requests``-shaped client.
        logger.info(
            "cisco_scanner_protocol_stub",
            note="Cisco IDE Security Scanner API contract not yet public",
        )
        return {
            "status": 410,
            "message": "configure when API published",
            "findings": [],
        }

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "User-Agent": "agent-airlock/cisco-ide-scanner-bridge",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }


__all__ = [
    "DEFAULT_NAME",
    "DEFAULT_TIMEOUT_S",
    "CiscoIDEScannerBridge",
]
