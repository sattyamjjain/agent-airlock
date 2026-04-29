"""``ConfigPathGuard`` — config-time path-traversal mitigation (CVE-2026-31402, v0.6.0+).

CVE-2026-31402 (CVSS 8.8, published 2026-04-27) is a path-traversal
in Claude Desktop's MCP-server-registration config loader: a hostile
config injects ``../`` -style paths into ``command`` or ``args`` and
writes outside the sandboxed MCP install dir during first launch.
This is structurally distinct from the STDIO meta-CVE (CVE-2026-30616
class), which is about argv injection at runtime; this guard is
config-time validation, not runtime.

The eight traversal classes covered:

* ``../`` POSIX traversal
* ``..\\`` Windows traversal
* URL-encoded ``%2e%2e`` (single + double encoded)
* UNC paths (``\\\\?\\C:\\`` / ``\\\\server\\share``)
* Symlink escape from ``host_root``
* NULL-byte truncation (``ok\x00/../etc/passwd``)
* Raw absolute paths outside ``host_root``
* Mixed-encoding combinations

Reference
---------
* CVE-2026-31402 (NVD, 2026-04-27):
  https://nvd.nist.gov/vuln/detail/CVE-2026-31402
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Literal
from urllib.parse import unquote

import structlog

from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.config_path_guard")

Verdict = Literal["allow", "block"]
Platform = Literal["posix", "windows", "auto"]


class ConfigPathTraversalError(AirlockError):
    """Raised by :meth:`ConfigPathGuard.evaluate_or_raise` on a block verdict."""

    def __init__(
        self,
        message: str,
        *,
        offending_path: str,
        rule: str,
    ) -> None:
        self.offending_path = offending_path
        self.rule = rule
        super().__init__(message)


@dataclass(frozen=True)
class PathFinding:
    """One offending path entry from a config evaluation."""

    field_name: str
    """Where in the config the path appeared (``"command"``, ``"args[2]"``, …)."""

    raw_value: str
    rule: str
    detail: str = ""


@dataclass(frozen=True)
class ConfigInspection:
    """Result of one ``ConfigPathGuard.evaluate`` call."""

    verdict: Verdict
    findings: tuple[PathFinding, ...] = field(default_factory=tuple)


class ConfigPathGuard:
    """Validate every filesystem path inside an MCP server-registration config.

    The guard operates on the spec's ``{"command", "args", "env",
    "workingDirectory"}`` shape but tolerates extra keys.
    """

    def __init__(
        self,
        *,
        host_root: Path | str,
        platform: Platform = "auto",
        allow_symlinks: bool = False,
    ) -> None:
        self._host_root = Path(host_root).resolve()
        self._platform = platform
        self._allow_symlinks = allow_symlinks

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, server_config: dict[str, Any]) -> ConfigInspection:
        findings: list[PathFinding] = []

        cmd = server_config.get("command")
        if isinstance(cmd, str):
            f = self._inspect("command", cmd)
            if f is not None:
                findings.append(f)

        args = server_config.get("args") or ()
        if isinstance(args, (list, tuple)):
            for idx, value in enumerate(args):
                if isinstance(value, str):
                    f = self._inspect(f"args[{idx}]", value)
                    if f is not None:
                        findings.append(f)

        wd = server_config.get("workingDirectory")
        if isinstance(wd, str):
            f = self._inspect("workingDirectory", wd, must_be_inside_host_root=True)
            if f is not None:
                findings.append(f)

        env = server_config.get("env") or {}
        if isinstance(env, dict):
            for k, v in env.items():
                if isinstance(v, str) and ("/" in v or "\\" in v):
                    f = self._inspect(f"env[{k}]", v)
                    if f is not None:
                        findings.append(f)

        verdict: Verdict = "block" if findings else "allow"
        logger.info(
            "config_path_evaluated",
            verdict=verdict,
            findings=len(findings),
            host_root=str(self._host_root),
        )
        return ConfigInspection(verdict=verdict, findings=tuple(findings))

    def evaluate_or_raise(self, server_config: dict[str, Any]) -> ConfigInspection:
        inspection = self.evaluate(server_config)
        if inspection.verdict == "block":
            f0 = inspection.findings[0]
            raise ConfigPathTraversalError(
                f"config path refused ({f0.rule}): {f0.field_name}={f0.raw_value!r}",
                offending_path=f0.raw_value,
                rule=f0.rule,
            )
        return inspection

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    def _inspect(
        self,
        field_name: str,
        raw: str,
        *,
        must_be_inside_host_root: bool = False,
    ) -> PathFinding | None:
        if "\x00" in raw:
            return PathFinding(
                field_name=field_name,
                raw_value=raw,
                rule="null_byte_truncation",
                detail="path contains an embedded NULL byte",
            )

        decoded_once = unquote(raw)
        decoded_twice = unquote(decoded_once)
        if decoded_twice != decoded_once:
            return PathFinding(
                field_name=field_name,
                raw_value=raw,
                rule="double_encoded",
                detail=(
                    f"path decodes through two URL-decode passes ({raw!r} → "
                    f"{decoded_once!r} → {decoded_twice!r})"
                ),
            )

        decoded = decoded_once
        if any(ch in decoded for ch in ("\x01", "\x02", "\x03")):
            return PathFinding(
                field_name=field_name,
                raw_value=raw,
                rule="control_char",
                detail="path contains low-range control characters",
            )

        platform = self._platform
        if platform == "auto":
            platform = "windows" if sys.platform.startswith("win") else "posix"

        if platform == "windows":
            traversal = self._inspect_windows(decoded)
        else:
            traversal = self._inspect_posix(decoded)
        if traversal is not None:
            return PathFinding(
                field_name=field_name,
                raw_value=raw,
                rule=traversal,
                detail=f"decoded value: {decoded!r}",
            )

        if must_be_inside_host_root:
            try:
                resolved = Path(decoded).expanduser().resolve(strict=False)
            except OSError:
                return PathFinding(
                    field_name=field_name,
                    raw_value=raw,
                    rule="unresolvable",
                    detail="path could not be resolved",
                )
            if not self._is_inside(resolved):
                return PathFinding(
                    field_name=field_name,
                    raw_value=raw,
                    rule="absolute_outside_host_root",
                    detail=(f"resolved {resolved!s} is outside host_root {self._host_root!s}"),
                )
            if not self._allow_symlinks and resolved.is_symlink():
                return PathFinding(
                    field_name=field_name,
                    raw_value=raw,
                    rule="symlink_escape",
                    detail=f"{resolved!s} is a symlink",
                )

        return None

    def _inspect_posix(self, decoded: str) -> str | None:
        if "../" in decoded or decoded == ".." or decoded.endswith("/.."):
            return "posix_dot_dot_traversal"
        # Absolute path that is NOT under host_root after normalisation.
        try:
            pp = PurePosixPath(decoded)
        except ValueError:
            return "unparseable"
        if pp.is_absolute():
            normalised = os.path.normpath(decoded)
            try:
                resolved = Path(normalised).expanduser().resolve(strict=False)
            except OSError:
                return "unresolvable"
            if not self._is_inside(resolved):
                return "absolute_outside_host_root"
        return None

    def _inspect_windows(self, decoded: str) -> str | None:
        if "..\\" in decoded or "../" in decoded or decoded.endswith(".."):
            return "windows_dot_dot_traversal"
        if decoded.startswith(("\\\\?\\", "\\\\.\\")):
            return "windows_unc_or_devicepath"
        if decoded.startswith("\\\\"):
            return "windows_unc"
        try:
            pp = PureWindowsPath(decoded)
        except ValueError:
            return "unparseable"
        if pp.is_absolute():
            try:
                resolved = Path(decoded).resolve(strict=False)
            except OSError:
                return "unresolvable"
            if not self._is_inside(resolved):
                return "absolute_outside_host_root"
        return None

    def _is_inside(self, candidate: Path) -> bool:
        try:
            candidate.relative_to(self._host_root)
            return True
        except ValueError:
            return False


__all__ = [
    "ConfigInspection",
    "ConfigPathGuard",
    "ConfigPathTraversalError",
    "PathFinding",
    "Platform",
    "Verdict",
]
