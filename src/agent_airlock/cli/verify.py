"""Airlock verify command for Agent-Airlock (V0.4.0).

Verifies Airlock protection status and generates badge information:
- Protected: STRICT_POLICY + sandbox_required + audit enabled
- Lite: Basic protection (types + ghost args only)
- Unsealed: No tool-call firewall

This is used by the GitHub Action to generate badges.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger("agent-airlock.cli.verify")


@dataclass
class VerificationResult:
    """Result of verification scan."""

    seal_status: str  # "protected", "lite", "unsealed"
    protected_count: int
    lite_count: int
    unsealed_count: int
    details: dict[str, Any]

    @property
    def badge_color(self) -> str:
        """Get badge color for GitHub."""
        if self.seal_status == "protected":
            return "brightgreen"
        elif self.seal_status == "lite":
            return "yellow"
        else:
            return "red"

    @property
    def badge_label(self) -> str:
        """Get badge label."""
        if self.seal_status == "protected":
            return "Protected by Airlock"
        elif self.seal_status == "lite":
            return "Airlock-Lite"
        else:
            return "Unsealed Agent"


class VerificationScanner:
    """Scanner for verifying Airlock protection status."""

    def __init__(self, path: Path) -> None:
        """Initialize scanner."""
        self.path = path
        self.protected_count = 0
        self.lite_count = 0
        self.unsealed_count = 0
        self.details: dict[str, Any] = {
            "strict_mode_tools": [],
            "sandbox_tools": [],
            "basic_tools": [],
            "unprotected_tools": [],
        }

    def scan(self) -> VerificationResult:
        """Scan codebase for protection status."""
        for py_file in self.path.rglob("*.py"):
            path_str = str(py_file)
            if any(skip in path_str for skip in ["venv", ".venv", "__pycache__", ".git"]):
                continue

            self._scan_file(py_file)

        # Determine overall seal status
        total = self.protected_count + self.lite_count + self.unsealed_count
        if total == 0:
            seal_status = "unsealed"  # No tools found
        elif self.unsealed_count == 0 and self.lite_count == 0:
            seal_status = "protected"
        elif self.unsealed_count == 0:
            seal_status = "lite"
        else:
            seal_status = "unsealed"

        return VerificationResult(
            seal_status=seal_status,
            protected_count=self.protected_count,
            lite_count=self.lite_count,
            unsealed_count=self.unsealed_count,
            details=self.details,
        )

    def _scan_file(self, file: Path) -> None:
        """Scan a single file."""
        try:
            content = file.read_text()
        except Exception:
            return

        lines = content.split("\n")

        # Find tool functions
        tool_pattern = r"@(tool|function_tool|secure_tool|mcp\.tool)\b"

        for i, line in enumerate(lines):
            if re.search(tool_pattern, line):
                func_name = self._extract_function_name(lines, i)
                protection = self._check_protection_level(lines, i)

                if protection == "protected":
                    self.protected_count += 1
                    self.details["strict_mode_tools"].append(f"{file.name}:{func_name}")
                elif protection == "sandbox":
                    self.protected_count += 1
                    self.details["sandbox_tools"].append(f"{file.name}:{func_name}")
                elif protection == "basic":
                    self.lite_count += 1
                    self.details["basic_tools"].append(f"{file.name}:{func_name}")
                else:
                    self.unsealed_count += 1
                    self.details["unprotected_tools"].append(f"{file.name}:{func_name}")

    def _extract_function_name(self, lines: list[str], decorator_line: int) -> str:
        """Extract function name from decorator position."""
        for i in range(decorator_line, min(decorator_line + 10, len(lines))):
            match = re.search(r"def\s+(\w+)\s*\(", lines[i])
            if match:
                return match.group(1)
        return "unknown"

    def _check_protection_level(self, lines: list[str], decorator_line: int) -> str:
        """Check protection level at decorator position.

        Returns:
            "protected" - STRICT_POLICY or strict_mode + sandbox
            "sandbox" - sandbox=True
            "basic" - @Airlock() with defaults
            "none" - no Airlock decorator
        """
        context_start = max(0, decorator_line - 10)
        context = "\n".join(lines[context_start : decorator_line + 1])

        # Check for Airlock decorator
        if not re.search(r"@Airlock|@MCPAirlock", context):
            return "none"

        # Check for STRICT_POLICY or strict_mode=True
        if re.search(r"STRICT_POLICY|strict_mode\s*=\s*True|unknown_args\s*=.*BLOCK", context):
            return "protected"

        # Check for sandbox=True
        if re.search(r"sandbox\s*=\s*True", context):
            return "sandbox"

        # Basic protection
        return "basic"


def verify(path: str = ".", output_format: str = "text") -> VerificationResult:
    """Verify Airlock protection status.

    Args:
        path: Root path to scan.
        output_format: Output format ("text", "json", or "badge").

    Returns:
        VerificationResult with protection status.
    """
    scanner = VerificationScanner(Path(path))
    result = scanner.scan()

    if output_format == "text":
        _print_result(result)
    elif output_format == "json":
        _print_json_result(result)
    elif output_format == "badge":
        _print_badge_url(result)

    return result


def _print_result(result: VerificationResult) -> None:
    """Print result in human-readable format."""
    print("\n=== Airlock Verification Report ===\n")

    # Status badge
    if result.seal_status == "protected":
        print("Status: Protected by Airlock")
    elif result.seal_status == "lite":
        print("Status: Airlock-Lite")
    else:
        print("Status: Unsealed Agent")

    print()
    print(f"Protected tools (STRICT/sandbox): {result.protected_count}")
    print(f"Lite protection (basic Airlock): {result.lite_count}")
    print(f"Unprotected tools: {result.unsealed_count}")
    print()

    if result.details["strict_mode_tools"]:
        print("STRICT/protected tools:")
        for tool in result.details["strict_mode_tools"][:5]:
            print(f"  {tool}")
        if len(result.details["strict_mode_tools"]) > 5:
            print(f"  ... and {len(result.details['strict_mode_tools']) - 5} more")

    if result.details["unprotected_tools"]:
        print("\nUnprotected tools (needs Airlock):")
        for tool in result.details["unprotected_tools"][:5]:
            print(f"  {tool}")
        if len(result.details["unprotected_tools"]) > 5:
            print(f"  ... and {len(result.details['unprotected_tools']) - 5} more")


def _print_json_result(result: VerificationResult) -> None:
    """Print result in JSON format."""
    import json

    data = {
        "seal_status": result.seal_status,
        "protected_count": result.protected_count,
        "lite_count": result.lite_count,
        "unsealed_count": result.unsealed_count,
        "badge_color": result.badge_color,
        "badge_label": result.badge_label,
        "details": result.details,
    }

    print(json.dumps(data, indent=2))


def _print_badge_url(result: VerificationResult) -> None:
    """Print shields.io badge URL."""
    from urllib.parse import quote

    label = quote(result.badge_label)
    color = result.badge_color

    url = f"https://img.shields.io/badge/{label}-{color}"
    print(url)


def main() -> int:
    """CLI entry point."""
    import sys

    args = sys.argv[1:]

    path = "."
    output_format = "text"

    for i, arg in enumerate(args):
        if arg == "--path" and i + 1 < len(args):
            path = args[i + 1]
        elif arg == "--json":
            output_format = "json"
        elif arg == "--badge":
            output_format = "badge"

    result = verify(path, output_format)

    # Exit code based on seal status
    if result.seal_status == "unsealed":
        return 1
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
