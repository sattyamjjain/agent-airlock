"""Airlock doctor command for Agent-Airlock (V0.4.0).

Scans a codebase for security issues and suggests improvements:
- Unprotected tool decorators
- Unsafe patterns (**kwargs, subprocess.shell)
- Missing Airlock imports
- Potential secret exposure
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import structlog

logger = structlog.get_logger("agent-airlock.cli.doctor")


@dataclass
class Issue:
    """A detected issue in the codebase."""

    file: Path
    line: int
    severity: str  # "error", "warning", "info"
    code: str  # Issue code like "AIRLOCK001"
    message: str
    suggestion: str | None = None


@dataclass
class DoctorReport:
    """Report from the doctor scan."""

    issues: list[Issue] = field(default_factory=list)
    files_scanned: int = 0
    protected_tools: int = 0
    unprotected_tools: int = 0

    @property
    def has_errors(self) -> bool:
        return any(i.severity == "error" for i in self.issues)

    @property
    def has_warnings(self) -> bool:
        return any(i.severity == "warning" for i in self.issues)


class DoctorScanner:
    """Scanner for detecting security issues in Python code."""

    # Patterns that indicate tool decorators
    TOOL_DECORATORS = [
        r"@tool\b",
        r"@function_tool\b",
        r"@secure_tool\b",
        r"@mcp\.tool\b",
    ]

    # Patterns that indicate Airlock protection
    AIRLOCK_DECORATORS = [
        r"@Airlock\b",
        r"@airlock\b",
        r"@MCPAirlock\b",
    ]

    # Dangerous patterns
    DANGEROUS_PATTERNS = [
        (
            r"subprocess\.call.*shell\s*=\s*True",
            "AIRLOCK002",
            "subprocess with shell=True detected",
        ),
        (r"subprocess\.run.*shell\s*=\s*True", "AIRLOCK002", "subprocess with shell=True detected"),
        (r"os\.system\(", "AIRLOCK002", "os.system() detected"),
        (r"eval\(", "AIRLOCK003", "eval() detected"),
        (r"exec\(", "AIRLOCK003", "exec() detected"),
    ]

    # Patterns that indicate kwargs acceptance (bypasses schema)
    KWARGS_PATTERN = r"def\s+\w+\s*\([^)]*\*\*kwargs[^)]*\)"

    def __init__(self, path: Path) -> None:
        """Initialize scanner.

        Args:
            path: Root path to scan.
        """
        self.path = path
        self.report = DoctorReport()

    def scan(self) -> DoctorReport:
        """Scan the codebase.

        Returns:
            DoctorReport with all detected issues.
        """
        for py_file in self.path.rglob("*.py"):
            # Skip virtual environments and caches
            path_str = str(py_file)
            if any(
                skip in path_str
                for skip in ["venv", ".venv", "__pycache__", ".git", "node_modules"]
            ):
                continue

            self._scan_file(py_file)

        return self.report

    def _scan_file(self, file: Path) -> None:
        """Scan a single Python file."""
        try:
            content = file.read_text()
        except Exception as e:
            logger.debug("file_read_error", file=str(file), error=str(e))
            return

        self.report.files_scanned += 1
        lines = content.split("\n")

        # Check for tool decorators without Airlock
        self._check_unprotected_tools(file, content, lines)

        # Check for dangerous patterns
        self._check_dangerous_patterns(file, content, lines)

        # Check for **kwargs in tool functions
        self._check_kwargs_usage(file, content, lines)

        # Check for potential secrets
        self._check_secrets(file, content, lines)

    def _check_unprotected_tools(self, file: Path, content: str, lines: list[str]) -> None:
        """Check for tool decorators without Airlock protection."""
        tool_pattern = "|".join(self.TOOL_DECORATORS)
        airlock_pattern = "|".join(self.AIRLOCK_DECORATORS)

        for i, line in enumerate(lines):
            if re.search(tool_pattern, line):
                self.report.unprotected_tools += 1

                # Check if Airlock is applied nearby (within 5 lines above)
                context_start = max(0, i - 5)
                context = "\n".join(lines[context_start : i + 1])

                if re.search(airlock_pattern, context):
                    self.report.protected_tools += 1
                    self.report.unprotected_tools -= 1
                else:
                    self.report.issues.append(
                        Issue(
                            file=file,
                            line=i + 1,
                            severity="warning",
                            code="AIRLOCK001",
                            message="Tool decorator without @Airlock protection",
                            suggestion="Add @Airlock() decorator above the @tool decorator",
                        )
                    )

    def _check_dangerous_patterns(self, file: Path, content: str, lines: list[str]) -> None:
        """Check for dangerous code patterns."""
        for pattern, code, message in self.DANGEROUS_PATTERNS:
            for i, line in enumerate(lines):
                if re.search(pattern, line):
                    self.report.issues.append(
                        Issue(
                            file=file,
                            line=i + 1,
                            severity="error",
                            code=code,
                            message=message,
                            suggestion="Use Airlock with sandbox=True for dangerous operations",
                        )
                    )

    def _check_kwargs_usage(self, file: Path, content: str, lines: list[str]) -> None:
        """Check for **kwargs in function signatures."""
        for i, line in enumerate(lines):
            if re.search(self.KWARGS_PATTERN, line):
                # Check if this is a tool function (has @tool nearby)
                context_start = max(0, i - 5)
                context = "\n".join(lines[context_start : i + 1])

                tool_pattern = "|".join(self.TOOL_DECORATORS)
                if re.search(tool_pattern, context):
                    self.report.issues.append(
                        Issue(
                            file=file,
                            line=i + 1,
                            severity="warning",
                            code="AIRLOCK004",
                            message="Tool function accepts **kwargs (bypasses schema validation)",
                            suggestion="Define explicit parameters instead of **kwargs",
                        )
                    )

    def _check_secrets(self, file: Path, content: str, lines: list[str]) -> None:
        """Check for potential hardcoded secrets."""
        secret_patterns = [
            (r'api_key\s*=\s*["\'][A-Za-z0-9_-]{20,}["\']', "potential API key"),
            (r'password\s*=\s*["\'][^"\']+["\']', "potential hardcoded password"),
            (r'secret\s*=\s*["\'][A-Za-z0-9_-]{20,}["\']', "potential secret"),
            (r'AWS_SECRET_ACCESS_KEY\s*=\s*["\'][^"\']+["\']', "AWS secret key"),
        ]

        for pattern, desc in secret_patterns:
            for i, line in enumerate(lines):
                if re.search(pattern, line, re.IGNORECASE):
                    self.report.issues.append(
                        Issue(
                            file=file,
                            line=i + 1,
                            severity="error",
                            code="AIRLOCK005",
                            message=f"Potential hardcoded secret: {desc}",
                            suggestion="Use environment variables or a secrets manager",
                        )
                    )


def doctor(path: str = ".", output_format: str = "text") -> DoctorReport:
    """Run the Airlock doctor on a codebase.

    Args:
        path: Root path to scan.
        output_format: Output format ("text" or "json").

    Returns:
        DoctorReport with all detected issues.
    """
    scanner = DoctorScanner(Path(path))
    report = scanner.scan()

    if output_format == "text":
        _print_report(report)
    elif output_format == "json":
        _print_json_report(report)

    return report


def _print_report(report: DoctorReport) -> None:
    """Print report in human-readable format."""
    print("\n=== Airlock Doctor Report ===\n")

    print(f"Files scanned: {report.files_scanned}")
    print(f"Protected tools: {report.protected_tools}")
    print(f"Unprotected tools: {report.unprotected_tools}")
    print()

    if not report.issues:
        print("No issues found!")
        return

    # Group by severity
    errors = [i for i in report.issues if i.severity == "error"]
    warnings = [i for i in report.issues if i.severity == "warning"]
    info = [i for i in report.issues if i.severity == "info"]

    if errors:
        print(f"Errors ({len(errors)}):")
        for issue in errors:
            print(f"  {issue.file}:{issue.line}")
            print(f"    [{issue.code}] {issue.message}")
            if issue.suggestion:
                print(f"    Suggestion: {issue.suggestion}")
        print()

    if warnings:
        print(f"Warnings ({len(warnings)}):")
        for issue in warnings:
            print(f"  {issue.file}:{issue.line}")
            print(f"    [{issue.code}] {issue.message}")
            if issue.suggestion:
                print(f"    Suggestion: {issue.suggestion}")
        print()

    if info:
        print(f"Info ({len(info)}):")
        for issue in info:
            print(f"  {issue.file}:{issue.line} - {issue.message}")
        print()

    # Summary
    if report.has_errors:
        print("Status: FAILED - Security issues found")
    elif report.has_warnings:
        print("Status: WARNING - Potential issues found")
    else:
        print("Status: PASSED")


def _print_json_report(report: DoctorReport) -> None:
    """Print report in JSON format."""
    import json

    data = {
        "files_scanned": report.files_scanned,
        "protected_tools": report.protected_tools,
        "unprotected_tools": report.unprotected_tools,
        "issues": [
            {
                "file": str(i.file),
                "line": i.line,
                "severity": i.severity,
                "code": i.code,
                "message": i.message,
                "suggestion": i.suggestion,
            }
            for i in report.issues
        ],
        "has_errors": report.has_errors,
        "has_warnings": report.has_warnings,
    }

    print(json.dumps(data, indent=2))


# CLI entry point (for use with click or argparse)
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

    report = doctor(path, output_format)

    return 1 if report.has_errors else 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
