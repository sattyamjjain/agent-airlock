"""Tests for cli/doctor.py module (V0.4.0)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from agent_airlock.cli.doctor import (
    DoctorReport,
    DoctorScanner,
    Issue,
    doctor,
)


class TestIssue:
    """Test the Issue dataclass."""

    def test_basic_issue(self) -> None:
        """Test creating a basic issue."""
        issue = Issue(
            file=Path("/app/code.py"),
            line=42,
            severity="warning",
            code="AIRLOCK001",
            message="Test message",
        )
        assert issue.file == Path("/app/code.py")
        assert issue.line == 42
        assert issue.severity == "warning"
        assert issue.code == "AIRLOCK001"

    def test_issue_with_suggestion(self) -> None:
        """Test issue with suggestion."""
        issue = Issue(
            file=Path("/app/code.py"),
            line=42,
            severity="error",
            code="AIRLOCK002",
            message="Dangerous pattern detected",
            suggestion="Use Airlock with sandbox=True",
        )
        assert issue.suggestion == "Use Airlock with sandbox=True"


class TestDoctorReport:
    """Test the DoctorReport dataclass."""

    def test_empty_report(self) -> None:
        """Test empty report."""
        report = DoctorReport()
        assert report.files_scanned == 0
        assert report.protected_tools == 0
        assert report.unprotected_tools == 0
        assert report.issues == []

    def test_has_errors_false(self) -> None:
        """Test has_errors is False when no errors."""
        report = DoctorReport(
            issues=[
                Issue(
                    file=Path("test.py"),
                    line=1,
                    severity="warning",
                    code="AIRLOCK001",
                    message="Warning",
                )
            ]
        )
        assert report.has_errors is False

    def test_has_errors_true(self) -> None:
        """Test has_errors is True when errors exist."""
        report = DoctorReport(
            issues=[
                Issue(
                    file=Path("test.py"),
                    line=1,
                    severity="error",
                    code="AIRLOCK002",
                    message="Error",
                )
            ]
        )
        assert report.has_errors is True

    def test_has_warnings_false(self) -> None:
        """Test has_warnings is False when no warnings."""
        report = DoctorReport(issues=[])
        assert report.has_warnings is False

    def test_has_warnings_true(self) -> None:
        """Test has_warnings is True when warnings exist."""
        report = DoctorReport(
            issues=[
                Issue(
                    file=Path("test.py"),
                    line=1,
                    severity="warning",
                    code="AIRLOCK001",
                    message="Warning",
                )
            ]
        )
        assert report.has_warnings is True


class TestDoctorScanner:
    """Test the DoctorScanner class."""

    def test_scan_empty_directory(self) -> None:
        """Test scanning an empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = DoctorScanner(Path(tmpdir))
            report = scanner.scan()
            assert report.files_scanned == 0

    def test_scan_finds_unprotected_tool(self) -> None:
        """Test scanner finds unprotected tool decorator."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create file with unprotected tool
            code = """
from some_lib import tool

@tool
def my_tool(x: int) -> int:
    return x * 2
"""
            (Path(tmpdir) / "tools.py").write_text(code)

            scanner = DoctorScanner(Path(tmpdir))
            report = scanner.scan()

            assert report.files_scanned == 1
            assert report.unprotected_tools == 1
            assert any(i.code == "AIRLOCK001" for i in report.issues)

    def test_scan_recognizes_protected_tool(self) -> None:
        """Test scanner recognizes protected tool."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
from some_lib import tool
from agent_airlock import Airlock

@Airlock()
@tool
def my_tool(x: int) -> int:
    return x * 2
"""
            (Path(tmpdir) / "tools.py").write_text(code)

            scanner = DoctorScanner(Path(tmpdir))
            report = scanner.scan()

            assert report.protected_tools == 1
            assert report.unprotected_tools == 0

    def test_scan_detects_subprocess_shell(self) -> None:
        """Test scanner detects subprocess with shell=True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
import subprocess

def run_command(cmd: str) -> str:
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout.decode()
"""
            (Path(tmpdir) / "utils.py").write_text(code)

            scanner = DoctorScanner(Path(tmpdir))
            report = scanner.scan()

            assert any(i.code == "AIRLOCK002" for i in report.issues)

    def test_scan_detects_os_system(self) -> None:
        """Test scanner detects os.system()."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
import os

def run_command(cmd: str) -> int:
    return os.system(cmd)
"""
            (Path(tmpdir) / "utils.py").write_text(code)

            scanner = DoctorScanner(Path(tmpdir))
            report = scanner.scan()

            assert any(i.code == "AIRLOCK002" for i in report.issues)

    def test_scan_detects_eval(self) -> None:
        """Test scanner detects eval()."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
def dangerous(code: str):
    return eval(code)
"""
            (Path(tmpdir) / "utils.py").write_text(code)

            scanner = DoctorScanner(Path(tmpdir))
            report = scanner.scan()

            assert any(i.code == "AIRLOCK003" for i in report.issues)

    def test_scan_detects_exec(self) -> None:
        """Test scanner detects exec()."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
def dangerous(code: str):
    exec(code)
"""
            (Path(tmpdir) / "utils.py").write_text(code)

            scanner = DoctorScanner(Path(tmpdir))
            report = scanner.scan()

            assert any(i.code == "AIRLOCK003" for i in report.issues)

    def test_scan_detects_kwargs_in_tool(self) -> None:
        """Test scanner detects **kwargs in tool functions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
from some_lib import tool

@tool
def my_tool(**kwargs):
    return kwargs
"""
            (Path(tmpdir) / "tools.py").write_text(code)

            scanner = DoctorScanner(Path(tmpdir))
            report = scanner.scan()

            assert any(i.code == "AIRLOCK004" for i in report.issues)

    def test_scan_detects_hardcoded_api_key(self) -> None:
        """Test scanner detects hardcoded API keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
api_key = "sk_test_FAKE_KEY_FOR_TESTING_1234567890"
"""
            (Path(tmpdir) / "config.py").write_text(code)

            scanner = DoctorScanner(Path(tmpdir))
            report = scanner.scan()

            assert any(i.code == "AIRLOCK005" for i in report.issues)

    def test_scan_detects_hardcoded_password(self) -> None:
        """Test scanner detects hardcoded passwords."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
password = "mysecretpassword"
"""
            (Path(tmpdir) / "config.py").write_text(code)

            scanner = DoctorScanner(Path(tmpdir))
            report = scanner.scan()

            assert any(i.code == "AIRLOCK005" for i in report.issues)

    def test_scan_skips_venv(self) -> None:
        """Test scanner skips venv directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create venv directory with problematic code
            venv_dir = Path(tmpdir) / "venv" / "lib"
            venv_dir.mkdir(parents=True)
            code = """
import os
os.system("rm -rf /")
"""
            (venv_dir / "dangerous.py").write_text(code)

            scanner = DoctorScanner(Path(tmpdir))
            report = scanner.scan()

            # Should not find issues in venv
            assert report.files_scanned == 0

    def test_scan_skips_pycache(self) -> None:
        """Test scanner skips __pycache__ directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pycache_dir = Path(tmpdir) / "__pycache__"
            pycache_dir.mkdir()
            (pycache_dir / "module.cpython-311.py").write_text("eval('bad')")

            scanner = DoctorScanner(Path(tmpdir))
            report = scanner.scan()

            assert report.files_scanned == 0


class TestDoctorFunction:
    """Test the doctor() function."""

    def test_doctor_returns_report(self) -> None:
        """Test doctor function returns a report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            report = doctor(path=tmpdir)
            assert isinstance(report, DoctorReport)

    def test_doctor_text_output(self, capsys: pytest.CaptureFixture) -> None:
        """Test doctor function with text output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            doctor(path=tmpdir, output_format="text")
            captured = capsys.readouterr()
            assert "Airlock Doctor Report" in captured.out

    def test_doctor_json_output(self, capsys: pytest.CaptureFixture) -> None:
        """Test doctor function with JSON output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            doctor(path=tmpdir, output_format="json")
            captured = capsys.readouterr()
            assert "files_scanned" in captured.out
            assert "issues" in captured.out


class TestMultipleToolDecorators:
    """Test scanning with different tool decorator styles."""

    def test_function_tool_decorator(self) -> None:
        """Test scanning @function_tool decorator."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
from agents import function_tool

@function_tool
def my_tool(x: int) -> int:
    return x * 2
"""
            (Path(tmpdir) / "tools.py").write_text(code)

            scanner = DoctorScanner(Path(tmpdir))
            report = scanner.scan()

            assert report.unprotected_tools == 1

    def test_secure_tool_decorator(self) -> None:
        """Test scanning @secure_tool decorator."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
from agent_airlock.mcp import secure_tool

@secure_tool
def my_tool(x: int) -> int:
    return x * 2
"""
            (Path(tmpdir) / "tools.py").write_text(code)

            scanner = DoctorScanner(Path(tmpdir))
            report = scanner.scan()

            # secure_tool is detected as a tool but not protected by @Airlock
            # The scanner checks for explicit @Airlock decorator
            assert report.unprotected_tools == 1

    def test_mcp_tool_decorator(self) -> None:
        """Test scanning @mcp.tool decorator."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
from mcp import mcp

@mcp.tool
def my_tool(x: int) -> int:
    return x * 2
"""
            (Path(tmpdir) / "tools.py").write_text(code)

            scanner = DoctorScanner(Path(tmpdir))
            report = scanner.scan()

            assert report.unprotected_tools == 1
