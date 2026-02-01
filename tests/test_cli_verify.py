"""Tests for cli/verify.py module (V0.4.0)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from agent_airlock.cli.verify import (
    VerificationResult,
    VerificationScanner,
    verify,
)


class TestVerificationResult:
    """Test the VerificationResult dataclass."""

    def test_protected_status(self) -> None:
        """Test protected seal status."""
        result = VerificationResult(
            seal_status="protected",
            protected_count=5,
            lite_count=0,
            unsealed_count=0,
            details={},
        )
        assert result.seal_status == "protected"
        assert result.badge_color == "brightgreen"
        assert result.badge_label == "Protected by Airlock"

    def test_lite_status(self) -> None:
        """Test lite seal status."""
        result = VerificationResult(
            seal_status="lite",
            protected_count=2,
            lite_count=3,
            unsealed_count=0,
            details={},
        )
        assert result.seal_status == "lite"
        assert result.badge_color == "yellow"
        assert result.badge_label == "Airlock-Lite"

    def test_unsealed_status(self) -> None:
        """Test unsealed seal status."""
        result = VerificationResult(
            seal_status="unsealed",
            protected_count=1,
            lite_count=1,
            unsealed_count=2,
            details={},
        )
        assert result.seal_status == "unsealed"
        assert result.badge_color == "red"
        assert result.badge_label == "Unsealed Agent"


class TestVerificationScanner:
    """Test the VerificationScanner class."""

    def test_scan_empty_directory(self) -> None:
        """Test scanning an empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = VerificationScanner(Path(tmpdir))
            result = scanner.scan()

            assert result.seal_status == "unsealed"
            assert result.protected_count == 0
            assert result.lite_count == 0
            assert result.unsealed_count == 0

    def test_scan_protected_tool_with_strict_policy(self) -> None:
        """Test scanner identifies protected tools with STRICT_POLICY."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
from some_lib import tool
from agent_airlock import Airlock, STRICT_POLICY

@Airlock(policy=STRICT_POLICY)
@tool
def my_tool(x: int) -> int:
    return x * 2
"""
            (Path(tmpdir) / "tools.py").write_text(code)

            scanner = VerificationScanner(Path(tmpdir))
            result = scanner.scan()

            assert result.protected_count == 1
            assert result.seal_status == "protected"

    def test_scan_protected_tool_with_strict_mode(self) -> None:
        """Test scanner identifies protected tools with strict_mode=True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
from some_lib import tool
from agent_airlock import Airlock

@Airlock(strict_mode=True)
@tool
def my_tool(x: int) -> int:
    return x * 2
"""
            (Path(tmpdir) / "tools.py").write_text(code)

            scanner = VerificationScanner(Path(tmpdir))
            result = scanner.scan()

            assert result.protected_count == 1

    def test_scan_protected_tool_with_unknown_args_block(self) -> None:
        """Test scanner identifies protected tools with unknown_args=BLOCK."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
from some_lib import tool
from agent_airlock import Airlock, UnknownArgsMode

@Airlock(unknown_args=UnknownArgsMode.BLOCK)
@tool
def my_tool(x: int) -> int:
    return x * 2
"""
            (Path(tmpdir) / "tools.py").write_text(code)

            scanner = VerificationScanner(Path(tmpdir))
            result = scanner.scan()

            assert result.protected_count == 1

    def test_scan_sandbox_tool(self) -> None:
        """Test scanner identifies sandbox-protected tools."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
from some_lib import tool
from agent_airlock import Airlock

@Airlock(sandbox=True)
@tool
def dangerous_tool(code: str) -> str:
    exec(code)
    return "done"
"""
            (Path(tmpdir) / "tools.py").write_text(code)

            scanner = VerificationScanner(Path(tmpdir))
            result = scanner.scan()

            assert result.protected_count == 1
            assert "sandbox_tools" in result.details

    def test_scan_basic_airlock_tool(self) -> None:
        """Test scanner identifies basic Airlock-protected tools."""
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

            scanner = VerificationScanner(Path(tmpdir))
            result = scanner.scan()

            assert result.lite_count == 1
            assert result.seal_status == "lite"

    def test_scan_unprotected_tool(self) -> None:
        """Test scanner identifies unprotected tools."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
from some_lib import tool

@tool
def my_tool(x: int) -> int:
    return x * 2
"""
            (Path(tmpdir) / "tools.py").write_text(code)

            scanner = VerificationScanner(Path(tmpdir))
            result = scanner.scan()

            assert result.unsealed_count == 1
            assert result.seal_status == "unsealed"

    def test_scan_mixed_protection_levels(self) -> None:
        """Test scanner with mixed protection levels in separate files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Protected tool
            protected_code = """
from some_lib import tool
from agent_airlock import Airlock, STRICT_POLICY

@Airlock(policy=STRICT_POLICY)
@tool
def protected_tool(x: int) -> int:
    return x * 2
"""
            (Path(tmpdir) / "protected.py").write_text(protected_code)

            # Basic tool (without STRICT_POLICY - this is "lite")
            basic_code = """
from some_lib import tool
from agent_airlock import Airlock

@Airlock()
@tool
def basic_tool(x: int) -> int:
    return x + 1
"""
            (Path(tmpdir) / "basic.py").write_text(basic_code)

            # Unprotected tool (no Airlock)
            unprotected_code = """
from some_lib import tool

@tool
def unprotected_tool(x: int) -> int:
    return x - 1
"""
            (Path(tmpdir) / "unprotected.py").write_text(unprotected_code)

            scanner = VerificationScanner(Path(tmpdir))
            result = scanner.scan()

            # With mixed protection, overall status should be unsealed
            assert result.unsealed_count == 1
            assert result.seal_status == "unsealed"

    def test_scan_all_protected_gives_protected_status(self) -> None:
        """Test that all protected gives protected status."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
from some_lib import tool
from agent_airlock import Airlock, STRICT_POLICY

@Airlock(policy=STRICT_POLICY)
@tool
def tool1(x: int) -> int:
    return x * 2

@Airlock(sandbox=True)
@tool
def tool2(x: int) -> int:
    return x + 1
"""
            (Path(tmpdir) / "tools.py").write_text(code)

            scanner = VerificationScanner(Path(tmpdir))
            result = scanner.scan()

            assert result.seal_status == "protected"

    def test_scan_mcp_airlock_decorator(self) -> None:
        """Test scanner recognizes MCPAirlock decorator."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
from some_lib import tool
from agent_airlock import MCPAirlock, STRICT_POLICY

@MCPAirlock(policy=STRICT_POLICY)
@tool
def my_tool(x: int) -> int:
    return x * 2
"""
            (Path(tmpdir) / "tools.py").write_text(code)

            scanner = VerificationScanner(Path(tmpdir))
            result = scanner.scan()

            assert result.protected_count == 1

    def test_scan_skips_venv(self) -> None:
        """Test scanner skips venv directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            venv_dir = Path(tmpdir) / "venv" / "lib"
            venv_dir.mkdir(parents=True)
            code = """
from some_lib import tool

@tool
def unprotected(x: int) -> int:
    return x
"""
            (venv_dir / "tools.py").write_text(code)

            scanner = VerificationScanner(Path(tmpdir))
            result = scanner.scan()

            assert result.unsealed_count == 0


class TestVerifyFunction:
    """Test the verify() function."""

    def test_verify_returns_result(self) -> None:
        """Test verify function returns a result."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = verify(path=tmpdir)
            assert isinstance(result, VerificationResult)

    def test_verify_text_output(self, capsys: pytest.CaptureFixture) -> None:
        """Test verify function with text output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            verify(path=tmpdir, output_format="text")
            captured = capsys.readouterr()
            assert "Airlock Verification Report" in captured.out

    def test_verify_json_output(self, capsys: pytest.CaptureFixture) -> None:
        """Test verify function with JSON output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            verify(path=tmpdir, output_format="json")
            captured = capsys.readouterr()
            assert "seal_status" in captured.out
            assert "badge_color" in captured.out

    def test_verify_badge_output(self, capsys: pytest.CaptureFixture) -> None:
        """Test verify function with badge output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            verify(path=tmpdir, output_format="badge")
            captured = capsys.readouterr()
            assert "img.shields.io" in captured.out


class TestProtectionLevelChecking:
    """Test protection level detection logic."""

    def test_context_window_for_airlock(self) -> None:
        """Test that Airlock within context window is detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Airlock 3 lines above tool
            code = """
from some_lib import tool
from agent_airlock import Airlock

@Airlock()
# Some comment
@tool
def my_tool(x: int) -> int:
    return x * 2
"""
            (Path(tmpdir) / "tools.py").write_text(code)

            scanner = VerificationScanner(Path(tmpdir))
            result = scanner.scan()

            assert result.lite_count == 1
            assert result.unsealed_count == 0

    def test_extract_function_name(self) -> None:
        """Test function name extraction."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
from some_lib import tool

@tool
def specific_function_name(x: int) -> int:
    return x * 2
"""
            (Path(tmpdir) / "tools.py").write_text(code)

            scanner = VerificationScanner(Path(tmpdir))
            result = scanner.scan()

            # Check that function name appears in details
            assert any(
                "specific_function_name" in tool
                for tool in result.details.get("unprotected_tools", [])
            )


class TestBadgeProperties:
    """Test badge property calculations."""

    def test_protected_badge(self) -> None:
        """Test badge for protected status."""
        result = VerificationResult(
            seal_status="protected",
            protected_count=5,
            lite_count=0,
            unsealed_count=0,
            details={},
        )
        assert "brightgreen" in result.badge_color
        assert "Protected" in result.badge_label

    def test_lite_badge(self) -> None:
        """Test badge for lite status."""
        result = VerificationResult(
            seal_status="lite",
            protected_count=2,
            lite_count=3,
            unsealed_count=0,
            details={},
        )
        assert "yellow" in result.badge_color
        assert "Lite" in result.badge_label

    def test_unsealed_badge(self) -> None:
        """Test badge for unsealed status."""
        result = VerificationResult(
            seal_status="unsealed",
            protected_count=0,
            lite_count=0,
            unsealed_count=5,
            details={},
        )
        assert "red" in result.badge_color
        assert "Unsealed" in result.badge_label
