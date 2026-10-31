"""0.10.29: scan-tools reads a real ``mcp.types.ToolAnnotations`` model.

Raised in openai/openai-agents-python#5315: on mcp 2.3 the hint fields are snake_case
(``read_only_hint``), so ``annotations.readOnlyHint`` raises AttributeError, and until
0.10.29 scan-tools ignored any annotations value that was not a mapping. The model is now
read through ``model_dump(by_alias=True, exclude_none=True)``.

This module needs the ``[mcp]`` extra. CI's "Assert the extra-backed tests are not
silently skipped" step runs it, so a skip there fails the build.
"""

from __future__ import annotations

import pytest

from agent_airlock.capabilities import Capability
from agent_airlock.scan import infer_required_capability, resolve_policy, scan_tool

mcp_types = pytest.importorskip("mcp.types")


def _annotations(**hints: bool) -> object:
    """A real ``ToolAnnotations``, built from the spec's camelCase names on any mcp."""
    return mcp_types.ToolAnnotations.model_validate(hints)


def _tool(annotations: object) -> dict[str, object]:
    return {
        "name": "get_env",
        "description": "Read one environment variable.",
        "annotations": annotations,
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string", "maxLength": 64}},
            "additionalProperties": False,
        },
    }


class TestRealToolAnnotations:
    def test_a_trusted_model_is_read(self) -> None:
        tool = _tool(_annotations(readOnlyHint=True, openWorldHint=False))
        assert infer_required_capability(tool, trusted=True) == Capability.FILESYSTEM_READ

    def test_an_unset_hint_keeps_its_spec_default(self) -> None:
        """``exclude_none``: an unset ``openWorldHint`` reads as open-world."""
        tool = _tool(_annotations(readOnlyHint=True))
        assert infer_required_capability(tool, trusted=True) == (
            Capability.FILESYSTEM_READ | Capability.NETWORK_HTTPS
        )

    def test_an_untrusted_model_lowers_nothing(self) -> None:
        tool = _tool(_annotations(readOnlyHint=True, openWorldHint=False))
        result = scan_tool(tool, resolve_policy("strict"), server="srv")
        assert "FILESYSTEM_DELETE" in result.inferred_capability
        assert result.untrusted_hints == ["readOnlyHint: true", "openWorldHint: false"]

    def test_a_trusted_model_passes_the_strict_policy(self) -> None:
        tool = _tool(_annotations(readOnlyHint=True, openWorldHint=False))
        result = scan_tool(tool, resolve_policy("strict"), server="srv", trusted_servers={"srv"})
        assert result.passed, [v.code for v in result.violations]
