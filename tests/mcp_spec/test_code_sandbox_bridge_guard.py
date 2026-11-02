"""Tests for CodeSandboxBridgeGuard (CVE-2026-120338 anchor).

The guard refuses a tool-call argument that reaches the sandbox host runtime
(Pyodide-to-JS proxy, Deno host API, Node child_process bridge). The strings
here are detection shapes, not working exploits: each is the one-line bridge
spelling the guard matches, fed to the guard and asserted refused.
"""

from __future__ import annotations

import pytest

from agent_airlock.mcp_spec.code_sandbox_bridge_guard import (
    BridgeGroup,
    CodeSandboxBridgeGuard,
    CodeSandboxBridgeVerdict,
)


class TestDenies:
    """Host-bridge spellings are refused, and the matched primitive is named."""

    def test_pyodide_js_deno_write(self) -> None:
        guard = CodeSandboxBridgeGuard()
        decision = guard.evaluate(
            {
                "code": (
                    "import js\n"
                    "js.Deno.writeTextFile("
                    "'/srv/venv/lib/python3.12/site-packages/x.pth', 'import os')"
                )
            }
        )
        assert not decision.allowed
        assert decision.verdict is CodeSandboxBridgeVerdict.DENY_BRIDGE
        assert decision.matched_primitive == "js.Deno"
        assert decision.group is BridgeGroup.PYODIDE_JS
        assert decision.field == "code"

    def test_from_js_import(self) -> None:
        guard = CodeSandboxBridgeGuard()
        decision = guard.evaluate({"code": "from js import Deno"})
        assert not decision.allowed
        assert decision.group is BridgeGroup.PYODIDE_JS

    def test_deno_read(self) -> None:
        guard = CodeSandboxBridgeGuard()
        decision = guard.evaluate({"code": "await Deno.readTextFile('/etc/passwd')"})
        assert not decision.allowed
        assert decision.matched_primitive == "Deno host API"
        assert decision.group is BridgeGroup.DENO_API

    def test_node_child_process(self) -> None:
        guard = CodeSandboxBridgeGuard()
        decision = guard.evaluate({"code": "require('child_process').execSync('id')"})
        assert not decision.allowed
        assert decision.group is BridgeGroup.NODE_BRIDGE
        assert decision.matched_primitive == "require(child_process)"

    @pytest.mark.parametrize(
        "code",
        [
            "import js",
            "x = pyodide.ffi.to_js({})",
            "pyodide.code.run_js('1')",
            'Deno.writeFile("/x", data)',
            "Deno.open('/x')",
            "Deno.remove('/x')",
            "Deno.mkdir('/x')",
            "new Deno.Command('sh')",
            "Deno.run({cmd: ['id']})",
            "Deno.env.get('TOKEN')",
            "Deno.connect({port: 22})",
            "Deno.listen({port: 80})",
            "process.binding('spawn_sync')",
            'require("child_process")',
            'import("child_process")',
            "const cp = 'node:child_process'",
        ],
    )
    def test_each_primitive(self, code: str) -> None:
        guard = CodeSandboxBridgeGuard()
        assert not guard.evaluate({"code": code}).allowed

    def test_nested_field_path(self) -> None:
        guard = CodeSandboxBridgeGuard()
        decision = guard.evaluate(
            {"payload": {"steps": ["ok", {"body": "js.Deno.readTextFile('/etc/shadow')"}]}}
        )
        assert not decision.allowed
        assert decision.field == "payload.steps[1].body"
        assert decision.matched_primitive == "js.Deno"

    def test_bytes_argument(self) -> None:
        guard = CodeSandboxBridgeGuard()
        decision = guard.evaluate({"code": b"from js import Deno"})
        assert not decision.allowed
        assert decision.group is BridgeGroup.PYODIDE_JS

    def test_extra_bridge(self) -> None:
        guard = CodeSandboxBridgeGuard(extra_bridges=frozenset({"globalThis.Deno"}))
        decision = guard.evaluate({"code": "x = globalThis.Deno.pid"})
        assert not decision.allowed
        assert decision.group is BridgeGroup.EXTRA
        assert decision.matched_primitive == "globalThis.Deno"


class TestAllows:
    """Pure Python, prose about the API, and look-alike names pass."""

    @pytest.mark.parametrize(
        "args",
        [
            {"code": "import math\nprint(math.sqrt(2))"},
            {"code": "df = pd.read_csv('data.csv')"},
            {"note": "the Deno docs say you can read files from the sandbox"},
            {"code": "jsonify(x)"},
            {"code": "import json\njson.dumps({'a': 1})"},
            {"code": "label = 'Deno Industries'"},
            {"code": "denominator = 3"},
            {"code": "runner = build()"},
            None,
        ],
    )
    def test_allowed(self, args: dict[str, object] | None) -> None:
        guard = CodeSandboxBridgeGuard()
        decision = guard.evaluate(args)
        assert decision.allowed
        assert decision.verdict is CodeSandboxBridgeVerdict.ALLOW


class TestFailClosed:
    """Input the guard cannot fully inspect is refused, not skipped."""

    def test_depth_33_refused(self) -> None:
        guard = CodeSandboxBridgeGuard()
        nested: object = "import math"
        for _ in range(33):
            nested = [nested]
        decision = guard.evaluate({"code": nested})
        assert not decision.allowed
        assert decision.verdict is CodeSandboxBridgeVerdict.DENY_UNINSPECTABLE

    def test_cycle_refused(self) -> None:
        guard = CodeSandboxBridgeGuard()
        loop: list[object] = []
        loop.append(loop)
        decision = guard.evaluate({"code": loop})
        assert not decision.allowed
        assert decision.verdict is CodeSandboxBridgeVerdict.DENY_UNINSPECTABLE

    def test_non_utf8_bytes_refused(self) -> None:
        guard = CodeSandboxBridgeGuard()
        decision = guard.evaluate({"code": b"\xff\xfe import js"})
        assert not decision.allowed
        assert decision.verdict is CodeSandboxBridgeVerdict.DENY_UNINSPECTABLE

    def test_bad_extra_bridges_type(self) -> None:
        with pytest.raises(TypeError):
            CodeSandboxBridgeGuard(extra_bridges=["globalThis.Deno"])  # type: ignore[arg-type]


class TestPreset:
    """The preset scopes the guard to the code-execution tool class."""

    def test_defaults_shape(self) -> None:
        from agent_airlock.policy_presets import code_sandbox_bridge_defaults

        preset = code_sandbox_bridge_defaults()
        assert preset["preset_id"] == "code_sandbox_bridge"
        assert preset["default_action"] == "deny"
        assert preset["cves"] == ("CVE-2026-120338",)
        assert "generate_prefab_ui" in preset["tool_name_patterns"]
        assert preset["recommended_config"] == {"startup_hook_check": "warn"}

    def test_guard_screens_code_tool(self) -> None:
        from agent_airlock.policy_presets import code_sandbox_bridge_defaults

        preset = code_sandbox_bridge_defaults()
        guard = preset["guard"]
        tool = "generate_prefab_ui"
        assert tool in preset["tool_name_patterns"]
        assert not guard.evaluate({"code": "js.Deno.readTextFile('/etc/passwd')"}).allowed

    def test_unscoped_tool_not_in_patterns(self) -> None:
        from agent_airlock.policy_presets import code_sandbox_bridge_defaults

        preset = code_sandbox_bridge_defaults()
        assert "search_docs" not in preset["tool_name_patterns"]

    def test_extra_patterns_and_bridges(self) -> None:
        from agent_airlock.policy_presets import code_sandbox_bridge_defaults

        preset = code_sandbox_bridge_defaults(
            extra_bridges=frozenset({"Bun.spawn"}),
            extra_tool_name_patterns=("eval_python",),
        )
        assert "eval_python" in preset["tool_name_patterns"]
        assert not preset["guard"].evaluate({"code": "Bun.spawn(['id'])"}).allowed
