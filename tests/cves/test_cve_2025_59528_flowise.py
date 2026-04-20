"""CVE-2025-59528 — Flowise CustomMCP RCE via JS ``Function()`` constructor.

Flowise's ``/api/v1/node-load-method/customMCP`` passed user-supplied
strings directly into JavaScript ``Function()`` and ``eval``. CVSS 10.0.
Patched in v3.0.6 (Sept 2025) but CSA documented active exploitation
in April 2026 — ~12-15K instances still exposed.

This regression codifies the offending token set (``Function(``,
``new Function``, ``eval(``, ``Deno.eval``, ``vm.runInNewContext``) so
the same class cannot land in any tool we register.

Primary sources
---------------
- CSA research note (2026-04-09):
  https://labs.cloudsecurityalliance.org/research/csa-research-note-flowise-mcp-rce-exploitation-20260409-csa/
- GitLab advisory:
  https://advisories.gitlab.com/npm/flowise/CVE-2025-59528/
"""

from __future__ import annotations

import pytest

from agent_airlock.exceptions import AirlockError
from agent_airlock.policy_presets import (
    FlowiseEvalTokenError,
    flowise_cve_2025_59528_check,
    flowise_cve_2025_59528_defaults,
)


class TestFlowiseEvalTokenBan:
    def test_01_clean_manifest_passes(self) -> None:
        """A tool whose handler is a simple function name is fine."""
        flowise_cve_2025_59528_check([{"name": "read_file", "handler": "readFile", "config": "{}"}])

    def test_02_function_constructor_banned(self) -> None:
        with pytest.raises(FlowiseEvalTokenError) as exc:
            flowise_cve_2025_59528_check(
                [{"name": "evil", "handler": "const f = new Function('x','return x')"}]
            )
        # "new Function" triggers first since it appears earlier in the token tuple.
        assert "Function" in str(exc.value)

    def test_03_eval_banned(self) -> None:
        with pytest.raises(FlowiseEvalTokenError):
            flowise_cve_2025_59528_check([{"name": "evil", "config": "return eval(userInput)"}])

    def test_04_deno_eval_banned(self) -> None:
        with pytest.raises(FlowiseEvalTokenError):
            flowise_cve_2025_59528_check([{"name": "evil", "handler": "await Deno.eval(payload)"}])

    def test_05_vm_runInNewContext_banned(self) -> None:
        with pytest.raises(FlowiseEvalTokenError):
            flowise_cve_2025_59528_check(
                [
                    {
                        "name": "evil",
                        "handler": "vm.runInNewContext(expr, ctx)",
                    }
                ]
            )


class TestDefaultsBundle:
    def test_banned_tokens_advertised(self) -> None:
        cfg = flowise_cve_2025_59528_defaults()
        banned = cfg["banned_tokens"]
        for tok in ("Function(", "new Function", "eval(", "Deno.eval", "vm.runInNewContext"):
            assert tok in banned, f"{tok!r} missing from banned_tokens"

    def test_source_cites_csa(self) -> None:
        cfg = flowise_cve_2025_59528_defaults()
        assert "cloudsecurityalliance" in cfg["source"]


class TestErrorBaseClass:
    def test_is_airlock_error(self) -> None:
        with pytest.raises(AirlockError):
            flowise_cve_2025_59528_check([{"name": "evil", "handler": "eval(x)"}])
