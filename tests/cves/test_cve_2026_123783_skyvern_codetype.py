"""CVE-2026-123783 — Skyvern script sandbox: functions rebuilt from raw bytecode with ``types.CodeType``.

Vulnerability (from NVD, CNA VulnCheck):
    "Skyvern through 1.0.56 contains a sandbox bypass vulnerability that allows authenticated
    users to execute code by reconstructing functions from raw bytecode with types.CodeType.
    Attackers can deploy scripts that evade the is_safe_script_code AST denylist and import
    blocked modules such as subprocess or socket to run code in the Skyvern server process."
    Fixed in 1.0.57 by commit 31a64c1a (Skyvern-AI/skyvern#8937), which adds ``CodeType``,
    ``FunctionType`` and ``LambdaType`` to the blocked attributes, and ``sys`` and ``types`` to
    the blocked imports.

Advisory: https://www.vulncheck.com/advisories/skyvern-through-1.0.56-script-sandbox-bypass-via-types-codetype-bytecode
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-123783
CVSS:     8.8 (HIGH) — AV:N/AC:L/PR:L/UI:N, CWE-184

Airlock fit: partial.
    **In scope:** a code-tool argument escaping the restriction the tool declares, the
    documented shape in ``docs/cve-triage.md`` ("Code injection into an interpreter sink"), and
    the same split as CVE-2026-53710. **Out of scope:** Skyvern's own AST denylist, which is
    upstream's to fix, and the authenticated-user precondition: this guard's whole input is the
    call's arguments, so it cannot see who sent them.

    ``EvalRCEGuard`` had the shape of the bug: it refused a string argument only when it saw
    an eval-family call. These payloads call none, so on 0.10.31 routes a to p were all
    allowed. Observed against ``v0.10.31`` while writing this module: ``allowed=True`` for
    every payload in the fixture, and for ``exec`` in fullwidth letters. The guard now screens
    for the code object itself, on by default. Skyvern's fix names three of the routes; the
    fixture covers the rest of the class, in its own routes g to p.

What this does not close
------------------------
A denylist of names has the limit that made this CVE. :class:`TestDocumentedLimit` pins
payloads that still pass, and the module docstring of ``eval_rce_guard`` says the defence for
them is isolation. The honest claim is that the guard refuses the disclosed route and every
route it can read a name for, and that running the code in a sandbox is still the job.
"""

from __future__ import annotations

import json
import marshal
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock.mcp_spec.eval_rce_guard import (
    DEFAULT_EVAL_SINKS,
    EvalRCEGuard,
    EvalRCEVerdict,
)
from agent_airlock.policy_presets import stdio_guard_eval_defaults_2026_05_15

CVE = "CVE-2026-123783"

NVD_DESCRIPTION = (
    "Skyvern through 1.0.56 contains a sandbox bypass vulnerability that allows authenticated "
    "users to execute code by reconstructing functions from raw bytecode with types.CodeType. "
    "Attackers can deploy scripts that evade the is_safe_script_code AST denylist and import "
    "blocked modules such as subprocess or socket to run code in the Skyvern server process."
)
NVD_CWES = ["CWE-184"]

_FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "cve_2026_123783_skyvern_codetype.json").read_text(
        encoding="utf-8"
    )
)

#: A code object's bytes, which differ by Python version, for the marshal route.
_CODE_BYTES = repr(marshal.dumps((lambda: 42).__code__))


def _payload(code: str) -> str:
    """A fixture payload, with the marshal route's bytes filled in for this interpreter."""
    return code.replace('b"<code object bytes>"', _CODE_BYTES)


PAYLOADS = [
    pytest.param(_payload(entry["code"]), id=entry["route"]) for entry in _FIXTURE["payloads"]
]
BENIGN = [pytest.param(text, id=text[:32]) for text in _FIXTURE["benign"]]

#: Payload c, the alias route, which the published-package check runs too.
PAYLOAD_ALIAS = next(
    entry["code"] for entry in _FIXTURE["payloads"] if entry["route"].startswith("c_")
)


def _refused_as_a_code_object(args: Any) -> None:
    decision = EvalRCEGuard().evaluate(args)
    assert decision.allowed is False
    assert decision.verdict is EvalRCEVerdict.DENY_EVAL_SINK
    assert decision.matched_sink == "code_object"
    assert "builds or fetches a Python code object (CVE-2026-123783 class)" in decision.detail


class TestThePayloadsAreReal:
    """A payload that does not run proves nothing about the guard that refuses it."""

    @pytest.mark.parametrize("payload", PAYLOADS)
    def test_each_route_returns_42_on_this_interpreter(self, payload: str, tmp_path: Path) -> None:
        done = subprocess.run(
            [sys.executable, "-I", "-c", f"{payload}\nprint(result)\n"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert done.returncode == 0, done.stderr
        assert done.stdout.strip() == "42"

    @pytest.mark.parametrize("payload", PAYLOADS)
    def test_no_route_calls_a_sink_or_runs_a_command(self, payload: str) -> None:
        for name in ("eval(", "exec(", "compile(", "__import__(", "getattr("):
            assert name not in payload
        for name in ("subprocess", "socket", "os.system", "Popen"):
            assert name not in payload


class TestEveryRouteIsRefused:
    @pytest.mark.parametrize("payload", PAYLOADS)
    def test_as_a_string(self, payload: str) -> None:
        _refused_as_a_code_object({"code": payload})

    @pytest.mark.parametrize("payload", PAYLOADS)
    def test_nested_two_levels_deep(self, payload: str) -> None:
        _refused_as_a_code_object({"request": {"scripts": [payload]}})
        _refused_as_a_code_object({"request": [{"code": payload}]})

    @pytest.mark.parametrize("payload", PAYLOADS)
    def test_as_utf8_bytes(self, payload: str) -> None:
        _refused_as_a_code_object({"code": payload.encode("utf-8")})

    def test_the_alias_is_refused_at_the_line_that_takes_it(self) -> None:
        _refused_as_a_code_object({"code": "CT = types.CodeType"})

    def test_the_fix_needs_no_configuration(self) -> None:
        guard = EvalRCEGuard(extra_sinks=frozenset({"runpy.run_path"}))
        assert guard.evaluate({"code": PAYLOAD_ALIAS}).allowed is False


class TestBenignStringsPass:
    @pytest.mark.parametrize("text", BENIGN)
    def test_it_is_allowed(self, text: str) -> None:
        decision = EvalRCEGuard().evaluate({"code": text})
        assert decision.allowed is True
        assert decision.verdict is EvalRCEVerdict.ALLOW


class TestDocumentedLimit:
    """The module docstring names these blind spots; pin them rather than imply them away."""

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param(
                'def f():\n    return 42\n\nc = type(f).__dict__["__co" + "de__"].__get__(f)\n',
                id="dunder-assembled-through-the-type",
            ),
            pytest.param(
                'import timeit\ntimeit.timeit("x = 42", number=1)\n',
                id="a-module-that-runs-source-text",
            ),
            pytest.param(
                'import code\ncode.InteractiveInterpreter().runsource("x = 42")\n',
                id="an-interpreter-that-runs-source-text",
            ),
        ],
    )
    def test_it_still_passes_this_screen(self, payload: str) -> None:
        # Stating it here is the point: isolation is the defence for these, and a reader must
        # not take this fixture as a claim that a denylist closes the class.
        assert EvalRCEGuard().evaluate({"code": payload}).allowed is True

    @pytest.mark.parametrize(
        "payload",
        [
            'getattr(f, "__co" + "de__")',
            # Passed until 0.10.33: the same primitive under other spellings.
            'def f():\n    return 42\n\nc = f.__getattribute__("__co" + "de__")\n',
            'import operator\nc = operator.attrgetter("__co" + "de__")(f)\n',
            'import inspect\nc = inspect.getattr_static(f, "__co" + "de__")\n',
        ],
    )
    def test_the_getattr_family_is_refused_as_the_sink_it_is(self, payload: str) -> None:
        # The docstring's limit is "through something other than the getattr family".
        decision = EvalRCEGuard().evaluate({"code": payload})
        assert decision.allowed is False
        assert decision.matched_sink == "getattr"

    def test_an_operator_can_name_a_runner_with_extra_sinks(self) -> None:
        guard = EvalRCEGuard(extra_sinks=frozenset({"runsource"}))
        decision = guard.evaluate({"code": 'interpreter.runsource("x = 42")'})
        assert decision.matched_sink == "runsource"


class TestScopeBoundary:
    """Pin the halves of this CVE that agent-airlock does **not** reach."""

    def test_guard_cannot_see_who_sent_the_argument(self) -> None:
        # The authenticated-user precondition is invisible to it: the payload decides.
        guard = EvalRCEGuard()
        for args in (
            {"code": PAYLOAD_ALIAS},
            {"code": PAYLOAD_ALIAS, "authorization": "Bearer placeholder"},
        ):
            assert guard.evaluate(args).allowed is False

    def test_the_sink_set_the_presets_copy_is_unchanged(self) -> None:
        # The screen is not a sink: its names would never match the call-shape regex.
        for name in ("CodeType", "FunctionType", "LambdaType", "__code__", "code_object"):
            assert name not in DEFAULT_EVAL_SINKS

    def test_preset_does_not_claim_this_cve(self) -> None:
        # The preset claims the CVEs it addresses. Skyvern's AST denylist is not one of them.
        preset = stdio_guard_eval_defaults_2026_05_15()
        assert CVE not in preset["cves"]
        assert preset["cves"] == ("CVE-2026-44717",)


class TestWatcherAdmittedThisOnTheText:
    """The record is argument-shaped on its text; CWE-184 alone only asks for triage."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_sink_signal_alone_would_have_filed_it(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, []) == "candidate"

    def test_the_cwe_alone_would_only_ask_for_triage(self) -> None:
        assert classify_shape("", NVD_CWES) == "triage-required"
