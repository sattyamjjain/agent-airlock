"""CVE-2026-111451 — Wheels CLI MCP tool arguments reach deploy shells, file paths and generated CFML.

Vulnerability (from NVD, GHSA-cghp-86c6-6fjc and the Wheels and LuCLI sources, retrieved 2026-10-23):
    Wheels CLI 4.0.0 through 4.1.1 uses caller-supplied values without validating or
    escaping them. The advisory lists eight defects. Three of them reach the CLI as the
    arguments of an MCP tool call, the seam this library sits on:

    - ``wheels deploy`` interpolates its release, version or rollback value into remote
      shell commands, container names and image tags without escaping, so a value that
      carries a shell metacharacter runs commands on every deploy host as the SSH user.
      Through 4.1.0 ``deploy`` was listed as an MCP tool; 4.1.1 hid it. Its advertised
      input schema was empty, but LuCLI's ``tools/call`` forwards every argument key to
      the module as ``key=value`` regardless, and Wheels 4.1.0 reads ``release=<value>``
      exactly as it reads ``--release=<value>``, the version its deploy parser uses.
    - ``packages remove`` and ``generate`` take a name with no validation, so ``..`` or a
      ``../`` prefix deletes the project's contents or writes ``.cfm`` files outside it.
    - Model, property, action and app names are interpolated into generated CFML, so a
      ``#`` expression or a quote in a name becomes executable code.

    Fixed in 4.1.2, which validates names and versions strictly and shell-escapes every
    interpolated value.

Advisory: https://github.com/wheels-dev/wheels/security/advisories/GHSA-cghp-86c6-6fjc
Fix:      https://github.com/wheels-dev/wheels/releases/tag/v4.1.2
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-111451
CVSS:     7.8 (HIGH) — CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
CWE:      CWE-78 (NVD); CWE-22, CWE-78, CWE-94 (advisory)

Airlock fit: partial.
    **In scope: the three argument shapes.** Each is refused by a primitive that already
    exists, so this is a second-defence fixture, not a new guard or preset:

    - The deploy value, in the argv LuCLI builds from the call, is refused by
      ``StdioCommandInjectionGuard`` when it carries a shell metacharacter: the
      CVE-2026-108953 pattern. ``_lucli_argv`` repeats LuCLI's lines, as ``_spawn_config``
      does for CVE-2026-79538.
    - A traversal name is refused by ``SafePathValidator``: the CVE-2026-57496 pattern.
    - A name carrying a CFML ``#`` or a quote is refused by strict validation when the tool
      declares the identifier shape a Wheels name has: the CVE-2026-105793 pattern. No
      guard reads CFML, so the declared shape is the whole defence for that half.

    **Out of reach.** A deploy value that comes from a CI variable or a branch name never
    crosses a tool call. Package archive contents, ``destroy`` following a symlink on disk,
    unencoded output in generated views and a stale RustCFML process id are not arguments
    either. Two boundaries are pinned below: a bare ``$VAR`` passes the stdio guard, as in
    CVE-2026-108953, and a name declared as a bare ``str``, the shape the Wheels MCP schema
    advertised, admits the CFML delimiter. The complete fix is the upstream validation and
    escaping in 4.1.2.
"""

from __future__ import annotations

from typing import Annotated, Literal

import pytest
from pydantic import StringConstraints
from scripts.cve_watcher import classify_shape

from agent_airlock.core import Airlock
from agent_airlock.mcp_spec.stdio_command_injection_guard import (
    StdioCommandInjectionGuard,
    StdioCommandInjectionVerdict,
)
from agent_airlock.policy_presets import mcp_stdio_command_injection_preset_defaults
from agent_airlock.safe_types import SafePathValidationError, SafePathValidator

CVE = "CVE-2026-111451"

#: NVD's description, verbatim, so the classifier assertions below are checked against
#: the real record rather than a paraphrase of it.
NVD_DESCRIPTION = (
    "Wheels CLI 4.0.0 through 4.1.1 insufficiently validates or escapes caller-supplied "
    "values and package contents. Deploy release/version/rollback values can execute shell "
    "commands on deploy hosts as the SSH user and on the CI runner during builds. Package "
    "removal and destroy paths can delete unintended files; package extraction can "
    "overwrite other vendor files; generator names can write outside the project or inject "
    "executable CFML into generated code. Inputs may originate from CI variables, branch "
    "names, packages or an AI agent using the CLI's MCP tools. Also relevant are unencoded "
    "display properties in generated scaffold show views since 4.1.0 and in generated "
    "admin views, permitting stored XSS, and stale process-ID handling in RustCFML server "
    "commands that can terminate an unrelated process. This is fixed in 4.1.2; existing "
    "affected generated views also require the documented edit."
)

#: NVD's CWE. The advisory adds CWE-22 and CWE-94; CWE-78 is what filed it.
NVD_CWES = ["CWE-78"]

#: A Wheels model, controller, property or action name: a CFML identifier. Declaring it
#: is what lets strict validation refuse anything else. The Wheels MCP schema advertised
#: the ``generate`` tool's ``name`` as free text.
WheelsName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9_]*$")]

# Deploy arguments as an MCP client sends them. A positional reaches the module as an
# `arg<n>` key (Wheels' `toArgv` puts those back in position), so `rollback <version>`
# arrives as {"arg1": "rollback", "arg2": <version>}.
DEPLOY_BENIGN: tuple[tuple[str, dict[str, str]], ...] = (
    ("release tag", {"release": "v1.2.3"}),
    ("dated version", {"version": "2026.10.23"}),
    ("rollback to a tag", {"arg1": "rollback", "arg2": "v1"}),
)

# The advisory's shape: a deploy value carrying a shell metacharacter. PLACEHOLDER stands
# where a real payload would put a command, so nothing here runs anything.
DEPLOY_ESCAPES: tuple[tuple[str, dict[str, str]], ...] = (
    ("command substitution in release", {"release": "PLACEHOLDER$(PLACEHOLDER)"}),
    ("backtick in version", {"version": "PLACEHOLDER`PLACEHOLDER`"}),
    ("semicolon in release", {"release": "PLACEHOLDER;PLACEHOLDER"}),
    ("pipe in version", {"version": "PLACEHOLDER|PLACEHOLDER"}),
    ("and-chain in a rollback target", {"arg1": "rollback", "arg2": "PLACEHOLDER&&PLACEHOLDER"}),
    ("newline in release", {"release": "PLACEHOLDER\nPLACEHOLDER"}),
)

# Names the generators and `packages` exist to take.
NAMES = ("User", "BlogPost", "admin_users", "PLACEHOLDER")
PACKAGE_NAMES = ("wheels-sentry", "PLACEHOLDER")

# `packages remove ..` and `generate controller ../x`: a traversal segment in a name.
TRAVERSALS = (
    "..",
    "../PLACEHOLDER",
    "../../PLACEHOLDER",
    "PLACEHOLDER/../../PLACEHOLDER",
    "..\\PLACEHOLDER",
)

# A CFML expression delimiter or a quote in a name, which the generator interpolates into
# generated source. PLACEHOLDER names no variable, so even evaluated these do nothing.
CFML_BREAKOUTS = (
    "PLACEHOLDER#PLACEHOLDER#",
    "#PLACEHOLDER#",
    'PLACEHOLDER"PLACEHOLDER',
    "PLACEHOLDER'PLACEHOLDER",
)


def _lucli_argv(tool: str, arguments: dict[str, str]) -> dict[str, object]:
    """The argv LuCLI hands the Wheels module for an MCP ``tools/call``.

    ``McpCommand.executeModuleTool`` in LuCLI, the same lines since its MCP server shipped
    in March 2026::

        List<String> argv = new ArrayList<>();
        argv.add(toolName);
        for (Map.Entry<String, Object> entry : args.entrySet()) {
            ...
            argv.add(key + "=" + stringValue);
        }

    Every key goes through, declared in the tool's input schema or not, and a string value
    is passed as itself. Wheels' ``argvToCollection`` maps ``release=<value>`` to the same
    key as ``--release=<value>``.
    """
    return {"command": tool, "args": [f"{key}={value}" for key, value in arguments.items()]}


def _guard() -> StdioCommandInjectionGuard:
    """Stock guard. No operator tuning: the default metachar set is enough."""
    return StdioCommandInjectionGuard()


def _generate() -> Airlock:
    @Airlock(return_dict=True)
    def generate(type: Literal["model", "controller", "view", "scaffold"], name: WheelsName) -> str:
        return f"wheels generate {type} {name}"

    return generate  # type: ignore[return-value]


class TestTheDeployValueIsRefused:
    """The shell-injection half, as it reached the CLI over MCP through 4.1.0."""

    @pytest.mark.parametrize(
        ("label", "arguments"), DEPLOY_ESCAPES, ids=[c[0] for c in DEPLOY_ESCAPES]
    )
    def test_a_metacharacter_in_a_deploy_value_is_denied(
        self, label: str, arguments: dict[str, str]
    ) -> None:
        decision = _guard().evaluate(_lucli_argv("deploy", arguments))
        assert decision.verdict is StdioCommandInjectionVerdict.DENY_SHELL_METACHAR, label
        assert decision.allowed is False

    @pytest.mark.parametrize(
        ("label", "arguments"), DEPLOY_BENIGN, ids=[c[0] for c in DEPLOY_BENIGN]
    )
    def test_a_plain_deploy_value_passes(self, label: str, arguments: dict[str, str]) -> None:
        assert _guard().evaluate(_lucli_argv("deploy", arguments)).allowed is True, label

    def test_an_undeclared_key_reaches_the_argv(self) -> None:
        # The deploy tool advertised no properties. LuCLI forwarded the key anyway, so the
        # value the guard must judge is in the argv.
        argv = _lucli_argv("deploy", {"release": "v1"})
        assert argv == {"command": "deploy", "args": ["release=v1"]}


class TestATraversalNameIsRefused:
    """``packages remove ..`` and ``generate ... ../x``: the path half."""

    @pytest.mark.parametrize("name", NAMES + PACKAGE_NAMES)
    def test_a_plain_name_passes(self, name: str) -> None:
        assert str(SafePathValidator()(name)) == name

    @pytest.mark.parametrize("name", TRAVERSALS)
    def test_a_traversal_name_is_refused(self, name: str) -> None:
        with pytest.raises(SafePathValidationError):
            SafePathValidator()(name)


class TestADeclaredNameShapeRefusesTheCfmlBreakout:
    """The code-injection half: strict validation of the narrow name shape."""

    @pytest.mark.parametrize("name", NAMES)
    def test_a_wheels_name_generates(self, name: str) -> None:
        result = _generate()(type="model", name=name)
        assert isinstance(result, dict)
        assert result.get("success") is True
        assert result.get("result") == f"wheels generate model {name}"

    @pytest.mark.parametrize("name", CFML_BREAKOUTS + TRAVERSALS)
    def test_a_name_outside_the_shape_is_a_validation_error(self, name: str) -> None:
        result = _generate()(type="model", name=name)
        assert isinstance(result, dict)
        assert result.get("success") is False
        assert result.get("status") == "blocked"
        assert result.get("block_reason") == "validation_error"


class TestScopeBoundary:
    """Pin where the second defence stops, and that no preset claims this CVE."""

    def test_a_bare_dollar_var_in_a_deploy_value_still_passes(self) -> None:
        # `$VAR` with no `$(` is not in the default metachar set, as in CVE-2026-108953:
        # `$` is ordinary in real arguments. A deploy host that still splices the value
        # into a shell would expand the variable; the complete fix is 4.1.2's escaping.
        argv = _lucli_argv("deploy", {"release": "PLACEHOLDER$PLACEHOLDER"})
        assert _guard().evaluate(argv).allowed is True

    def test_a_name_declared_as_free_text_admits_the_cfml_breakout(self) -> None:
        # The Wheels schema took `name` as free text. The contract refuses only what the
        # tool declares, so for a tool that does not narrow it the fix is the generator's
        # own validation (4.1.2), not anything expressible here.
        @Airlock(return_dict=True)
        def generate_freeform(type: str, name: str) -> str:
            return f"wheels generate {type} {name}"

        for name in CFML_BREAKOUTS:
            result = generate_freeform(type="model", name=name)
            assert isinstance(result, dict)
            assert result.get("success") is True, name

    def test_no_guard_reads_a_cfml_delimiter(self) -> None:
        # Neither the stdio guard nor the path validator knows CFML, which is why the
        # declared shape is the whole defence for that half.
        for name in CFML_BREAKOUTS:
            argv = _lucli_argv("generate", {"type": "model", "name": name})
            assert _guard().evaluate(argv).allowed is True, name
            assert str(SafePathValidator()(name)) == name

    def test_preset_does_not_claim_this_cve(self) -> None:
        # The preset claims the CVEs it addresses. It does not address Wheels' missing
        # escaping; it refuses the metacharacter that escaping would have neutralised.
        preset = mcp_stdio_command_injection_preset_defaults()
        assert CVE not in str(preset.get("cves", ()))


class TestWatcherAdmittedThisOnBothSignals:
    """Either signal alone would have filed it: the description and CWE-78."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_description_alone_files_it(self) -> None:
        # "shell", in "execute shell commands", is the sink word.
        assert classify_shape(NVD_DESCRIPTION, []) == "candidate"

    def test_the_argument_shaped_cwe_alone_files_it(self) -> None:
        assert classify_shape("", ["CWE-78"]) == "candidate"
