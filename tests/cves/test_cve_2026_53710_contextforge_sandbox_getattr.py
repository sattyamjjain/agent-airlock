"""CVE-2026-53710 — ContextForge python_sandbox_server: RestrictedPython escape via raw ``getattr``.

Vulnerability (from GHSA-xm98-3vcf-fph7 and NVD):
    Prior to 1.0.2, the ``python_sandbox_server`` sub-project exposes raw
    ``getattr`` through ``safe_builtins``, bypassing RestrictedPython's
    ``_getattr_`` mediation, and its ``validate_code`` pre-check searches for
    **literal** dangerous dunder strings. The advisory's proof of concept
    therefore builds those dunder names at runtime, walks the Python class
    hierarchy through the exposed ``getattr``, reaches ``subprocess.Popen`` and
    runs an OS command. Its transcript records the decisive line:
    ``validation={'valid': True, 'message': 'Code passed validation'}`` followed
    by ``success=True`` — the code passed the sandbox's own check and then
    escaped it. Fixed in 1.0.2.

Advisory: https://github.com/advisories/GHSA-xm98-3vcf-fph7
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-53710
CVSS:     10.0 (CRITICAL) — CWE-94 + CWE-693

Airlock fit: partial.
    Three compounding weaknesses in the advisory, and agent-airlock reaches one,
    per the split in ``docs/cve-triage.md``.

    **Out of scope:** weakness 3, "The ``execute_code`` MCP tool can be exposed
    over HTTP/SSE transport with no authentication layer." Same documented shape
    as CVE-2026-33032 and CVE-2026-23744. Also out of scope is the repair itself
    — removing ``getattr`` from someone else's ``safe_builtins`` is upstream's
    1.0.2, not something a contract layer can express.

    **In scope:** the primitive. A caller-supplied ``code`` argument carrying a
    payload that reaches an interpreter sink is the documented in-scope shape
    (``docs/cve-triage.md``, "Code injection into an interpreter sink"), and
    ``getattr`` is already in :data:`DEFAULT_EVAL_SINKS`. So this is a
    **second-defence regression fixture against an existing guard, not a new
    guard** — the CVE-2026-90898 / CVE-2026-57124 pattern.

Why this is *not* the CVE-2026-59971 case, filed the same day
-------------------------------------------------------------
Both are CVSS 10.0, both have an unauthenticated-HTTP-endpoint half, and they
land on opposite sides of the seam. The difference is whether the tool declares
a restriction that the argument then escapes.

``execute_sql`` (CVE-2026-59971, dispositioned out of scope in
``tests/cves/README.md``) declares no restriction: running caller-supplied SQL
is its entire contract, so no argument smuggles anything the sink did not
intend, and only the missing authentication is a defect.

``execute_code`` declares a restricted subset — ``validate_code`` runs,
``safe_builtins`` is curated, ``_getattr_`` mediation is *supposed* to be in
place. The payload escapes the subset the tool advertised. That is an argument
carrying something the sink did not intend, which is the seam.

The two defences are complementary, and neither is complete alone
-----------------------------------------------------------------
This is the part worth stating plainly rather than claiming coverage.

Upstream's ``validate_code`` denies **literal dunder strings**. The guard here
denies **sink calls**. They fail on opposite inputs, which
:class:`TestTheTwoDefencesCoverDifferentHalves` pins in both directions:

- The advisory's runtime-constructed payload contains no literal ``__class__``,
  so ``validate_code`` passes it — and it must still spell ``getattr(``, so this
  guard refuses it. That is exactly the gap that was exploited.
- A payload using plain attribute access (``"".__class__.__mro__``) calls no
  sink, so this guard **allows** it — and it does contain the literal dunder, so
  ``validate_code`` catches it.

So the honest claim is not "agent-airlock fixes CVE-2026-53710". It is: a
deny-by-default sink check at the tool-call boundary refuses the payload that
defeated the string denylist, and the two layers want to be run together.
:class:`TestDocumentedLimit` pins the guard's own stated blind spot as well.
"""

from __future__ import annotations

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock.mcp_spec.eval_rce_guard import DEFAULT_EVAL_SINKS, EvalRCEGuard, EvalRCEVerdict
from agent_airlock.policy_presets import stdio_guard_eval_defaults_2026_05_15

CVE = "CVE-2026-53710"

#: NVD's description, verbatim, so the classifier assertions below are checked
#: against the real record rather than a paraphrase of it.
NVD_DESCRIPTION = (
    "MCP Context Forge is an AI gateway, registry, and proxy for MCP, A2A, REST, and gRPC "
    "APIs. Prior to 1.0.2, the python_sandbox_server in "
    "mcp-servers/python/python_sandbox_server/src/python_sandbox_server/server_fastmcp.py "
    "exposes raw getattr through safe_builtins, omits a required _getattr_ guard, and relies "
    "on validate_code checks for literal dangerous dunder strings. An attacker can construct "
    "dunder names at runtime, traverse the Python class hierarchy, reach subprocess.Popen, "
    "and execute OS commands with the server process privileges through the execute_code MCP "
    "tool. The HTTP/SSE transport can expose this tool without authentication, while "
    "stdio-only deployments have reduced network reachability. The issue affects the "
    "python_sandbox_server subproject and does not directly affect the core Context Forge "
    "gateway or proxy components. This issue is fixed in version 1.0.2."
)

#: NVD's CWEs. CWE-94 is argument-shaped, which is what filed this one.
NVD_CWES = ["CWE-94", "CWE-693"]

# The advisory's payload shape: dunder names assembled at runtime so that a
# denylist searching for the literal strings sees nothing, then walked through
# the exposed `getattr` to reach `subprocess.Popen`.
PAYLOAD_RUNTIME_DUNDERS = (
    'D = "__" + "class" + "__"\n'
    'S = "__" + "subclasses" + "__"\n'
    'base = getattr(getattr("", D), "__mro__")[-1]\n'
    "for c in getattr(base, S)():\n"
    '    if c.__name__ == "Popen":\n'
    '        c(["/bin/sh", "-c", "id"])\n'
)

# The same traversal written the obvious way. Upstream's denylist catches this
# one; it is here to pin that this guard does *not*, which is the whole reason
# the two layers are complementary rather than redundant.
PAYLOAD_LITERAL_DUNDERS = 'x = "".__class__.__mro__[-1].__subclasses__()\n'

# Other sink spellings an attacker reaches for once `getattr` is refused.
PAYLOAD_IMPORT = "__import__('subprocess').Popen(['/bin/sh','-c','id'])\n"
PAYLOAD_EXEC = "exec('import subprocess; subprocess.Popen([\"id\"])')\n"

# What `execute_code` exists to run.
BENIGN_ARITHMETIC = "result = sum([1, 2, 3]) * 2\nprint(result)\n"
BENIGN_STRING_WORK = "words = 'a b c'.split()\nprint('-'.join(sorted(words)))\n"


def _guard() -> EvalRCEGuard:
    """The stock guard. No operator tuning — the defaults already carry `getattr`."""
    return EvalRCEGuard()


class TestTheAdvisoryPayloadIsRefused:
    """The disclosed proof-of-concept shape is denied at the argument boundary."""

    def test_runtime_constructed_dunder_traversal_is_denied(self) -> None:
        decision = _guard().evaluate({"code": PAYLOAD_RUNTIME_DUNDERS})
        assert decision.verdict is EvalRCEVerdict.DENY_EVAL_SINK
        assert decision.matched_sink == "getattr"

    @pytest.mark.parametrize(
        ("label", "payload", "sink"),
        [
            ("dunder_traversal", PAYLOAD_RUNTIME_DUNDERS, "getattr"),
            ("import_subprocess", PAYLOAD_IMPORT, "__import__"),
            ("bare_exec", PAYLOAD_EXEC, "exec"),
        ],
    )
    def test_each_route_to_popen_is_denied(self, label: str, payload: str, sink: str) -> None:
        decision = _guard().evaluate({"code": payload})
        assert decision.verdict is EvalRCEVerdict.DENY_EVAL_SINK, label
        assert decision.matched_sink == sink

    def test_getattr_is_a_default_sink_not_an_operator_addition(self) -> None:
        # The fix requires no configuration. If this ever stops being true, the
        # claim in this file's docstring stops being true with it.
        assert "getattr" in DEFAULT_EVAL_SINKS

    def test_the_tool_still_runs_the_code_it_exists_for(self) -> None:
        for benign in (BENIGN_ARITHMETIC, BENIGN_STRING_WORK):
            assert _guard().evaluate({"code": benign}).verdict is EvalRCEVerdict.ALLOW


class TestTheTwoDefencesCoverDifferentHalves:
    """Pin the complementarity in both directions, so neither is over-claimed.

    Upstream denies literal dunder strings; this guard denies sink calls. The
    advisory exists because only the first was deployed.
    """

    def test_the_advisory_payload_carries_no_literal_dunder(self) -> None:
        # This is *why* validate_code passed it — the advisory transcript records
        # "Code passed validation" immediately before the escape succeeded.
        assert "__class__" not in PAYLOAD_RUNTIME_DUNDERS
        assert "__subclasses__" not in PAYLOAD_RUNTIME_DUNDERS

    def test_the_sink_check_catches_what_the_string_denylist_missed(self) -> None:
        assert _guard().evaluate({"code": PAYLOAD_RUNTIME_DUNDERS}).verdict is (
            EvalRCEVerdict.DENY_EVAL_SINK
        )

    def test_the_string_denylist_catches_what_the_sink_check_misses(self) -> None:
        # Plain attribute access calls no sink, so this guard allows it. Stating
        # it here is the point: a reader must not take this fixture as a claim
        # that the sandbox escape class is closed by agent-airlock alone.
        assert "__class__" in PAYLOAD_LITERAL_DUNDERS
        assert _guard().evaluate({"code": PAYLOAD_LITERAL_DUNDERS}).verdict is (
            EvalRCEVerdict.ALLOW
        )


class TestDocumentedLimit:
    """The guard's own docstring names this blind spot; pin it rather than imply it away."""

    def test_a_constructed_sink_name_is_not_detected_by_default(self) -> None:
        # EvalRCEGuard matches the `[<ns>.]<label>(` shape. An attacker who also
        # assembles the *sink* name at runtime defeats that, exactly as the
        # module docstring says of `locals()["eval"](...)`.
        payload = 'f = __builtins__["get" + "attr"]\nf(object, "x")\n'
        assert _guard().evaluate({"code": payload}).verdict is EvalRCEVerdict.ALLOW

    def test_an_operator_can_close_it_with_extra_sinks(self) -> None:
        # The escape hatch the docstring points at actually works.
        payload = 'f = locals()["eval"]\nf("1+1")\n'
        tuned = EvalRCEGuard(extra_sinks=frozenset({"locals"}))
        assert tuned.evaluate({"code": payload}).verdict is EvalRCEVerdict.DENY_EVAL_SINK


class TestScopeBoundary:
    """Pin the halves of this CVE that agent-airlock does **not** reach."""

    def test_guard_cannot_see_the_missing_authentication_on_the_transport(self) -> None:
        # The guard's entire input is the call's arguments, so authentication is
        # structurally invisible to it: the verdict is identical for an
        # authenticated caller, an unauthenticated one, and a call carrying a
        # forged credential. That is the half upstream 1.0.2 owns.
        guard = _guard()
        verdicts = {
            guard.evaluate(args).verdict
            for args in (
                {"code": BENIGN_ARITHMETIC},
                {"code": BENIGN_ARITHMETIC, "authorization": None},
                {"code": BENIGN_ARITHMETIC, "authorization": "Bearer forged"},
            )
        }
        assert verdicts == {EvalRCEVerdict.ALLOW}

        # And the refusal is likewise unchanged by a valid-looking credential:
        # the payload decides, not the caller's identity.
        assert (
            guard.evaluate(
                {"code": PAYLOAD_RUNTIME_DUNDERS, "authorization": "Bearer legitimate"}
            ).verdict
            is EvalRCEVerdict.DENY_EVAL_SINK
        )

    def test_preset_does_not_claim_this_cve(self) -> None:
        # The preset claims the CVEs it *addresses*. It does not address
        # CVE-2026-53710, whose defect is upstream's safe_builtins configuration.
        # It refuses the payload that configuration let through.
        preset = stdio_guard_eval_defaults_2026_05_15()
        assert CVE not in preset["cves"]
        assert preset["cves"] == ("CVE-2026-44717",)


class TestWatcherAdmittedThisOnBothSignals:
    """Unlike CVE-2026-59971, filed the same day, this record is argument-shaped on its face.

    Both signals fire independently here: ``subprocess`` is a sink word and
    CWE-94 is in ``ARGUMENT_SHAPED_CWES``. That redundancy is why this one
    survives the negation-aware sink matching added alongside it, while
    CVE-2026-59971 — whose only sink match was the word ``stdio`` inside
    "The default stdio transport is not affected" — does not.
    """

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_sink_signal_alone_would_have_filed_it(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, []) == "candidate"

    def test_the_cwe_signal_alone_would_have_filed_it(self) -> None:
        assert classify_shape("", NVD_CWES) == "candidate"
