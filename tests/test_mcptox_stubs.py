"""Tests for ``benchmarks.mcptox.stubs``: ``@Airlock`` stand-ins and the verdict of a call.

Tools are synthetic. Calls run through the real ``@Airlock`` decorator; the canary list
is the ground truth for whether a tool body ran.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from benchmarks.mcptox.clean import ParamSpec, ToolSpec
from benchmarks.mcptox.parse import Call
from benchmarks.mcptox.policies import EndpointScope, FsScope, Tier, TierPolicy, ToolScope
from benchmarks.mcptox.stubs import (
    ADMITTED,
    REFUSED,
    UNREPLAYABLE,
    build_stub,
    build_stub_set,
    filesystem_policy,
    make_config,
    quiet_airlock_logs,
    run_call,
)

READ = ToolSpec("read_file", (ParamSpec("path", "path", True),))
FETCH = ToolSpec("fetch", (ParamSpec("url", "url", True), ParamSpec("from", "from_", False)))
POISON = ToolSpec("helper", ())
ROOT = "/srv/airlock-mcptox-test"
FS = FsScope(roots=(ROOT,), deny_patterns=("*.pem",), max_path_depth=15, allow_symlinks=False)
OPEN = EndpointScope(kind="open_web", ssrf_precheck=True)


def _tier(tier: Tier) -> TierPolicy:
    allowed = None if tier is Tier.G0 else ("read_file", "fetch")
    scopes = (
        {"read_file": ToolScope(fs=FS), "fetch": ToolScope(endpoint=OPEN)}
        if tier is Tier.LP
        else {}
    )
    return TierPolicy("s", tier, tier, allowed_tools=allowed, scopes=scopes)


@pytest.fixture(autouse=True)
def _scratch(tmp_path: Path) -> Iterator[None]:
    previous = Path.cwd()
    os.chdir(tmp_path)
    with quiet_airlock_logs():
        yield
    os.chdir(previous)


def _verdicts(tier: Tier, *calls: Call) -> list[tuple[str, str | None]]:
    stubs = build_stub_set((READ, FETCH), _tier(tier)).with_poisoned(POISON)
    out = []
    for call in calls:
        v = run_call(stubs, call)
        out.append((v.outcome, v.block_reason or v.reason))
    return out


class TestContract:
    def test_admitted_call_runs_the_body_with_wire_names(self) -> None:
        stubs = build_stub_set((READ, FETCH), _tier(Tier.G0))
        verdict = run_call(stubs, Call("fetch", {"url": "https://example.com", "from": "me"}))
        assert verdict.outcome == ADMITTED
        assert stubs.canary == [("fetch", {"url": "https://example.com", "from": "me"})]

    def test_any_value_type_is_accepted(self) -> None:
        verdicts = _verdicts(
            Tier.G0,
            Call("read_file", {"path": 5}),
            Call("read_file", {"path": ["a", {"b": None}]}),
            Call("read_file", {"path": True}),
        )
        assert [o for o, _ in verdicts] == [ADMITTED] * 3

    def test_missing_required_and_ghost_arguments_refused(self) -> None:
        verdicts = _verdicts(
            Tier.G0,
            Call("read_file", {}),
            Call("read_file", {"path": "/x", "invented": 1}),
        )
        assert verdicts == [(REFUSED, "validation_error"), (REFUSED, "ghost_arguments")]

    def test_mangled_name_cannot_stand_in_for_its_parameter(self) -> None:
        assert _verdicts(Tier.G0, Call("fetch", {"url": "u", "from_": "x"})) == [
            (REFUSED, "ghost_arguments")
        ]

    def test_unknown_and_glob_names_are_unreplayable(self) -> None:
        assert _verdicts(Tier.G, Call("nope", {}), Call("read_*", {})) == [
            (UNREPLAYABLE, "unknown_tool"),
            (UNREPLAYABLE, "glob_metacharacter_in_tool_name"),
        ]


class TestTiers:
    def test_poisoned_tool_admitted_under_g0_refused_under_g(self) -> None:
        assert _verdicts(Tier.G0, Call("helper", {})) == [(ADMITTED, None)]
        assert _verdicts(Tier.G, Call("helper", {})) == [(REFUSED, "policy_violation")]

    def test_lp_path_scope(self) -> None:
        verdicts = _verdicts(
            Tier.LP,
            Call("read_file", {"path": f"{ROOT}/report.txt"}),
            Call("read_file", {"path": "/elsewhere/report.txt"}),
            Call("read_file", {"path": f"{ROOT}/server.pem"}),
        )
        assert verdicts == [
            (ADMITTED, None),
            (REFUSED, "path_violation"),
            (REFUSED, "path_violation"),
        ]

    def test_lp_open_web_ssrf_precheck(self) -> None:
        verdicts = _verdicts(
            Tier.LP,
            Call("fetch", {"url": "https://example.com/page"}),
            Call("fetch", {"url": "http://169.254.169.254/latest"}),
            Call("fetch", {"url": "http://0x7f000001/"}),
            Call("fetch", {"url": "http://localhost:8080/"}),
        )
        assert verdicts[0] == (ADMITTED, None)
        assert verdicts[1] == (REFUSED, "ssrf_egress:deny_metadata")
        assert verdicts[2] == (REFUSED, "ssrf_egress:deny_loopback")
        assert verdicts[3] == (REFUSED, "endpoint_blocked")

    def test_layers(self) -> None:
        stubs = build_stub_set((READ, FETCH), _tier(Tier.LP))
        assert run_call(stubs, Call("read_file", {})).layer == "contract"
        assert run_call(stubs, Call("read_file", {"path": "/etc/passwd"})).layer == "policy"


class TestConfig:
    def test_env_override_away_from_block_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AIRLOCK_UNKNOWN_ARGS", "strip_and_log")
        with pytest.raises(RuntimeError, match="BLOCK"):
            make_config("read_file", None)

    def test_config_has_no_audit_log_sanitizer_or_honeypot(self) -> None:
        config = make_config("read_file", None)
        assert not config.enable_audit_log
        assert not config.sanitize_output
        assert config.honeypot_config is None

    def test_tilde_root_is_granted_literally_and_expanded(self) -> None:
        policy = filesystem_policy(
            FsScope(roots=("~/charts",), deny_patterns=(), max_path_depth=15, allow_symlinks=False)
        )
        roots = {str(r) for r in policy.allowed_roots}
        assert str((Path.cwd() / "~" / "charts").resolve()) in roots
        assert str(Path("~/charts").expanduser().resolve()) in roots

    def test_glob_name_refused_at_build(self) -> None:
        canary: list[tuple[str, dict[str, Any]]] = []
        with pytest.raises(ValueError, match="glob"):
            build_stub(
                ToolSpec("x*", ()), canary=canary, config=make_config("x*", None), policy=None
            )

    def test_harness_fault_is_reported_not_dropped(self) -> None:
        stubs = build_stub_set((READ,), _tier(Tier.G0))

        def broken(**_: Any) -> Any:
            raise RuntimeError("boom")

        stubs.stubs["read_file"] = broken
        verdict = run_call(stubs, Call("read_file", {"path": "/x"}))
        assert verdict.outcome == UNREPLAYABLE
        assert verdict.reason == "harness_error:RuntimeError"

    def test_with_poisoned_shares_canary_and_policy(self) -> None:
        base = build_stub_set((READ,), _tier(Tier.G))
        withp = base.with_poisoned(POISON)
        assert withp.canary is base.canary
        assert withp.policy is base.policy
        assert "helper" in withp.stubs and "helper" not in base.stubs
        assert base.with_poisoned(None).poisoned_tool is None
