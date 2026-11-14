"""0.10.35: ``ShellCommandPolicy`` checks where a command writes.

Until 0.10.35 the policy dropped every redirection target unread and an allow rule naming a
program admitted any of its options, so with ``echo`` and ``find`` allowed,
``echo x >/dev/sda`` and ``find / -delete`` were allowed, and the shipped preset allowed
``cat /dev/zero > /dev/sda`` (generalbots/generalbots#2366). A run of operator characters
was also one token, read as a redirection, so ``ls ;>x rm -rf /`` was one ``ls`` command.
A redirection that writes now has its target checked against ``redirect_deny`` and
``redirect_allow``, and ``find``'s write actions need an allow rule that names them.
No test here runs a shell or touches the network: each one only reads a command line.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_airlock import Airlock, SecurityPolicy, ShellCommandPolicy
from agent_airlock.policy_presets import shell_command_defaults

ALLOW_LIST = ShellCommandPolicy(allow=("ls", "cat", "echo", "find", "git status"), default="deny")
DENY_LIST = ShellCommandPolicy(
    deny=("rm", "dd", "shred", "wipefs", "mkfs", "chmod", "shutdown", "reboot"),
    default="allow",
)
WRITES = "the command writes to a path it may not write"
UNDECIDED = "a redirection target is not known until the shell runs it"


def _decide(command: Any, policy: ShellCommandPolicy = ALLOW_LIST) -> tuple[str, str]:
    decision = policy.decide(command)
    return decision.verdict, decision.rule


class TestRedirectionTargets:
    """A redirection that writes to a denied path is refused, whatever allowed the command."""

    @pytest.mark.parametrize(
        "command",
        [
            "echo x >/dev/sda",
            "echo x > /dev/sda",
            "echo x >>/etc/passwd",
            "echo x 1>/dev/sda",
            "echo x &>/dev/sda",
            "echo x &>>/dev/sda",
            "echo x >|/dev/sda",
            "echo x >& /dev/sda",
            "cat <>/dev/sda",
            "echo x | cat >/dev/nvme0n1",
            "ls > /tmp/../dev/sda",
            "ls > //dev/sda",
            "ls > /dev/null/../sda",
            "ls > /dev/fd/../sda",
            "echo x > ~/.bashrc",
            "echo x >> ~/.ssh/authorized_keys",
            "echo x > ~/.ssh/../.zshrc",
            ">/dev/sda echo x",
            "ls; >/etc/passwd",
            "sh -c 'echo x > /dev/sda'",
            "echo x 2>/dev/null >/dev/sda",
            'echo x >"/dev/sda"',
            "echo x > /dev/s\\da",
            "echo x >\\\n/dev/sda",
            "echo x > ~//.bashrc",
            "echo x 1<>/dev/sda",
            "{ echo x; } > /dev/sda",
            "(echo x) > /dev/sda",
            "exec 3>/dev/sda",
        ],
    )
    def test_it_is_denied(self, command: str) -> None:
        decision = ALLOW_LIST.decide(command)
        assert decision.verdict == "deny", (command, decision)
        assert decision.rule.startswith("redirect "), (command, decision)
        assert decision.detail == WRITES

    @pytest.mark.parametrize(
        "command",
        [
            "echo hi >/dev/null",
            "cat a 2>/dev/null",
            "echo x 2>&1",
            "echo x >&2",
            "echo x >&-",
            "echo x 2>&1-",
            "echo x >/dev/stderr",
            "echo x >/dev/fd/3",
            "ls > out.txt",
            "echo x >> logs/run.log",
            "cat < /etc/hosts",
            "cat <<< /etc/hosts",
            "cat <&3",
            "ls&>out.txt",
            "echo x > /dev/null 2>&1",
            "cat a &> /dev/null",
        ],
    )
    def test_it_is_allowed(self, command: str) -> None:
        assert _decide(command)[0] == "allow", command

    def test_the_refusal_names_the_writing_program(self) -> None:
        decision = ALLOW_LIST.decide("echo x | cat >/dev/sda")
        assert (decision.program, decision.rule) == ("cat", "redirect /dev/*")

    def test_the_detail_names_no_rule_or_glob(self) -> None:
        decision = ALLOW_LIST.decide("echo x >/etc/passwd")
        assert "/etc" not in decision.detail and "redirect" not in decision.detail

    def test_an_argv_list_has_no_redirections(self) -> None:
        assert _decide(["echo", "x", ">", "/dev/sda"]) == ("allow", "echo")

    @pytest.mark.parametrize(
        ("command", "rule"),
        [
            ("watch 'echo x > /dev/sda'", "redirect /dev/*"),
            ('bash -c "cat a > /etc/x"', "redirect /etc/*"),
            ("find . -exec sh -c 'echo x > /dev/sda' \\;", "redirect /dev/*"),
            ("git -c core.pager='cat > /etc/x' log", "redirect /etc/*"),
        ],
    )
    def test_a_line_a_wrapper_runs_is_checked_with_a_default_of_allow(
        self, command: str, rule: str
    ) -> None:
        assert _decide(command, DENY_LIST) == ("deny", rule)

    def test_a_deny_rule_still_decides_first(self) -> None:
        assert _decide("rm x >/dev/sda", DENY_LIST) == ("deny", "rm")


class TestOperatorRuns:
    """Operator characters are read as the operators a shell reads in them."""

    @pytest.mark.parametrize(
        "command",
        [
            "ls ;>/tmp/x rm -rf /",
            "ls |>/tmp/x rm -rf /",
            "ls &&>/tmp/x rm -rf /",
            "ls ||>/tmp/x rm -rf /",
        ],
    )
    def test_a_separator_before_a_redirection_still_separates(self, command: str) -> None:
        decision = ALLOW_LIST.decide(command)
        assert (decision.verdict, decision.program) == ("deny", "rm"), command

    def test_a_redirection_with_no_command_is_checked(self) -> None:
        assert _decide("echo x;>/etc/passwd") == ("deny", "redirect /etc/*")


class TestUndecidedTargets:
    """A target the shell decides when it runs is asked about, or denied with no ask rule."""

    @pytest.mark.parametrize(
        "command",
        [
            'echo x > "$DEV"',
            "echo x > $HOME/.bashrc",
            "echo x > /dev/sd?",
            "echo x > /dev/sd[a-z]",
            "echo x > /de{v..v}/sda",
            "echo x > ~root/.bashrc",
            "echo x > ~+/x",
        ],
    )
    def test_it_is_denied_with_no_ask_rule(self, command: str) -> None:
        decision = DENY_LIST.decide(command)
        assert (decision.verdict, decision.detail) == ("deny", UNDECIDED), command
        assert decision.rule.startswith("redirect"), command

    def test_it_is_asked_about_with_an_ask_rule(self) -> None:
        policy = ShellCommandPolicy(ask=("git push",), default="allow")
        decision = policy.decide('echo x > "$OUT"')
        assert (decision.verdict, decision.detail) == ("ask", UNDECIDED)

    def test_a_command_the_default_denies_is_still_denied(self) -> None:
        policy = ShellCommandPolicy(allow=("echo",), ask=("git push",), default="deny")
        assert policy.decide('curl x > "$OUT"').verdict == "deny"

    def test_a_denied_target_wins_over_an_undecided_one(self) -> None:
        policy = ShellCommandPolicy(ask=("git push",), default="allow")
        assert _decide('echo x > "$A" > /dev/sda', policy) == ("deny", "redirect /dev/*")


class TestFindWriteActions:
    """An allow rule for ``find`` admits ``-delete`` and ``-fprint*`` only when it names them."""

    @pytest.mark.parametrize(
        "command",
        [
            "find / -delete",
            ["find", "/", "-delete"],
            "find . -fprint /etc/cron.d/x",
            "find . -fprint0 out",
            "find . -fprintf out %p",
            "find . -fls out",
            "env find / -delete",
            "/usr/bin/find / -delete",
            "busybox find / -delete",
            "find / -delet\\e",
            "find / -de''lete",
            "find / -exec echo {} \\; -delete",
            ["find", "/", "-exec", "echo", "{}", ";", "-delete"],
        ],
    )
    def test_it_falls_to_the_default(self, command: Any) -> None:
        decision = ALLOW_LIST.decide(command)
        assert (decision.verdict, decision.rule, decision.program) == ("deny", "default", "find")
        assert "needs an allow rule that names it" in decision.detail

    def test_find_without_a_write_action_is_allowed(self) -> None:
        assert _decide("find . -name '*.py'") == ("allow", "find")

    def test_a_rule_naming_the_action_admits_it(self) -> None:
        policy = ShellCommandPolicy(allow=("find -delete", "echo"), default="deny")
        assert _decide("find . -name '*.pyc' -delete", policy) == ("allow", "find -delete")
        assert _decide("find / -exec echo {} \\; -delete", policy)[0] == "allow"
        assert _decide("find . -fprint out", policy)[0] == "deny"

    def test_an_option_glob_names_every_action_it_matches(self) -> None:
        policy = ShellCommandPolicy(allow=("find -fprint*",), default="deny")
        assert _decide("find . -fprint0 out", policy) == ("allow", "find -fprint*")

    def test_an_ask_rule_naming_find_still_asks(self) -> None:
        policy = ShellCommandPolicy(allow=("find",), ask=("find -delete",), default="deny")
        assert _decide("find / -delete", policy)[0] == "ask"

    def test_a_default_of_allow_admits_what_no_rule_names(self) -> None:
        # Documented: in a deny-list policy, deny "find -delete" to refuse it.
        assert _decide("find / -delete", DENY_LIST)[0] == "allow"
        policy = ShellCommandPolicy(deny=("find -delete",), default="allow")
        assert _decide("find / -delete", policy) == ("deny", "find -delete")


class TestThePreset:
    def test_it_refuses_writes_to_devices_and_system_paths(self) -> None:
        shell = shell_command_defaults()["shell_policy"]
        assert _decide("cat /dev/zero > /dev/sda", shell) == ("deny", "redirect /dev/*")
        assert _decide("ls > /etc/cron.d/x", shell) == ("deny", "redirect /etc/*")
        assert _decide("cat a 2>/dev/null", shell) == ("allow", "cat")

    def test_on_the_call_path_the_refusal_names_no_glob(self) -> None:
        @Airlock(policy=shell_command_defaults()["policy"])
        def run_shell(command: str) -> str:
            return f"ran {command}"

        result = run_shell(command="cat /dev/zero > /dev/sda")
        assert isinstance(result, dict) and result["success"] is False
        assert result["metadata"]["violation_type"] == "shell_command_denied"
        assert WRITES in result["error"] and "/dev/*" not in result["error"]
        assert run_shell(command="cat a 2>/dev/null") == "ran cat a 2>/dev/null"


class TestSettings:
    def test_an_empty_redirect_deny_restores_the_0_10_34_reading(self) -> None:
        policy = ShellCommandPolicy(allow=("echo",), default="deny", redirect_deny=())
        assert _decide("echo x >/dev/sda", policy) == ("allow", "echo")
        assert _decide("echo x > /dev/sd?", policy) == ("allow", "echo")

    def test_redirect_allow_carves_out_of_redirect_deny(self) -> None:
        policy = ShellCommandPolicy(allow=("echo",), redirect_allow=("/dev/sdz",))
        assert _decide("echo x >/dev/sdz", policy) == ("allow", "echo")
        assert _decide("echo x >/dev/null", policy) == ("deny", "redirect /dev/*")

    def test_a_custom_glob_matches_a_relative_target(self) -> None:
        policy = ShellCommandPolicy(allow=("echo",), redirect_deny=("*.env",))
        assert _decide("echo x > .env", policy) == ("deny", "redirect *.env")
        assert _decide("echo x > /dev/sda", policy) == ("allow", "echo")

    def test_canonical_carries_both_fields(self) -> None:
        canonical = ShellCommandPolicy().canonical()
        assert canonical["redirect_deny"] == list(ShellCommandPolicy().redirect_deny)
        assert "/dev/null" in canonical["redirect_allow"]  # type: ignore[operator]
        custom = ShellCommandPolicy(redirect_deny=("/srv/*",)).canonical()
        assert custom["redirect_deny"] == ["/srv/*"]

    def test_the_policy_digest_covers_the_redirect_settings(self) -> None:
        plain = SecurityPolicy(shell_command_policy=ShellCommandPolicy())
        off = SecurityPolicy(shell_command_policy=ShellCommandPolicy(redirect_deny=()))
        assert plain._compute_policy_digest() != off._compute_policy_digest()

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"redirect_deny": "/dev/*"},
            {"redirect_allow": "/dev/null"},
            {"redirect_deny": ("/dev/*", 1)},
            {"redirect_allow": [None]},
        ],
    )
    def test_a_value_that_is_not_a_tuple_of_strings_is_refused(
        self, kwargs: dict[str, Any]
    ) -> None:
        with pytest.raises(ValueError, match="takes a tuple of strings"):
            ShellCommandPolicy(**kwargs)

    def test_a_list_of_strings_is_stored_as_a_tuple(self) -> None:
        policy = ShellCommandPolicy(redirect_deny=["/srv/*"])  # type: ignore[arg-type]
        assert policy.redirect_deny == ("/srv/*",)
