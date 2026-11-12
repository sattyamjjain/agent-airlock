"""0.10.34: a substitution marker is refused where a shell substitutes it, not in quoted text.

Until 0.10.34 ``ShellCommandPolicy`` refused a backtick, ``$(``, ``<(`` or ``>(`` anywhere
in a command line, before reading its quoting. ``grep '`' a.txt`` and ``sed -n '/`/p'``
were refused as unanalyzable although POSIX ``sh`` substitutes nothing inside single
quotes, while ``grep '$HOME' a.txt`` and the argv list ``["grep", "`", "a.txt"]`` were
read as text. The scanner now refuses a marker where the shell performs the substitution:
unquoted, inside double quotes, in a line with a heredoc, in the text a followed wrapper
runs, and in the words of a program that runs them as shell text (``eval``, ``ssh``...).
No test here runs a shell or touches the network: each one only reads a command line.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_airlock import ShellCommandPolicy
from agent_airlock.shell_command_policy import _RUNS_ARGUMENTS_AS_SHELL, _SHELLS, _wrapper

POLICY = ShellCommandPolicy(
    allow=("grep", "sed -n", "printf", "echo", "cat"),
    deny=("curl", "rm"),
    default="deny",
)
ALLOW_ONLY = ShellCommandPolicy(allow=("grep", "sed -n", "echo", "printf"), default="deny")
REFUSAL = "the command cannot be checked: it uses command or process substitution"


def _rule(command: Any, policy: ShellCommandPolicy = POLICY) -> str:
    return policy.decide(command).rule


class TestQuotedTextIsRead:
    """Text a shell reads literally is judged by the rules, not refused."""

    @pytest.mark.parametrize(
        "command",
        [
            "grep '`' a.txt",
            "grep '$(x)' a.txt",
            "grep '<(x)' a.txt",
            "grep '>(x)' a.txt",
            "sed -n '/`/p' a.txt",
            "grep \\` a.txt",
            'echo "a \\` b"',
            'grep "\\$(x)" a.txt',
            'grep "<(x)" a.txt',
            "printf x | grep '`'",
            "grep '`' a.txt | sed -n '/`/p'",
        ],
    )
    def test_it_is_readable(self, command: str) -> None:
        decision = POLICY.decide(command)
        assert decision.rule != "unanalyzable", (command, decision.detail)

    def test_a_single_quoted_backtick_is_allowed_by_an_allow_rule(self) -> None:
        decision = ALLOW_ONLY.decide("grep '`' a.txt")
        assert (decision.verdict, decision.rule, decision.program) == ("allow", "grep", "grep")

    def test_the_string_and_the_argv_list_now_agree(self) -> None:
        assert POLICY.decide("grep '`' a.txt").verdict == "allow"
        assert POLICY.decide(["grep", "`", "a.txt"]).verdict == "allow"

    def test_a_followed_wrapper_reads_its_own_quoting(self) -> None:
        assert POLICY.decide(r"find . -exec grep '`' {} \;").verdict == "allow"
        assert POLICY.decide("bash -c \"grep '\\`' a.txt\"").verdict == "allow"
        assert POLICY.decide("watch -x grep '`' a.txt").verdict == "allow"


class TestSubstitutionIsRefused:
    """Where a shell performs the substitution, the command is refused as unanalyzable."""

    @pytest.mark.parametrize(
        "command",
        [
            "echo `id`",
            "echo $(id)",
            "echo a$(id)",
            "diff <(ls) b",
            "tee >(cat) a.txt",
            'grep "`id`" a.txt',
            'grep "$(id)" a.txt',
            "echo ${x:-$(id)}",
        ],
    )
    def test_unquoted_or_double_quoted(self, command: str) -> None:
        assert _rule(command) == "unanalyzable", command

    @pytest.mark.parametrize(
        "command",
        [
            "bash -c 'echo `id`'",
            "sh -c 'echo $(id)'",
            "sudo -s 'echo `id`'",
            "sudo -i 'echo $(id)'",
            r"find . -exec sh -c 'echo `id`' \;",
            "xargs sh -c 'echo $(id)'",
            "watch 'echo `id`'",
            "watch grep x '`id`'",
            "git -c core.pager='less `id`' log",
        ],
    )
    def test_in_the_text_a_followed_wrapper_runs(self, command: str) -> None:
        assert _rule(command) == "unanalyzable", command

    @pytest.mark.parametrize(
        "command",
        [
            "cat <<EOF\n'`id`'\nEOF",
            "cat <<'EOF'\n$(id)\nEOF",
            "grep x <<< '`'",
        ],
    )
    def test_in_a_line_with_a_heredoc(self, command: str) -> None:
        assert _rule(command) == "unanalyzable", command

    @pytest.mark.parametrize(
        "command",
        [
            "eval 'echo `id`'",
            "ssh h 'echo `id`'",
            "su -c 'echo $(id)'",
            "trap 'echo `id`' EXIT",
            "command eval 'echo `id`'",
            "sudo su -c 'echo `id`'",
            "timeout 5 ssh h 'echo $(id)'",
            "docker exec c sh -c 'echo `id`'",
            "strace -f bash -c 'echo `id`'",
        ],
    )
    def test_in_the_words_of_a_program_that_runs_them_as_shell_text(self, command: str) -> None:
        assert _rule(command) == "unanalyzable", command

    def test_in_a_comment_as_before(self) -> None:
        assert _rule("echo hi # `id`") == "unanalyzable"
        assert _rule("grep x a.txt # find the backtick") == "grep"

    def test_a_wrapped_double_quoted_substitution_is_denied_with_an_allow_list(self) -> None:
        assert ALLOW_ONLY.decide("bash -c 'grep \"`id`\" a'").verdict == "deny"

    def test_an_argv_list_for_a_program_that_runs_shell_text(self) -> None:
        assert _rule(["eval", "echo `id`"]) == "unanalyzable"
        assert _rule(["ssh", "h", "echo $(id)"]) == "unanalyzable"

    def test_the_refusal_reads_as_it_did(self) -> None:
        decision = POLICY.decide("echo `id`")
        assert (decision.verdict, decision.rule, decision.detail) == (
            "deny",
            "unanalyzable",
            REFUSAL,
        )
        assert POLICY.decide("eval 'echo `id`'").detail == REFUSAL
        assert POLICY.decide("cat <<EOF\n'`id`'\nEOF").detail == REFUSAL


class TestTheProgramList:
    def test_no_entry_is_a_wrapper_the_policy_already_follows(self) -> None:
        # A followed wrapper re-reads the text it runs, so it needs no raw check.
        for program in _RUNS_ARGUMENTS_AS_SHELL:
            assert _wrapper(program) is None, program
            assert program not in _SHELLS, program

    def test_each_entry_refuses_a_marker_in_its_words(self) -> None:
        for program in _RUNS_ARGUMENTS_AS_SHELL:
            assert _rule(f"{program} x 'echo `id`'") == "unanalyzable", program
            assert _rule(f"{program} x 'echo plain'") != "unanalyzable", program
