"""Contract tests for the unified ``airlock`` dispatcher (``agent_airlock.cli.__main__``).

The dispatcher's promise: ``airlock <cmd> ...`` behaves exactly like
``python -m agent_airlock.cli.<module> ...`` — same subcommand, same flags — because
it delegates to each module's own ``main(argv)`` and never re-declares options. These
tests pin that promise:

* every subcommand's ``--help`` exposes the same option flags whether reached through
  the dispatcher or by calling the target module directly (this also proves the
  space-form name routes to the *correct* module);
* ``airlock`` with no args lists the subcommands and exits 0;
* ``airlock <unknown>`` exits non-zero;
* every module under ``agent_airlock/cli/`` (bar dunders) is registered — a new CLI
  module cannot silently ship without a subcommand.
"""

from __future__ import annotations

import contextlib
import importlib
import io
import re
from pathlib import Path

import pytest

from agent_airlock.cli import __main__ as dispatcher

# The space-form contract: subcommand name -> module basename. Hardcoded on purpose
# (independent of the dispatcher's own registry) so a wrong mapping is caught.
EXPECTED: dict[str, str] = {
    "scan-tools": "scan_tools",
    "doctor": "doctor",
    "verify": "verify",
    "explain": "explain",
    "policy": "policy",
    "attest": "attest",
    "baseline": "baseline",
    "manifest": "manifest",
    "conformance": "conformance",
    "pack": "pack",
    "corpus-bench": "corpus_bench",
    "egress-bench": "egress_bench",
    "negotiation-bench": "negotiation_bench",
    "replay": "replay",
    "graph": "graph",
    "trace": "trace",
    "kill-switch": "kill_switch",
    "console": "console",
    "studio": "studio",
}

_FLAG_RE = re.compile(r"--[a-zA-Z][\w-]*")


def _capture(call) -> str:  # type: ignore[no-untyped-def]
    """Run ``call``, swallowing argparse's ``--help`` SystemExit; return stdout+stderr."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        with contextlib.suppress(SystemExit):
            call()
    return buf.getvalue()


def _help_flags(call) -> set[str]:  # type: ignore[no-untyped-def]
    return set(_FLAG_RE.findall(_capture(call)))


@pytest.mark.parametrize("command", sorted(EXPECTED))
def test_help_flags_match_direct_module(command: str) -> None:
    """`airlock <cmd> --help` exposes the same options as the module's own --help."""
    module_name = EXPECTED[command]
    try:
        module = importlib.import_module(f"agent_airlock.cli.{module_name}")
    except ImportError as exc:  # optional-extra module not installed in this env
        pytest.skip(f"{module_name} needs an optional extra: {exc}")

    direct = _help_flags(lambda: module.main(["--help"]))
    routed = _help_flags(lambda: dispatcher.main([command, "--help"]))

    assert "--help" in direct, f"{module_name}.main(['--help']) exposed no options"
    assert routed == direct, (
        f"'airlock {command} --help' options {sorted(routed)} != "
        f"'python -m agent_airlock.cli.{module_name} --help' options {sorted(direct)}"
    )


def test_no_args_lists_commands_and_exits_zero() -> None:
    out = _capture(lambda: _assert_exit(dispatcher.main([]), 0))
    for command in EXPECTED:
        assert command in out, f"subcommand {command!r} missing from `airlock` listing"


def test_help_flag_lists_commands() -> None:
    for flag in ("-h", "--help"):
        out = _capture(lambda f=flag: _assert_exit(dispatcher.main([f]), 0))
        assert "scan-tools" in out and "doctor" in out


def test_unknown_command_is_nonzero() -> None:
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        code = dispatcher.main(["definitely-not-a-command"])
    assert code != 0
    assert "unknown command" in buf.getvalue()


def test_every_cli_module_is_registered() -> None:
    """No CLI module may ship without a dispatcher subcommand."""
    cli_dir = Path(dispatcher.__file__).parent
    modules_on_disk = {
        p.stem for p in cli_dir.glob("*.py") if p.stem not in {"__init__", "__main__"}
    }
    registered = set(EXPECTED.values())
    assert modules_on_disk == registered, (
        f"unregistered CLI modules: {sorted(modules_on_disk - registered)}; "
        f"stale registrations: {sorted(registered - modules_on_disk)}"
    )


def test_registry_matches_dispatcher_commands() -> None:
    """The test's expected mapping must match the dispatcher's own registry."""
    dispatcher_map = {name: mod for name, (mod, _) in dispatcher._COMMANDS.items()}
    assert dispatcher_map == EXPECTED


def _assert_exit(code: int, expected: int) -> None:
    assert code == expected, f"expected exit {expected}, got {code}"
