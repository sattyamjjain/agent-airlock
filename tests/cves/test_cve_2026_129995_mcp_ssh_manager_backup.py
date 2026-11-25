"""CVE-2026-129995 — mcp-ssh-manager splices ssh_backup_* tool arguments into a shell command.

Vulnerability (from NVD and GHSA-qwwm-vrm9-4mw8):
    mcp-ssh-manager before 3.8.5: the builders in ``src/backup-manager.js`` concatenate the
    ``ssh_backup_create`` / ``restore`` / ``schedule`` / ``list`` tools' arguments
    (``database``, ``dbUser``, ``dbHost``, ``backupDir``, ``paths``, ``exclude``,
    ``schedule``, ``cronComment``) into a string that ``ssh.execCommand`` runs through the
    remote login shell. ``ssh_backup_schedule`` writes it to cron, and ``ssh_backup_list``
    skips the server policy, so it runs in readonly mode too. The earlier fix for
    the sibling database builders (GHSA-4jx9-2fwj-pg4j) did not cover these.

Advisory: https://github.com/bvisible/mcp-ssh-manager/security/advisories/GHSA-qwwm-vrm9-4mw8
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-129995
CVSS:     8.8 (HIGH) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H, CWE-78

Airlock fit: strong.
    The command is carried in the tool-call arguments, and
    :class:`~agent_airlock.tool_arg_sink_guard.ToolArgSinkGuard` refuses shell syntax in the
    arguments the operator names, at step 2.75 of the call path. A second-defence fixture
    against an existing guard, not a new guard.
"""

from __future__ import annotations

from typing import Any

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock import Airlock, AirlockConfig, SecurityPolicy
from agent_airlock.policy_presets import tool_arg_sink_defaults
from agent_airlock.tool_arg_sink_guard import ToolArgSinkGuard

CVE = "CVE-2026-129995"

#: NVD's description, verbatim, so the classifier assertions read the real record. The sibling
#: CVE's id is split across two literals: whole, it would count as tracked here.
NVD_DESCRIPTION = (
    "mcp-ssh-manager is an MCP server for managing servers over SSH with human approval, "
    "an encrypted vault, and a live audit trail. Prior to 3.8.5, ssh_backup_create, "
    "ssh_backup_restore, ssh_backup_schedule, and ssh_backup_list build remote shell "
    "commands from caller-controlled values in src/backup-manager.js and inline backup "
    "handlers in src/index.js without neutralizing shell metacharacters. Crafted "
    "database, connection, backup directory, path, exclusion, schedule, or comment "
    "arguments can therefore execute arbitrary OS commands on managed remote servers as "
    "the configured SSH user. ssh_backup_schedule can persist execution through cron. "
    "ssh_backup_list does not pass through the server policy check and remains available "
    "in readonly and restricted modes, allowing command execution despite those "
    "restrictions. Tool arguments can be supplied by a malicious or compromised MCP "
    "client or steered through indirect prompt injection; fully trusted benign arguments "
    "do not trigger the issue. The earlier database-helper remediation for CVE-2026-"
    "77383 "
    "applied shell quoting to src/database-manager.js but did not cover these parallel "
    "backup builders. This issue is fixed in version 3.8.5."
)

NVD_CWES = ["CWE-78"]

#: The arguments the advisory's table names as reaching a builder.
_SHELL_ARGS = frozenset(
    {
        "database",
        "dbUser",
        "dbPassword",
        "dbHost",
        "backupDir",
        "paths",
        "exclude",
        "targetPath",
        "schedule",
        "cronComment",
    }
)


def _tool(guard: ToolArgSinkGuard) -> Any:
    @Airlock(
        policy=SecurityPolicy(tool_arg_sink_guard=guard),
        config=AirlockConfig(enable_audit_log=False),
    )
    def ssh_backup(
        database: str = "",
        dbHost: str = "",  # noqa: N803 - the tool's own argument names
        backupDir: str = "",  # noqa: N803
        paths: list[str] | None = None,
        schedule: str = "",
        cronComment: str = "",  # noqa: N803
    ) -> str:
        return "ran"

    return ssh_backup


class TestTheAdvisorySPayloadsAreRefused:
    @pytest.mark.parametrize(
        "arguments",
        [
            {"database": "appdb; id > /tmp/pwned.txt; #"},
            {"backupDir": '/var/backups"; id > /tmp/pwned.txt; echo "'},
            {"dbHost": "db.internal`id`"},
            {"paths": ["/srv/app", "$(id)"]},
            {"schedule": "0 2 * * * root id #\n* * * * *"},
            {"cronComment": "nightly\n* * * * * id"},
        ],
    )
    def test_the_call_is_blocked(self, arguments: dict[str, Any]) -> None:
        refused = _tool(ToolArgSinkGuard(shell_args=_SHELL_ARGS))(**arguments)
        assert refused["success"] is False
        assert refused["block_reason"] == "tool_arg_sink"
        assert refused["metadata"]["argument"].split("[")[0] in arguments

    def test_the_listing_tool_s_argument_needs_no_server_policy(self) -> None:
        # ssh_backup_list never reached the server's own policy check; this one is the call's.
        refused = _tool(ToolArgSinkGuard(screen_all_str_args=True))(
            backupDir='/var/backups"; id > /tmp/pwned.txt; echo "'
        )
        assert refused["block_reason"] == "tool_arg_sink"

    def test_an_ordinary_backup_runs(self) -> None:
        tool = _tool(ToolArgSinkGuard(shell_args=_SHELL_ARGS))
        assert (
            tool(
                database="appdb",
                dbHost="db.internal",
                backupDir="/var/backups/nightly",
                paths=["/srv/app", "/etc/app.conf"],
                schedule="0 2 * * *",
                cronComment="nightly",
            )
            == "ran"
        )


class TestScopeBoundary:
    def test_preset_does_not_claim_this_cve(self) -> None:
        assert CVE not in tool_arg_sink_defaults()["cves"]


class TestWatcherAdmittedThisOnTheCweSignal:
    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_argument_shaped_cwe_alone_files_it(self) -> None:
        assert classify_shape("", ["CWE-78"]) == "candidate"
