"""Install commands meet the same lists and release-age check as package arguments (0.10.37).

GHSA-pm3r-rxg9-cj5j (published 2026-11-26T17:14:35Z, Critical): ``tzero-mcp`` 12.3.0 on npm
is malware. GHSA-v3pr-5www-qwjr (2026-11-27T21:31:59Z, Critical): ``qwen-tts-runtime`` 0.3.0
on PyPI is malware, one of a family published the same evening (``qwen-tts-cpu``,
``qwentts-gradio``, ``qwenvox-tts-3`` and their siblings). No snapshot in ``data/`` lists
them.

https://github.com/advisories/GHSA-pm3r-rxg9-cj5j
https://github.com/advisories/GHSA-v3pr-5www-qwjr

Measured on d763fb5c with a guard built from the preset and a lookup that says "published
12 h ago": ``{"package": "tzero-mcp@12.3.0"}`` was ``deny_release_too_new`` while
``{"command": "npm i tzero-mcp@12.3.0"}``, ``{"cmd": "npx -y tzero-mcp@12.3.0"}``, the MCP
launch ``{"command": "npx", "args": ["-y", "tzero-mcp@12.3.0"]}``, ``pip install`` and
``uvx`` of ``qwen-tts-runtime==0.3.0`` were all allowed: the guard read no command. An agent
installs through a shell tool far more often than through a ``package`` argument.

The clock is pinned, every lookup is a stub and the snapshot is pinned to 2026-11-20: no
test touches the network or runs a command.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from agent_airlock.mcp_spec import malware_advisory_feed
from agent_airlock.mcp_spec.install_command import InstallSpec, install_specs
from agent_airlock.mcp_spec.oidc_publish_window_guard import (
    OIDCPublishWindowGuard,
    OIDCPublishWindowVerdict,
)
from agent_airlock.policy_presets import npm_oidc_publish_window_guard_defaults

V = OIDCPublishWindowVerdict
SNAPSHOT = "malware_blast_2026_11_20.json"
NOW = datetime(2026, 11, 28, 4, 0, tzinfo=timezone.utc)
KEYS = (
    "blast_list",
    "blocked_packages",
    "advisories",
    "installs_from",
    "rescoped_names",
    "min_release_age",
    "release_time_lookup",
    "unknown_release_age",
    "release_age_allow",
)

# (installs_from, the command arguments, the matching package argument)
INSTALLS: list[tuple[str, dict[str, Any], dict[str, Any]]] = [
    ("npm", {"command": "npm i tzero-mcp@12.3.0"}, {"package": "tzero-mcp@12.3.0"}),
    ("npm", {"cmd": "npx -y tzero-mcp@12.3.0"}, {"package": "tzero-mcp@12.3.0"}),
    (
        "npm",
        {"command": "npx", "args": ["-y", "tzero-mcp@12.3.0"]},
        {"package": "tzero-mcp@12.3.0"},
    ),
    ("npm", {"argv": ["npm", "install", "tzero-mcp@12.3.0"]}, {"package": "tzero-mcp@12.3.0"}),
    ("npm", {"command": "cd app && npm i tzero-mcp@12.3.0"}, {"package": "tzero-mcp@12.3.0"}),
    ("npm", {"command": 'sh -c "npx -y tzero-mcp@12.3.0"'}, {"package": "tzero-mcp@12.3.0"}),
    (
        "pypi",
        {"command": "pip install qwen-tts-runtime==0.3.0"},
        {"package": "qwen-tts-runtime==0.3.0"},
    ),
    (
        "pypi",
        {"command": "uvx qwen-tts-runtime==0.3.0"},
        {"package": "qwen-tts-runtime==0.3.0"},
    ),
    (
        "pypi",
        {"command": "sudo pip install qwen-tts-runtime==0.3.0"},
        {"package": "qwen-tts-runtime==0.3.0"},
    ),
    (
        "pypi",
        {"command": "python3 -m pip install qwen-tts-runtime==0.3.0"},
        {"package": "qwen-tts-runtime==0.3.0"},
    ),
    (
        "pypi",
        {"command": "uv tool install qwen-tts-runtime@0.3.0"},
        {"package": "qwen-tts-runtime==0.3.0"},
    ),
]


def _install_id(row: tuple[str, dict[str, Any], dict[str, Any]]) -> str:
    return str(next(iter(row[1].values()))) if len(row[1]) == 1 else str(row[1])


class _Lookup:
    """Answers every question with one age and records what it was asked."""

    def __init__(self, age: timedelta | None) -> None:
        self.age = age
        self.asked: list[tuple[str, str, str | None]] = []

    def __call__(self, kind: str, name: str, version: str | None) -> datetime | None:
        self.asked.append((kind, name, version))
        return None if self.age is None else NOW - self.age


@pytest.fixture(autouse=True)
def snapshot_2026_11_20(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """The 2026-11-20 snapshot, which lists neither package, whatever ships later."""
    monkeypatch.setattr(malware_advisory_feed, "_newest_snapshot_name", lambda root: SNAPSHOT)
    malware_advisory_feed.load_malware_blast_snapshot.cache_clear()
    yield
    malware_advisory_feed.load_malware_blast_snapshot.cache_clear()


def _guard(installs_from: str, lookup: Any, **overrides: Any) -> OIDCPublishWindowGuard:
    cfg = npm_oidc_publish_window_guard_defaults(
        installs_from=installs_from, release_time_lookup=lookup
    )
    kwargs = {key: cfg[key] for key in KEYS} | overrides
    return OIDCPublishWindowGuard(**kwargs, clock=lambda: NOW)


class TestTheInstallsOfThe26And27November:
    @pytest.mark.parametrize("row", INSTALLS, ids=_install_id)
    def test_twelve_hours_old_the_command_is_refused_like_the_package(
        self, row: tuple[str, dict[str, Any], dict[str, Any]]
    ) -> None:
        installs_from, command, package = row
        guard = _guard(installs_from, _Lookup(timedelta(hours=12)))
        assert guard.evaluate(package).verdict is V.DENY_RELEASE_TOO_NEW
        decision = guard.evaluate(command)
        assert decision.verdict is V.DENY_RELEASE_TOO_NEW
        assert "the policy requires 7 d" in decision.detail

    @pytest.mark.parametrize("row", INSTALLS, ids=_install_id)
    def test_four_hundred_days_old_both_are_allowed(
        self, row: tuple[str, dict[str, Any], dict[str, Any]]
    ) -> None:
        installs_from, command, package = row
        guard = _guard(installs_from, _Lookup(timedelta(days=400)))
        assert guard.evaluate(package).allowed is True
        assert guard.evaluate(command).allowed is True

    def test_the_lookup_is_asked_in_the_installer_s_registry(self) -> None:
        lookup = _Lookup(timedelta(days=400))
        guard = _guard("any", lookup)
        guard.evaluate({"command": "npm i tzero-mcp && pip install qwen-tts-runtime"})
        assert lookup.asked == [("npm", "tzero-mcp", None), ("pypi", "qwen-tts-runtime", None)]

    def test_installs_from_pypi_still_judges_an_npm_install_as_its_package_argument(
        self,
    ) -> None:
        """The installer names the registry; skipping it would let ``npm i`` through."""
        young = _guard("pypi", _Lookup(timedelta(hours=12)))
        assert young.evaluate({"package": "tzero-mcp@12.3.0"}).verdict is V.DENY_RELEASE_TOO_NEW
        assert young.evaluate({"command": "npm i tzero-mcp@12.3.0"}).verdict is (
            V.DENY_RELEASE_TOO_NEW
        )
        old = _guard("pypi", _Lookup(timedelta(days=400)))
        assert old.evaluate({"command": "npm i tzero-mcp@12.3.0"}).allowed is True


class TestTheListsReadCommandsToo:
    def test_a_listed_release_in_a_command_reports_the_list_verdict(self) -> None:
        guard = _guard("npm", _Lookup(timedelta(days=400)))
        decision = guard.evaluate({"command": "npx -y @fdcasj_dfew/md-doc-mcp@1.0.0"})
        assert decision.verdict is V.DENY_BLAST_LIST_PAIR
        assert "GHSA-m5xq-h2p4-962g" in decision.detail

    def test_without_min_release_age_a_listed_release_is_still_refused(self) -> None:
        guard = _guard("npm", None, min_release_age=None, release_time_lookup=None)
        assert guard.evaluate({"command": "npm i @fdcasj_dfew/md-doc-mcp@1.0.0"}).verdict is (
            V.DENY_BLAST_LIST_PAIR
        )
        assert guard.evaluate({"command": "npm i tzero-mcp@12.3.0"}).allowed is True


class TestWhatTheGuardCannotRead:
    @pytest.mark.parametrize(
        ("command", "named"),
        [
            ("npm i $(cat pkgs)", "substitution"),
            ("pip install -r req.txt", "-r reads its packages from a file"),
            ("pip install -c constraints.txt x", "-c reads constraints from a file"),
            ("pip install -e .", "-e installs an editable project"),
            ("pip install .", "local path"),
            ("npm i ./pkg.tgz", "local path"),
            ("npm i $PKG", "a value the shell decides"),
            ("echo tzero-mcp | xargs npm i", "xargs or find -exec"),
            ("npx -c 'tzero --help'", "-c runs shell text"),
            ("python -c 'import os'", "inline code"),
        ],
    )
    def test_it_is_refused_as_uninspectable_naming_why(self, command: str, named: str) -> None:
        decision = _guard("any", _Lookup(timedelta(days=400))).evaluate({"command": command})
        assert decision.verdict is V.DENY_UNINSPECTABLE
        assert named in decision.detail

    @pytest.mark.parametrize("value", [42, {"run": "npm i x"}, ["npm", 1]])
    def test_a_command_of_another_shape_is_refused(self, value: Any) -> None:
        decision = _guard("npm", _Lookup(timedelta(days=400))).evaluate({"command": value})
        assert decision.verdict is V.DENY_UNINSPECTABLE


class TestCommandsWithNoInstall:
    @pytest.mark.parametrize(
        "command",
        ["ls -la", "npm test", "npm install", "pip list", "uv run pytest", "git status", ""],
    )
    def test_it_passes(self, command: str) -> None:
        lookup = _Lookup(timedelta(hours=1))
        assert _guard("any", lookup).evaluate({"command": command}).allowed is True
        assert lookup.asked == []

    def test_utf8_bytes_are_read_as_text(self) -> None:
        decision = _guard("npm", _Lookup(timedelta(hours=12))).evaluate(
            {"command": b"npm i tzero-mcp@12.3.0"}
        )
        assert decision.verdict is V.DENY_RELEASE_TOO_NEW


def _read(argv: list[str]) -> list[tuple[str, str, str | None]]:
    return [(spec.kind, spec.spec, spec.uninspectable) for spec in install_specs(argv)]


class TestInstallSpecs:
    @pytest.mark.parametrize(
        ("argv", "expected"),
        [
            (["npm", "i", "-D", "a", "b@1"], [("npm", "a", None), ("npm", "b@1", None)]),
            (["npm", "--registry", "r", "add", "a"], [("npm", "a", None)]),
            (["npx", "-p", "@a/cli", "ng", "new"], [("npm", "@a/cli", None)]),
            (["npm", "exec", "--", "create-x@2", "--y"], [("npm", "create-x@2", None)]),
            (["pnpm", "dlx", "create-x@1"], [("npm", "create-x@1", None)]),
            (["yarn", "global", "add", "z"], [("npm", "z", None)]),
            (["bunx", "--bun", "q@1", "--flag"], [("npm", "q@1", None)]),
            (["pip3.12", "install", "-i", "https://x/simple", "q"], [("pypi", "q", None)]),
            (["/opt/venv/bin/pip", "install", "-U", "q"], [("pypi", "q", None)]),
            (["uvx", "ruff@0.6.0", "check"], [("pypi", "ruff==0.6.0", None)]),
            (["uvx", "--from", "httpie", "http", "GET"], [("pypi", "httpie", None)]),
            (
                ["uv", "run", "--with", "a,b>=1,<2", "pytest"],
                [("pypi", "a", None), ("pypi", "b>=1,<2", None)],
            ),
            (["pipx", "run", "--spec", "black==24", "black"], [("pypi", "black==24", None)]),
            (["pipx", "inject", "venv", "p1"], [("pypi", "p1", None)]),
            (
                ["npm", "i", "git+https://github.com/a/b"],
                [("npm", "git+https://github.com/a/b", None)],
            ),
        ],
    )
    def test_each_installer_names_its_packages(
        self, argv: list[str], expected: list[tuple[str, str, str | None]]
    ) -> None:
        assert _read(argv) == expected

    @pytest.mark.parametrize(
        "argv",
        [
            ["npm", "test"],
            ["npm", "ci"],
            ["uv", "sync"],
            ["uv", "run", "pytest"],
            ["bun", "install"],
        ],
    )
    def test_a_command_naming_no_package_names_none(self, argv: list[str]) -> None:
        assert install_specs(argv) == []

    def test_a_clustered_short_option_is_read_letter_by_letter(self) -> None:
        [refused] = install_specs(["pip", "install", "-Ur", "req.txt"])
        assert refused.uninspectable == "-r reads its packages from a file"

    def test_an_unknown_option_is_a_flag_so_the_next_word_is_judged(self) -> None:
        assert _read(["pip", "install", "--some-new-flag", "tzero"]) == [("pypi", "tzero", None)]

    def test_a_fed_install_is_uninspectable(self) -> None:
        [fed] = install_specs(["npm", "i", "x"], fed=True)
        assert fed == InstallSpec(
            "npm", "npm", "npm install", "takes packages from xargs or find -exec"
        )
