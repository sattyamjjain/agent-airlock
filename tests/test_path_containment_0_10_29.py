"""0.10.29: path containment that holds at the open, not only at the check.

GHSA-52hc-jp32-qrr3 (Goblohan, CWE-367): ``validate_path`` documented atomic, TOCTOU-safe
resolution, but it checks a path as it resolves when it runs and holds nothing open, and
step 3 discarded the path it returned, so the tool opened the argument as passed. A
directory swapped for a symlink between the check and the tool's ``open()`` sent a write
outside ``allowed_roots``. Two related gaps turned up while reproducing it:

- ``SafePathValidator(root_dir=...)`` checked ``root_dir / path`` but returned the relative
  ``path``, which ``open()`` resolved against the working directory, outside the jail.
- ``_refuse_symlinked`` skipped its walk when the leaf did not exist yet and swallowed every
  ``OSError``, so ``ws/link/new.txt`` passed with ``link`` a symlink and
  ``allow_symlinks=False``.

``open_contained`` walks the checked path from the allowed root one component at a time
with ``O_NOFOLLOW``, ``FilesystemPolicy(bind_resolved_paths=True)`` hands the tool the
path that was checked, and the docstrings now say what is and is not atomic.
"""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path
from typing import Any

import pytest
from pydantic import TypeAdapter

from agent_airlock import Airlock, AirlockConfig, SecurityPolicy
from agent_airlock import filesystem as fs
from agent_airlock.filesystem import (
    FilesystemPolicy,
    PathValidationError,
    open_contained,
    open_contained_file,
    validate_path,
)
from agent_airlock.oversight import OversightRequest, OversightResponse, OversightVerdict
from agent_airlock.safe_types import SafePathValidator, create_safe_path_type

ATOMIC_OPEN = (
    os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "O_DIRECTORY")
)
needs_atomic_open = pytest.mark.skipif(
    not ATOMIC_OPEN, reason="os.open has no dir_fd or O_NOFOLLOW on this platform"
)
needs_symlinks = pytest.mark.skipif(not hasattr(os, "symlink"), reason="no os.symlink")


@pytest.fixture
def layout(tmp_path: Path) -> tuple[Path, Path]:
    """``ws/reports`` inside the root and an ``outside`` directory beside it."""
    base = tmp_path.resolve()
    ws, outside = base / "ws", base / "outside"
    (ws / "reports").mkdir(parents=True)
    outside.mkdir()
    return ws, outside


def _grant(request: OversightRequest) -> OversightResponse:
    return OversightResponse(request.request_id, OversightVerdict.GRANT)


def _swap_for_symlink(directory: Path, target: Path) -> None:
    """Replace ``directory`` with a symlink to ``target``: the advisory's swap."""
    directory.rmdir()
    directory.symlink_to(target, target_is_directory=True)


def _swap_after_check(monkeypatch: pytest.MonkeyPatch, directory: Path, target: Path) -> None:
    """Make the swap land between ``open_contained``'s check and its walk."""
    real = fs.validate_path

    def check_then_swap(*args: object, **kwargs: object) -> Path:
        resolved = real(*args, **kwargs)  # type: ignore[arg-type]
        _swap_for_symlink(directory, target)
        return resolved

    monkeypatch.setattr(fs, "validate_path", check_then_swap)


@needs_symlinks
class TestComponentSwap:
    """The reporter's sequence, opened through ``open_contained``."""

    @needs_atomic_open
    def test_swap_after_the_check_is_refused_and_writes_nothing(
        self, layout: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ws, outside = layout
        policy = FilesystemPolicy(allowed_roots=[ws])
        _swap_after_check(monkeypatch, ws / "reports", outside)
        with pytest.raises(PathValidationError) as raised:
            open_contained(ws / "reports" / "out.md", policy, os.O_WRONLY | os.O_CREAT)
        assert raised.value.violation_type == "symlink_detected"
        assert not (outside / "out.md").exists()

    @needs_atomic_open
    def test_swap_is_refused_when_the_policy_allows_symlinks(
        self, layout: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ws, outside = layout
        policy = FilesystemPolicy(allowed_roots=[ws], allow_symlinks=True)
        _swap_after_check(monkeypatch, ws / "reports", outside)
        with pytest.raises(PathValidationError) as raised:
            open_contained(str(ws / "reports" / "out.md"), policy, os.O_WRONLY | os.O_CREAT)
        assert raised.value.violation_type == "symlink_detected"
        assert not (outside / "out.md").exists()

    @needs_atomic_open
    def test_swap_to_a_directory_inside_the_root_is_refused_too(
        self, layout: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The walk never follows a symlink, wherever it points."""
        ws, _ = layout
        (ws / "elsewhere").mkdir()
        _swap_after_check(monkeypatch, ws / "reports", ws / "elsewhere")
        with pytest.raises(PathValidationError, match="now a symlink"):
            open_contained(ws / "reports" / "out.md", FilesystemPolicy(allowed_roots=[ws]))

    @needs_atomic_open
    def test_swap_before_the_call_is_refused_by_the_check(self, layout: tuple[Path, Path]) -> None:
        ws, outside = layout
        _swap_for_symlink(ws / "reports", outside)
        with pytest.raises(PathValidationError):
            open_contained(ws / "reports" / "out.md", FilesystemPolicy(allowed_roots=[ws]), 0)
        assert not (outside / "out.md").exists()

    @needs_atomic_open
    def test_without_a_swap_the_write_lands_inside_the_root(
        self, layout: tuple[Path, Path]
    ) -> None:
        """Control: the same open with nothing swapped writes where it was checked."""
        ws, outside = layout
        fd = open_contained(
            ws / "reports" / "out.md",
            FilesystemPolicy(allowed_roots=[ws]),
            os.O_WRONLY | os.O_CREAT,
        )
        with os.fdopen(fd, "w") as handle:
            handle.write("report")
        assert (ws / "reports" / "out.md").read_text() == "report"
        assert not (outside / "out.md").exists()

    def test_validate_path_alone_does_not_stop_the_swap(self, layout: tuple[Path, Path]) -> None:
        """Pins the window ``open_contained`` exists for: check, swap, plain ``open()``."""
        ws, outside = layout
        target = validate_path(str(ws / "reports" / "out.md"), FilesystemPolicy(allowed_roots=[ws]))
        _swap_for_symlink(ws / "reports", outside)
        with open(target, "w") as handle:  # noqa: PTH123 - the racy open under test
            handle.write("escaped")
        assert (outside / "out.md").exists()

    def test_unsupported_platform_refuses_rather_than_open(
        self, layout: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ws, _ = layout
        monkeypatch.setattr(fs.os, "supports_dir_fd", frozenset())
        with pytest.raises(PathValidationError) as raised:
            open_contained(ws / "reports" / "out.md", FilesystemPolicy(allowed_roots=[ws]))
        assert raised.value.violation_type == "atomic_open_unsupported"

    @pytest.mark.skipif(ATOMIC_OPEN, reason="this platform supports the atomic open")
    def test_no_dir_fd_here_means_atomic_open_unsupported(self, layout: tuple[Path, Path]) -> None:
        ws, _ = layout
        with pytest.raises(PathValidationError) as raised:
            open_contained(ws / "reports" / "out.md", FilesystemPolicy(allowed_roots=[ws]))
        assert raised.value.violation_type == "atomic_open_unsupported"


@needs_symlinks
class TestStaticSymlink:
    """Control: a symlink present at check time is still refused."""

    def test_validate_path_refuses_a_present_symlink(self, layout: tuple[Path, Path]) -> None:
        ws, outside = layout
        (ws / "link").symlink_to(outside, target_is_directory=True)
        (outside / "data.txt").write_text("outside")
        with pytest.raises(PathValidationError) as raised:
            validate_path(str(ws / "link" / "data.txt"), FilesystemPolicy(allowed_roots=[ws]))
        assert raised.value.violation_type in {"symlink_detected", "outside_allowed_roots"}

    @needs_atomic_open
    def test_open_contained_refuses_a_present_symlink(self, layout: tuple[Path, Path]) -> None:
        ws, _ = layout
        (ws / "real").mkdir()
        (ws / "real" / "data.txt").write_text("inside")
        (ws / "link").symlink_to(ws / "real", target_is_directory=True)
        with pytest.raises(PathValidationError) as raised:
            open_contained(ws / "link" / "data.txt", FilesystemPolicy(allowed_roots=[ws]))
        assert raised.value.violation_type == "symlink_detected"

    @needs_atomic_open
    def test_a_leaf_symlink_is_refused(self, layout: tuple[Path, Path]) -> None:
        ws, outside = layout
        (outside / "secret").write_text("outside")
        (ws / "reports" / "out.md").symlink_to(outside / "secret")
        policy = FilesystemPolicy(allowed_roots=[ws], allow_symlinks=True)
        with pytest.raises(PathValidationError):
            open_contained(ws / "reports" / "out.md", policy, os.O_WRONLY)
        assert (outside / "secret").read_text() == "outside"


@needs_symlinks
class TestMissingLeafSymlink:
    """``_refuse_symlinked`` walks the ancestors of a leaf that does not exist yet."""

    def test_missing_leaf_under_a_symlinked_directory_is_refused(self, tmp_path: Path) -> None:
        ws = tmp_path.resolve() / "ws"
        (ws / "real").mkdir(parents=True)
        (ws / "link").symlink_to(ws / "real", target_is_directory=True)
        policy = FilesystemPolicy(allowed_roots=[ws], allow_symlinks=False)
        with pytest.raises(PathValidationError) as raised:
            validate_path(str(ws / "link" / "new.txt"), policy)
        assert raised.value.violation_type == "symlink_detected"
        assert raised.value.details["symlink_location"] == str(ws / "link")

    def test_missing_leaf_under_a_real_directory_is_admitted(self, tmp_path: Path) -> None:
        """Control: the same missing leaf with no symlink in its ancestry passes."""
        ws = tmp_path.resolve() / "ws"
        (ws / "real").mkdir(parents=True)
        resolved = validate_path(str(ws / "real" / "new.txt"), FilesystemPolicy(allowed_roots=[ws]))
        assert resolved == ws / "real" / "new.txt"

    def test_missing_directories_below_a_symlink_are_walked(self, tmp_path: Path) -> None:
        ws = tmp_path.resolve() / "ws"
        (ws / "real").mkdir(parents=True)
        (ws / "link").symlink_to(ws / "real", target_is_directory=True)
        with pytest.raises(PathValidationError, match="symlink"):
            validate_path(
                str(ws / "link" / "a" / "b" / "c.txt"), FilesystemPolicy(allowed_roots=[ws])
            )

    def test_an_unreadable_component_refuses_rather_than_pass(self, tmp_path: Path) -> None:
        """Any error other than "not found" means the walk cannot say what it would follow."""
        ws = tmp_path.resolve() / "ws"
        ws.mkdir()
        (ws / "file.txt").write_text("a file, not a directory")
        with pytest.raises(PathValidationError) as raised:
            validate_path(str(ws / "file.txt" / "child"), FilesystemPolicy(allowed_roots=[ws]))
        assert raised.value.violation_type == "symlink_check_failed"
        assert raised.value.details == {"error": "NotADirectoryError"}

    def test_symlinks_allowed_still_admits_the_missing_leaf(self, tmp_path: Path) -> None:
        """Control: with ``allow_symlinks=True`` the ancestry is not walked."""
        ws = tmp_path.resolve() / "ws"
        (ws / "real").mkdir(parents=True)
        (ws / "link").symlink_to(ws / "real", target_is_directory=True)
        policy = FilesystemPolicy(allowed_roots=[ws], allow_symlinks=True)
        assert validate_path(str(ws / "link" / "new.txt"), policy) == ws / "real" / "new.txt"


class TestSafePathRelative:
    """``SafePathValidator(root_dir=...)`` returns the path under the root it checked."""

    @pytest.fixture
    def jail(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        base = tmp_path.resolve()
        ws, outside = base / "ws", base / "outside"
        ws.mkdir()
        outside.mkdir()
        (ws / "secret.txt").write_text("inside")
        (outside / "secret.txt").write_text("outside")
        monkeypatch.chdir(outside)
        return ws

    def test_relative_input_comes_back_absolute_under_the_root(self, jail: Path) -> None:
        result = SafePathValidator(root_dir=jail, deny_patterns=[])("secret.txt")
        assert result.is_absolute()
        assert result == jail / "secret.txt"
        assert result.read_text() == "inside"

    def test_the_jail_type_hands_the_tool_the_path_inside(self, jail: Path) -> None:
        jail_path = create_safe_path_type(root_dir=jail, deny_patterns=[])

        def read(path: Path) -> str:
            return Path(path).read_text()

        # The jail type is local to the test, so set it as an object, not a string.
        read.__annotations__ = {"path": jail_path, "return": str}
        tool = Airlock()(read)
        assert tool(path=Path("secret.txt")) == "inside"
        assert TypeAdapter(jail_path).validate_python("secret.txt") == jail / "secret.txt"

    def test_an_absolute_input_under_the_root_is_unchanged(self, jail: Path) -> None:
        """Control."""
        target = jail / "secret.txt"
        assert SafePathValidator(root_dir=jail, deny_patterns=[])(str(target)) == target

    def test_without_a_root_the_input_comes_back_as_given(self) -> None:
        """Control: no root, no resolution."""
        assert SafePathValidator(deny_patterns=[])("notes.txt") == Path("notes.txt")


class TestBindResolved:
    """``FilesystemPolicy(bind_resolved_paths=True)`` hands the tool what was checked."""

    @pytest.fixture
    def root(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        ws = tmp_path.resolve() / "ws"
        ws.mkdir()
        monkeypatch.chdir(ws)
        return ws

    @staticmethod
    def _config(root: Path, *, bind: bool) -> AirlockConfig:
        policy = FilesystemPolicy(allowed_roots=[root], bind_resolved_paths=bind)
        return AirlockConfig(filesystem_policy=policy)

    def test_keyword_str_argument_is_rebound(self, root: Path) -> None:
        @Airlock(config=self._config(root, bind=True))
        def opened(path: str) -> str:
            return path

        assert opened(path="notes.txt") == str(root / "notes.txt")

    def test_positional_argument_is_rebound(self, root: Path) -> None:
        @Airlock(config=self._config(root, bind=True))
        def opened(mode: str, path: str) -> str:
            return f"{mode}:{path}"

        assert opened("r", "notes.txt") == f"r:{root / 'notes.txt'}"

    def test_pathlib_argument_is_rebound_as_a_path(self, root: Path) -> None:
        @Airlock(config=self._config(root, bind=True))
        def opened(path: Path) -> Path:
            return path

        result = opened(path=Path("notes.txt"))
        assert result == root / "notes.txt"
        assert isinstance(result, Path)

    def test_keyword_only_argument_is_rebound(self, root: Path) -> None:
        @Airlock(config=self._config(root, bind=True))
        def opened(*, output_file: str) -> str:
            return output_file

        assert opened(output_file="out/report.md") == str(root / "out" / "report.md")

    def test_async_tool_is_rebound(self, root: Path) -> None:
        @Airlock(config=self._config(root, bind=True))
        async def opened(path: str) -> str:
            return path

        assert asyncio.run(opened(path="notes.txt")) == str(root / "notes.txt")

    def test_nested_values_are_passed_as_given(self, root: Path) -> None:
        @Airlock(config=self._config(root, bind=True))
        def opened(paths: list[str]) -> list[str]:
            return paths

        assert opened(paths=["a/notes.txt"]) == ["a/notes.txt"]

    def test_a_file_uri_is_passed_as_given(self, root: Path) -> None:
        @Airlock(config=self._config(root, bind=True))
        def opened(path: str) -> str:
            return path

        uri = (root / "notes.txt").as_uri()
        assert opened(path=uri) == uri

    def test_default_passes_the_original_value(self, root: Path) -> None:
        """Control: binding is opt-in."""

        @Airlock(config=self._config(root, bind=False))
        def opened(mode: str, path: str) -> str:
            return f"{mode}:{path}"

        assert opened("r", "notes.txt") == "r:notes.txt"

    def test_a_refused_path_is_still_refused(self, root: Path) -> None:
        @Airlock(config=self._config(root, bind=True))
        def opened(path: str) -> str:
            return path

        result = opened(path="../outside.txt")
        assert isinstance(result, dict)
        assert result["block_reason"] == "path_violation"

    @staticmethod
    def _escalated(root: Path, approver: Any, log: Any = None) -> AirlockConfig:  # noqa: ARG004
        config = TestBindResolved._config(root, bind=True)
        config.decision_log = log
        return config

    @staticmethod
    def _policy(approver: Any) -> SecurityPolicy:
        return SecurityPolicy(escalate_tools={"opened": "writes files"}, approver=approver)

    def test_a_granted_call_runs_with_the_rebound_path(self, root: Path) -> None:
        """The rebind is the policy's own change: it does not undo the approval."""

        @Airlock(config=self._escalated(root, _grant), policy=self._policy(_grant))
        def opened(mode: str, path: str, *, output_file: str) -> str:
            return f"{mode}:{path}:{output_file}"

        result = opened("r", "notes.txt", output_file="out.md")
        assert result == f"r:{root / 'notes.txt'}:{root / 'out.md'}"

    def test_the_decision_record_reads_the_rebound_path(self, root: Path) -> None:
        from agent_airlock.approvals import args_digest
        from agent_airlock.conformance.decision_log import DecisionLog

        log = DecisionLog(root / "decisions.jsonl")

        @Airlock(config=self._escalated(root, _grant, log), policy=self._policy(_grant))
        def opened(path: str) -> str:
            return path

        opened("notes.txt")
        (decision,) = [
            record.details or {}
            for record in log.records()
            if (record.details or {}).get("entry") == "decision"
        ]
        assert decision["args_digest"] == args_digest({"path": str(root / "notes.txt")})

    def test_a_change_made_while_the_approver_decided_is_still_refused(self, root: Path) -> None:
        tags = ["draft"]

        def approver(request: OversightRequest) -> OversightResponse:
            tags.append("final")  # another task edits the shared list meanwhile
            return OversightResponse(request.request_id, OversightVerdict.GRANT)

        ran: list[str] = []

        @Airlock(config=self._escalated(root, approver), policy=self._policy(approver))
        def opened(path: str, tags: list[str]) -> str:
            ran.append(path)
            return path

        result = opened(path="notes.txt", tags=tags)
        assert isinstance(result, dict) and result["block_reason"] == "policy_indeterminate"
        assert ran == []

    def test_toml_reads_the_option(self, tmp_path: Path) -> None:
        toml = tmp_path / "airlock.toml"
        toml.write_text(
            '[airlock.filesystem]\nallowed_roots = ["/srv"]\nbind_resolved_paths = true\n'
        )
        config = AirlockConfig.from_toml(toml)
        assert config.filesystem_policy is not None
        assert config.filesystem_policy.bind_resolved_paths is True


@needs_atomic_open
class TestOpenContainedFile:
    """The file-object form of ``open_contained``."""

    def test_writes_and_reads_inside_the_root(self, tmp_path: Path) -> None:
        ws = tmp_path.resolve()
        policy = FilesystemPolicy(allowed_roots=[ws])
        with open_contained_file(ws / "a.txt", policy, "w") as handle:
            handle.write("hello")
        with open_contained_file(ws / "a.txt", policy) as handle:
            assert handle.read() == "hello"
        with open_contained_file(ws / "a.txt", policy, "ab") as handle:
            handle.write(b"!")
        assert (ws / "a.txt").read_text() == "hello!"

    def test_exclusive_create_refuses_an_existing_file(self, tmp_path: Path) -> None:
        ws = tmp_path.resolve()
        (ws / "a.txt").write_text("x")
        with (
            pytest.raises(FileExistsError),
            open_contained_file(ws / "a.txt", FilesystemPolicy(allowed_roots=[ws]), "x"),
        ):
            pass

    @pytest.mark.parametrize("mode", ["", "rw", "rr", "q", "rbt", "w+x"])
    def test_an_invalid_mode_is_refused(self, tmp_path: Path, mode: str) -> None:
        with (
            pytest.raises(ValueError, match="invalid mode"),
            open_contained_file(tmp_path / "a.txt", FilesystemPolicy(), mode),
        ):
            pass

    def test_a_missing_directory_is_an_ordinary_os_error(self, tmp_path: Path) -> None:
        ws = tmp_path.resolve()
        with (
            pytest.raises(FileNotFoundError),
            open_contained_file(
                ws / "missing" / "a.txt", FilesystemPolicy(allowed_roots=[ws]), "w"
            ),
        ):
            pass

    def test_a_denied_pattern_is_refused_before_opening(self, tmp_path: Path) -> None:
        ws = tmp_path.resolve()
        policy = FilesystemPolicy(allowed_roots=[ws], deny_patterns=["*.env"])
        with pytest.raises(PathValidationError) as raised:
            open_contained(ws / "prod.env", policy, os.O_WRONLY | os.O_CREAT)
        assert raised.value.violation_type == "denied_pattern"
        assert not (ws / "prod.env").exists()


class TestDocstringClaims:
    """Neither docstring claims ``validate_path`` prevents TOCTOU races."""

    @pytest.mark.parametrize(
        "doc", [fs.__doc__, validate_path.__doc__], ids=["module", "validate_path"]
    )
    def test_no_atomicity_claim_for_validate_path(self, doc: str | None) -> None:
        assert doc is not None
        assert not re.search(r"prevents? TOCTOU|atomic path resolution", doc, re.IGNORECASE)
        assert "open_contained" in doc
