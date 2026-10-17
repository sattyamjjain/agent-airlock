"""0.10.25 (security): a ``~`` path is checked in the form a tool opens, too.

``validate_path`` resolved ``~/.ssh/id_rsa`` with ``os.path.realpath`` only, which does not
expand ``~``: it became ``$CWD/~/.ssh/id_rsa``. With the working directory inside an
allowed root, that literal form passed, and a tool that calls ``os.path.expanduser`` then
opened the real ``$HOME/.ssh/id_rsa``. Now both forms must pass, and a ``~user`` prefix the
process cannot expand is refused.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import Airlock, AirlockConfig, is_refusal
from agent_airlock.filesystem import FilesystemPolicy, PathValidationError, validate_path

READS: list[str] = []


def read_key(path: str) -> str:
    """A tool that expands ``~``, as a real file-reading tool often does."""
    READS.append(path)
    return Path(os.path.expanduser(path)).read_text(encoding="utf-8")


def read_many(paths: list[str]) -> int:
    READS.extend(paths)
    return len(paths)


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """An allowed root holding the working directory, and a home outside it with a key."""
    root = tmp_path / "root"
    root.mkdir()
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "id_rsa").write_text("PRIVATE KEY", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(root)
    READS.clear()
    return {"root": root, "home": home}


class TestTheFailOpenIsClosed:
    def test_the_literal_form_alone_still_passes(self, layout: dict[str, Path]) -> None:
        """The pre-0.10.25 check: ``$CWD/~/.ssh/id_rsa`` is inside the root."""
        policy = FilesystemPolicy(allowed_roots=[layout["root"]])
        literal = validate_path(str(layout["root"] / "~" / ".ssh" / "id_rsa"), policy)
        assert literal.is_relative_to(layout["root"].resolve())

    def test_a_home_outside_the_roots_is_refused(self, layout: dict[str, Path]) -> None:
        policy = FilesystemPolicy(allowed_roots=[layout["root"]])
        with pytest.raises(PathValidationError) as exc:
            validate_path("~/.ssh/id_rsa", policy)
        assert exc.value.violation_type == "outside_allowed_roots"
        assert exc.value.path == "~/.ssh/id_rsa"
        assert exc.value.details["form"] == "home_expanded"

    def test_the_refusal_does_not_tell_the_model_the_home_directory(
        self, layout: dict[str, Path]
    ) -> None:
        policy = FilesystemPolicy(allowed_roots=[layout["root"]])
        with pytest.raises(PathValidationError) as exc:
            validate_path("~/.ssh/id_rsa", policy)
        assert "resolved_path" not in exc.value.details
        assert str(layout["home"]) not in repr(exc.value.details)

    def test_a_tool_that_expands_tilde_never_runs(self, layout: dict[str, Path]) -> None:
        guarded = Airlock(
            config=AirlockConfig(filesystem_policy=FilesystemPolicy(allowed_roots=[layout["root"]]))
        )(read_key)
        result = guarded(path="~/.ssh/id_rsa")
        assert is_refusal(result), result
        assert result["block_reason"] == "path_violation"
        assert READS == []

    def test_a_nested_tilde_path_is_refused_too(self, layout: dict[str, Path]) -> None:
        guarded = Airlock(
            config=AirlockConfig(filesystem_policy=FilesystemPolicy(allowed_roots=[layout["root"]]))
        )(read_many)
        result = guarded(paths=["notes.txt", "~/.ssh/id_rsa"])
        assert is_refusal(result), result
        assert READS == []

    @pytest.mark.parametrize("path", ["~", " ~/.ssh/id_rsa", "~/../home/.ssh/id_rsa"])
    def test_other_spellings_of_home_are_refused(self, layout: dict[str, Path], path: str) -> None:
        policy = FilesystemPolicy(allowed_roots=[layout["root"]])
        with pytest.raises(PathValidationError):
            validate_path(path, policy)


class TestAHomeThatCannotBeExpandedIsRefused:
    def test_an_unknown_user(self, layout: dict[str, Path]) -> None:
        policy = FilesystemPolicy(allowed_roots=[layout["root"]])
        with pytest.raises(PathValidationError) as exc:
            validate_path("~airlock-no-such-user-zz9/notes.txt", policy)
        assert exc.value.violation_type == "unresolvable_home"

    @pytest.mark.skipif(sys.platform == "win32", reason="a backslash is a separator there")
    def test_a_backslash_after_the_tilde(self, layout: dict[str, Path]) -> None:
        policy = FilesystemPolicy(allowed_roots=[layout["root"]])
        with pytest.raises(PathValidationError) as exc:
            validate_path("~\\.ssh\\id_rsa", policy)
        assert exc.value.violation_type == "unresolvable_home"


class TestBothFormsMustPass:
    def test_both_inside_the_roots_passes(
        self, layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home = layout["root"] / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        policy = FilesystemPolicy(allowed_roots=[layout["root"]])
        resolved = validate_path("~/notes.txt", policy)
        # The literal form is what is returned, as before.
        assert resolved == (layout["root"] / "~" / "notes.txt").resolve()

    def test_a_home_inside_with_the_working_directory_outside_is_refused(
        self, layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        home = layout["root"] / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        policy = FilesystemPolicy(allowed_roots=[layout["root"]])
        with pytest.raises(PathValidationError) as exc:
            validate_path("~/notes.txt", policy)
        assert exc.value.violation_type == "outside_allowed_roots"
        assert "form" not in exc.value.details  # the literal form failed first

    def test_a_deny_pattern_only_the_expanded_form_matches(
        self, layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        vault = layout["root"] / "vault"
        vault.mkdir()
        monkeypatch.setenv("HOME", str(vault))
        policy = FilesystemPolicy(allowed_roots=[layout["root"]], deny_patterns=["**/vault/**"])
        with pytest.raises(PathValidationError) as exc:
            validate_path("~/notes.txt", policy)
        assert exc.value.violation_type == "denied_pattern"
        assert exc.value.details["form"] == "home_expanded"
        assert "resolved_path" not in exc.value.details

    def test_a_symlinked_home_is_refused_without_naming_the_link(
        self, layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = layout["root"] / "real-home"
        real.mkdir()
        (real / "notes.txt").write_text("x", encoding="utf-8")
        link = layout["root"] / "link-home"
        link.symlink_to(real, target_is_directory=True)
        monkeypatch.setenv("HOME", str(link))
        policy = FilesystemPolicy(allowed_roots=[layout["root"]], allow_symlinks=False)
        with pytest.raises(PathValidationError) as exc:
            validate_path("~/notes.txt", policy)
        assert exc.value.violation_type == "symlink_detected"
        assert exc.value.details == {"form": "home_expanded"}

    def test_a_path_without_a_tilde_is_checked_as_before(self, layout: dict[str, Path]) -> None:
        policy = FilesystemPolicy(allowed_roots=[layout["root"]])
        with pytest.raises(PathValidationError) as exc:
            validate_path(str(layout["home"] / ".ssh" / "id_rsa"), policy)
        assert exc.value.violation_type == "outside_allowed_roots"
        assert "resolved_path" in exc.value.details
        assert "form" not in exc.value.details


class TestNestedHomeRelativeValuesAreChecked:
    """A nested ``~user/...`` string under a key not named like a path is a path by shape.

    ``_is_absolute_or_escaping`` treated only ``~/`` and ``~\\`` as home-relative, so a
    ``~root/.ssh/id_rsa`` nested in a container under an ordinary key was never
    path-checked. Free-text approximations (``~5``, ``~ 10 minutes``) stay non-paths.
    """

    def _tool(self, root: Path) -> Any:
        @Airlock(
            config=AirlockConfig(
                filesystem_policy=FilesystemPolicy(allowed_roots=[root]),
                enable_audit_log=False,
            )
        )
        def store(meta: dict[str, Any]) -> int:
            return len(meta)

        return store

    def test_nested_tilde_user_path_is_refused(self, layout: dict[str, Path]) -> None:
        result = self._tool(layout["root"])(meta={"note": "~root/.ssh/id_rsa"})
        assert isinstance(result, dict)
        assert result["success"] is False

    @pytest.mark.parametrize("text", ["~5", "~ 10 minutes", "about ~3 hours"])
    def test_free_text_approximation_is_not_a_path(
        self, layout: dict[str, Path], text: str
    ) -> None:
        assert self._tool(layout["root"])(meta={"note": text}) == 1
