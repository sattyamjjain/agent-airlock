"""Preset registry parity — no factory without an entry, no entry without a factory.

This repo has repeatedly shipped preset drift: a preset that exists but is not enumerated,
or a name in the docs that no longer resolves. Two legs were already machine-checked
(``tests/test_public_api.py::TestPresetRegistryCoversExports`` and
``tests/test_marketplace_metadata.py::test_all_exported_zero_arg_presets_are_registered``,
both registry-vs-exports). This module closes the remaining legs and states all of them in
one place, in both directions:

1. every ``@preset``-registered factory is in ``policy_presets.__all__``;
2. every preset the package root claims to re-export actually resolves (root export is a
   deliberately curated subset, so this is the only direction that is an invariant);
3. every ``policy_presets.<name>`` referenced in README.md or docs/ resolves to a real,
   registered factory — so prose can never name a preset that does not exist.

Leg 1 caught a live break when it was written: ``mcp_spec_2026_07_28_handle_trust_defaults``
shipped in v0.8.69 registered and re-exported from the package root, but absent from
``policy_presets.__all__``.

There is deliberately no README preset *table* asserted here: the README documents presets
inline inside the OWASP / integration matrices rather than in a single table, so leg 3
checks the references that actually exist instead of a table that does not.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import agent_airlock
import agent_airlock.policy_presets as policy_presets
from agent_airlock.policy_presets import _PRESET_REGISTRY

REPO_ROOT = Path(__file__).resolve().parents[2]

#: ``policy_presets.<name>`` as written in prose.
_PRESET_REFERENCE = re.compile(r"policy_presets\.([a-z_][a-z_0-9]*)")


def _registered() -> set[str]:
    return set(_PRESET_REGISTRY)


def _documentation_files() -> list[Path]:
    files = [REPO_ROOT / "README.md"]
    files.extend(sorted((REPO_ROOT / "docs").rglob("*.md")))
    return [path for path in files if path.is_file()]


def _referenced_presets() -> dict[str, set[str]]:
    """Map ``preset name -> {relative source paths}`` across README + docs."""
    found: dict[str, set[str]] = {}
    for path in _documentation_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for name in _PRESET_REFERENCE.findall(text):
            found.setdefault(name, set()).add(path.relative_to(REPO_ROOT).as_posix())
    return found


class TestPresetRegistryParity:
    def test_registry_is_not_empty(self) -> None:
        """Guard against the whole check silently passing on an empty set."""
        assert len(_registered()) > 50

    def test_every_registered_preset_is_in_module_all(self) -> None:
        exported = set(policy_presets.__all__)
        missing = sorted(_registered() - exported)
        assert not missing, (
            "registered preset(s) missing from agent_airlock.policy_presets.__all__: "
            f"{missing}. Add them to __all__ so the preset is part of the documented "
            "surface, not just the registry."
        )

    def test_package_root_preset_reexports_all_resolve(self) -> None:
        """Package-root re-export is a *curated subset*, not a parity requirement.

        Only some presets are promoted to ``agent_airlock.<name>``; the rest are reached as
        ``agent_airlock.policy_presets.<name>``. So this asserts the direction that is
        actually an invariant: anything the root claims to re-export must resolve on the
        presets module. It does not demand that every preset be promoted.
        """
        promoted = sorted(name for name in _registered() if name in set(agent_airlock.__all__))
        assert promoted, "expected at least some presets promoted to the package root"
        broken = [name for name in promoted if not hasattr(agent_airlock, name)]
        assert not broken, f"package root lists preset(s) it cannot resolve: {broken}"

    def test_module_all_has_no_dangling_names(self) -> None:
        """Every name in ``__all__`` must actually exist on the module."""
        dangling = sorted(
            name for name in policy_presets.__all__ if not hasattr(policy_presets, name)
        )
        assert not dangling, f"policy_presets.__all__ names non-existent symbol(s): {dangling}"


class TestDocumentedPresetsResolve:
    def test_documentation_references_at_least_one_preset(self) -> None:
        """If the regex stops matching, the rest of this class would pass vacuously."""
        assert _referenced_presets(), "no policy_presets.<name> references found in README/docs"

    def test_every_documented_preset_exists(self) -> None:
        referenced = _referenced_presets()
        missing = {
            name: sorted(sources)
            for name, sources in referenced.items()
            if not hasattr(policy_presets, name)
        }
        assert not missing, (
            "documentation names preset(s) that do not exist: "
            f"{missing}. Either add the factory or fix the prose."
        )

    def test_every_documented_preset_is_registered(self) -> None:
        referenced = _referenced_presets()
        registered = _registered()
        unregistered = {
            name: sorted(sources)
            for name, sources in referenced.items()
            if hasattr(policy_presets, name) and name not in registered
        }
        assert not unregistered, (
            "documentation names preset(s) that exist but are not @preset-registered, so "
            f"list_active() and the coverage matrix under-count them: {unregistered}"
        )


@pytest.mark.parametrize(
    "name",
    ["mcp_spec_2026_07_28_handle_trust_defaults", "MCP_SPEC_2026_07_28_HANDLE_TRUST"],
)
def test_handle_trust_regression(name: str) -> None:
    """The specific v0.8.69 break this module was written for. Pinned so it cannot recur."""
    assert name in policy_presets.__all__
    assert hasattr(policy_presets, name)
