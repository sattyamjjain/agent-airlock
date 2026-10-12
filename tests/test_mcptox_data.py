"""Tests for ``benchmarks.mcptox.data``: pinned download, verification, case keys.

No network: every test that reaches the download path replaces ``urllib.request.urlopen``
with an in-memory fake. Fixtures are synthetic; no MCPTox text appears here.
"""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from typing import Any

import pytest
from benchmarks.mcptox import data as data_mod


class _FakeResponse:
    def __init__(self, payload: bytes, headers: dict[str, str] | None = None) -> None:
        self._buf = io.BytesIO(payload)
        self.headers = headers or {}

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _patch_urlopen(
    monkeypatch: pytest.MonkeyPatch, payload: bytes, headers: dict[str, str] | None = None
) -> list[Any]:
    calls: list[Any] = []

    def fake(request: Any, timeout: float = 0) -> _FakeResponse:
        calls.append(request)
        return _FakeResponse(payload, headers)

    monkeypatch.setattr(data_mod.urllib.request, "urlopen", fake)
    return calls


def _leftovers(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir()) if directory.exists() else []


class TestFetch:
    def test_verified_download_is_renamed_into_place(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        payload = b'{"servers": {}}'
        calls = _patch_urlopen(monkeypatch, payload)
        dest = tmp_path / "cache" / "response_all.json"
        out = data_mod.fetch(
            dest,
            url="https://example.invalid/file.json",
            expected_sha256=hashlib.sha256(payload).hexdigest(),
        )
        assert out == dest
        assert dest.read_bytes() == payload
        assert _leftovers(dest.parent) == ["response_all.json"]
        assert len(calls) == 1

    def test_checksum_mismatch_deletes_and_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_urlopen(monkeypatch, b"tampered bytes")
        dest = tmp_path / "cache" / "response_all.json"
        with pytest.raises(data_mod.ChecksumMismatchError):
            data_mod.fetch(dest, url="https://example.invalid/f", expected_sha256="0" * 64)
        assert not dest.exists()
        assert _leftovers(dest.parent) == []

    def test_size_cap_aborts_and_cleans_up(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_urlopen(monkeypatch, b"x" * 5000)
        dest = tmp_path / "c" / "f.json"
        with pytest.raises(RuntimeError, match="cap"):
            data_mod.fetch(
                dest, url="https://example.invalid/f", expected_sha256="0" * 64, max_bytes=1000
            )
        assert _leftovers(dest.parent) == []

    def test_declared_length_over_cap_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_urlopen(monkeypatch, b"tiny", headers={"Content-Length": "999999"})
        dest = tmp_path / "c" / "f.json"
        with pytest.raises(RuntimeError, match="declares"):
            data_mod.fetch(
                dest, url="https://example.invalid/f", expected_sha256="0" * 64, max_bytes=1000
            )
        assert _leftovers(dest.parent) == []

    def test_non_https_refused_before_any_request(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = _patch_urlopen(monkeypatch, b"")
        with pytest.raises(ValueError, match="HTTPS"):
            data_mod.fetch(tmp_path / "f.json", url="http://example.invalid/f")
        assert calls == []

    def test_pinned_constants(self) -> None:
        assert data_mod.MCPTOX_COMMIT in data_mod.MCPTOX_URL
        assert data_mod.MCPTOX_URL.startswith("https://raw.githubusercontent.com/")
        assert len(data_mod.MCPTOX_SHA256) == 64
        assert data_mod.MAX_DOWNLOAD_BYTES > data_mod.MCPTOX_BYTES


class TestResolve:
    def test_cache_layout(self, tmp_path: Path) -> None:
        assert data_mod.cache_path(tmp_path) == (
            tmp_path / "mcptox" / data_mod.MCPTOX_COMMIT / "response_all.json"
        )

    def test_missing_cache_needs_fetch_flag(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AIRLOCK_BENCH_DATA", str(tmp_path))
        calls = _patch_urlopen(monkeypatch, b"")
        with pytest.raises(data_mod.DataUnavailableError, match="--fetch"):
            data_mod.resolve_data_path(None, fetch_missing=False)
        assert calls == []

    def test_fetch_flag_downloads_into_cache(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        payload = b'{"servers": {"s": {}}}'
        monkeypatch.setenv("AIRLOCK_BENCH_DATA", str(tmp_path))
        monkeypatch.setattr(data_mod, "MCPTOX_SHA256", hashlib.sha256(payload).hexdigest())
        _patch_urlopen(monkeypatch, payload)
        path = data_mod.resolve_data_path(None, fetch_missing=True)
        assert path == data_mod.cache_path(tmp_path)
        assert path.read_bytes() == payload

    def test_data_override_is_verified(self, tmp_path: Path) -> None:
        bogus = tmp_path / "response_all.json"
        bogus.write_text('{"servers": {}}')
        with pytest.raises(data_mod.ChecksumMismatchError):
            data_mod.resolve_data_path(bogus)

    def test_data_override_missing(self, tmp_path: Path) -> None:
        with pytest.raises(data_mod.DataUnavailableError):
            data_mod.resolve_data_path(tmp_path / "nope.json")

    def test_load_rejects_other_json(self, tmp_path: Path) -> None:
        path = tmp_path / "x.json"
        path.write_text(json.dumps({"rows": []}))
        with pytest.raises(ValueError, match="servers"):
            data_mod.load(path)


def _instance(case_id: int, *, poisoned: str, record_poisoned: str | None = None) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": case_id,
        "query": "synthetic query",
        "system": "synthetic system",
        "response": {},
        "label": {},
    }
    if record_poisoned is not None:
        record["poisoned_tool"] = record_poisoned
    return {
        "security_risk_description": "synthetic",
        "wrong_data": 0,
        "datas": [record],
        "metadata": {"paradigm": "Template-2", "security risk": "Privacy Leakage"},
        "poisoned_tool": poisoned,
    }


class TestCases:
    def _doc(self) -> dict[str, Any]:
        return {
            "servers": {
                "Alpha": {
                    "malicious_instance": [_instance(7, poisoned="a"), _instance(7, poisoned="b")]
                },
                "Beta": {
                    "malicious_instance": [
                        _instance(7, poisoned="inst", record_poisoned="Tool: x\\nArguments:")
                    ]
                },
            }
        }

    def test_keys_are_unique_although_ids_repeat(self) -> None:
        cases = list(data_mod.iter_cases(self._doc()))
        assert [c.key for c in cases] == ["00-000", "00-001", "01-000"]
        assert len({c.key for c in cases}) == len(cases)

    def test_record_level_poisoned_tool_wins_and_is_normalised(self) -> None:
        cases = list(data_mod.iter_cases(self._doc()))
        assert cases[0].poisoned_tool == "a"
        assert cases[2].poisoned_tool == "Tool: x\nArguments:"
        assert cases[2].paradigm == "Template-2"
        assert cases[2].risk == "Privacy Leakage"

    def test_more_than_one_record_refused(self) -> None:
        doc = self._doc()
        doc["servers"]["Alpha"]["malicious_instance"][0]["datas"].append({})
        with pytest.raises(ValueError, match="expected 1"):
            list(data_mod.iter_cases(doc))

    def test_normalise_only_rewrites_escaped_separators(self) -> None:
        assert data_mod.normalise_tool_text("a\\nb") == "a\nb"
        # Real newlines present: an escaped \n is part of a value and stays.
        assert data_mod.normalise_tool_text("a\nC:\\new") == "a\nC:\\new"
        assert data_mod.normalise_tool_text("a\r\nb") == "a\nb"
