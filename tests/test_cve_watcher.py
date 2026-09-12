"""Unit tests for the NVD CVE watcher (scripts/cve_watcher.py).

The watcher files GitHub issues on a cron. Two things therefore have to be
true before it is trusted to run unattended, and both are asserted here:

1. **It does not spam.** Every dedup layer suppresses, the per-run cap holds
   the excess back rather than dropping it, and a deep queue stops new filings
   entirely.
2. **Its relevance filter is not decorative.** NVD's keywordSearch matches
   indexed fields, so "mcp" alone returns NVIDIA nForce chipset CVEs. If the
   corroboration filter regressed, the watcher would open issues for Linux
   kernel bugs.

No network: every test injects a fake fetcher, and the GitHub lookups
short-circuit when no token/owner is supplied.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.cve_watcher import (
    ARGUMENT_SHAPED_CWES,
    already_tracked,
    classify_shape,
    collect_new_cves,
    extract,
    is_relevant,
)


def _nvd(cve_id: str, description: str, cvss: float | None = 7.0) -> dict[str, Any]:
    """Minimal NVD 2.0 record shaped like the fields `extract` reads."""
    metrics = (
        {"cvssMetricV31": [{"cvssData": {"baseScore": cvss, "baseSeverity": "HIGH"}}]}
        if cvss is not None
        else {}
    )
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-09-01T00:00:00.000",
            "metrics": metrics,
            "descriptions": [{"lang": "en", "value": description}],
        }
    }


class TestIsRelevant:
    @pytest.mark.parametrize(
        "text",
        [
            "A flaw in the Model Context Protocol server allows command injection.",
            "mcp-atlassian permits arbitrary file write via download_path.",
            "Claude Code hooks allow remote code execution.",
            "Flowise CustomMCP node evaluates attacker-controlled JavaScript.",
            "An agentic tool-call loop in OpenClaw bypasses the exec denylist.",
            "Windsurf auto-loads an MCP config with no user consent.",
        ],
    )
    def test_ecosystem_text_is_relevant(self, text: str) -> None:
        assert is_relevant(text) is True

    @pytest.mark.parametrize(
        "text",
        [
            "A buffer overflow in the JPEG decoder of libfoo 1.2.",
            "SQL injection in an unrelated PHP forum.",
            "",
        ],
    )
    def test_unrelated_text_is_not_relevant(self, text: str) -> None:
        assert is_relevant(text) is False

    def test_nvidia_nforce_hardware_is_suppressed(self) -> None:
        """The documented false positive: nForce southbridges are 'MCP' parts.

        NVD returns these for the keyword `mcp`. Filing them would open triage
        issues for Linux kernel CVEs that have nothing to do with the protocol.
        """
        text = (
            "A race condition in the ueagle-atm driver on NVIDIA nForce MCP61 "
            "chipset southbridge hardware allows a local user to crash the kernel."
        )
        assert is_relevant(text) is False

    def test_hardware_words_do_not_suppress_a_real_mcp_cve(self) -> None:
        """Suppression must not fire when a genuine term carried the match."""
        text = (
            "The Model Context Protocol stdio transport in mcp-server-git allows "
            "argument injection. Affected chipset-adjacent builds are unaffected."
        )
        assert is_relevant(text) is True

    def test_bare_claude_attribution_does_not_match(self) -> None:
        """AI-authored-patch credit lines appear in unrelated projects now."""
        text = "Fix a refcount leak in the SCSI midlayer. (This patch was written by Claude.)"
        assert is_relevant(text) is False


class TestAlreadyTracked:
    def test_reads_the_real_ledger(self) -> None:
        """Sanity: the shipped catalog is a non-trivial suppression source."""
        tracked = already_tracked()
        assert len(tracked) > 20
        assert "CVE-2026-30616" in tracked

    def test_reads_ids_from_filenames_and_bodies(self, tmp_path: Path) -> None:
        docs = tmp_path / "index.md"
        docs.write_text("| CVE-2026-11111 | something |\n", encoding="utf-8")
        suite = tmp_path / "cves"
        suite.mkdir()
        (suite / "test_cve_2026_22222_thing.py").write_text("# no id in body\n")
        found = already_tracked((docs, suite))
        assert found == {"CVE-2026-11111", "CVE-2026-22222"}

    def test_missing_paths_are_not_an_error(self, tmp_path: Path) -> None:
        assert already_tracked((tmp_path / "nope.md",)) == set()


class TestCollectNewCves:
    def test_emits_a_genuinely_new_cve(self, tmp_path: Path) -> None:
        new, state = collect_new_cves(
            ledger_paths=(tmp_path / "empty.md",),
            state_path=tmp_path / "state.json",
            fetcher=lambda kw: [_nvd("CVE-2026-99001", "MCP stdio command injection.")],
        )
        assert [e["id"] for e in new] == ["CVE-2026-99001"]
        assert state["filed_cves"] == ["CVE-2026-99001"]

    def test_ledger_suppresses(self, tmp_path: Path) -> None:
        ledger = tmp_path / "index.md"
        ledger.write_text("CVE-2026-99002 already covered\n", encoding="utf-8")
        new, _ = collect_new_cves(
            ledger_paths=(ledger,),
            state_path=tmp_path / "state.json",
            fetcher=lambda kw: [_nvd("CVE-2026-99002", "MCP stdio command injection.")],
        )
        assert new == []

    def test_state_file_suppresses(self, tmp_path: Path) -> None:
        state_path = tmp_path / "state.json"
        state_path.write_text(json.dumps({"filed_cves": ["CVE-2026-99003"]}), encoding="utf-8")
        new, _ = collect_new_cves(
            ledger_paths=(tmp_path / "empty.md",),
            state_path=state_path,
            fetcher=lambda kw: [_nvd("CVE-2026-99003", "MCP stdio command injection.")],
        )
        assert new == []

    def test_irrelevant_description_is_dropped(self, tmp_path: Path) -> None:
        new, _ = collect_new_cves(
            ledger_paths=(tmp_path / "empty.md",),
            state_path=tmp_path / "state.json",
            fetcher=lambda kw: [_nvd("CVE-2026-99004", "Heap overflow in a PNG parser.")],
        )
        assert new == []

    def test_duplicate_across_keywords_emitted_once(self, tmp_path: Path) -> None:
        new, _ = collect_new_cves(
            ledger_paths=(tmp_path / "empty.md",),
            state_path=tmp_path / "state.json",
            fetcher=lambda kw: [_nvd("CVE-2026-99005", "Anthropic MCP server flaw.")],
        )
        assert len(new) == 1

    def test_corrupt_state_file_is_survivable(self, tmp_path: Path) -> None:
        state_path = tmp_path / "state.json"
        state_path.write_text("{not json", encoding="utf-8")
        new, _ = collect_new_cves(
            ledger_paths=(tmp_path / "empty.md",),
            state_path=state_path,
            fetcher=lambda kw: [_nvd("CVE-2026-99006", "MCP protocol flaw.")],
        )
        assert [e["id"] for e in new] == ["CVE-2026-99006"]

    def test_state_is_not_written_by_collect(self, tmp_path: Path) -> None:
        """The caller persists, so a dry run leaves no trace."""
        state_path = tmp_path / "state.json"
        collect_new_cves(
            ledger_paths=(tmp_path / "empty.md",),
            state_path=state_path,
            fetcher=lambda kw: [_nvd("CVE-2026-99007", "MCP protocol flaw.")],
        )
        assert not state_path.exists()


class TestBackPressure:
    def test_per_run_cap_keeps_the_most_severe(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.cve_watcher as mod

        monkeypatch.setattr(mod, "MAX_NEW_PER_RUN", 2)
        batch = [
            _nvd(f"CVE-2026-990{i}", "MCP stdio command injection.", cvss=float(i))
            for i in (1, 9, 5)
        ]
        new, state = collect_new_cves(
            ledger_paths=(tmp_path / "empty.md",),
            state_path=tmp_path / "state.json",
            fetcher=lambda kw, b=batch: b if kw == "mcp" else [],
        )
        assert [e["id"] for e in new] == ["CVE-2026-9909", "CVE-2026-9905"]
        # Held-back CVEs must NOT be recorded as filed, or they are lost.
        assert "CVE-2026-9901" not in state["filed_cves"]

    def test_deep_queue_holds_everything(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.cve_watcher as mod

        monkeypatch.setattr(mod, "MAX_OPEN_UNTRIAGED", 1)
        monkeypatch.setattr(mod, "open_untriaged_count", lambda owner, token: 5)
        new, state = collect_new_cves(
            ledger_paths=(tmp_path / "empty.md",),
            state_path=tmp_path / "state.json",
            fetcher=lambda kw: [_nvd("CVE-2026-99008", "MCP protocol flaw.")],
        )
        assert new == []
        assert state["filed_cves"] == []


class TestExtract:
    def test_flattens_the_nvd_shape(self) -> None:
        got = extract(_nvd("CVE-2026-99009", "MCP flaw.", cvss=9.8))
        assert got["id"] == "CVE-2026-99009"
        assert got["cvss"] == 9.8
        assert got["severity"] == "HIGH"
        assert got["description"] == "MCP flaw."

    def test_missing_metrics_do_not_raise(self) -> None:
        got = extract(_nvd("CVE-2026-99010", "MCP flaw.", cvss=None))
        assert got["cvss"] is None
        assert got["severity"] is None


# ---------------------------------------------------------------------------
# Shape classifier, pinned against the first real queue
# ---------------------------------------------------------------------------

#: The ten CVEs the watcher filed in its first 48 hours (2026-09-05/06), with
#: the description and CWEs as NVD served them and the disposition a human
#: actually gave each issue. Six were closed out-of-scope, four kept.
#:
#: This is the classifier's regression corpus precisely because it is not
#: synthetic: it is the queue that made the criterion necessary. If a change to
#: `_SINK_RE` or `ARGUMENT_SHAPED_CWES` starts re-opening the six server-side
#: authorization CVEs, or starts dropping the four argument-shaped ones, it
#: fails here.
_FIRST_QUEUE: tuple[tuple[str, str, tuple[str, ...], str], ...] = (
    (
        "CVE-2026-85178",
        "Helicone's VaultManager.getDecryptedProviderKeyById() function in the GET "
        "/v1/vault/key/{providerKeyId} endpoint fails to validate the requester's "
        "organization against the vault key's organization identifier.",
        ("CWE-639",),
        "triage-required",
    ),
    (
        "CVE-2026-18905",
        "IBM ContextForge MCP Gateway could allow a remote authenticated attacker to "
        "obtain sensitive information due to a DNS rebinding vulnerability during tool "
        "invocation.",
        ("CWE-918",),
        "triage-required",
    ),
    (
        "CVE-2026-84779",
        "Subscriber Broken Access Control in Agentimus - AI SEO, llms.txt & MCP for AI "
        "Agents <= 1.51.0 versions.",
        ("CWE-862",),
        "triage-required",
    ),
    (
        "CVE-2026-79746",
        "when a bearer key with accessType: 'servers' is used against a group route, "
        "isBearerKeyAllowedForRequest grants access to the entire group as long as any "
        "single server in that group appears in the key",
        ("CWE-863",),
        "triage-required",
    ),
    (
        "CVE-2026-77822",
        "IBM ContextForge MCP Gateway could allow a remote authenticated attacker to "
        "obtain sensitive information due to server-side request forgery via DNS "
        "rebinding.",
        ("CWE-918",),
        "triage-required",
    ),
    (
        "CVE-2026-85620",
        "Postgres MCP Pro 0.3.0 contains a restricted-mode bypass vulnerability where "
        "function-name validation is not applied to RangeFunction nodes in FROM clauses. "
        "Attackers can execute file-reading functions like pg_read_file through "
        "FROM-clause syntax to read arbitrary files despite restricted-mode protections.",
        ("CWE-863",),
        "candidate",
    ),
    (
        "CVE-2026-18486",
        "IBM ContextForge MCP Gateway could allow a remote authenticated attacker to "
        "obtain sensitive credentials and escalate privileges due to improper validation "
        "of jq filters.",
        ("CWE-200",),
        "candidate",
    ),
    (
        "CVE-2026-19591",
        "OpenAI Codex CLI misclassified certain PowerShell commands as safe because their "
        "command-safety parser interpreted PowerShell's stop-parsing token (--%) "
        "differently than PowerShell itself.",
        ("CWE-150",),
        "candidate",
    ),
    (
        "CVE-2026-79744",
        "MCPHub's PUT /api/system-config endpoint (handler updateSystemConfig) performs no "
        "authorization check. It is protected only by the app-wide authentication "
        "middleware and a rate limiter - it never inspects req.user.",
        ("CWE-269", "CWE-862"),
        "triage-required",
    ),
    (
        "CVE-2026-79748",
        "the POST /api/servers and PUT /api/servers/:name endpoints in MCPHub create/update "
        "MCP server configurations and then immediately spawn the configured stdio process "
        "via child_process.spawn.",
        ("CWE-862",),
        "candidate",
    ),
)


class TestShapeClassifier:
    """Separate what airlock could guard from what it structurally cannot.

    The distinction is not severity and not keyword relevance — all ten of these
    are genuine MCP-ecosystem CVEs and five are CVSS >= 8.6. It is whether the
    defect is carried in an argument the caller supplies.
    """

    @pytest.mark.parametrize(
        "cve,description,cwes,expected",
        [(c, d, w, e) for c, d, w, e in _FIRST_QUEUE],
        ids=[c for c, _d, _w, _e in _FIRST_QUEUE],
    )
    def test_matches_the_human_disposition(
        self, cve: str, description: str, cwes: tuple[str, ...], expected: str
    ) -> None:
        assert classify_shape(description, cwes) == expected

    def test_the_first_queue_would_have_opened_four_not_ten(self) -> None:
        """The volume claim, asserted rather than asserted-in-prose."""
        shapes = [classify_shape(d, w) for _c, d, w, _e in _FIRST_QUEUE]
        assert shapes.count("candidate") == 4
        assert shapes.count("triage-required") == 6

    def test_server_side_authz_alone_is_not_a_candidate(self) -> None:
        assert classify_shape("The endpoint performs no authorization check.", ("CWE-862",)) == (
            "triage-required"
        )

    def test_an_argument_shaped_cwe_alone_is_enough(self) -> None:
        assert classify_shape("Some MCP defect with no sink word.", ("CWE-77",)) == "candidate"

    def test_a_sink_word_upgrades_a_server_side_cwe(self) -> None:
        """CVE-2026-79748's shape: missing authz, but the primitive is a spawn."""
        assert (
            classify_shape("no authz check; then calls child_process.spawn", ("CWE-862",))
            == "candidate"
        )

    def test_empty_description_is_triage_required(self) -> None:
        assert classify_shape("", ()) == "triage-required"


class TestSsrfArgumentShape:
    """SSRF is argument-shaped only when the argument is the defect.

    The watcher shipped with no way to see CVE-2026-19753 (mcp-rdf-explorer,
    CWE-918 HIGH 7.3) even though ``ssrf_egress_guard.py`` exists precisely to
    refuse that shape — it classified ``triage-required`` and no issue was ever
    opened.

    The fix is a sink word, not a new entry in :data:`ARGUMENT_SHAPED_CWES`,
    because promoting CWE-918 wholesale would overturn two human dispositions
    in the pinned first queue. Both directions are asserted here so a later
    widening of the CWE set fails loudly rather than quietly re-opening them.
    """

    #: CVE-2026-19753, as NVD served it. The attacker supplies the bad URL.
    _RDF_EXPLORER = (
        "A vulnerability was detected in Model Context Protocol mcp-rdf-explorer "
        "1.0.0. Affected is the function explore_url of the file src/index.ts. "
        "Executing manipulation of the argument url can lead to server-side "
        "request forgery."
    )

    #: CVE-2026-18905 / CVE-2026-77822. The URL is legitimate; DNS betrays it
    #: *after* validation, so there is no bad argument for airlock to refuse.
    _DNS_REBIND = (
        "IBM ContextForge MCP Gateway could allow a remote authenticated attacker "
        "to obtain sensitive information due to a DNS rebinding vulnerability "
        "during tool invocation."
    )

    def test_a_manipulated_argument_is_a_candidate(self) -> None:
        assert classify_shape(self._RDF_EXPLORER, ("CWE-918",)) == "candidate"

    def test_dns_rebinding_ssrf_stays_triage_required(self) -> None:
        """The human disposition on the first queue must survive this change."""
        assert classify_shape(self._DNS_REBIND, ("CWE-918",)) == "triage-required"

    def test_cwe_918_alone_is_still_not_enough(self) -> None:
        """The CWE is not the signal — the named argument is."""
        assert "CWE-918" not in ARGUMENT_SHAPED_CWES
        assert classify_shape("Server-side request forgery.", ("CWE-918",)) == "triage-required"

    def test_the_guard_this_protects_still_exists(self) -> None:
        """A sink word for a shape nothing refuses would be noise, not triage."""
        from agent_airlock.ssrf_egress_guard import SSRFEgressGuard

        assert SSRFEgressGuard is not None


class TestExtractCarriesShape:
    def test_extract_populates_cwes_and_shape(self) -> None:
        record = {
            "cve": {
                "id": "CVE-2026-00001",
                "published": "2026-09-06T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "MCP server spawns child_process."}],
                "weaknesses": [{"description": [{"value": "CWE-862"}]}],
            }
        }
        got = extract(record)
        assert got["cwes"] == ["CWE-862"]
        assert got["shape"] == "candidate"

    def test_missing_weaknesses_do_not_raise(self) -> None:
        got = extract(_nvd("CVE-2026-00002", "An MCP authorization defect."))
        assert got["cwes"] == []
        assert got["shape"] == "triage-required"
