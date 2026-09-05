"""Poll NVD for MCP-ecosystem CVEs that agent-airlock does not yet cover.

Writes a JSON list to stdout of CVEs that are **not** already recorded in
this repo's CVE ledger, in the persistent watcher state file, or in an
existing ``cve-response`` issue. Exits 0 either way; the caller branches
on whether stdout is an empty list.

Used by ``.github/workflows/cve-watcher.yml``.

Uses NVD REST API 2.0. ``NVD_API_KEY`` is optional but recommended —
without it the rate limit is 5 requests / 30s, which is why the query
keyword list below is kept deliberately short.

Provenance
----------
The *mechanism* here — NVD keyword feed, layered dedup, a description
corroboration filter, back-pressure caps — is shared with the sibling
repo ``agent-audit-kit``'s watcher, which is where those lessons were
learned in production. The *content* is this repo's own:

* ``QUERY_KEYWORDS`` and ``_RELEVANCE_RE`` are derived from what
  ``docs/cves/`` actually tracks, not from audit-kit's rule set. Notably
  ``langchain``/``langgraph`` are **not** included: agent-airlock ships
  LangChain integrations but its CVE catalog contains no LangChain
  advisory, so querying for them would file issues for CVEs this repo has
  no guard story for.
* The ledger is ``docs/cves/index.md`` plus the ``tests/cves/`` filenames,
  since a CVE here is only really "covered" once it has a regression test.
* The issue checklist names this repo's artifacts (mcp_spec guard,
  ``@preset`` factory, ``tests/cves/`` regression, catalog regeneration).

Dedup strategy (three layers, any one suppresses):

1. The ledger — ``docs/cves/index.md`` and ``tests/cves/`` filenames.
2. ``.airlock/cve-watcher-state.json`` — every CVE the watcher has filed,
   so an untriaged CVE is not re-opened on every cron run.
3. CVE ids found in ``cve-response`` issues, open **and** closed, so a CVE
   closed as out-of-scope is not re-filed forever. This is the fallback
   for when the cached state file is lost.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

NVD_SEARCH = "https://services.nvd.nist.gov/rest/json/cves/2.0"

ROOT = Path(__file__).resolve().parent.parent

# Kept short on purpose: one NVD request per keyword per run, against a
# 5-req/30s unauthenticated limit. Breadth comes from _RELEVANCE_RE, which
# costs nothing — every advisory in docs/cves/ is MCP-adjacent, so "mcp"
# alone recovers most of them.
QUERY_KEYWORDS: tuple[str, ...] = (
    "mcp",
    "model context protocol",
    "claude code",
    "anthropic",
    "agentic",
)

LEDGER_PATHS: tuple[Path, ...] = (
    ROOT / "docs" / "cves" / "index.md",
    ROOT / "tests" / "cves",
)
STATE_PATH = ROOT / ".airlock" / "cve-watcher-state.json"

RESPONSE_LABEL = "cve-response"
DEFERRED_LABEL = "cve-deferred"

# Back-pressure. Unlike the sibling repo, agent-airlock's publish.yml has no
# gate that blocks a release on open cve-response issues, so these caps exist
# only to stop one vendor's advisory batch becoming forty issues in one cron
# run. Nothing is dropped: `filed_cves` records only what is actually emitted,
# so a held-back CVE is found again next run — which is also why the NVD
# window is 7 days rather than the cron interval.
MAX_NEW_PER_RUN = int(os.environ.get("AIRLOCK_CVE_MAX_NEW_PER_RUN", "5"))
MAX_OPEN_UNTRIAGED = int(os.environ.get("AIRLOCK_CVE_MAX_OPEN_UNTRIAGED", "10"))
WINDOW_HOURS = int(os.environ.get("AIRLOCK_CVE_WINDOW_HOURS", "168"))

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

# NVD's keywordSearch matches indexed fields (CPE names, reference URLs), not
# only the description. "mcp" is three letters that collide with unrelated
# hardware: NVIDIA nForce chipsets are literally "MCP" parts, so Linux kernel
# CVEs touching them come back as hits. A match therefore has to corroborate
# in the description text before anything is filed.
#
# Two words need care rather than a bare match:
#
#   "claude" — AI-authored-patch attribution lines ("written by Claude...")
#              now appear in unrelated projects' commit messages, so `claude`
#              only counts next to a product word.
#   "agent"  — user agent, SNMP agent, agent process. Only compound forms.
#
# Product terms are the ones docs/cves/ actually tracks, ranked by how often
# they appear there. Kept broad: a missed CVE is worse than a filed irrelevant
# one, and the watcher logs what it dropped.
_RELEVANCE_RE = re.compile(
    r"\bmcp\b"
    r"|model[- ]context[- ]protocol"
    r"|claude[- ](?:code|desktop|agent|sdk|mcp)"
    r"|claude\.ai"
    r"|\banthropic\b"
    r"|\bwindsurf\b"
    r"|\bgitpilot\b"
    r"|\bmcpjam\b"
    r"|\bflowise\b"
    r"|\bopenclaw\b"
    r"|\bmcp-atlassian\b"
    r"|\bcontext7\b"
    r"|\bmcp-server-(?:git|kubernetes)\b"
    r"|\bnginx-ui\b"
    r"|\blitellm\b"
    r"|\blibrechat\b"
    r"|\bagentcore\b"
    r"|\blerobot\b"
    r"|\brepomix\b"
    r"|\bcodebase-mcp\b"
    r"|\bcline\b"
    r"|\bagentic\b"
    r"|\bai[- ]agent"
    r"|\btool[- ](?:call|poisoning)"
    r"|\bagent (?:framework|runtime|pipeline|orchestrat)",
    re.IGNORECASE,
)

# Documented false-positive source: NVIDIA nForce "MCP" southbridge parts.
# Only suppresses when the text shows the hardware sense and none of the
# ecosystem terms above carried it.
_HARDWARE_NOISE_RE = re.compile(
    r"nforce|\bmcp\d{2,}\b|southbridge|chipset",
    re.IGNORECASE,
)


def is_relevant(description: str) -> bool:
    """Does the CVE text itself mention the ecosystem this repo guards?

    Guards against NVD matching a keyword in a CPE name or reference URL
    rather than in the vulnerability text. See the note above
    ``_RELEVANCE_RE``.
    """
    text = description or ""
    if not _RELEVANCE_RE.search(text):
        return False
    # A hardware-sense hit only survives if something other than a bare
    # "mcp" carried it.
    if _HARDWARE_NOISE_RE.search(text):
        without_bare_mcp = re.sub(r"\bmcp\b", " ", text, flags=re.IGNORECASE)
        return bool(_RELEVANCE_RE.search(without_bare_mcp))
    return True


def already_tracked(paths: tuple[Path, ...] = LEDGER_PATHS) -> set[str]:
    """CVE ids already carried by the catalog or the regression suite."""
    found: set[str] = set()
    for path in paths:
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file():
                    found |= set(_CVE_RE.findall(child.name.upper().replace("_", "-")))
                    if child.suffix in {".md", ".py"}:
                        found |= set(
                            _CVE_RE.findall(child.read_text(encoding="utf-8", errors="ignore"))
                        )
        elif path.is_file():
            found |= set(_CVE_RE.findall(path.read_text(encoding="utf-8", errors="ignore")))
    return found


def _load_state(state_path: Path) -> dict[str, Any]:
    if not state_path.is_file():
        return {"filed_cves": []}
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"filed_cves": []}
    if not isinstance(data, dict):
        return {"filed_cves": []}
    data.setdefault("filed_cves", [])
    return data


def _save_state(state_path: Path, state: dict[str, Any]) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def _github_issues(owner_repo: str | None, token: str | None, state: str) -> list[dict[str, Any]]:
    """Paginated ``cve-response`` issue fetch. Empty list on any failure."""
    if not owner_repo or not token:
        return []
    out: list[dict[str, Any]] = []
    page = 1
    while page <= 20:  # hard cap: 20 x 100 = 2000 issues
        url = (
            f"https://api.github.com/repos/{owner_repo}/issues"
            f"?state={state}&labels={RESPONSE_LABEL}&per_page=100&page={page}"
        )
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "agent-airlock cve-watcher",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                batch = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            sys.stderr.write(f"cve-watcher: issue fetch failed (page {page}): {exc}\n")
            return out
        if not batch:
            break
        out.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return out


def issue_cve_ids(owner_repo: str | None, token: str | None) -> set[str]:
    """CVE ids across **all** cve-response issues, open and closed."""
    found: set[str] = set()
    for issue in _github_issues(owner_repo, token, "all"):
        blob = f"{issue.get('title') or ''}\n{issue.get('body') or ''}"
        found |= set(_CVE_RE.findall(blob))
    return found


def open_untriaged_count(owner_repo: str | None, token: str | None) -> int:
    """Open ``cve-response`` issues carrying no ``cve-deferred`` label.

    Returns 0 when the API is unreachable: back-pressure must never be the
    reason a disclosure goes unfiled.
    """
    count = 0
    for issue in _github_issues(owner_repo, token, "open"):
        labels = {lbl.get("name") for lbl in (issue.get("labels") or [])}
        if DEFERRED_LABEL not in labels:
            count += 1
    return count


def _fetch(keyword: str, window_hours: int = WINDOW_HOURS) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    params = {
        "keywordSearch": keyword,
        "pubStartDate": (now - timedelta(hours=window_hours)).strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 50,
    }
    url = f"{NVD_SEARCH}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"User-Agent": "agent-airlock cve-watcher"})
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        req.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"cve-watcher: NVD fetch failed for {keyword!r}: {exc}\n")
        return []
    vulns = data.get("vulnerabilities")
    return vulns if isinstance(vulns, list) else []


def extract(vuln: dict[str, Any]) -> dict[str, Any]:
    """Flatten one NVD record to the fields the issue template uses."""
    cve = vuln.get("cve") or {}
    cvss: float | None = None
    severity: str | None = None
    metrics = (cve.get("metrics") or {}).get("cvssMetricV31") or []
    if metrics:
        cvss_data = metrics[0].get("cvssData") or {}
        cvss = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity")
    desc = ""
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "cvss": cvss,
        "severity": severity,
        "description": desc,
    }


def collect_new_cves(
    *,
    ledger_paths: tuple[Path, ...] = LEDGER_PATHS,
    state_path: Path = STATE_PATH,
    github_token: str | None = None,
    owner_repo: str | None = None,
    fetcher: Callable[[str], list[dict[str, Any]]] = _fetch,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Collect undocumented CVEs with layered dedup.

    Returns ``(new_entries, updated_state)``. The caller persists the state,
    so a dry run leaves no trace.
    """
    state = _load_state(state_path)
    filed = set(state.get("filed_cves", []))
    suppressed = already_tracked(ledger_paths) | filed | issue_cve_ids(owner_repo, github_token)

    seen: set[str] = set()
    results: list[dict[str, Any]] = []
    dropped: list[str] = []
    for keyword in QUERY_KEYWORDS:
        for vuln in fetcher(keyword):
            entry = extract(vuln)
            cve_id = entry["id"]
            if not cve_id or cve_id in suppressed or cve_id in seen:
                continue
            seen.add(cve_id)
            if not is_relevant(entry.get("description") or ""):
                # NVD matched an indexed field, not the text. See is_relevant().
                dropped.append(cve_id)
                continue
            results.append(entry)

    if dropped:
        sys.stderr.write(
            f"cve-watcher: dropped {len(dropped)} keyword hit(s) with no "
            f"ecosystem mention in the description: {', '.join(sorted(dropped))}\n"
        )

    # Applied here, not in the workflow's issue step: `filed_cves` below records
    # exactly what this function returns, so a cap applied afterwards would mark
    # held-back CVEs as filed and lose them.
    if results:
        backlog = open_untriaged_count(owner_repo, github_token)
        if backlog >= MAX_OPEN_UNTRIAGED:
            sys.stderr.write(
                f"cve-watcher: {backlog} untriaged {RESPONSE_LABEL} issue(s) already open "
                f"(limit {MAX_OPEN_UNTRIAGED}); holding {len(results)} CVE(s) until the "
                f"queue drains: {', '.join(e['id'] for e in results)}\n"
            )
            return [], state
        if len(results) > MAX_NEW_PER_RUN:
            results.sort(key=lambda e: e.get("cvss") or 0.0, reverse=True)
            held = results[MAX_NEW_PER_RUN:]
            results = results[:MAX_NEW_PER_RUN]
            sys.stderr.write(
                f"cve-watcher: capped at {MAX_NEW_PER_RUN} new issue(s) this run; holding "
                f"{len(held)} for later: {', '.join(e['id'] for e in held)}\n"
            )

    if results:
        state["filed_cves"] = sorted(filed | {str(e["id"]) for e in results})
    return results, state


def main() -> int:
    state_path = Path(os.environ.get("AIRLOCK_CVE_WATCHER_STATE", str(STATE_PATH)))
    results, state = collect_new_cves(
        state_path=state_path,
        github_token=os.environ.get("GITHUB_TOKEN"),
        owner_repo=os.environ.get("GITHUB_REPOSITORY"),
    )
    sys.stdout.write(json.dumps(results, indent=2))
    # Only persist when about to file. The workflow branches on stdout, so if
    # it crashes between "stdout written" and "issue filed" the state must
    # already mark the CVE or the next run duplicates it.
    if results:
        _save_state(state_path, state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
