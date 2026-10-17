"""Blind least-privilege labels for the LP tier, one per tool, for the 35 servers with clean queries.

**How these were written.** From the output of ``python -m benchmarks.mcptox clean-view``
alone, which prints each server's clean tool blocks and clean queries and nothing from the
attack side. They were committed in their own commit, before the replay code existed, and
their sha256 is recorded in ``RESULTS.md``. No poisoned tool, attack query or recorded
model response was read while writing them.

**What a label says.** What kind of resource a tool's arguments address, so the LP tier
can scope it (:mod:`.policies` derives the actual roots and hosts from the clean queries):

* ``fs`` - local filesystem paths: the tool gets a ``FilesystemPolicy``;
* ``url_allowlist`` - URLs of a known service: an ``EndpointPolicy`` allowlist (the hosts
  in the server's clean queries plus ``extra_hosts``, which are public service domains);
* ``url_open_web`` - a browser, fetcher or scraper that may go anywhere public: an
  ``EndpointPolicy()`` that refuses private, loopback, link-local and metadata targets,
  plus an ``SSRFEgressGuard`` pre-check;
* ``none`` - nothing LP can scope with these primitives (API identifiers, messages,
  queries, SQL, code, shell commands, email recipients, remote-repository paths).

``agent_airlock`` has no primitive for a recipient allowlist, a SQL or shell parser, or a
JavaScript sandbox, so tools whose risk lives there are ``none`` here, and the LP tier can
refuse nothing on them beyond G. That is a scope limit of the library, reported as such.

**Evidence pointers** cite clean data by position only and never quote it:
``clean_querys[N]`` (a clean query on the server that exercises the resource),
``description`` (the tool's clean description), ``args:<name>`` (the declared argument
carrying the resource) and ``repository`` (the server's public repository URL).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

FS = "fs"
URL_ALLOWLIST = "url_allowlist"
URL_OPEN_WEB = "url_open_web"
NONE = "none"
SCOPES = frozenset({FS, URL_ALLOWLIST, URL_OPEN_WEB, NONE})


@dataclass(frozen=True)
class ToolLabel:
    """One tool's LP label.

    Attributes:
        scopes: One or more of :data:`SCOPES` (``none`` alone means unscoped).
        evidence: Pointers into the server's clean data (see the module docstring).
        extra_hosts: Public service domains added to a ``url_allowlist``.
        note: Why the label is what it is, in the labeller's words.
    """

    scopes: tuple[str, ...]
    evidence: tuple[str, ...]
    extra_hosts: tuple[str, ...] = ()
    note: str = ""


def _fs(*evidence: str, note: str = "") -> ToolLabel:
    return ToolLabel((FS,), evidence, note=note)


def _open_web(*evidence: str, note: str = "") -> ToolLabel:
    return ToolLabel((URL_OPEN_WEB,), evidence, note=note)


def _allowlist(*evidence: str, extra_hosts: tuple[str, ...] = (), note: str = "") -> ToolLabel:
    return ToolLabel((URL_ALLOWLIST,), evidence, extra_hosts=extra_hosts, note=note)


def _none(*evidence: str, note: str = "") -> ToolLabel:
    return ToolLabel((NONE,), evidence, note=note)


def _all_none(names: Iterable[str], *evidence: str, note: str = "") -> dict[str, ToolLabel]:
    return {name: _none(*evidence, note=note) for name in names}


_REMOTE_REPO = "a path here names a file in a remote repository, not on the local filesystem"
_EMAIL = "recipients are neither paths nor URLs; agent_airlock has no recipient allowlist"
_FALLBACK_FS = "no clean query on this server names a path, so LP derives no root (G)"

LABELS: dict[str, dict[str, ToolLabel]] = {
    "FileSystem": {
        "read_file": _fs("description", "args:path", "clean_querys[0]", "clean_querys[1]"),
        "read_multiple_files": _fs("description", "args:paths", "clean_querys[1]"),
        "write_file": _fs("description", "args:path", "clean_querys[2]"),
        "edit_file": _fs("description", "args:path", "clean_querys[3]"),
        "create_directory": _fs("description", "args:path", "clean_querys[4]"),
        "list_directory": _fs("description", "args:path", "clean_querys[5]"),
        "directory_tree": _fs("description", "args:path", "clean_querys[6]"),
        "move_file": _fs("description", "args:source", "args:destination", "clean_querys[7]"),
        "search_files": _fs("description", "args:path", "clean_querys[8]"),
        "get_file_info": _fs("description", "args:path", "clean_querys[9]"),
        "list_allowed_directories": _none("clean_querys[10]", note="takes no arguments"),
    },
    "Puppeteer": {
        "puppeteer_navigate": _open_web(
            "description", "args:url", "clean_querys[0]", note="a browser can be sent anywhere"
        ),
        "puppeteer_screenshot": _none(
            "args:name", "clean_querys[1]", note="name labels an in-memory screenshot"
        ),
        "puppeteer_click": _none("args:selector", "clean_querys[2]"),
        "puppeteer_fill": _none("args:selector", "clean_querys[3]"),
        "puppeteer_select": _none("args:selector", "clean_querys[4]"),
        "puppeteer_hover": _none("args:selector", "clean_querys[5]"),
        "puppeteer_evaluate": _none(
            "args:script", "clean_querys[6]", note="JavaScript; agent_airlock does not parse it"
        ),
    },
    "AmapMap": {
        **_all_none(
            [
                "maps_regeocode",
                "maps_geo",
                "maps_weather",
                "maps_search_detail",
                "maps_bicycling",
                "maps_direction_walking",
                "maps_direction_driving",
                "maps_direction_transit_integrated",
                "maps_distance",
                "maps_text_search",
                "maps_around_search",
            ],
            "description",
            note="coordinates, addresses and POI ids for a maps API",
        ),
        "maps_ip_location": _none(
            "args:ip", "clean_querys[2]", note="ip is a geolocation lookup key, not a fetch target"
        ),
    },
    "AdFin": {
        "upload_invoice_to_adfin": _fs("description", "args:invoice_path", "clean_querys[0]"),
        **_all_none(
            [
                "put_schedules",
                "get_schedules_templates",
                "put_schedules_templates",
                "get_schedules_templates_settings",
                "put_schedules_templates_settings",
                "put_schedules_messages",
                "put_invoices_id_void",
                "put_invoices_id_mark_as_paid",
                "put_invoices_id_activate",
                "get_customers",
                "put_customers",
                "post_customers",
                "get_customers_id_directdebitmandates",
                "put_customers_id_directdebitmandates",
                "put_customers_directdebitmandates_id_cancel",
                "get_apps_clientId_webhooks_webhookId",
                "delete_apps_clientId_webhooks_webhookId",
                "put_apps_clientId_webhooks_digest",
            ],
            "description",
            "args:request_data",
            note="API objects and identifiers",
        ),
        "put_apps_clientId_webhooks_webhookId": _allowlist(
            "description",
            "args:request_data",
            "clean_querys[17]",
            note="request_data carries the webhook target url; no clean query names a host",
        ),
    },
    "Flomo": {"write_note": _none("args:content", "clean_querys[0]")},
    "Github": {
        **_all_none(
            [
                "search_repositories",
                "create_repository",
                "create_issue",
                "create_pull_request",
                "fork_repository",
                "create_branch",
                "list_commits",
                "list_issues",
                "update_issue",
                "add_issue_comment",
                "search_code",
                "search_issues",
                "search_users",
                "get_issue",
                "get_pull_request",
                "list_pull_requests",
                "create_pull_request_review",
            ],
            "repository",
            note="GitHub API identifiers and text",
        ),
        "create_or_update_file": _none("args:path", "clean_querys[0]", note=_REMOTE_REPO),
        "get_file_contents": _none("args:path", "clean_querys[3]", note=_REMOTE_REPO),
        "push_files": _none("args:files", "clean_querys[4]", note=_REMOTE_REPO),
    },
    "AWSKnowledgeBase": {"retrieve_from_aws_kb": _none("description", "clean_querys[0]")},
    "Slack": _all_none(
        [
            "slack_list_channels",
            "slack_post_message",
            "slack_reply_to_thread",
            "slack_add_reaction",
            "slack_get_channel_history",
            "slack_get_thread_replies",
            "slack_get_users",
            "slack_get_user_profile",
        ],
        "description",
        note="channel, thread and user identifiers and message text",
    ),
    "KeywordsPeopleUse": _all_none(
        ["people-also-ask", "google-autocomplete", "forums", "semantic-keywords"],
        "description",
        note="search queries for a keyword API",
    ),
    "Claude Post": {
        "search-emails": _none("clean_querys[0]"),
        "get-email-content": _none("clean_querys[1]"),
        "count-daily-emails": _none("clean_querys[2]"),
        "send-email": _none("args:to", "clean_querys[3]", note=_EMAIL),
    },
    "DumplingAI": {
        "get-youtube-transcript": _allowlist(
            "description",
            "args:videoUrl",
            "clean_querys[0]",
            extra_hosts=("youtube.com", "m.youtube.com", "youtu.be"),
            note="YouTube video URLs only",
        ),
        **_all_none(
            [
                "search",
                "get-autocomplete",
                "search-maps",
                "search-places",
                "search-news",
                "get-google-reviews",
            ],
            "description",
            note="search queries for a search API; nothing is fetched by URL",
        ),
        "scrape": _open_web("description", "args:url", "clean_querys[7]"),
        "crawl": _open_web("description", "args:url", "clean_querys[8]"),
        "extract": _open_web("description", "args:url", "clean_querys[9]"),
        "screenshot": _open_web("description", "args:url", "clean_querys[10]"),
        "doc-to-text": _open_web("args:file", "clean_querys[11]", note="fetches a file by URL"),
        "convert-to-pdf": _open_web("args:file", "clean_querys[12]", note="fetches a file by URL"),
        "merge-pdfs": _open_web("args:files", "clean_querys[13]", note="fetches files by URL"),
        "trim-video": _open_web("args:videoUrl", "clean_querys[14]", note="fetches a video"),
        "extract-document": _open_web("args:files", "clean_querys[15]", note="fetches by URL"),
        "extract-image": _open_web("args:images", "clean_querys[16]", note="fetches by URL"),
        "extract-audio": _open_web("args:audio", "clean_querys[17]", note="fetches by URL"),
        "extract-video": _open_web("args:video", "clean_querys[18]", note="fetches by URL"),
        "read-pdf-metadata": _open_web("args:files", "clean_querys[19]", note="fetches by URL"),
    },
    "HyperBrowser": {
        "scrape_webpage": _open_web("description", "args:url", "clean_querys[0]"),
        "crawl_webpages": _open_web("description", "args:url", "clean_querys[1]"),
        "extract_structured_data": _open_web("description", "args:urls", "clean_querys[2]"),
        **{
            name: _open_web(
                "description",
                "args:task",
                f"clean_querys[{index}]",
                note=(
                    "a browsing agent; a URL inside a natural-language task is not extracted "
                    "by agent_airlock, only a task that is itself a URL is checked"
                ),
            )
            for index, name in (
                (3, "browser_use_agent"),
                (4, "openai_computer_use_agent"),
                (5, "claude_computer_use_agent"),
            )
        },
        "search_with_bing": _none("args:query", "clean_querys[6]"),
        "create_profile": _none("clean_querys[7]"),
        "delete_profile": _none("args:profileId", "clean_querys[8]"),
        "list_profiles": _none("clean_querys[9]"),
    },
    "SQLite": _all_none(
        [
            "read_query",
            "write_query",
            "create_table",
            "list_tables",
            "describe_table",
            "append_insight",
        ],
        "description",
        note="SQL and memo text; agent_airlock does not parse SQL",
    ),
    "QuickChart": {
        "generate_chart": _none("description", "clean_querys[0]"),
        "download_chart": _fs("description", "args:outputPath", "clean_querys[1]"),
    },
    "Sequential Thinking": {"sequentialthinking": _none("description", "clean_querys[0]")},
    "Email": {
        **{
            name: _fs(
                "args:attachments",
                note="attachments may name local files; " + _FALLBACK_FS,
            )
            for name in ("sendBulkMail", "sendMail", "sendHtmlMail")
        },
        "sendSimpleMail": _none("args:to", "clean_querys[18]", note=_EMAIL),
        "getAttachment": _fs("args:saveToFile", "clean_querys[25]", note=_FALLBACK_FS),
        **_all_none(
            [
                "waitForReply",
                "searchEmails",
                "listEmails",
                "getContacts",
                "getEmailDetail",
                "deleteEmail",
                "moveEmail",
                "listFolders",
                "markMultipleAsRead",
                "markMultipleAsUnread",
                "markAsRead",
                "markAsUnread",
            ],
            "args",
            note="mailbox identifiers, folders and search terms",
        ),
    },
    "Fetch": {"fetch": _open_web("description", "args:url", "clean_querys[0]")},
    "12306-mcp": {"search": _none("args:fromCity", "clean_querys[0]")},
    "Commander": {
        "get_config": _none("description", "clean_querys[9]"),
        "set_config_value": _none(
            "description", note="sets server configuration; its value is not a path argument"
        ),
        "read_file": _fs("description", "args:path", "clean_querys[2]"),
        "read_multiple_files": _fs("description", "args:paths"),
        "write_file": _fs("description", "args:path", "clean_querys[0]"),
        "create_directory": _fs("description", "args:path", "clean_querys[6]"),
        "list_directory": _fs("description", "args:path", "clean_querys[3]"),
        "move_file": _fs("description", "args:source", "args:destination", "clean_querys[7]"),
        "search_files": _fs("description", "args:path", "clean_querys[4]"),
        "search_code": _fs("description", "args:path", "clean_querys[8]"),
        "get_file_info": _fs("description", "args:path", "clean_querys[5]"),
        "edit_block": _fs("description", "args:file_path"),
        "execute_command": _none(
            "args:command",
            "clean_querys[1]",
            note="a shell command string; agent_airlock does not parse commands",
        ),
        **_all_none(
            ["read_output", "force_terminate", "list_sessions", "list_processes", "kill_process"],
            "description",
            note="process and session identifiers",
        ),
    },
    "Redis": _all_none(["set", "get", "delete", "list"], "description", note="keys and values"),
    "Everything": _all_none(
        [
            "echo",
            "add",
            "printEnv",
            "longRunningOperation",
            "sampleLLM",
            "getTinyImage",
            "annotatedMessage",
            "getResourceReference",
        ],
        "description",
        note="demonstration tools with scalar arguments",
    ),
    "Gitlab": {
        **_all_none(
            [
                "search_repositories",
                "create_repository",
                "create_issue",
                "create_merge_request",
                "fork_repository",
                "create_branch",
            ],
            "repository",
            note="GitLab API identifiers and text",
        ),
        "create_or_update_file": _none("args:file_path", "clean_querys[9]", note=_REMOTE_REPO),
        "get_file_contents": _none("args:file_path", "clean_querys[4]", note=_REMOTE_REPO),
        "push_files": _none("args:files", "clean_querys[3]", note=_REMOTE_REPO),
    },
    "E2B": {
        "run_code": _none(
            "description", "clean_querys[0]", note="code runs in E2B's sandbox; not parsed here"
        )
    },
    "gNucleus Text to CAD": {"text_to_cad": _none("description", "clean_querys[0]")},
    "Gyazo": {
        "gyazo_search": _none("args:query", "clean_querys[1]"),
        "gyazo_image": _allowlist(
            "description",
            "args:id_or_url",
            "clean_querys[2]",
            extra_hosts=("gyazo.com", "i.gyazo.com"),
            note="a Gyazo id or a Gyazo URL",
        ),
        "gyazo_latest_image": _none("args:name", "clean_querys[3]"),
        "gyazo_upload": _none(
            "args:imageData", "clean_querys[4]", note="refererUrl is metadata, not fetched"
        ),
    },
    "mcp-simple-arxiv": _all_none(
        ["search_papers", "get_paper_data", "list_categories", "update_categories"],
        "description",
        note="arXiv queries and identifiers",
    ),
    "Memory": _all_none(
        [
            "create_entities",
            "create_relations",
            "add_observations",
            "delete_entities",
            "delete_observations",
            "delete_relations",
            "read_graph",
            "search_nodes",
            "open_nodes",
        ],
        "description",
        note="knowledge-graph entities and text",
    ),
    "BraveSearch": _all_none(
        ["brave_web_search", "brave_local_search"], "description", note="search queries"
    ),
    "AgentQL": {
        "extract-web-data": _open_web(
            "description", "args:url", "clean_querys[0]", "clean_querys[3]"
        )
    },
    "AlphaVantage": _all_none(
        [
            "stock_quote",
            "time_series_intraday",
            "time_series_daily",
            "time_series_daily_adjusted",
            "time_series_weekly",
            "time_series_weekly_adjusted",
            "time_series_monthly",
            "time_series_monthly_adjusted",
            "realtime_bulk_quotes",
            "symbol_search",
            "market_status",
            "realtime_options",
            "historical_options",
            "news_sentiment",
            "top_gainers_losers",
            "insider_transactions",
            "analytics_fixed_window",
            "analytics_sliding_window",
            "company_overview",
            "etf_profile",
        ],
        "description",
        note="ticker symbols and API options",
    ),
    "Codacy": _all_none(
        [
            "codacy_list_organization_repositories",
            "codacy_search_organization_srm_items",
            "codacy_search_repository_srm_items",
            "codacy_list_repository_issues",
            "codacy_list_repository_pull_requests",
            "codacy_list_files",
            "codacy_get_file_issues",
            "codacy_get_file_coverage",
            "codacy_get_pull_request_files_coverage",
            "codacy_get_pull_request_git_diff",
            "codacy_list_pull_request_issues",
            "codacy_get_repository_with_analysis",
            "codacy_get_file_with_analysis",
            "codacy_get_file_clones",
            "codacy_get_repository_pull_request",
            "codacy_get_issue",
            "codacy_get_pattern",
            "codacy_list_repository_tool_patterns",
            "codacy_list_tools",
            "codacy_list_repository_tools",
        ],
        "repository",
        note="Codacy API identifiers for remote repositories",
    ),
    "Financial Dataset": _all_none(
        [
            "get_income_statements",
            "get_balance_sheets",
            "get_cash_flow_statements",
            "get_current_stock_price",
            "get_historical_stock_prices",
            "get_company_news",
            "get_available_crypto_tickers",
            "get_crypto_prices",
            "get_historical_crypto_prices",
            "get_current_crypto_price",
            "get_sec_filings",
        ],
        "description",
        note="tickers, dates and API options",
    ),
    "Prisma": {
        name: _fs(
            "description",
            "args:projectCWD",
            note="projectCWD is a local project directory; " + _FALLBACK_FS,
        )
        for name in (
            "migrate-status",
            "migrate-dev",
            "migrate-reset",
            "Prisma-Postgres-account-status",
            "Create-Prisma-Postgres-Database",
            "Prisma-Login",
            "Prisma-Studio",
        )
    },
    "ClickHouse": _all_none(
        ["list_databases", "list_tables", "run_select_query"],
        "description",
        note="database names and SQL; agent_airlock does not parse SQL",
    ),
    "EverArt": {"generate_image": _none("description", "clean_querys[0]")},
}
