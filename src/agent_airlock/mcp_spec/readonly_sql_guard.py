"""Read-only SQL guard for tool arguments (v0.10.34+, CVE-2026-125322 + CVE-2026-61789).

Two advisories against MCP database servers, one class: a tool that promises read-only
access runs SQL text a model wrote.

- **CVE-2026-125322** (pgEdge Postgres MCP Server below 1.1.0, CWE-89, NVD 2026-11-10):
  the ``where`` parameter of ``count_rows`` accepted subqueries against tables other than
  the one named in the call, so the row count became an oracle over any table the
  database role could read.
  https://nvd.nist.gov/vuln/detail/CVE-2026-125322 (GHSA-fhv3-x3jh-grj7)
- **CVE-2026-61789** (bytebase DBHub below 0.22.6, CWE-436, NVD 2026-10-30): the
  read-only check treated every ``--`` as a comment, while MySQL and MariaDB need
  whitespace, a control character or the end of the line after it, so text the check
  skipped as a comment ran as a second statement.
  https://nvd.nist.gov/vuln/detail/CVE-2026-61789 (GHSA-j656-3hf2-fvjc)

What it does
------------
:class:`ReadOnlySQLGuard` reads two kinds of argument, named by field:

- **Statement fields** (``sql``, ``query``, ``statement``) hold a whole statement. It
  must be one statement, start with ``SELECT``, ``WITH``, ``VALUES``, ``SHOW``,
  ``DESCRIBE`` / ``DESC`` or ``EXPLAIN``, and contain no data-changing keyword
  (``EXPLAIN ANALYZE DELETE`` runs the ``DELETE``, so the whole text is read), no
  ``SELECT ... INTO`` and no function from a short list that reads files, runs commands
  or runs SQL held in a string.
- **Fragment fields** (``where``, ``filter``, ``condition``, ``having``, ``order_by``)
  hold a piece the server splices into a fixed query. A fragment may not read another
  table (``SELECT``, PostgreSQL and MySQL's ``TABLE name`` shorthand, PostgreSQL's
  ``table_to_xml`` family), carry a comment, end the clause (``;``, ``UNION``,
  parentheses that do not balance) or hold anything a statement may not.

The text is tokenised once per dialect the way that database reads it: comments
(``--``, ``/* */``, MySQL's ``#``), string literals and quoted identifiers are told apart
from code, so ``name = 'a;b -- c'`` passes and a ``--`` that MySQL runs as two minus signs
is read as code. A MySQL executable comment (``/*!`` with an optional version, and
MariaDB's ``/*M!``) is code: its body is inspected, and in a fragment it is refused as a
comment. ``dialect="generic"`` (the default) reads the value as MySQL, PostgreSQL and
SQLite in turn and refuses it when any reading does, since a text can hide a statement
from one database's rules and not another's. Anything the tokeniser cannot read to the
end (an unterminated literal, comment or dollar quote, a NUL, a bare carriage return
inside a line comment) is ``DENY_UNINSPECTABLE``.

What it does not cover
----------------------
- Other query languages (DQL, Cypher, GraphQL, MongoDB filters, Elasticsearch DSL). The
  guard reads SQL only; a field holding another language is read as SQL and will
  usually be refused as not a read statement.
- A server that builds SQL from arguments the guard is not told about. Only the named
  fields are read; mapping keys are never read as SQL.
- SQL Server and Oracle quoting (``[name]`` is read only as SQLite reads it, Oracle's
  ``q'[...]'`` not at all), MySQL in ``ANSI_QUOTES`` or ``NO_BACKSLASH_ESCAPES`` mode and
  PostgreSQL with ``standard_conforming_strings`` off: use ``generic`` for those, whose
  PostgreSQL and MySQL readings cover them.
- Functions that write or leak outside the short list: user-defined functions,
  ``nextval``, ``set_config``, ``pg_relation_size`` and the like. Run the server's role
  read-only too; the guard narrows what reaches the database, it does not replace that.
- The guard is a tokeniser, not a parser. It refuses on a keyword's presence, so a
  column named like a write keyword (``copy``, ``call``) must be quoted, and
  ``SELECT ... FOR UPDATE`` is refused (PostgreSQL refuses it in a read-only
  transaction too).

Companion preset
----------------
:func:`agent_airlock.policy_presets.readonly_sql_tool_args_2026_125322_defaults`
returns the recommended config dict.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from typing import Any

from .._log import structlog

logger = structlog.get_logger("agent-airlock.mcp_spec.readonly_sql_guard")


#: Argument names whose value is a whole SQL statement.
DEFAULT_STATEMENT_FIELDS: frozenset[str] = frozenset({"sql", "query", "statement"})

#: Argument names whose value is a piece spliced into a fixed query.
DEFAULT_FRAGMENT_FIELDS: frozenset[str] = frozenset(
    {"where", "filter", "condition", "having", "order_by"}
)

#: Accepted ``dialect`` values. ``generic`` reads every value as each of the other three.
DIALECTS: frozenset[str] = frozenset({"postgres", "mysql", "sqlite", "generic"})

# Leading keywords of a statement that only reads. ``DESC`` is MySQL's short DESCRIBE.
_READ_STATEMENT_KEYWORDS: frozenset[str] = frozenset(
    {"SELECT", "WITH", "VALUES", "SHOW", "DESCRIBE", "DESC", "EXPLAIN"}
)

# Keywords that change data, schema or permissions, refused anywhere outside literals:
# inside a WITH clause (PostgreSQL's data-modifying CTEs) and after EXPLAIN as well.
# PRAGMA is refused only when it sets a value (``=`` or the call form), and INTO only
# after a read keyword (``SELECT ... INTO``); both are handled in ``_write_hit``.
_WRITE_KEYWORDS: frozenset[str] = frozenset(
    {
        "INSERT",
        "UPDATE",
        "DELETE",
        "MERGE",
        "UPSERT",
        "REPLACE",
        "TRUNCATE",
        "DROP",
        "ALTER",
        "CREATE",
        "GRANT",
        "REVOKE",
        "COPY",
        "CALL",
        "EXEC",
        "EXECUTE",
        "DO",
        "VACUUM",
        "ATTACH",
    }
)

# Write keywords that are also read-only string or number functions (MySQL's INSERT()
# and TRUNCATE(), everyone's REPLACE()). Followed by ``(`` they are the function: no
# dialect accepts a statement of that shape.
_WRITE_KEYWORDS_ALSO_FUNCTIONS: frozenset[str] = frozenset({"INSERT", "REPLACE", "TRUNCATE"})

# Functions that read server files, run commands, reach other servers or run SQL held in
# a string literal the guard does not read, plus MySQL's ``INTO OUTFILE / DUMPFILE``.
# Matched case-insensitively as a bare word or a quoted identifier.
_DANGEROUS_FUNCTIONS: frozenset[str] = frozenset(
    {
        "pg_read_file",
        "pg_read_binary_file",
        "pg_ls_dir",
        "lo_import",
        "lo_export",
        "dblink",
        "dblink_exec",
        "query_to_xml",
        "query_to_xmlschema",
        "query_to_xml_and_xmlschema",
        "ts_stat",
        "load_file",
        "sys_exec",
        "sys_eval",
        "xp_cmdshell",
        "load_extension",
        "readfile",
        "writefile",
        "outfile",
        "dumpfile",
    }
)

# What reads another table from inside a fragment: a SELECT, the ``TABLE name`` shorthand
# (PostgreSQL, MySQL 8), and PostgreSQL functions that return a table's rows by name.
_SUBQUERY_KEYWORDS: frozenset[str] = frozenset({"SELECT", "TABLE"})
_TABLE_READING_FUNCTIONS: frozenset[str] = frozenset(
    {
        "table_to_xml",
        "table_to_xmlschema",
        "table_to_xml_and_xmlschema",
        "schema_to_xml",
        "schema_to_xmlschema",
        "schema_to_xml_and_xmlschema",
        "database_to_xml",
        "database_to_xmlschema",
        "database_to_xml_and_xmlschema",
    }
)

#: Nesting deeper than this is refused rather than walked, as in ``FilterEvalRCEGuard``.
_MAX_DEPTH = 32

# A shown token is cut to this many characters: the detail never repeats the value.
_TOKEN_SHOWN = 40

_SPACE = frozenset(" \t\n\r\f\v")
_DOLLAR_TAG_RE = re.compile(r"\$(?:[A-Za-z_\x80-\U0010ffff][A-Za-z0-9_\x80-\U0010ffff]*)?\$")
_STATEMENT = "statement"
_FRAGMENT = "fragment"
_GENERIC_READINGS: tuple[str, ...] = ("mysql", "postgres", "sqlite")


class ReadOnlySQLVerdict(str, enum.Enum):
    """Stable reason codes for :class:`ReadOnlySQLDecision`."""

    ALLOW = "allow"
    DENY_STACKED_STATEMENT = "deny_stacked_statement"
    DENY_WRITE_STATEMENT = "deny_write_statement"
    DENY_SUBQUERY_IN_FRAGMENT = "deny_subquery_in_fragment"
    DENY_COMMENT_IN_FRAGMENT = "deny_comment_in_fragment"
    DENY_DANGEROUS_FUNCTION = "deny_dangerous_function"
    DENY_UNINSPECTABLE = "deny_uninspectable"


@dataclass(frozen=True)
class ReadOnlySQLDecision:
    """Outcome of a single :meth:`ReadOnlySQLGuard.evaluate` call.

    Same five fields as ``FilterEvalRCEDecision``, so guards chain on ``allowed``.

    Attributes:
        allowed: True iff no argument the guard reads broke a rule.
        verdict: A stable :class:`ReadOnlySQLVerdict` value.
        detail: The field, whether it was read as a statement or a fragment, the verdict,
            the token that decided it and the dialect reading that saw it. Never the value.
        matched_field: The field path that was refused (``"where"``,
            ``"params.where"``, ``"sql[1]"``), or ``None`` when ``allowed=True``.
        matched_pattern: The deciding token (``"SELECT"``, ``";"``, ``"--"``), or
            ``"uninspectable"``; ``None`` when ``allowed=True``.
    """

    allowed: bool
    verdict: ReadOnlySQLVerdict
    detail: str
    matched_field: str | None
    matched_pattern: str | None


@dataclass(frozen=True)
class _Rules:
    """How one database tokenises SQL text: only the differences the guard needs."""

    name: str
    backslash_escapes: bool  # '\' escapes inside '...' (and "..." when it is a string)
    double_quote_string: bool  # "..." is a string literal, not an identifier
    hash_comment: bool  # '#' starts a comment to the end of the line
    dash_comment_needs_space: bool  # '--' is a comment only before whitespace or the end
    nested_comments: bool  # '/* /* */ */' is one comment
    dollar_quotes: bool  # $tag$...$tag$ strings; '$' continues but never starts a name
    escape_strings: bool  # E'...' strings with backslash escapes
    backtick_identifiers: bool
    bracket_identifiers: bool  # [name] (SQLite, after SQL Server)
    executable_comments: bool  # /*! ... */ and /*M! ... */ run their body


_RULES: dict[str, _Rules] = {
    "postgres": _Rules(
        name="postgres",
        backslash_escapes=False,
        double_quote_string=False,
        hash_comment=False,
        dash_comment_needs_space=False,
        nested_comments=True,
        dollar_quotes=True,
        escape_strings=True,
        backtick_identifiers=False,
        bracket_identifiers=False,
        executable_comments=False,
    ),
    "mysql": _Rules(
        name="mysql",
        backslash_escapes=True,
        double_quote_string=True,
        hash_comment=True,
        dash_comment_needs_space=True,
        nested_comments=False,
        dollar_quotes=False,
        escape_strings=False,
        backtick_identifiers=True,
        bracket_identifiers=False,
        executable_comments=True,
    ),
    "sqlite": _Rules(
        name="sqlite",
        backslash_escapes=False,
        double_quote_string=False,
        hash_comment=False,
        dash_comment_needs_space=False,
        nested_comments=False,
        dollar_quotes=False,
        escape_strings=False,
        backtick_identifiers=True,
        bracket_identifiers=True,
        executable_comments=False,
    ),
}

# A token is ``(kind, text)``: ``word`` (upper-cased), ``punct`` (one character),
# ``literal`` (its opening quote), ``qident`` (the quoted name, unescaped) or ``comment``
# (its opener; ``/*!`` for a MySQL executable comment, whose body follows as code).
_Token = tuple[str, str]


class _Unreadable(Exception):
    """The tokeniser could not read the value to its end (private; never leaves evaluate())."""

    def __init__(self, why: str) -> None:
        super().__init__(why)
        self.why = why


def _is_word_char(ch: str, *, dollar: bool) -> bool:
    # Every database here reads any non-ASCII character as part of a name.
    if ord(ch) >= 128:
        return True
    return ch.isalnum() or ch == "_" or (dollar and ch == "$")


class _Lexer:
    """One pass over ``text`` under one dialect's rules."""

    def __init__(self, text: str, rules: _Rules) -> None:
        self._s = text
        self._n = len(text)
        self._i = 0
        self._r = rules
        self._in_executable = False
        self.tokens: list[_Token] = []

    def run(self) -> list[_Token]:
        s = self._s
        while self._i < self._n:
            ch = s[self._i]
            if ch in _SPACE:
                self._i += 1
            elif ch == "\x00":
                raise _Unreadable("holds a NUL character, which databases read differently")
            elif self._comment():
                continue
            elif self._in_executable and s.startswith("*/", self._i):
                self._in_executable = False
                self._i += 2
            elif ch == "'":
                self._literal("'", backslash=self._r.backslash_escapes)
            elif ch == '"':
                self._double_quote()
            elif ch == "`" and self._r.backtick_identifiers:
                self._quoted_name("`")
            elif ch == "[" and self._r.bracket_identifiers:
                self._bracket_name()
            elif ch == "$" and self._r.dollar_quotes and (tag := _DOLLAR_TAG_RE.match(s, self._i)):
                self._dollar_quote(tag)
            elif ch.isascii() and ch.isdigit():
                self._number()
            elif _is_word_char(ch, dollar=not self._r.dollar_quotes):
                self._word()
            else:
                self.tokens.append(("punct", ch))
                self._i += 1
        if self._in_executable:
            raise _Unreadable("opens a MySQL executable comment it never closes")
        return self.tokens

    # -- comments ----------------------------------------------------------------------

    def _comment(self) -> bool:
        s, i = self._s, self._i
        if s.startswith("--", i):
            after = s[i + 2] if i + 2 < self._n else ""
            if self._r.dash_comment_needs_space and after and after not in _SPACE:
                if ord(after) < 32 or after == "\x7f":
                    raise _Unreadable("puts a control character after '--'")
                return False  # MySQL reads '--1' as two minus signs: code
            self._line_comment("--")
            return True
        if s[i] == "#" and self._r.hash_comment:
            self._line_comment("#")
            return True
        if s.startswith("/*", i):
            self._block_comment()
            return True
        return False

    def _line_comment(self, opener: str) -> None:
        if self._in_executable:
            raise _Unreadable("nests a comment inside a MySQL executable comment")
        s, i = self._s, self._i
        newline = s.find("\n", i)
        stop = self._n if newline < 0 else newline
        body = s[i:stop]
        # PostgreSQL ends a line comment at '\r', SQLite and MySQL only at '\n'. A CRLF
        # ending reads alike everywhere; any other '\r' does not.
        inner = body[:-1] if newline >= 0 and body.endswith("\r") else body
        if "\r" in inner:
            raise _Unreadable("puts a bare carriage return in a line comment")
        self.tokens.append(("comment", opener))
        self._i = stop

    def _block_comment(self) -> None:
        s, i = self._s, self._i
        if self._in_executable:
            raise _Unreadable("nests a comment inside a MySQL executable comment")
        if self._r.executable_comments and (s.startswith("/*!", i) or s.startswith("/*M!", i)):
            j = i + (3 if s.startswith("/*!", i) else 4)
            while j < self._n and s[j].isascii() and s[j].isdigit():
                j += 1  # the optional server version: the body runs on any version here
            self.tokens.append(("comment", "/*!"))
            self._in_executable = True
            self._i = j
            return
        depth, j = 1, i + 2
        while j < self._n:
            if s.startswith("*/", j):
                depth -= 1
                j += 2
                if depth == 0:
                    break
            elif self._r.nested_comments and s.startswith("/*", j):
                depth += 1
                j += 2
            else:
                j += 1
        if depth:
            raise _Unreadable("opens a block comment it never closes")
        self.tokens.append(("comment", "/*"))
        self._i = j

    # -- literals and quoted names -----------------------------------------------------

    def _literal(self, quote: str, *, backslash: bool, opener: str | None = None) -> None:
        s, j = self._s, self._i + 1
        while j < self._n:
            c = s[j]
            if backslash and c == "\\":
                j += 2
            elif c == quote:
                if j + 1 < self._n and s[j + 1] == quote:
                    j += 2
                else:
                    self.tokens.append(("literal", opener or quote))
                    self._i = j + 1
                    return
            else:
                j += 1
        raise _Unreadable(f"opens a {quote} quote it never closes")

    def _double_quote(self) -> None:
        if self._r.double_quote_string:
            self._literal('"', backslash=self._r.backslash_escapes)
            return
        i = self._i
        if self._r.dollar_quotes and i >= 2 and self._s[i - 2 : i].upper() == "U&":
            # PostgreSQL's U&"..." spells a name with escapes ('pg\005fread\005ffile').
            raise _Unreadable('uses a Unicode-escaped name (U&"...") the guard does not decode')
        self._quoted_name('"')

    def _quoted_name(self, quote: str) -> None:
        s, j = self._s, self._i + 1
        parts: list[str] = []
        while j < self._n:
            c = s[j]
            if c == quote:
                if j + 1 < self._n and s[j + 1] == quote:
                    parts.append(quote)
                    j += 2
                    continue
                self.tokens.append(("qident", "".join(parts)))
                self._i = j + 1
                return
            parts.append(c)
            j += 1
        raise _Unreadable(f"opens a {quote} quoted name it never closes")

    def _bracket_name(self) -> None:
        end = self._s.find("]", self._i + 1)
        if end < 0:
            raise _Unreadable("opens a [ quoted name it never closes")
        self.tokens.append(("qident", self._s[self._i + 1 : end]))
        self._i = end + 1

    def _dollar_quote(self, match: re.Match[str]) -> None:
        tag = match.group(0)
        end = self._s.find(tag, match.end())
        if end < 0:
            raise _Unreadable("opens a dollar quote it never closes")
        self.tokens.append(("literal", "$"))
        self._i = end + len(tag)

    # -- words and numbers -------------------------------------------------------------

    def _number(self) -> None:
        # Never absorb '$': PostgreSQL before 15 reads '1$$x$$' as 1 then a dollar quote.
        s, j = self._s, self._i + 1
        while j < self._n and (_is_word_char(s[j], dollar=False) or s[j] == "."):
            j += 1
        self.tokens.append(("word", s[self._i : j].upper()))
        self._i = j

    def _word(self) -> None:
        s, j = self._s, self._i + 1
        while j < self._n and _is_word_char(s[j], dollar=True):
            j += 1
        word = s[self._i : j].upper()
        self._i = j
        if self._r.escape_strings and word == "E" and s.startswith("'", j):
            self._literal("'", backslash=True, opener="E'")
            return
        self.tokens.append(("word", word))


# -- rules over the token stream --------------------------------------------------------

_Hit = tuple[ReadOnlySQLVerdict, str]


def _code(tokens: list[_Token]) -> list[_Token]:
    return [token for token in tokens if token[0] != "comment"]


def _named(token: _Token, names: frozenset[str]) -> bool:
    kind, text = token
    return kind in ("word", "qident") and text.lower() in names


def _dangerous_hit(code: list[_Token]) -> _Hit | None:
    for token in code:
        if _named(token, _DANGEROUS_FUNCTIONS):
            return ReadOnlySQLVerdict.DENY_DANGEROUS_FUNCTION, token[1]
    return None


def _write_hit(code: list[_Token]) -> _Hit | None:
    for idx, (kind, text) in enumerate(code):
        if kind != "word":
            continue
        rest = code[idx + 1 :]
        if text in _WRITE_KEYWORDS:
            if text in _WRITE_KEYWORDS_ALSO_FUNCTIONS and rest[:1] == [("punct", "(")]:
                continue
            return ReadOnlySQLVerdict.DENY_WRITE_STATEMENT, text
        if text == "INTO":
            return ReadOnlySQLVerdict.DENY_WRITE_STATEMENT, text
        if text == "PRAGMA" and (("punct", "=") in rest or ("punct", "(") in rest):
            return ReadOnlySQLVerdict.DENY_WRITE_STATEMENT, text
    return None


def _check_statement(tokens: list[_Token]) -> _Hit | None:
    code = _code(tokens)
    for idx, (kind, text) in enumerate(code):
        if kind == "punct" and text == "\\":
            # Outside a literal a backslash is a client command (psql's \!, mysql's \g).
            return ReadOnlySQLVerdict.DENY_STACKED_STATEMENT, text
        if kind == "punct" and text == ";" and idx + 1 < len(code):
            return ReadOnlySQLVerdict.DENY_STACKED_STATEMENT, text
    hit = _dangerous_hit(code) or _write_hit(code)
    if hit is not None:
        return hit
    lead = next((token for token in code if token != ("punct", "(")), None)
    if lead is None:
        return None  # nothing but comments and parentheses: nothing runs
    if lead[0] != "word" or lead[1] not in _READ_STATEMENT_KEYWORDS:
        return ReadOnlySQLVerdict.DENY_WRITE_STATEMENT, lead[1]
    return None


def _check_fragment(tokens: list[_Token]) -> _Hit | None:
    code = _code(tokens)
    for token in code:
        if (token[0] == "word" and token[1] in _SUBQUERY_KEYWORDS) or _named(
            token, _TABLE_READING_FUNCTIONS
        ):
            return ReadOnlySQLVerdict.DENY_SUBQUERY_IN_FRAGMENT, token[1]
    for kind, text in tokens:
        if kind == "comment":
            return ReadOnlySQLVerdict.DENY_COMMENT_IN_FRAGMENT, text
    depth = 0
    for kind, text in code:
        if kind == "word" and text == "UNION":
            return ReadOnlySQLVerdict.DENY_STACKED_STATEMENT, text
        if kind != "punct":
            continue
        if text in (";", "\\"):
            return ReadOnlySQLVerdict.DENY_STACKED_STATEMENT, text
        if text == "(":
            depth += 1
        elif text == ")":
            depth -= 1
            if depth < 0:
                return ReadOnlySQLVerdict.DENY_STACKED_STATEMENT, text
    if depth:
        return ReadOnlySQLVerdict.DENY_STACKED_STATEMENT, "("
    return _dangerous_hit(code) or _write_hit(code)


def _require_str_frozenset(name: str, value: object) -> frozenset[str]:
    if not isinstance(value, frozenset):
        raise TypeError(f"{name} must be a frozenset[str]; got {type(value).__name__}")
    for member in value:
        if not isinstance(member, str):
            raise TypeError(f"{name} members must be str; got {type(member).__name__}")
    return value


class ReadOnlySQLGuard:
    """Refuse SQL in tool arguments that does more than one read.

    Anchors CVE-2026-125322 (a subquery in a ``where`` fragment) and CVE-2026-61789 (a
    second statement hidden from a read-only check by MySQL's ``--`` rule). The guard
    tokenises; it never runs, parses into a plan or rewrites the SQL.

    Args:
        statement_fields: Argument names whose value is a whole statement. Defaults to
            :data:`DEFAULT_STATEMENT_FIELDS`.
        fragment_fields: Argument names whose value is spliced into a fixed query.
            Defaults to :data:`DEFAULT_FRAGMENT_FIELDS`. A name may not be in both sets.
        dialect: ``"postgres"``, ``"mysql"``, ``"sqlite"`` or ``"generic"`` (every one of
            the three; the default, and the right choice when the database is unknown).

    Raises:
        TypeError: A field set is not a frozenset of str, or ``dialect`` is not a str.
        ValueError: ``dialect`` is not one of :data:`DIALECTS`, or a name is in both sets.
    """

    def __init__(
        self,
        *,
        statement_fields: frozenset[str] = DEFAULT_STATEMENT_FIELDS,
        fragment_fields: frozenset[str] = DEFAULT_FRAGMENT_FIELDS,
        dialect: str = "generic",
    ) -> None:
        self._statement_fields = _require_str_frozenset("statement_fields", statement_fields)
        self._fragment_fields = _require_str_frozenset("fragment_fields", fragment_fields)
        if not isinstance(dialect, str):
            raise TypeError(f"dialect must be a str; got {type(dialect).__name__}")
        if dialect not in DIALECTS:
            raise ValueError(f"dialect must be one of {sorted(DIALECTS)}; got {dialect!r}")
        both = statement_fields & fragment_fields
        if both:
            raise ValueError(f"a field cannot be both a statement and a fragment: {sorted(both)}")
        self._readings = _GENERIC_READINGS if dialect == "generic" else (dialect,)

    def evaluate(self, args: Mapping[str, Any] | None) -> ReadOnlySQLDecision:
        """Decide whether the SQL in the call's arguments only reads.

        Values are walked at any depth, as ``FilterEvalRCEGuard`` walks them: inside
        mappings, lists, tuples and sets, with ``bytes`` decoded as strict UTF-8. A string
        is read as a fragment when a key on its path is a fragment field, otherwise as a
        statement when one is a statement field; other strings are not read. Refused as
        ``DENY_UNINSPECTABLE``: arguments that are not a mapping, nesting deeper than 32
        levels, a container that contains itself, bytes that are not UTF-8, and any
        object in a read field that is not text, a number, a bool or ``None``.

        Args:
            args: The tool call's argument dict. ``None`` (no args) is allowed.

        Returns:
            :class:`ReadOnlySQLDecision`. Callers map ``allowed=False`` to a refusal.
        """
        if args is None:
            return self._allow("no args to inspect")
        if not isinstance(args, Mapping):
            return self._deny_uninspectable(
                "args", "is not a mapping, so no field name says how to read it", None
            )
        top = frozenset({id(args)})
        for key, value in args.items():
            decision = self._scan_value(
                str(key), value, role=self._role(key, None), depth=1, ancestors=top
            )
            if decision is not None:
                return decision
        return self._allow("no read-only SQL rule broken")

    def _role(self, key: object, inherited: str | None) -> str | None:
        # A fragment anywhere on the path wins: it is the stricter reading.
        if inherited == _FRAGMENT or key in self._fragment_fields:
            return _FRAGMENT
        if inherited == _STATEMENT or key in self._statement_fields:
            return _STATEMENT
        return None

    def _scan_value(
        self,
        field: str,
        value: Any,
        *,
        role: str | None,
        depth: int,
        ancestors: frozenset[int],
    ) -> ReadOnlySQLDecision | None:
        """Inspect a str or bytes value, or walk a container; ``None`` when nothing fires."""
        if isinstance(value, (str, bytes, bytearray, memoryview)):
            if role is None:
                return None
            if isinstance(value, str):
                text = value
            else:
                try:
                    text = bytes(value).decode("utf-8")
                except UnicodeDecodeError:
                    return self._deny_uninspectable(
                        field, "is bytes that are not valid UTF-8", None
                    )
            return self._inspect(field, text, role)
        children: list[tuple[str, Any, str | None]]
        if isinstance(value, Mapping):
            children = [
                (f"{field}.{key}", item, self._role(key, role)) for key, item in value.items()
            ]
        elif isinstance(value, (list, tuple, set, frozenset)):
            children = [(f"{field}[{idx}]", item, role) for idx, item in enumerate(value)]
        elif role is None or value is None or isinstance(value, (int, float, Decimal, Fraction)):
            return None  # bool is an int; numbers render as numbers
        else:
            return self._deny_uninspectable(
                field, f"holds a {type(value).__name__}, which the guard cannot read as SQL", None
            )
        if depth >= _MAX_DEPTH:
            return self._deny_uninspectable(field, f"nests deeper than {_MAX_DEPTH} levels", None)
        if id(value) in ancestors:
            return self._deny_uninspectable(field, "contains itself", None)
        inner = ancestors | {id(value)}
        for child_field, child, child_role in children:
            decision = self._scan_value(
                child_field, child, role=child_role, depth=depth + 1, ancestors=inner
            )
            if decision is not None:
                return decision
        return None

    def _inspect(self, field: str, text: str, role: str) -> ReadOnlySQLDecision | None:
        check = _check_fragment if role == _FRAGMENT else _check_statement
        for reading in self._readings:
            try:
                tokens = _Lexer(text, _RULES[reading]).run()
            except _Unreadable as exc:
                return self._deny_uninspectable(field, exc.why, reading)
            hit = check(tokens)
            if hit is not None:
                return self._deny(field, role, reading, *hit)
        return None

    def _allow(self, reason: str) -> ReadOnlySQLDecision:
        return ReadOnlySQLDecision(
            allowed=True,
            verdict=ReadOnlySQLVerdict.ALLOW,
            detail=reason,
            matched_field=None,
            matched_pattern=None,
        )

    def _deny(
        self, field: str, role: str, reading: str, verdict: ReadOnlySQLVerdict, token: str
    ) -> ReadOnlySQLDecision:
        shown = token if len(token) <= _TOKEN_SHOWN else token[:_TOKEN_SHOWN] + "..."
        logger.warning(
            "readonly_sql_refused",
            matched_field=field,
            verdict=verdict.value,
            token=shown,
            dialect=reading,
        )
        return ReadOnlySQLDecision(
            allowed=False,
            verdict=verdict,
            detail=(
                f"field {field!r} read as a {role}: {verdict.value} at token {shown!r} "
                f"(read as {reading} SQL)"
            ),
            matched_field=field,
            matched_pattern=shown,
        )

    def _deny_uninspectable(self, field: str, why: str, reading: str | None) -> ReadOnlySQLDecision:
        logger.warning(
            "readonly_sql_uninspectable", matched_field=field, reason=why, dialect=reading
        )
        where = f" when read as {reading} SQL" if reading else ""
        return ReadOnlySQLDecision(
            allowed=False,
            verdict=ReadOnlySQLVerdict.DENY_UNINSPECTABLE,
            detail=(
                f"field {field!r} {why}{where}, so the guard cannot inspect all of it; "
                "refused rather than skipped"
            ),
            matched_field=field,
            matched_pattern="uninspectable",
        )


__all__ = [
    "DEFAULT_FRAGMENT_FIELDS",
    "DEFAULT_STATEMENT_FIELDS",
    "DIALECTS",
    "ReadOnlySQLDecision",
    "ReadOnlySQLGuard",
    "ReadOnlySQLVerdict",
]
