# Read-only SQL guard for tool arguments (CVE-2026-125322 + CVE-2026-61789, v0.10.34+)

`agent_airlock.mcp_spec.readonly_sql_guard.ReadOnlySQLGuard` checks the SQL a model puts
in a database tool's arguments before the tool runs it. Put it in front of any tool that
promises read-only access.

## Why

Two MCP database servers ran model-written SQL while promising the model could only read:

| CVE | Server | What got through |
|---|---|---|
| [CVE-2026-125322](https://nvd.nist.gov/vuln/detail/CVE-2026-125322) (CWE-89) | pgEdge Postgres MCP Server below 1.1.0 | The `where` parameter of `count_rows` took a subquery on another table, so the row count leaked that table's contents one predicate at a time |
| [CVE-2026-61789](https://nvd.nist.gov/vuln/detail/CVE-2026-61789) (CWE-436) | bytebase DBHub below 0.22.6 | The read-only check treated every `--` as a comment. MySQL and MariaDB need whitespace after it, so `--1` is two minus signs to them, and a second statement after it ran |

The same two shapes apply to any server that splices a model's text into SQL or trusts a
"read-only" check that tokenises differently from its database.

## What it refuses

The guard reads two kinds of argument, chosen by the argument's name.

**Statement fields** hold one whole statement (`sql`, `query`, `statement` by default).

| Verdict | When |
|---|---|
| `DENY_STACKED_STATEMENT` | A `;` followed by anything but whitespace or comments, or a backslash outside a literal (a client command such as psql's `\!`) |
| `DENY_WRITE_STATEMENT` | The statement does not start with `SELECT`, `WITH`, `VALUES`, `SHOW`, `DESCRIBE` / `DESC` or `EXPLAIN`; or a data-changing keyword appears anywhere outside a literal (`INSERT`, `UPDATE`, `DELETE`, `MERGE`, `UPSERT`, `REPLACE`, `TRUNCATE`, `DROP`, `ALTER`, `CREATE`, `GRANT`, `REVOKE`, `COPY`, `CALL`, `EXEC`, `EXECUTE`, `DO`, `VACUUM`, `ATTACH`, a `PRAGMA` that sets a value, `SELECT ... INTO`) |
| `DENY_DANGEROUS_FUNCTION` | A call that reads server files, runs commands, reaches another server or runs SQL held in a string: `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`, `lo_import`, `lo_export`, `dblink`, `dblink_exec`, `query_to_xml` (and its two schema variants), `ts_stat`, `load_file`, `sys_exec`, `sys_eval`, `xp_cmdshell`, `load_extension`, `readfile`, `writefile`, and `INTO OUTFILE` / `INTO DUMPFILE` |
| `DENY_UNINSPECTABLE` | The guard could not read the text to its end (see below) |

A write keyword anywhere includes a PostgreSQL data-modifying CTE
(`WITH d AS (DELETE ... RETURNING *) SELECT ...`) and `EXPLAIN ANALYZE DELETE`, which runs
the `DELETE`. `REPLACE(`, `INSERT(` and `TRUNCATE(` followed by a parenthesis are the
string and number functions of the same name and pass.

**Fragment fields** hold a piece the server splices into a fixed query (`where`,
`filter`, `condition`, `having`, `order_by` by default).

| Verdict | When |
|---|---|
| `DENY_SUBQUERY_IN_FRAGMENT` | `SELECT`, the `TABLE name` shorthand (PostgreSQL, MySQL 8), or a PostgreSQL function that returns another table's rows by name (`table_to_xml`, `schema_to_xml`, `database_to_xml` and their variants) |
| `DENY_COMMENT_IN_FRAGMENT` | Any comment, a MySQL executable comment (`/*! ... */`) included |
| `DENY_STACKED_STATEMENT` | `;`, `UNION`, a backslash, or parentheses that do not balance (`1=1) OR (1=1` closes the server's own clause) |
| `DENY_WRITE_STATEMENT`, `DENY_DANGEROUS_FUNCTION` | Everything a statement field refuses |

String literals, quoted names and comments are told apart from code first, so
`name = 'a;b -- c'` passes.

## Dialects

Pass the database the tool talks to:

```python
from agent_airlock import ReadOnlySQLGuard

guard = ReadOnlySQLGuard(dialect="postgres")  # "postgres" | "mysql" | "sqlite" | "generic"
```

Each dialect is read the way that database reads it:

- **mysql**: `#` comments, `--` a comment only before whitespace or the end of the text,
  backslash escapes in `'...'` and `"..."` (both are strings), backtick names, and
  executable comments (`/*!50000 ... */`, MariaDB's `/*M! ... */`) whose body runs, so the
  guard reads it as code.
- **postgres**: nested `/* /* */ */` comments, `$tag$...$tag$` dollar quotes, `E'...'`
  strings with backslash escapes, and no backslash escapes in plain `'...'`.
- **sqlite**: `[name]` and backtick names, no backslash escapes.

`generic`, the default, reads the value as MySQL, PostgreSQL and SQLite in turn and
refuses it when any of the three does. A text can hide a statement from one database's
rules and not from another's: `SELECT 1 # 2; DROP TABLE t` is one statement to MySQL and
two to PostgreSQL. So `generic` refuses a little more than a named dialect does
(`SELECT $$a;b$$` is fine on PostgreSQL and refused under `generic`). Name the dialect
when you know it.

## Naming a tool's fields

The guard reads only the fields you name. A string is read as a fragment when any key on
its path is a fragment field, otherwise as a statement when one is a statement field.
Nested values, lists and bytes are walked:

```python
guard = ReadOnlySQLGuard(
    statement_fields=frozenset({"sql"}),
    fragment_fields=frozenset({"where", "order_by"}),
    dialect="postgres",
)

decision = guard.evaluate({"table": "orders", "where": "1=1 AND (SELECT count(*) FROM users) > 0"})
# decision.allowed is False
# decision.verdict is ReadOnlySQLVerdict.DENY_SUBQUERY_IN_FRAGMENT
# decision.matched_field == "where", decision.matched_pattern == "SELECT"
```

`query` is in the default statement fields, and many search tools use an argument called
`query` for plain text. Put the guard on database tools only, or pass your own field sets.
A name may not be in both sets.

The decision's `detail` names the field, the verdict, the token that decided it and the
dialect reading that saw it. It never repeats the value.

## Refused as uninspectable

`DENY_UNINSPECTABLE` means the guard could not read all of the text, so it refuses rather
than skips:

- an unterminated literal, quoted name, block comment, dollar quote or executable comment;
- a NUL character, a bare carriage return inside a `--` line comment, or a control
  character after MySQL's `--` (databases end or read these differently);
- a comment nested inside a MySQL executable comment;
- PostgreSQL's `U&"..."` names, which can spell a function with escapes;
- arguments that are not a mapping, bytes that are not UTF-8, nesting deeper than 32
  levels, a container that contains itself, or an object in a read field that is not
  text, a number, a bool or `None`.

## Companion preset

```python
from agent_airlock.policy_presets import readonly_sql_tool_args_2026_125322_defaults

config = readonly_sql_tool_args_2026_125322_defaults(dialect="mysql")
# config["preset_id"] == "readonly_sql_tool_args_2026_125322"
# config["severity"] == "medium"
# config["default_action"] == "deny"
# config["cves"] == ("CVE-2026-125322", "CVE-2026-61789")
```

The preset checks its arguments by building a guard, so a wrong dialect or field set
raises before the dict comes back.

## Honest scope

- The guard tokenises; it does not parse. It refuses on a keyword's presence, so a column
  named like a write keyword (`copy`, `call`) has to be quoted, and
  `SELECT ... FOR UPDATE` is refused (PostgreSQL refuses it in a read-only transaction
  too).
- SQL only. DQL, Cypher, GraphQL, MongoDB filters and Elasticsearch DSL are out of scope.
- Only the fields you name are read. A server that builds SQL from other arguments, or
  from mapping keys, is not covered.
- SQL Server and Oracle quoting are not modelled (`[name]` is read only as SQLite reads
  it). MySQL in `ANSI_QUOTES` or `NO_BACKSLASH_ESCAPES` mode, and PostgreSQL with
  `standard_conforming_strings` off, read strings differently from the named dialects:
  use `generic`, whose PostgreSQL and MySQL readings cover them.
- Functions that write or leak outside the list above are not refused: user-defined
  functions, `nextval`, `set_config`, `pg_relation_size`. Run the database role read-only
  as well. The guard narrows what reaches the database; it does not replace the role.
