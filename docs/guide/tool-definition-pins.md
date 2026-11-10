# Tool-definition pins

`ToolDefinitionPinGuard` pins a tool's definition when an operator approves it and refuses
the tool once that definition moves. There is no trust on first use: an unseen tool is
refused, not learned.

Since 0.10.29 a pin also covers `annotations` and `outputSchema`, a whole `tools/list`
result can be checked at once, a FastMCP server can check its own tools, and a client can
check every listing it receives. Until then the pin left both fields out and nothing wired
the guard to FastMCP or to a listing.

## What a pin covers

| Pin version | Fields |
| --- | --- |
| 1 (0.8.84 to 0.10.28) | `name`, `description`, `inputSchema` |
| 2 (the default since 0.10.29) | the above, plus `annotations` and `outputSchema` |

A server could flip `readOnlyHint` or change the result contract under a pinned name, and
version 1 read neither. In version 2 the two new fields are normalised: a `None` value is
dropped at any depth, and an absent field, `null` and `{}` read the same. So a server that
serialises an absent field differently is not drifting. Key order never matters. `title`,
`_meta` and other server bookkeeping are not pinned.

```python
from agent_airlock.mcp_spec.tool_definition_pin_guard import ToolDefinitionPinGuard

guard = ToolDefinitionPinGuard()
guard.approve(reviewed_definition)  # a version 2 pin

decision = guard.check(definition_from_the_server)
decision.verdict  # e.g. deny_annotations_drift, with changed_fields=("annotations",)
```

Single-field drift has its own verdict: `deny_description_drift`, `deny_schema_drift`,
`deny_annotations_drift` or `deny_output_schema_drift`. Anything else is
`deny_multi_field_drift`.

## Storing pins

`guard.pins` is `{tool name: (digest, pin version)}`. Store it, and load it back with
`guard.pin(name, digest, pin_version=...)`.

A digest made before 0.10.29 is a version 1 digest. `canonical_digest(definition,
pin_version=1)` reproduces it, and `pin(name, digest, pin_version=1)` loads it so it
verifies as before, ignoring annotations and the output schema. A pin loaded from a digest
has no stored definition, so drift from it cannot say which field moved:
`changed_fields` is empty and the detail says `unknown`.

## Whole listings

`guard.check_listing(tools)` judges a `tools/list` result: a mapping with `tools`, an
object with `.tools` (the MCP SDK's `ListToolsResult`), or the list itself, each tool a
mapping or a pydantic model of one.

- A tool that was never approved is refused, as is one that drifted, one listed twice and
  one that cannot be read, a tool with no name included.
- A pinned tool the listing leaves out is reported in `missing` and refuses nothing: the
  ceiling only shrank.
- `admitted` names the tools a client may expose. `validate_listing` raises
  `ToolListingDriftError` instead.

## On the client

Call `admit_tools_list(guard, result)` on every listing: the first one, and every one
after, whether or not the server sent `notifications/tools/list_changed`. A new listing is
a ceiling to check against the pins, not a refresh to adopt.

```python
from agent_airlock.mcp_spec.tool_definition_pin_guard import list_tools_pinned

tools = await list_tools_pinned(session, guard)  # raises ToolListingDriftError on drift
tools = await list_tools_pinned(session, guard, on_drift="filter")  # keeps the rest
```

`list_tools_pinned` calls `session.list_tools()` (an MCP `ClientSession` or a FastMCP
`Client`) and returns the result in its own shape. With `on_drift="filter"`, the tools the
pins do not admit are dropped, and a listing that cannot be read raises anyway. With the
guard's `enforce` off, the listing comes back unchanged.

A paginated server lists one page per call, and `list_tools_pinned` checks each page on its
own. A tool listed on two pages reads as clean twice, and `missing` counts the tools on the
other pages. For a server that paginates, use `list_all_tools_pinned`:

```python
from agent_airlock.mcp_spec.tool_definition_pin_guard import list_all_tools_pinned

tools = await list_all_tools_pinned(session, guard)  # reads every page, judges them once
tools = await list_all_tools_pinned(session, guard, on_drift="filter", max_pages=20)
```

It follows each cursor, collects the tools and runs `admit_tools_list` once on all of them,
so a tool on two pages is a duplicate, and `missing` covers the whole listing. The result
has the first page's shape with no cursor left on it. With `on_drift="filter"`, every copy
of a duplicate is dropped.

These raise `ToolListingDriftError` in every mode, with `enforce` off too, because there is
no whole listing to judge: a cursor seen twice, a cursor that is not a string, a page that
is not a listing, more than `max_pages` pages (100 by default, and the page past it is never
requested), and a session that cannot follow a cursor. An empty cursor ends the listing;
nothing past it is read, so nothing past it is admitted.

The SDKs differ, and it handles each of them:

| Session | How it pages | Comes back as |
| --- | --- | --- |
| `ClientSession`, mcp 2.x | `params=`, result has `next_cursor` | `ListToolsResult` |
| `ClientSession`, mcp 1.x | `params=`, result has `nextCursor` | `ListToolsResult` |
| `mcp.Client`, mcp 2.x | `cursor=`, result has `next_cursor` | `ListToolsResult` |
| FastMCP `Client` 3 and 4 | `list_tools_mcp(cursor=...)` | a list, as `list_tools()` gives |

FastMCP's own `list_tools()` flattens the pages, so it is not used here: versions 3 and 4 stop
at a repeated cursor with only a warning, and version 2 returns page 1 and drops the cursor.
Version 2's page call takes no cursor either, so on a server that pages it raises. Pass
`client.session` instead.

## On a FastMCP server

```python
from agent_airlock.mcp import create_secure_mcp_server, tool_definitions

guard = ToolDefinitionPinGuard()
mcp, secure = create_secure_mcp_server("Reports", pin_guard=guard)

@secure
def send_report(recipient: str) -> str:
    ...

# At review time: approve what the server serves, and store guard.pins.
for definition in await tool_definitions(mcp):
    guard.approve(definition)
```

With `pin_guard` set, the server:

- refuses to start while one of its tools is unpinned or drifted. A client connecting gets
  the refusal (`tools/list refused: not admitted by the pins: ...`);
- lists only the tools the pins admit, on every `tools/list`, so a tool added or replaced
  after startup is caught the next time a client lists;
- refuses a `tools/call` of any tool the pins do not admit, with an `AIRLOCK_BLOCK` error
  result, so a hidden tool cannot be called by name.

`tool_definitions(server)` gives one definition per tool name: the version a call of that
name resolves to. `check_server_tools(server, guard)` runs the startup check on its own.
With the guard's `enforce` off, the server only logs what it would refuse.
