# `airlock policy coverage` — every tool named by a rule

A `SecurityPolicy` with an empty `allowed_tools` and `default_deny=False` admits any tool it
does not deny. A tool added to the codebase later is then admitted without anyone deciding
to admit it. `airlock policy coverage` lists every `@Airlock` tool of a module and fails
when one is admitted only that way. Run it in CI the way you would fail on an unclassified
route.

```console
$ airlock policy coverage --module myapp.tools --policy myapp.policy:POLICY
policy coverage of myapp.tools under myapp.policy:POLICY (4 tools)
  denied               delete_all    denied_tools: delete_*
  allowed_by_name      read_file     allowed_tools: read_file
  admitted_by_default  send_email    no rule names it; allowed_tools is empty
  escalated            wire_money    escalate_tools: wire_*

1 tool is admitted only because allowed_tools is empty: send_email
Name each in allowed_tools, deny it, or escalate it.
$ echo $?
1
```

## Options

| Option | |
| --- | --- |
| `--module` | The module or package whose tools to check. A package is walked, every module under it imported |
| `--policy` | The `SecurityPolicy` to check them against, as `MODULE:NAME` (`NAME` may be dotted) |
| `--format` | `text` (the default) or `json`: `{"module", "policy", "tools": [{"tool", "class", "rule"}], "uncovered"}` |

The current directory goes on the import path first, so a project's own package imports
without being installed.

## The classes

Each tool gets exactly one class, in the order `SecurityPolicy.check` decides:

| Class | When |
| --- | --- |
| `denied` | a `denied_tools` pattern matches it; or `allowed_tools` is not empty and nothing on it matches; or `default_deny=True` with an empty `allowed_tools` |
| `escalated` | an `escalate_tools` pattern matches a tool the lists above admit |
| `allowed_by_name` | its exact name is on `allowed_tools` |
| `allowed_by_pattern` | an `allowed_tools` glob matches it |
| `admitted_by_default` | none of the above, because `allowed_tools` is empty |

The classes are read from the policy's fields, so nothing is called on it and no
rate-limit token is spent. Roles, time windows and rate limits still apply when a call is
made. Coverage only says whether a rule names the tool.

## Exit codes

| Code | |
| --- | --- |
| 0 | every tool is denied, escalated, or allowed by name or pattern |
| 1 | at least one tool is `admitted_by_default` |
| 2 | the module or the policy could not be loaded, the policy is a resolver (it cannot be classified without a call's context), or the module has no `@Airlock` tools |

## Which tools are found

A tool is a module-level attribute that is an `@Airlock` wrapper or has one beneath it,
`@requires` above `@Airlock` included. It is keyed by the name its calls are checked by,
and a tool imported into several modules counts once. Methods and tools kept only in a
registry are not found.

## In a test

```python
import myapp.tools
from agent_airlock.testing import assert_policy_covers
from myapp.policy import POLICY


def test_every_tool_is_named_by_the_policy() -> None:
    assert_policy_covers(myapp.tools, POLICY)
```

`assert_policy_covers` takes a module or package, or a list of tools and tool names. It
raises `AssertionError` naming the tools admitted only by default, and returns the report
otherwise.
