# Dispatch arguments

A tool that calls a function by a name it was given hands the model a choice of code.
`ToolArgSinkGuard(dispatch_args=...)` reads that name before the tool runs. It is part of the
guard described in [Shell and installer arguments](shell-and-installer-arguments.md): `@Airlock`
runs it at step 2.75, and it is off until a policy sets it.

| Field | Default | What it does |
|---|---|---|
| `dispatch_args` | `{}` | maps each argument that names a function to the names it may hold. The argument must hold one name its allowlist admits or, with an empty allowlist, one that `DEFAULT_DISPATCH_DENY` does not match |

## The CVE

[CVE-2026-119050](https://nvd.nist.gov/vuln/detail/CVE-2026-119050) (CVSS 3.1 8.1, CVSS 4.0
9.2, CWE-470): Agno through 3.1.11 ships `PandasTools` with two such tools.
`create_pandas_dataframe` passes the model's `create_using_function` to
`getattr(pandas, ...)`, and `run_dataframe_operation` passes `operation` to
`getattr(dataframe, ...)`. A prompt-injected agent can have the first call
`pandas.read_pickle` on a path it chooses, which unpickles the file and so runs code, or another
reader to read local files. There was no fixed release when this page was written
([agno-agi/agno#8699](https://github.com/agno-agi/agno/issues/8699)).

The dangerous value is a plain identifier, `read_pickle`. It holds no shell syntax and no
`eval(` text, so neither the shell screen nor the eval guards see it. `dispatch_args` answers
the shape, not Agno: any tool that turns an argument into a function call, whether by
`getattr`, a lookup in a table the caller indexes, or `importlib`.

## Allowlist

List the names each tool supports:

```python
import pandas as pd

from agent_airlock import Airlock, SecurityPolicy, ToolArgSinkGuard

guard = ToolArgSinkGuard(
    dispatch_args={
        "create_using_function": ("read_csv",),
        "operation": ("head", "tail", "describe", "info"),
    }
)
frames: dict[str, pd.DataFrame] = {}


@Airlock(policy=SecurityPolicy(tool_arg_sink_guard=guard))
def create_pandas_dataframe(
    dataframe_name: str, create_using_function: str, function_parameters: dict
) -> str:
    frames[dataframe_name] = getattr(pd, create_using_function)(**function_parameters)
    return dataframe_name


@Airlock(policy=SecurityPolicy(tool_arg_sink_guard=guard))
def run_dataframe_operation(
    dataframe_name: str, operation: str, operation_parameters: dict
) -> str:
    return str(getattr(frames[dataframe_name], operation)(**operation_parameters))
```

`create_using_function="read_pickle"` and `operation="to_pickle"` are refused before `getattr`
runs; `read_csv` and `describe` run. A tool's call is read only for the arguments it takes, so
one guard can serve both tools.

An allowed reader still reads whatever path it is handed. Pair the guard with a
`FilesystemPolicy`: step 3 reads paths nested in arguments too, so an absolute or traversing
path such as `/etc/passwd` or `../../etc/passwd` under `function_parameters` is refused unless
it lies inside your roots.

## Default denylist

With an empty allowlist, `dispatch_args={"operation": ()}`, any identifier passes unless
`DEFAULT_DISPATCH_DENY` (in `agent_airlock.tool_arg_sink_guard`) matches it. The patterns are
shell-style and matched against the name case-folded:

`_*` (private and dunder names), `*pickle*`, `read_*`, `to_*`, `load`, `loads`, `load_*`,
`eval`, `exec`, `compile`, `system`, `popen`, `spawn*`, `open`, `import_module`,
`__import__`, `getattr`, `setattr`, `delattr`, `globals`, `locals`, `vars`, `breakpoint`.

`read_*` and `to_*` cover pandas' file readers and writers, and also harmless converters such
as `to_dict`. A tool that needs one lists it in an allowlist, which replaces the denylist for
that argument.

## What is read

- **The argument by its parameter name**, or its `**kwargs` key. A positional argument is
  read under its parameter's name. An argument the call does not pass is not read, so a
  parameter's default never is.
- **One name, as a `str`.** `None`, a number, bytes or a list is refused. The name must be
  one ASCII identifier (letters, digits and underscores, not starting with a digit), matched
  whole, so `head\n`, `head()` and `x; id` are refused.
- **A dotted path** (`pandas.read_csv`) passes only when the argument's allowlist names it
  exactly.
- **An allowlist matches exactly and by case**: `Head` is not `head`. The denylist is
  case-folded: `READ_PICKLE` is refused.
- **A `str` subclass** is read as the characters it holds, whatever its `__eq__` or
  `__hash__` claims.

## The refusal

In `deny` mode a refused name is the usual blocked response: `block_reason`
`"tool_arg_sink"`, and `metadata` with the `argument`, the `verdict` `deny_dispatch_name`, and
the `token`: the refused name, cut at 64 characters, or for a value that is no name the
character that shows it. The `error` names the argument and the name, never another value.
With an allowlist, `fix_hints` list the names it accepts and say how to add a name that is
meant; without one, they say so for the denylist. The pattern that matched is never quoted. In
`warn` mode the finding is logged as `airlock_tool_arg_sink_warn_only` and the call runs.

## Preset

`policy_presets.reflection_sink_defaults()` turns the check on in `warn` mode, so adopting it
cannot break a host on day one:

```python
from agent_airlock import Airlock
from agent_airlock.policy_presets import reflection_sink_defaults

preset = reflection_sink_defaults(dispatch_args={"operation": ("head", "describe")})


@Airlock(policy=preset["policy"])
def run_dataframe_operation(dataframe_name: str, operation: str) -> str:
    return f"ran {operation} on {dataframe_name}"
```

Read the log, then pass `mode="deny"`. To keep a policy of your own, pass `preset["guard"]`
as its `tool_arg_sink_guard`. The preset lists CVE-2026-119050 under `"cves"` and maps to
OWASP MCP05 and CWE-470.

## Honest scope

- **Top-level arguments only.** A name inside another argument, a model's field or a
  mapping's value, is that argument's content and is not read. Give the name its own
  parameter.
- **One name per argument.** A list of names is refused, not read item by item.
- **The denylist is a backstop.** It cannot see what an admitted method does with its
  parameters: `DataFrame.query`, which it admits, evaluates an expression string. An allowlist
  of the operations a tool supports is the control.
- **It reads names, not functions.** A tool that resolves names through a table of its own
  safe functions does not need it.
