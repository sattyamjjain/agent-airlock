# Secrets in Tool Arguments

A tool call's arguments are model output, so they can carry what output masking exists to
catch: a key the model read earlier, a password a user typed, a whole environment dump. A
memory tool then stores it where every later run reads it back. `ArgumentSecretGuard`
(0.10.29) screens arguments before the tool runs.

```python
from agent_airlock import Airlock, SecurityPolicy
from agent_airlock.argument_secret_guard import ArgumentSecretGuard

policy = SecurityPolicy(argument_secret_guard=ArgumentSecretGuard())


@Airlock(policy=policy)
def add_memories(fact: str) -> str:
    ...


add_memories(fact="export DB_PASSWORD=hunter2-prod")
# {"success": False, "block_reason": "argument_secret",
#  "metadata": {"function": "add_memories", "argument": "fact", "kinds": ["password"]}, ...}
```

The guard runs at step 2.76, after the shell-syntax screen. It reads every string in the
call's arguments, positional and nested ones included (a mapping's keys too), and an integer
as its digits, through the sanitizer's detectors: every secret detector (API keys, AWS keys,
passwords, private keys, JWTs, connection strings, environment dumps) and email, phone, SSN
and card numbers. IP addresses are left out by default, since hosts are ordinary arguments.

The refusal names the argument (or its nested place, such as `profile.contacts[1]`) and the
kind of data. It never repeats the value.

## Options

| Option | Default | What it does |
| --- | --- | --- |
| `mode` | `"block"` | `"block"` refuses the call. `"mask"` masks a top-level string argument passed by keyword, so the tool gets `b***@example.com`, and refuses anything it cannot mask in place: a nested value, or one passed by position |
| `detectors` | see above | The `SensitiveDataType` members to run |
| `free_text_args` | none | Arguments left unscreened |
| `tools` | every tool | Tool-name patterns (`fnmatch`) the guard applies to |
| `pii_locales` | none | Locale tags for the PII detectors, as `sanitize_output` takes them |

Arguments nested deeper than 32 levels, or containing themselves, are refused: they cannot
be screened.

## The memory-write preset

`argument_secret_defaults()` turns the guard on for tools named like memory writes:
`*memory*`, `remember*`, `save_*` and `add_memories`.

```python
from agent_airlock import Airlock
from agent_airlock.policy_presets import argument_secret_defaults

preset = argument_secret_defaults()


@Airlock(policy=preset["policy"])
def remember_fact(fact: str) -> str:
    ...
```

Pass `tools=("*",)` to screen every tool, and `free_text_args=` for arguments that must stay
free text. To keep a policy of your own, set its `argument_secret_guard` to `preset["guard"]`.

## What it catches, measured

The detectors find secrets by shape, so a secret with no shape passes. On the 25-case
bypass corpus from chenhz01/mem0-7283-conformance (vendored in
`tests/fixtures/third_party/chenhz01_mem0_7283/`), run as the argument of a memory write,
the guard catches 5 of the 23 cases a gate should refuse and lets both clean controls
through, with no false positive. The 18 it misses include a plain passphrase with no
label (`the wifi password is blue`), a credential in another language, a base64 or hex
value, and a key whose body does not have its provider's length. The counts are pinned in
`tests/test_argument_secret_guard_0_10_29.py`.
