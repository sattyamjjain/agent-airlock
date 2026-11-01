# PII & Secret Masking

Agent-Airlock detects and masks sensitive data in tool outputs.

## Why Sanitize Outputs?

LLMs can leak sensitive data through:
- Conversation history
- Training data extraction
- Prompt injection attacks
- Logging and monitoring

Sanitizing outputs prevents accidental exposure.

## Quick Start

```python
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(
    sanitize_output=True,
    mask_pii=True,
    mask_secrets=True,
)

@Airlock(config=config)
def get_customer(customer_id: int) -> dict:
    return {
        "name": "John Doe",
        "email": "john@example.com",
        "ssn": "123-45-6789",
    }

result = get_customer(customer_id=123)
# Returns (default masking strategies):
# {
#     "name": "John Doe",
#     "email": "j***@example.com",
#     "ssn": "[REDACTED]"
# }
```

## What Gets Masked

- **A string result** is masked and, past `max_output_chars`, truncated.
- **A dict, list, tuple or set** is masked value by value and keeps its type.
  Dictionary keys are masked too; when two keys mask to the same string, the later ones
  get a ` (2)`, ` (3)` suffix, so no value is dropped. It is never truncated, because
  truncating its serialized form would hand back a different type.
- **Any other object** (a Pydantic model, a dataclass) is returned as it is, since
  rebuilding it with masked fields could break its own invariants. What was detected in
  it is logged as `output_sensitive_data_unmasked` and returned as a warning that says it
  was *not* masked. The same goes for a value inside a dict, list, tuple or set that the
  walk cannot rebuild (bytes, a model, a dataclass, a deque...): it is left as it is, and
  what was found in it is reported as not masked. Return a dict or a string to have it
  masked. Numbers no detector can match (under nine digits, or a float with a fractional
  part) are not read, so a result full of numbers stays fast; `bytes` are decoded, and the
  first 100,000 characters of a value are read.
- **A value whose text cannot be read** (its `str()` raises, as an ORM row bound to a closed
  session does) is returned as it is, unchecked, with a warning that says so.
- **A result nested too deeply to rebuild** is refused as `output_unreadable` rather than
  returned unmasked.

The audit record's `result_preview` is masked like its `args_preview`, whatever
`sanitize_output` is set to.

Until 0.10.11 only string results were masked. Every other result was reported as
masked, in the log, the warnings and the audit record, and returned raw. Until 0.10.28
dictionary keys were left alone, a value the walk could not rebuild was skipped without a
warning, and `result_preview` held the raw text when output masking was off or the result
was returned unmasked; an unreadable value, or a result too deep to walk, escaped the call
as an exception after the tool had run.

## Sensitive Data Types

"Masked As" is what `@Airlock` returns, using each type's default strategy.

The detectors for ASCII-shaped values (email, phone, card, IP, API and AWS keys, JWT, and
the India types) read word boundaries the ASCII way, so a value written right next to
Devanagari, Arabic, Hebrew, Thai or Bengali text (`ईमेलbob@example.com`) is masked like a
space-separated one; until 0.10.29 it was not. A no-break or other Unicode space between
the groups of a number still counts as a separator. A chained address
(`bob-@list.dan@ex.org`) is masked whole.

### PII (Personally Identifiable Information)

Masked when `mask_pii=True` (the default).

| Type | Pattern Example | Masked As |
|------|-----------------|-----------|
| Email | `john@example.com` | `j***@example.com` |
| Phone | `555-123-4567` | `555***567` |
| SSN | `123-45-6789` | `[REDACTED]` |
| Credit Card | `4111111111111111` | `**** **** **** 1111` |
| IP Address | `192.168.1.100` | `192***100` |

A card number may be split by one consistent `-` or space (`4111-1111-1111-1111`,
`4111 1111 1111 1111`). `pii_locales=["in"]` adds Aadhaar, PAN, UPI ID, IFSC, Devanagari names and Indian
mobile numbers.

### Secrets

Masked when `mask_secrets=True` (the default).

| Type | Pattern Example | Masked As |
|------|-----------------|-----------|
| API Key | `sk-abcdefghijklmnopqrstuvwxyz` | `sk-abcd...wxyz` |
| AWS Key | `AKIAIOSFODNN7EXAMPLE` | `AKIAIOS...MPLE` |
| Password | `password=secret123` | `password=[REDACTED]` |
| JWT | `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abc` | `eyJhbGciOi...[JWT]` |
| Connection String | `postgres://user:pass@host` | `[REDACTED]` |
| Private Key | `-----BEGIN PRIVATE KEY-----` | `[REDACTED]` |
| Environment dump | three or more `API_KEY=...` lines | each value `[REDACTED]` |

Detection is by known shape. An API key is an OpenAI key (legacy `sk-...`, or
`sk-proj-`/`sk-svcacct-`/`sk-admin-`), an Anthropic `sk-ant-...` key, a Google `AIza` key, a
GitHub `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_` token or a Slack `xox` token; a
shorter or unrecognised key passes through. Since 0.10.29 the GitHub and Slack prefixes match
in any case with a body of at least 20 (GitHub) or 10 (Slack) token characters, and an AWS
`AKIA` id matches in lowercase too (its 16-character body still fixed). An environment dump is
three or more `KEY=VALUE` lines (`export` allowed) or JSON `"key": "value"` pairs whose key ends
in `_KEY`, `_TOKEN`, `_SECRET` or `_PAT` or contains `PASSWORD`, in any case: each such value
is masked whatever it looks like. A password is
the value (8+ characters) after `password`, `passwd`, `pwd`, `secret` or `token` and `=` or
`:`. The private-key rule masks the whole PEM block, or the header and the base64 lines after it
when the `END` line is missing. There is no separate
bearer-token type: the JWT in `Bearer eyJ...` is masked by the JWT rule.

## Masking Strategies

`@Airlock` masks each type with its default strategy, the one the tables above show:
`FULL` for SSN, password, private key and connection string, `TYPE_ONLY` for IFSC, and
`PARTIAL` for the rest. `AirlockConfig` has no strategy setting. To choose a strategy, run
the standalone sanitizer with a `mask_config` mapping:

```python
from agent_airlock import MaskingStrategy, SensitiveDataType, sanitize_output

def mask_email(strategy: MaskingStrategy) -> str:
    config = {SensitiveDataType.EMAIL: strategy}
    return sanitize_output("john@example.com", mask_config=config).content

# Full redaction
mask_email(MaskingStrategy.FULL)       # [REDACTED]

# Partial masking (the default for email)
mask_email(MaskingStrategy.PARTIAL)    # j***@example.com

# Type only
mask_email(MaskingStrategy.TYPE_ONLY)  # [EMAIL]

# Hash (for correlation)
mask_email(MaskingStrategy.HASH)       # [HMAC:3f9a8c2e1b7d4065]
```

The mapping replaces the defaults: a type you leave out of it is masked `FULL`.

`HASH` is an HMAC-SHA256 tag of 16 hex characters under a key (0.10.29). Until then it was an
unkeyed sha256 cut to 8 characters, which anyone could recompute for every phone number or PAN
and so reverse. Pass the request's key as `hash_key=` so one value gets one tag for the whole
request (joins keep working); without one, each call makes its own key, so tags from two calls
cannot be joined. `sanitize_structured` uses one key for a whole structure. Pass
`reverse_map={}` to have it filled with each tag and the value it stands for: that map is for
the host, never for the model.

## Hidden HTML

`AirlockConfig(strip_hidden_html=True)` (0.10.29) removes the parts of an HTML result a person
cannot see before it is masked: elements an inline style hides (`display:none`,
`visibility:hidden`, `opacity:0`, `font-size:0`, a `text-indent` of -100 or more units), the
`hidden` attribute, and comments. Text with the `sr-only`, `visually-hidden` or
`visuallyhidden` class is kept, since a screen reader reads it. Only inline styles are read: a
stylesheet rule that hides an element is not. `sanitize_output(..., strip_hidden_html=True)`
does the same for one string.

## Arguments, Not Only Results

Masking covers what a tool returns. To screen what the model passes in, see
[Secrets in tool arguments](argument-secrets.md).

## Selective Detection

`AirlockConfig` switches detection by group: `mask_pii`, `mask_secrets` and
`pii_locales`. To enable or disable specific data types, use the standalone functions:

```python
from agent_airlock import (
    SensitiveDataType, WorkspacePIIConfig, mask_sensitive_data, sanitize_with_workspace_config,
)

text = "john@example.com, SSN 123-45-6789, card 4111111111111111"

# Only mask specific types
masked, detections = mask_sensitive_data(
    text,
    types=[SensitiveDataType.SSN, SensitiveDataType.CREDIT_CARD],
)
# john@example.com, SSN [REDACTED], card **** **** **** 1111

# Mask all except specific types
config = WorkspacePIIConfig(
    workspace_id="ops",
    disabled_types=[SensitiveDataType.IP_ADDRESS],
)
sanitize_with_workspace_config("host 10.0.0.12, owner ops@example.com", config).content
# host 10.0.0.12, owner o***@example.com
```

## Workspace-Specific Rules

For multi-tenant applications. `sanitize_with_workspace_config` returns a
`SanitizationResult`; the masked text is its `content`.

```python
from agent_airlock import MaskingStrategy, WorkspacePIIConfig, sanitize_with_workspace_config

# Enterprise workspace: Don't mask internal emails
enterprise_config = WorkspacePIIConfig(
    workspace_id="acme-corp",
    allow_email_domains=["acme.com", "acme.internal"],
)

# Sales workspace: Mask competitor emails
sales_config = WorkspacePIIConfig(
    workspace_id="sales",
    mask_email_domains=["competitor1.com", "competitor2.com"],
)

# HR workspace: Custom patterns
hr_config = WorkspacePIIConfig(
    workspace_id="hr",
    custom_patterns={
        "employee_id": r"EMP-\d{6}",
        "salary": r"\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?",
    },
    custom_strategies={
        "salary": MaskingStrategy.FULL,
    },
)

# Apply workspace config
content = "Contact: alice@acme.com or bob@competitor1.com"
result = sanitize_with_workspace_config(content, sales_config)
# result.content == "Contact: alice@acme.com or b***@competitor1.com"
```

A custom pattern is masked as `[REDACTED]`, or as `[EMPLOYEE_ID]` (its name in capitals)
when its strategy is `TYPE_ONLY`.

## Phone Number Filtering

Allow specific phone prefixes:

```python
from agent_airlock import WorkspacePIIConfig, sanitize_with_workspace_config

config = WorkspacePIIConfig(
    workspace_id="support",
    allow_phone_prefixes=["+1800", "1800", "+1888"],  # Toll-free
)

content = "Call us: 1-800-555-1234 or 555-123-4567"
result = sanitize_with_workspace_config(content, config)
# result.content == "Call us: 1-800-555-1234 or 555***567"
```

## Output Truncation

Limit the size of string results to prevent token bloat (structured results are
masked but not truncated; see above):

```python
from agent_airlock import AirlockConfig

config = AirlockConfig(
    sanitize_output=True,
    max_output_chars=10000,  # Character limit (default 20000; 0 = no limit)
)
```

`max_output_chars` is the only limit applied. `AirlockConfig` also has a
`max_output_tokens` field, deprecated because nothing has ever truncated on it; setting it
warns.

When truncated, a notice is appended, inside the limit:
```
[OUTPUT TRUNCATED: Showing 10,000 of 15,000 characters]
```

## Streaming Support

`@Airlock` masks each item a generator tool yields as it would a returned value, and runs
each step of the generator under the call's network airgap and context. Until 0.10.20 it
did neither. A coroutine or a lazy iterator a tool returns (`map`, `filter`, an iterator or
async iterator class that is not a context manager) is guarded the same way since 0.10.28,
returned on its own or inside a returned dict, list, tuple, set, pydantic model or
dataclass: each step runs under
the call's airgap and context, and each value is masked. It comes back as a coroutine,
generator or async generator, so an iterator's other attributes are gone: a database
cursor loses `fetchall()` and a `csv.reader` its `line_num` (return `cursor.fetchall()` to
hand back a list). An Airlock
refusal raised while one of these runs (a `NetworkBlockedError`, say) is written to the
audit log as a block before the consumer gets the exception; the call's own record, written
when it returned, counts none of the values. What `StreamingAirlock` adds is a cap on the
whole stream: `max_output_chars` counted across chunks, ending the stream once it is
reached. Wrap the generator for that:

```python
from agent_airlock import StreamingAirlock, AirlockConfig

config = AirlockConfig(
    sanitize_output=True,
    mask_pii=True,
)

streaming = StreamingAirlock(config)

def generate_report():
    yield "Customer: john@example.com"
    yield "Phone: 555-123-4567"

for chunk in streaming.wrap_generator(generate_report()):
    print(chunk)
# Customer: j***@example.com
# Phone: 555***567
```

## Sanitization Results

Get details about what was masked:

```python
from agent_airlock import sanitize_output

content = "Email: john@example.com, SSN: 123-45-6789"
result = sanitize_output(content, mask_pii=True)

print(result.content)
# "Email: j***@example.com, SSN: [REDACTED]"

print(result.detection_count)
# 2

print(result.detections)
# [
#     {"type": "email", "value": "john@example.com", "start": 7, "end": 23,
#      "full_match": "john@example.com", "masked_as": "j***@example.com"},
#     {"type": "ssn", "value": "123-45-6789", "start": 30, "end": 41,
#      "full_match": "123-45-6789", "masked_as": "[REDACTED]"}
# ]
```

Each detection holds the original `value`, so treat the list as sensitive.
