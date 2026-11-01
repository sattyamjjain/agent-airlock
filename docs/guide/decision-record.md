# Decision records

Since 0.10.29 `@Airlock` can write each call's decision to a hash-chained log before the
tool runs, and the call's outcome after it, naming the decision by its hash. Until then the
`DecisionLog` was fed only after the fact (`append_audit_record`, or the
`airlock-conformance record` CLI), and the JSON-lines audit record, written once the call
had run, carried no policy, rule or argument digest.

```python
from agent_airlock import Airlock, AirlockConfig
from agent_airlock.conformance.decision_log import DecisionLog

log = DecisionLog("decisions.jsonl")


@Airlock(config=AirlockConfig(decision_log=log))
def pay(to: str, amount: int) -> str:
    ...
```

## What a call writes

| Entry | Written | `stage` | `decision` |
| --- | --- | --- | --- |
| `decision` | after every pre-execution gate, before the tool can run; a refused call writes one too | `policy` | `allow` or `block` |
| `outcome` | after the tool returns, raises, or has its result refused | `execute` | `allow` when it returned, `block` when its result or its network access was refused, `error` when it raised |

A refused call writes its decision and no outcome. Both entries carry the tool, the agent
and the session, and both writes finish before the call goes on: on the async path they run
in a worker thread (`asyncio.to_thread`) and are awaited, never fired and forgotten.

If the decision of an admitted call cannot be written, the call is refused as
`policy_indeterminate` and the tool does not run. If the outcome cannot be written, the
call has already run: the failure is logged as `decision_log_write_failed` and the result
is returned.

## What a decision entry holds

The entry's `details`, all hashed into its `record_hash`:

| Field | What it is |
| --- | --- |
| `policy_digest` | the digest of the policy the call was judged by |
| `args_digest` | sha256 of the bound arguments in canonical JSON (`agent_airlock.approvals.args_digest`, the digest approvals bind to) |
| `unserializable_args` | the arguments the digest could only mark by type: a host object JSON cannot encode, or a value nested too deep to read |
| `stripped_args` | the ghost arguments step 1 stripped, by name |
| `caller_digest` | over what the caller supplied: the tool, `args_digest` and `stripped_args` |
| `authority_digest` | over the state the call was judged by: agent, roles, session, workspace, user, a digest of the call's metadata, and `policy_digest` |
| `decision_context_digest` | over the two above |
| `verdict` | `allow` or `block` |
| `rule_id` | the rule that refused: the policy check's violation type (`tool_denied`, `rate_limited`, `role_required`) or else the block reason (`ghost_arguments`, `path_violation`) |
| `layer` | the call-path step that refused, as `core.py` numbers it: `1:ghost_arguments`, `2:policy`, `2.5:sequence_guard`, `3:filesystem_paths` |

Splitting the context digest means two calls with the same arguments from different agents
share a `caller_digest` and differ in `authority_digest`, and the same agent sending other
arguments keeps its `authority_digest`.

An absent value is named, never left out:

| Value | Where | Means |
| --- | --- | --- |
| `no_policy` | `policy_digest` | the decorator has no policy |
| `not_evaluated` | `policy_digest` | the call was refused before a policy was resolved: by a gate ahead of step 2, or a resolver that returned none |
| `no_refusal` | `rule_id`, `layer` | nothing refused the call |
| `unreadable` | `args_digest` | the arguments nest deeper than 32 levels or contain themselves |

The entry stores digests and argument names, never argument values or results, as the log
always has.

An outcome entry's `details` are `decision_hash` (the decision's `record_hash`), `outcome`
(`returned`, `raised`, `refused_after_run` or `network_blocked`) and, when the call raised,
`error_type`.

## Checking the log

`DecisionLog.verify()` re-reads the file and checks every hash. An edited, reordered or
deleted record fails at its sequence number, and loading a log that does not verify raises
`DecisionLogError`:

```bash
airlock-conformance verify --log decisions.jsonl
```

## Checkpoints and pruning

A log grows with every call. To prune it, record a checkpoint of the chain head and remove
the records it covers:

```python
import os

key = os.environ["AIRLOCK_CHECKPOINT_KEY"].encode()
log = DecisionLog("decisions.jsonl", checkpoint_key=key)
checkpoint = log.checkpoint()  # appended to decisions.jsonl.checkpoints
log.prune(checkpoint)          # the log now starts at checkpoint.seq + 1
```

With a `checkpoint_key`, each checkpoint carries an HMAC-SHA256 of its sequence number,
head hash and time. The pruned log still verifies, from the checkpoint whose head is the
record just before its first. `verify()` also checks:

- every checkpoint the remaining records cover matches the record at its sequence number,
  so a chain rebuilt with fresh hashes fails at the first checkpoint it passes;
- a checkpoint past the last record means records were removed from the end;
- with a key, an unsigned or edited checkpoint fails; without one, a pruned log whose
  checkpoint is signed cannot be verified.

`prune()` refuses a log that does not verify, since pruning it would drop the evidence that
it broke. After a restart, a log pruned through its head goes on from its last checkpoint
rather than starting again at sequence 0.

The CLI reads the key from an environment variable, so it stays out of the command line
and shell history:

```bash
airlock-conformance verify --log decisions.jsonl --checkpoint-key-env AIRLOCK_CHECKPOINT_KEY
```

## The audit record and the OTel hash

The JSON-lines audit record of a call that stripped ghost arguments now names them
(`stripped_args`) and keeps the arguments as the caller sent them, masked like
`args_preview`, in `requested_args_preview`. `args_preview` still shows what the tool got.
A call that stripped nothing writes the same record as before.

The OTel audit record's `args_hash` is now the canonical `args_digest`, 64 hex characters.
Until 0.10.29 it was `json.dumps(default=str)` cut to 16 characters, under which an object
read as whatever its `str()` said.
