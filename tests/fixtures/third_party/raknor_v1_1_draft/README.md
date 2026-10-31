# Raknor agent-governance-standard v1.1 draft vectors

Copied unmodified from
[raknor-ai/agent-governance-standard](https://github.com/raknor-ai/agent-governance-standard)
at commit `9f9742f1a3abbb30ac2c0931f95061893af5a55e`:

| File here | Upstream path | Proposal |
|---|---|---|
| `resource-governance/vectors.json` | `conformance/v1.1-draft/resource-governance/vectors.json` | [#4](https://github.com/raknor-ai/agent-governance-standard/issues/4), SC-AG-05 resource limits |
| `fail-closed/vectors.json` | `conformance/v1.1-draft/fail-closed/vectors.json` | [#3](https://github.com/raknor-ai/agent-governance-standard/issues/3), SC-AG-07 fail-closed evaluation |

**License.** The upstream `conformance/v1.1-draft/README.md` dedicates the files in that
directory to the public domain under CC0 1.0, as an exception to the repository's CC BY 4.0
default. Each file also carries `"license": "CC0-1.0"`.

The vectors are draft, non-normative test material. The `tests/test_raknor_*_0_10_29.py`
modules drive them through Airlock's own API; the mapping from a vector to an Airlock call
is in each module's docstring. Do not edit these files: refresh them from a newer upstream
commit and update the commit above.
