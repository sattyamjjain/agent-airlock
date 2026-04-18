"""Benchmark MCP 2025-11-25 OAuth 2.1 + PKCE hot paths.

Any remote MCP server that accepts OAuth runs PKCE on every authorization
flow; the MCP-server side additionally validates an access-token audience
on every tool call. We benchmark:

- PKCE generate + verify round-trip (client-side, once per login).
- `validate_access_token_audience` against a list-form `aud` claim
  (server-side, once per tool call — the hot one).
"""

from __future__ import annotations

from agent_airlock.mcp_spec.oauth import (
    generate_pkce_challenge,
    generate_pkce_verifier,
    validate_access_token_audience,
    validate_pkce_pair,
)

RESOURCE = "https://mcp.example.com/"
AUD_LIST_CLAIM = {
    "aud": [
        "https://other.example.com/",
        "https://mcp.example.com/",
        "https://another.example.com/",
    ]
}


def _pkce_roundtrip() -> bool:
    verifier = generate_pkce_verifier()
    challenge = generate_pkce_challenge(verifier)
    return validate_pkce_pair(verifier, challenge)


def test_pkce_generate_verify_roundtrip(benchmark):
    assert benchmark(_pkce_roundtrip) is True


def test_access_token_audience_match(benchmark):
    benchmark(validate_access_token_audience, AUD_LIST_CLAIM, expected_audience=RESOURCE)
