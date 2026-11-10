# Binding discovered OAuth metadata to its URL

A client that discovers an authorization server reads a metadata document and uses the issuer
it names. RFC 8414 section 3.3 says that issuer must be the identifier the well-known URL was
built from, or the document must not be used. MCP 2026-07-28's
[discovery page](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery)
repeats the rule. RFC 9728 section 3.3 says the same of a protected resource's `resource`,
[below](#protected-resource-metadata).

`AuthorizationServerMetadata` takes no URL, so its constructor cannot check that: a document
naming any issuer parses. Read a document you fetched with `from_discovery`:

```python
from agent_airlock.mcp_spec import AuthorizationServerMetadata, IssuerMismatchError
from agent_airlock.mcp_spec.oauth import validate_authorization_response_iss

discovery_url = "https://as.example/.well-known/oauth-authorization-server"
document = {
    "issuer": "https://as.example",
    "authorization_endpoint": "https://as.example/authorize",
    "token_endpoint": "https://as.example/token",
    "code_challenge_methods_supported": ["S256"],
}

try:
    metadata = AuthorizationServerMetadata.from_discovery(document, discovery_url=discovery_url)
except IssuerMismatchError:
    raise SystemExit("do not use this document")

# Later, on the redirect back. A raw `metadata.issuer` from the constructor is not safe here:
# a document can name any issuer, and once that value is the expected one this check cannot
# catch the mix-up.
validate_authorization_response_iss(
    {"code": "placeholder", "iss": "https://as.example"},
    expected_issuer=metadata.issuer,
)
```

A refusal says what is wrong and repeats neither URL. `issuer_from_discovery_url` and
`validate_metadata_issuer` are the two steps on their own.

## Which URL to pass

Pass the URL you built and requested, never the address a redirect ended on (`response.url`).
The document at the end of an open redirect names that address, so it would pass.

These are the forms the MCP page has a client try, and the issuer each one comes from:

| Well-known URL | Issuer |
|---|---|
| `https://as.example/.well-known/oauth-authorization-server` | `https://as.example` |
| `https://as.example/.well-known/openid-configuration` | `https://as.example` |
| `https://as.example/.well-known/oauth-authorization-server/tenant1` | `https://as.example/tenant1` |
| `https://as.example/.well-known/openid-configuration/tenant1` | `https://as.example/tenant1` |
| `https://as.example/tenant1/.well-known/openid-configuration` | `https://as.example/tenant1` |

Anything else raises `IssuerMismatchError`: no well-known segment, two of them,
`oauth-authorization-server` appended to a path, a query, a fragment, userinfo, an invalid port,
a dot or empty segment or a path parameter, and whatever the metadata URL screen refuses (plain
http off loopback, a character a URL must percent-encode). A client that falls back to the root
well-known for a tenant issuer built that URL from the origin, so a document there naming the
tenant is refused.

## What it compares

Scheme, host, port and path as strings: no case folding, and `:443` is not the same as no port.
Trailing slashes are forgiven, through the normalizer the `iss` check uses, so the two checks
cannot disagree. Nothing else is. That is one step more lenient than the text: RFC 8414 says
"identical", and MCP 2026-07-28's authorization page rules out trailing-slash normalization for
`iss`.

## What it does not do

It binds a document to a URL. It does not decide which server to trust: a server's document
about itself, at its own well-known URL, passes. The choice is yours, from the configured
identifier or the resource's `authorization_servers` (RFC 9728), and the URL you pass should
come from that choice. The check earns its keep where discovery is not fully in the hands of the
party the document names: an open redirect on the well-known path, a stale or cached document, or
a resource server steering discovery.

## Protected resource metadata

Before it finds the authorization server, an MCP client reads the server's protected resource
metadata (RFC 9728). RFC 9728 section 3.3 says the `resource` that document returns must be the
resource identifier the client built the metadata URL from, or the document must not be used.
Without that check a malicious MCP server names another server there, and a client that sends it
as the RFC 8707 `resource` parameter gets a token minted for that server, which the malicious
server then receives. That was CVE-2026-123272 in mcp-go and CVE-2026-123271 in ChatCLI.

`ProtectedResourceMetadata` takes no URL either, so read a fetched document with its own
`from_discovery`:

```python
from agent_airlock.mcp_spec import ProtectedResourceMetadata, ResourceMismatchError

server_url = "https://mcp.example.com/mcp"
document = {
    "resource": "https://mcp.example.com/mcp",
    "authorization_servers": ["https://as.example"],
}

try:
    metadata = ProtectedResourceMetadata.from_discovery(document, resource_url=server_url)
except ResourceMismatchError:
    raise SystemExit("do not use this document")
```

Pass the MCP server URL you connected to: you built
`/.well-known/oauth-protected-resource` from it, or followed a `resource_metadata` URL from that
server's 401, where RFC 9728 has the request URL. After a fall back to the root well-known URL,
the identifier is the server's origin, and a document there that names the server's full URL is
refused. Never pass `response.url`.

The comparison uses the token audience check's key, so on any two URLs both can read they
agree: case in the scheme and host, a trailing slash and a default port are forgiven, and a different scheme, host,
port, path or query is not. A `resource` must also pass the metadata URL screen and hold no
userinfo. `validate_protected_resource` is the check on its own.

Whatever the document says, send the MCP server's own canonical URL as the `resource` parameter,
as the MCP authorization page requires. ChatCLI's fix does that.
