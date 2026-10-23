# Trusted ciphertext transport client

The `AgentVaultCloud` module implements the fixed PostgREST routes described in
[`supabase/README.md`](../supabase/README.md). It is not yet wired into a production
broker. Cloud signup, refresh-token custody, pairing, durable encrypted storage and the
verified sync state machine remain separate implementation work.

## Ownership and interface

The broker owns one `SupabaseTransport` actor. A trusted authentication owner supplies
its user access token as a redacted `CloudAccessToken`, and later replaces or invalidates
it. No environment variable, shell password or raw MCP token endpoint is provided.
The token type hides bytes behind the same owned buffer used by browser credentials.
Only the fixed cloud HTTP adapter receives its reveal SPI. The initializer checks header
syntax, not JWT signature, issuer, claims or device enrollment. The authentication owner
must supply a genuine user session; this is not an administrative-key login interface.
Only `sb_publishable_` configuration keys are accepted.

The interface has five operations: create a vault, put an immutable object, read changes,
read a head and compare-and-swap a head. Caller data cannot select a route, header, method,
redirect destination, browser connection or generic HTTP operation. Endpoint configuration
is a trusted HTTPS origin with no user information, path, query or fragment.

The architectural guard rejects cloud dependencies in the bridge, MCP transport, browser,
IPC and human app roles. The cloud module depends on the credential wrapper; it never
links the synthetic `VaultCore` package. Graph/SPI checks are maintenance controls, not an
OS sandbox or protection against a hostile maintainer.

## Response and failure behavior

- HTTP redirects are refused; returned URLs must equal the requested URL. Cookies,
  credential storage and caches are disabled. Request/resource timeouts are 15/20 seconds.
- Response chunks are checked before append against an 8 MiB accumulated-body limit.
  This does not bound all Foundation/networking/JSON-decoder memory.
- Change pages request at most three rows, enough to fit three maximum-size hex-encoded
  objects. Every row must name the requested vault, have a strictly increasing positive
  sequence, and contain a unique digest equal to SHA-256 of its decoded object bytes.
  Invalid hex, oversize objects, excess rows and inconsistent digests fail before return.
- Head rows are bounded to one, match the requested vault and require positive revision
  and a 32-byte digest. Head/cursor values remain untrusted coordination metadata.
- There are no automatic retries. Interrupted or malformed write completion returns
  `writeUnconfirmed`; callers must reconcile the immutable object/head before retrying.
  Replacing or invalidating a token fences old responses. It does not recall a request
  already delivered to the server or revoke a remote session.
- Errors are fixed codes. No server error body, token, cookie or credential is returned
  through the error path. Token diagnostics and mirrors are redacted. Transient request
  headers, JSON and Foundation copies are not proven erased.

The client verifies transport digests only. It cannot establish membership, author role,
format validity, rollback resistance or absence of withholding. A sync owner must verify
signed objects and pinned checkpoints before committing authority or releasing a credential.
The 1 MiB object cap is the current transport cap, not a reviewed successor vault format.

## Current verification scope

Nine native URLProtocol-backed tests exercise fixed requests, hostile response data,
digest/cursor checks, conditional conflicts, uncertain writes, declared/chunked response
bounds, invalidation and cancellation. They make no real network connections. Native root
tests report 371 passing tests with existing Chromium/Keychain opt-ins inactive. Twelve
credential/timeout/graph tests pass in normal and optimized Python; ten actual compiler
probes check that ordinary imports cannot reveal login fields or cloud token bytes.

These fixtures do not establish a live PostgREST/JWT/signup flow, installed token custody,
Linux runtime behavior, protected approval signing or production readiness. Native database
checks are a separate component test. Both sides must be exercised together on an approved
dedicated host before claiming cloud integration complete.
