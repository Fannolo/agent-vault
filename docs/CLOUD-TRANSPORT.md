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
Its reveal method is in a separate `CloudTokenUse` SPI group. The architectural guard
allows that import only in `SupabaseTransport.swift`. The browser roles' `CredentialUse`
import cannot reveal it; a compiler probe checks this. The initializer checks header
syntax, not JWT signature, issuer, claims or device enrollment. The authentication owner
must supply a genuine user session; this is not an administrative-key login interface.
Only `sb_publishable_` configuration keys are accepted.

The interface has five operations: create a vault, put an immutable object, read changes,
read a head and compare-and-swap a head. Caller data cannot select a route, header, method,
redirect destination, browser connection or generic HTTP operation. Endpoint configuration
is a trusted HTTPS origin with no user information, path, query or fragment. The
endpoint stores a canonical origin: lowercase ASCII DNS host, no default port 443. The
macOS loader reports a lowercase host for an uppercase request host, so a non-canonical
origin would fail the exact response-URL check on every request.

`createVault` succeeds only when this session owns the id. It sends a plain insert. A new
id returns 201. An existing id returns PostgREST 409 (`23505`), and the client then reads
the row through RLS: the owner sees it (idempotent success); another account's id is
invisible and returns `conflict`. The earlier `resolution=ignore-duplicates` request
reported success for another account's id: native PostgreSQL 17.11 returns `INSERT 0 0`
without error for that `ON CONFLICT DO NOTHING` statement.

The architectural guard allows only the approved production consumer
`AgentVaultBrokerDaemon` to reach `AgentVaultCloud`. Every other non-test target is
refused. This includes the CLI's MCP server, Core, the bridge, browser, IPC, app roles and
any target added later. A new consumer needs an explicit allowlist change. The cloud
module depends on the credential wrapper; it never
links the synthetic `VaultCore` package. Graph/SPI checks are maintenance controls, not an
OS sandbox or protection against a hostile maintainer.

## Response and failure behavior

- HTTP redirects are refused before a request goes to the new destination; returned
  URLs must equal the requested URL. Cookies, credential storage and caches are disabled.
  Request/resource timeouts are 15/20 seconds. On Linux, FoundationNetworking cannot
  deliver a redirect from a test `URLProtocol`. The Linux test calls the delegate through
  the `URLSessionTaskDelegate` protocol, as the loader does. The end-to-end redirect
  fixture runs on macOS only.
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
  Unrecognized write statuses, including 400 (`head_invalid`) and 500 (`vault_quota` and
  the current `40001` head conflict), are also `writeUnconfirmed`. 401 is `unauthorized`
  and 403 (RLS or owner-check denial) is `denied`. 409 is `conflict`. Read failures keep
  the transport's code: a redirect, foreign URL or oversize reply is `invalidResponse`, and
  loss or cancellation is `unavailable`.
- A head conflict returns `conflict` only after the server raises a `PT409`-coded error.
  PostgREST maps that code to HTTP 409; it maps the current `40001` raise to 500
  ([PostgREST errors](https://docs.postgrest.org/en/stable/references/errors.html)).
  That server change is pending integration from the cloud-transport branch. Until it
  lands, a lost compare-and-swap race is reported as `writeUnconfirmed`. Neither mapping
  has run against a live PostgREST server.
- Replacing or invalidating a token only fences responses. The client discards any
  response for an older token generation. `invalidate()` does not cancel in-flight URL
  tasks. A request admitted before invalidation can still be sent with the old token, and
  its transient header copy can live until the 20-second resource timeout. Nothing recalls
  a request already sent, and nothing revokes a remote session.
- Task cancellation ends the local wait and cancels the URL task. If the request was
  already sent, the server may still apply the write; the caller gets `unavailable` for a
  read and `writeUnconfirmed` for a write.
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
