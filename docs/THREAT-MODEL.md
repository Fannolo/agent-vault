# Threat model

## Current prototype

The prototype protects against routine credential disclosure through its implemented
MCP tools: no secret-returning operation, no arbitrary network destination, no shell
execution, typed outputs and fixed public error codes. Grants are checked on each
invocation, not inferred from a successful initialization.

It **does not** protect against arbitrary code running as the same macOS user.
Such a process may edit metadata, invoke developer commands, launch another
development client context, access Keychain if authorized by macOS, or observe
process/UI state. Launch client IDs and private filesystem permissions do not
authenticate an individual agent installation. Root, administrator compromise and
a compromised credential broker are also outside the current guarantee.

The GitHub adapter trusts `api.github.com` and normal OS TLS validation. A service
receiving a credential can misuse it. Output schemas discard unapproved fields;
they do not prove that a malicious service cannot encode secrets into valid fields.
Returned account data is authorized business output and may still be confidential.

The Swift SDK is a pinned dependency, not audited here. The server uses stdio,
not its OAuth or HTTP transports. General protocol resource exhaustion remains a
separate hardening item. There is no production release, native code signing,
notarization, entitlement isolation, protected approval UI or browser login service.

Enrollment updates Keychain and metadata in separate operations. A process crash
between them can leave an orphaned Keychain item; crash-safe enrollment recovery,
account deletion and rotation are tracked lifecycle work. Do not enroll durable
production credentials in this prototype. Capacity limits keep normal metadata
growth below the storage ceiling; they do not replace pruning or account lifecycle.

## Target boundaries

The hardened broker must hold credentials and browser state outside the agent's
OS privileges. Its IPC must authenticate the actual bridge/client principal and
enrollment; signing a shared bridge does not identify the model behind it. Policy
and trusted adapter code cannot reside in agent-writable workspaces. Per-call
approval uses a protected human UI and freezes client, operation and inputs.

Revocation must invalidate pending permissions and local sessions. An external
request already dispatched may complete. Audit retention and tamper evidence need
an explicit design; the prototype's latest 1,000 events are local mutable history,
not an immutable log or security witness.

## Regression boundaries

- Missing, expired, revoked, wrong-client and wrong-account grants.
- Concurrent reservations exceeding a budget, including separate processes.
- Revocation while a provider request is in flight.
- Corrupt state, symlinks, hard links and permissive files.
- Raw secrets in errors, metadata, logs, hashes or output schemas.
- Header injection, redirects and oversized provider output.
- Unknown tool names and additional input keys, including impersonation fields.
- Prompt-injected attempts to add destinations, install adapters or export sessions.

Tests use synthetic credentials. Opt-in native tests delete only their own unique
Keychain entries. Live user accounts must not be fixtures.
