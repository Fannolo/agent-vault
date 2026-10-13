# Implementation contract

The Contracts target contains data-only wire DTOs and separate XPC protocols.
Read RPC carries no client identity; the broker binds the authenticated connection
to a registered UID/principal. Admin mutations require a broker-issued, single-use
challenge signed by a protected human-app key. The human app stores only its own
approval signing key, never service credentials. Credential entry crosses only
the authenticated admin channel. No generic request/destination/script is supported.

Production XPC listeners enforce distinct exact signing requirements and allowed
UIDs before activation; clients enforce the broker requirement. Ad hoc development
fixtures pin cdhash, not a reproducible identifier. Production broker refuses root
and refuses an expected UID equal to its client UID. Runtime proof requires an
installed dedicated UID; local same-UID fixtures prove message/code requirements
only. No privileged installation or migration is part of development verification.

Read operations are accounts, fixed action run, approved-request resume and cancel.
Responses are closed status codes plus typed account/profile/request data. Admin
operations include enrollment, rotation, deletion, pairing, grants, revocation,
pending invocation approval/rejection, recovery and pruning. begin freezes a validated
request, bounds its lifetime and returns a random challenge payload; authorize
verifies the signature against a broker-configured public key and consumes it before
applying the frozen request. Tokens/signatures from one challenge cannot authorize
another challenge. For fixture testing only, a generated software P256 key is used.
Production signing uses a Keychain/Secure Enclave user-presence protected key.

Browser ownership remains in a broker-linked adapter. Workflows are fixed demo and
GitHub web-profile reads. The app may show a human continuation view, but the MCP
bridge receives no raw page, cookie, password, profile path or automation endpoint.
Tests use a fixed local fixture origin supplied by trusted test configuration only;
production uses HTTPS GitHub origins. MFA/CAPTCHA require human continuation.

Module boundaries are Contracts, IPC transport, Core, BrokerDaemon, MCP bridge,
Mac App and Browser adapter. The MCP bridge must not link Core/SecretStore.
Each worker edits its own worktree and commits before root integration. No worker
installs a service, changes unrelated apps, reads real user credentials, uploads
private evidence or closes an unverified milestone.
