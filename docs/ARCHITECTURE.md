# Architecture

The package graph enforces three roles, checked by `scripts/verify-boundaries.py`:

| Module | Responsibility | Secret-store access |
|---|---|---|
| Contracts | Closed DTOs and separate read/admin XPC protocols | None |
| IPC | Peer code/UID authentication, bounded wire validation and empty probe | None |
| Runtime | Protected installed configuration, material files and owner lease | Daemon material only |
| Core | Policy, lifecycle journal, approval verifier, private Keychain and fixed API adapter | Broker only |
| BrokerDaemon | Dedicated-user service; composes Core with authenticated IPC | Yes |
| MCPTransport / MCPBridge | Bounded stdio and four fixed read tools | None |
| Bridge | Installed read client; no caller-selected identity, state path or destination | None |
| AppSupport / App | Secure enrollment forms, pairing, grants, approvals and audit export | Own approval signing key only |
| Browser | Fixed ephemeral WebKit workflow library, verified on synthetic sites | Caller-supplied transient bytes; production disconnected |

The signed bridge binds to the paired OS UID. `clientInfo` and tool arguments do not select
identity. `accounts_list`, `action_run`, `request_resume` and `request_cancel` map to closed
ReadRequest values. Enrollment, rotation, deletion, pairing, grants, revocation, approval,
recovery and pruning are available only on the authenticated admin service and require a
frozen single-use challenge signature.

Core reserves attempt budget transactionally before reading a credential. An approved request
is bound to its client, account, action and grant and is consumed before dispatch. Failed
attempts still consume budget. Expiry and revocation are checked inside locked state access,
after Keychain access, and at final completion. Per-account lifecycle guards plus the daemon's
exclusive process lease prevent overlapping credential recovery/rotation.

Production state is a version-2 HMAC envelope. Account lifecycle and approval fields are required;
corruption and downgrade fail closed without overwriting the evidence. Interrupted intent is
recovered using known Keychain IDs only. Version-1 developer state is not migrated automatically.

Production browser deployment remains a separate architectural gate. A broker-linked web view
needs a compatible isolated GUI host for human MFA/CAPTCHA. The current LaunchDaemon cannot
vend that view across the DTO-only XPC channel. See BROWSER-DEPLOYMENT.md.

Developer fixtures, preview software keys and the legacy same-user CLI are development tools,
excluded from the signed review bundle. No existing browser profile, global MCP configuration,
application, company document or user credential is changed by building and testing.
