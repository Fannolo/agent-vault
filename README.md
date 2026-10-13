# Agent Vault

Agent Vault is a native macOS credential broker for fixed agent operations, with a human
approval app and a thin stdio MCP bridge.

**Development build: dedicated-user isolation, real protected-key signing and notarization
remain release gates. Do not use production passwords or PINs yet.**

Implemented, with component checks:

- Authenticated, separate read/admin XPC channels with exact code-hash and kernel UID checks.
- A daemon designed for a dedicated user, protected configuration, explicit private Keychain
  and owner lease. Its installed dedicated-user behavior remains unverified.
- Recoverable enrollment, rotation/deletion, per-call approvals, expiry, revocation and budgets.
- Native secure forms, client/grant management, pending approvals and private audit export.
- Four production bridge tools: `accounts_list`, `action_run`, `request_resume`, `request_cancel`.
- Fixed `demo.status` and `github.profile` operations, returning only typed results.
- Bounded stdio before SDK parsing, authenticated metadata and safe public error codes.
- A controlled WebKit library tested with real hostile loopback pages. Production browser
  actions are disabled pending the isolated GUI deployment described in the plan.

The bridge and app do not link Core or the service credential store. Permissions belong to
an authenticated bridge and paired OS user; a model-supplied identity does not authorize calls.
The legacy CLI below remains a same-user development fixture and is excluded from distribution
review bundles.

## Try the synthetic demo

Requires macOS 14 or newer and Swift 6.2 or newer. The official Swift MCP SDK is
pinned to `0.12.1`; dependency revisions are recorded in `Package.resolved`.

```sh
swift build
swift test
.build/debug/agent-vault demo
```

The last command creates a synthetic Keychain credential and prints account,
client and grant IDs. It grants `demo.status` for one hour with a 20-call limit.
It never prints the synthetic credential. Start the server with the returned client ID:

```sh
.build/debug/agent-vault mcp --client-id CLIENT_UUID --development
```

An MCP client can call:

```json
{"name":"accounts_list","arguments":{}}
```

```json
{"name":"action_run","arguments":{"accountId":"ACCOUNT_UUID","action":"demo.status"}}
```

For an automated smoke test using only synthetic data:

```sh
python3 scripts/verify-mcp.py
```

By default the smoke test checks MCP initialization, tool discovery and denied
calls without touching Keychain. An optional integration check creates and deletes
only its own temporary Keychain entries:

```sh
python3 scripts/verify-mcp.py --keychain-demo
AGENT_VAULT_KEYCHAIN_TEST=1 swift test --filter nativeKeychainRoundTripWhenExplicitlyEnabled
```

## GitHub development account

Use a disposable, minimally scoped token for development. Enter it only at the
hidden terminal prompt, never in chat, command arguments or an environment variable:

```sh
.build/debug/agent-vault enroll github
.build/debug/agent-vault client
.build/debug/agent-vault grant --client-id CLIENT_UUID --account-id ACCOUNT_UUID --seconds 3600 --calls 20
```

Then call `action_run` with `github.profile`. The destination, method and output
schema are fixed. Redirects are rejected; upstream errors and headers are not returned.
The GitHub service and local operating system remain trusted.

```sh
.build/debug/agent-vault revoke-grant --grant-id GRANT_UUID
.build/debug/agent-vault revoke-client --client-id CLIENT_UUID
```

Attempted operations consume budget even if the provider fails. Revocation blocks
new calls and suppresses the result of an in-flight call; it cannot recall a request
already received by the provider.

## Local plugin and release work

`plugin.json` and `mcp.json` launch `/Library/AgentVault/agent-vault-bridge mcp` through a
small script. No development client ID or secret is passed in the host environment. Cloning
or building does not install the plugin, daemon, app or account or modify other applications.

Run the complete local checks:

```sh
swift test --force-resolved-versions
python3 scripts/verify-mcp.py
python3 scripts/verify-boundaries.py
python3 scripts/verify-xpc.py
python3 scripts/verify-installer.py
```

The XPC harness uses uniquely named temporary user launch agents and removes exactly its own
jobs. It proves same-UID process authentication only. The release script creates a Developer ID
signed review bundle under ignored `dist/`, with a dependency inventory and manifest; it never
installs. A matching Developer ID provisioning profile is required for the app's protected
Keychain key. Missing provisioning/notarization or unmeasured isolation does not become a
production-ready release.

State and credentials for the legacy CLI default to `~/.local/share/agent-vault/` and its own
Keychain namespace. Installed broker state is separate under `/private/var/db/agent-vault`.
No existing developer state or personal Keychain is migrated automatically.

See the [implementation plan](docs/IMPLEMENTATION-PLAN.md),
[architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT-MODEL.md),
[native app](docs/NATIVE-APP.md), [IPC evidence](docs/IPC.md), and [security policy](SECURITY.md).
