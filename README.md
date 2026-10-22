# Agent Vault

Agent Vault is building a free, open-source password manager for agents on macOS and Linux,
with native local vaults/private browsers and client-side encrypted cloud synchronization.
An agent should notice a website is logged out, ask whether it may use an approved account,
and request private login without receiving password text.

The current app is a macOS broker for fixed operations. Linux UI/broker, cloud signup/sync
and general website operation are not implemented yet. The first portable component is
the standalone [sealed-record core](Packages/VaultCore), tested on macOS and Linux with
bidirectional synthetic ciphertext exchange. It is not connected to current app products.
Its corrected codec passes 21 tests per platform and 12 deliberate-defense-removal checks;
Opus 5.5 and Grok 4.7 accepted that bounded unit. Version 1 stays fixture-only until a reviewed format
with padding and explicit key commitment is ready for real-password storage.
See the [product goal](docs/PRODUCT-GOAL.md), [multi-platform design](docs/design/multiplatform/DESIGN.md)
and [codec evidence](docs/verification/portable-codec-v1.json) for scope and remaining work.

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
- A separate Chromium host and authenticated link with scoped losses, dispatch deadlines,
  post-probe authorization and a native challenge-image/input relay. Synthetic U5 tests
  join the real host to the app model; the old WebKit engine has been removed. Production
  browser actions remain disabled pending installed isolation and service verification.

The bridge and app do not link Core or the service credential store. Permissions belong to
an authenticated bridge and paired OS user; a model-supplied identity does not authorize calls.
The legacy CLI below remains a same-user development fixture and is excluded from distribution
review bundles.

## Portable codec development

The separate package uses pinned Swift Crypto and synthetic fixtures only. It has no CLI,
cloud access, Keychain access or executable product:

```sh
swift test --package-path Packages/VaultCore --force-resolved-versions
```

On an arm64 macOS development host with Docker and OpenSSL at
`/opt/homebrew/bin/openssl`, run the current membership interoperability and deliberate-defect
checks. Use the result path printed by the first command:

```sh
python3 -I scripts/verify-membership.py --unit u1
python3 -I scripts/verify-membership-controls.py --unit u1 PATH_TO_RESULT_JSON
```

These checks prove bounded codec behavior, not account signup, live cloud sync, installed
OS isolation or a production password manager.

The root build has a fixture-only integration guard covering direct and transitive
dependencies, aliases and controlled source paths. The synthetic membership extension passes
55 tests on each platform and agrees on all 150 pinned Ed25519 cases. Both producer directions,
independent A/B readers, rejected signature flips and restored reads pass. All 20 policy
controls are detected; the separate low-order-key removal is detected on Linux and masked
by the native backend. The Python verifier passes 61 tests in normal and optimized modes.
Opus 5.5, Grok 4.7 and Codex accept this bounded source and measured evidence.

The [U1 record](docs/verification/membership-u1.json) describes the actual results and limits.
Its runtime receipts describe the measured `7972b59` checkpoint. A later CI test-only
correction changes the bound test-file hash; the record keeps those epochs separate.
The [membership document](docs/design/multiplatform/MEMBERSHIP.md) retains its frozen
pre-verification introduction because the receipts bind its bytes. Current status is recorded
here and in the [implementation plan](docs/IMPLEMENTATION-PLAN.md). The harness must be
decomposed and re-recorded before further feature growth. This package remains fixture-only
and is not linked to the app.

[U0's evidence](docs/verification/membership-u0.json) applies to the unchanged 21-test codec
checkpoint at `aab2b7c`. Its default verifier pins that historical source; it does not accept
the larger U1 package. Its Linux validation-removal result and native backend masking remain
separate from the earlier interoperability record.

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

## Real credential enrollment

Enter service credentials only in the signed native app's secure fields. The app sends
an authenticated administrative request to the broker. Terminal enrollment is refused,
even when a controlling TTY is available; passwords and tokens are never command arguments,
environment variables or terminal prompts. The development CLI exposes only `demo.status`.

Do not enroll production credentials until provisioning, protected-key signing and installed
isolation gates pass. The fixed `github.profile` adapter remains available through the
production broker/app architecture; it is not exposed by the synthetic terminal fixture.
Revocation blocks new calls and suppresses in-flight results, but cannot recall a request
already received by the approved service.

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
