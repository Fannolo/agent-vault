# Agent Vault

Agent Vault lets an agent request a fixed service operation while the application
uses credentials internally. The project is a macOS development prototype with a
native Swift core and a stdio MCP interface.

**This version does not isolate credentials from an agent with unrestricted access
to the same macOS account. It is not ready for production passwords or PINs.**
The signed broker, authenticated IPC, human approval app and controlled browser
remain implementation milestones.

## Implemented

- Native Keychain enrollment, with private terminal entry for GitHub tokens.
- Exact client/account/action grants with expiry, revocation and persistent call budgets.
- Two MCP tools: `accounts_list` and `action_run`.
- A synthetic `demo.status` action and a fixed `github.profile` action that performs
  `GET https://api.github.com/user` and returns only `login` and `id`.
- Private, locked metadata storage with atomic replacement and a bounded audit history.
- Stable public error codes, strict tool inputs, and no raw credential retrieval tool.

MCP `clientInfo` does not grant permissions. The development client ID is selected
by the launching host. **That ID is configuration, not client authentication.**
A same-user process can run the CLI, alter grants or launch a server under another
development client ID. The next broker milestone addresses this boundary.

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

## Local plugin package

`plugin.json` and `mcp.json` describe a local plugin. Build with `swift build -c release`,
then configure `AGENT_VAULT_CLIENT_ID` in the host's MCP launch environment.
`scripts/run-mcp.sh` refuses to start without that configuration or a built binary.
The package is not automatically installed in a host by cloning this repository.
No cloud server or OpenAI directory listing is provisioned.

Metadata defaults to `~/.local/share/agent-vault/`. Credentials use the Keychain
service `io.agent-vault.credentials.v1`. State and Keychain namespace overrides
exist for developer tests; MCP callers cannot change them through tool arguments.
Terminal enrollment rejects tokens longer than 256 bytes. The development CLI
does not yet offer account deletion, credential rotation or recovery of enrollment
interrupted between Keychain and metadata writes. Use temporary namespaces for
disposable test accounts. Metadata caps are 128 accounts, 128 clients and 512 grants;
new enrollment/grants fail at capacity while revocation remains available.

See the [implementation plan](docs/IMPLEMENTATION-PLAN.md),
[architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT-MODEL.md),
and [security reporting policy](SECURITY.md).
