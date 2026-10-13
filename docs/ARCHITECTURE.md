# Architecture and current implementation

The target product has a signed credential broker, a private human app and a thin
MCP bridge. Agents receive account metadata and action outcomes. Credentials,
cookies, browser profiles and login state belong to the broker.

The prototype implements the domain and authorization logic in `AgentVaultCore`.
`Broker` reserves persistent call budget before reading a credential. It dispatches
only the account's fixed action, then rechecks expiry and revocation before returning
output. `KeychainStore` alone wraps `SecItemAdd`, `SecItemCopyMatching` and
`SecItemDelete`. `FileStateStore` owns private metadata, grants and bounded audit
events; it serializes threads and cooperating processes, refuses unsafe existing
files and replaces state atomically.

`AgentVaultCLI` owns developer commands, hidden terminal input and the MCP adapter.
The official SDK owns transport and protocol lifecycle. The MCP surface has no
grant mutation, raw-secret read, credential export, arbitrary command, URL, request
header or browser-evaluation parameters. Unknown tool inputs fail closed.

## Reconciliation with the design

The implementation is the first domain milestone, not the complete hardened
architecture. The CLI and MCP server currently run the core inside their process
under the same user. A host-configured development client ID selects grants; it
is not an authenticated installation identity. The human app, signed cross-account
IPC and browser service are absent. Do not interpret Keychain-at-rest protection
as confinement from same-user code.

Human authorization currently happens through explicit developer grant commands.
Grants apply only to read-only actions. No per-call human-presence approval is
implemented. Credentials enter through a TTY rather than a GUI. These are deliberate
milestone limits, not equivalent implementations of the pending controls.

The target grants bind authenticated clients to exact accounts, actions, resource
constraints, expiry, budgets and approval rules. Approval freezes an invocation and
cannot authorize edited inputs. Sessions remain broker-owned, bind to the grant and
close on revocation. Client labels supplied by models are audit metadata only.

## External effects

Local reservation cannot guarantee exactly-once external effects across a crash.
This version exposes only read-only operations. Future mutations must use provider
idempotency or return an uncertain-outcome state for reconciliation before retrying.

The browser milestone uses reviewed site workflows, exact origin validation and
typed output. It never exports cookies, CDP endpoints or general scripting controls.
Human MFA and CAPTCHA steps remain human steps.

## Interfaces

The domain is closed over `Service`, `Action` and `OperationResult`. `StateStore`
provides a single transactional ownership boundary. `SecretStore` and
`ServiceAdapter` permit synthetic tests without real credentials. Production
dispatch uses compiled-in adapters; the agent cannot install executable recipes.
The executable's Swift package exposes no reusable library product.

Documentation references: [MCP stdio transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports),
[official Swift SDK](https://github.com/modelcontextprotocol/swift-sdk/tree/0.12.1),
and [GitHub authenticated user endpoint](https://docs.github.com/en/rest/users/users#get-the-authenticated-user).
