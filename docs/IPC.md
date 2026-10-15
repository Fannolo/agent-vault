# Broker IPC

`AgentVaultIPC` connects three programs over XPC: the broker, the MCP bridge and the
human app. The bridge may use only the read service. The app may use only the admin
service. Both services belong to the broker. The module depends only on
`AgentVaultContracts` and the shared strict JSON guard. It contains no secret store, so linking it into the bridge does
not give the bridge credential access.

This is development code. Tests and a same-UID cross-process harness verify the identity
checks. Separation by a dedicated broker UID has not been run. See
[Unproven](#unproven).

## Configuration

`IPCConfiguration` is the identity policy shared by all three roles.

| Field | Meaning |
| --- | --- |
| `readServiceName` | Mach service of the bridge-facing read listener. |
| `adminServiceName` | Mach service of the app-facing admin listener. |
| `brokerRequirement` | Code requirement that clients enforce on the broker. |
| `readRequirement` | Code requirement that the read listener enforces on the bridge. |
| `adminRequirement` | Code requirement that the admin listener enforces on the app. |
| `brokerUID` | Effective UID of the broker. Clients enforce it on every reply. |
| `allowedUID` | The only client effective UID that the broker accepts. |
| `development` | Selects fixture rules: cdhash pins and the per-user bootstrap. |

`validate(for:)` runs inside every server and client initializer. It fails with
`invalid_configuration` in these cases:

- A UID is 0 or `UInt32.max`, or the process runs as root. This applies in every mode.
- The process's effective UID is not the UID of its role.
- In production, `brokerUID` equals `allowedUID`.
- The service names are equal or are not reverse-DNS names.
- The three requirements are not distinct.
- A requirement does not compile.
- A requirement's canonical form contains `or`, `!`, `always` or `never`.
- A development requirement does not pin a `cdhash`.
- A production requirement lacks `anchor apple generic`, an `identifier` or a team
  (`certificate leaf[subject.OU]`).

`IPCConfiguration.load(contentsOf:)` reads a standalone IPC file and rejects unknown keys
and final symlinks. `IPCConfiguration.readProtectedFile(atPath:)` returns the bytes of a
file only under these conditions:

- The file is a root-owned regular file that group and others cannot write.
- Its directory is root-owned, and group and others cannot write it.

Use `readProtectedFile` for the production deployment configuration. Otherwise a
same-user process could point the bridge at its own service or requirement.

## Identity checks

The broker activates two listeners. Before activation, it sets each listener's connection
code requirement. For each new connection, it does these steps in order:

1. Rejects a peer whose `effectiveUserIdentifier` is not `allowedUID`.
2. Sets the role's requirement on the connection with `setCodeSigningRequirement`.
3. Exports only that role's protocol and activates the connection.

The broker binds the accepted UID to the connection. It compares the UID with
`NSXPCConnection.current()` on each message and passes it to every handler. A request
carries no client identity. The broker does not use the private audit token, KVC or a
PID lookup.

The clients set `brokerRequirement` on the connection before activation. They also check
`effectiveUserIdentifier == brokerUID` on every reply. In production, a client connects
with `.privileged`, so the name is looked up in the system bootstrap, where the broker's
LaunchDaemon lives. A same-user launch agent therefore cannot shadow it. Development
fixtures use the per-user (`gui`) domain.

XPC checks a client's requirement only on messages the client receives. A request sent
to an impostor is still delivered. The harness confirmed this: with the probe below
disabled, a spoofed broker's handler received the bridge's `run` request. For an admin
`enroll`, that request would contain the credential. For this reason, each new client
connection first sends an empty payload: `perform(Data())` or `begin(Data())`. The broker
answers it with `invalid_request` and does not call any handler. A client sends real
requests only after that reply passes the requirement and UID checks. An interrupted
connection is invalidated, so its replacement is probed again.

## Wire format

Requests are flat JSON objects of the contract DTOs. Each operation has an exact key set.
A missing key, an extra key or a `null` fails with `invalid_request`. The decoder
validates the keys before it builds the typed value.

| Read operation | Keys besides `operation` |
| --- | --- |
| `accounts` | none |
| `run` | `accountID`, `action` |
| `resume`, `cancel` | `requestID` |

| Admin operation | Keys besides `operation` |
| --- | --- |
| `enroll` | `service`, `credential` (1–8192 bytes) |
| `rotate` | `accountID`, `credential` (1–8192 bytes) |
| `deleteAccount` | `accountID` |
| `pairClient` | `uid` (not 0, not 2³²−1 or 2³²−2) |
| `grant` | `clientID`, `accountID`, `duration` (0 < s ≤ 86 400), `callLimit` (1–10 000), `requiresApproval` |
| `revokeGrant` | `grantID` |
| `revokeClient` | `clientID` |
| `approveInvocation`, `rejectInvocation` | `requestID` |
| `recover`, `prune` | none |

`authorize` takes a 36-character UUID string and a signature of 8–72 bytes. That range
covers both DER and raw P-256 signatures.

Each reply is a JSON object with exactly one key: `readReply`, `snapshot`, `challenge`,
`adminReply` or `error`. Each method accepts only its own kinds plus `error`. The server
checks every reply with the same validator as the client. If a handler's output fails
that check, the server sends `unavailable` instead. The validator enforces these rules:

- Status and audit-outcome values are lowercase tokens of at most 64 bytes.
- A read status is one of the closed `ReadOutcomeStatus` or `ReadFailureStatus` tokens in
  `AgentVaultContracts`. Each status carries exactly its own fields. A profile reply has both
  `login` and `userID`. An accounts reply has `accounts`. `approval_required`,
  `human_step_required` and `cancelled` carry `requestID`. `ready` and every failure carry
  nothing else.
- A login matches `[A-Za-z0-9][A-Za-z0-9-]{0,38}` and a user ID is positive (`AccountProfile`).
- A pending status is `waiting` or `approved`.
- A snapshot has at most 128 accounts, 128 clients, 512 grants, 128 pending entries and
  1,000 audit entries. The key sets are exact.
- A challenge payload is 16–1024 bytes, with a required 32-byte nonce.

A snapshot at every maximum count encodes to 368,128 bytes and crosses XPC in a test.
The reply cap is 512 KiB.

The broker can put four fixed codes on the wire: `invalid_request`, `request_too_large`,
`busy` and `unavailable`. Clients add `connection_failed`, `broker_rejected`, `timeout`,
`malformed_reply` and `invalid_configuration`. An error never contains request bytes,
peer data or handler error text.

`IPCLimits.standard` sets these limits:

| Limit | Value |
| --- | --- |
| Request size | 16 KiB |
| Reply size | 512 KiB |
| In flight per connection | 4 |
| Read handlers in flight | 32 |
| Admin handlers in flight | 4, independent of read handlers |
| Connections per service | 16 |

When a limit is exceeded, the broker returns `busy` or refuses the connection.
Empty authentication probes are rejected before acquiring a handler slot, so saturated
read handlers cannot prevent a new authenticated admin connection from probing the broker.

## Integration

`VaultXPCServer(configuration:limits:read:snapshot:begin:authorize:)` takes four async
handlers. Each receives the bound kernel UID:

- `(UInt32, ReadRequest) -> ReadReply`
- `(UInt32) -> AdminSnapshot`
- `(UInt32, AdminRequest) -> AdminChallenge`. Throw `AdminRejection(status:)` to send an
  `AdminReply` instead. Any other error becomes `unavailable`.
- `(UInt32, UUID, Data) -> AdminReply`

`VaultReadClient.perform(_:)` returns a `ReadReply`. `VaultAdminClient` has three methods:

- `snapshot()`
- `begin(_:)`, which returns `.challenge(AdminChallenge)` or `.rejected(AdminReply)`
- `authorize(id:signature:)`

All of them throw `IPCError`. The root wires the app's `VaultAdminClient` adapter. For
example, the adapter maps `snapshot.audit` to the UI's audit entries, and the UI uses
`pending.status` so that an approved invocation is not offered for approval again.

This layer needs no change to the contract DTOs. The reply envelope and the empty-payload
probe belong to the transport.

## Browser-host boundary

`AgentVaultWebHostProtocol` is a separate, credential-bearing wire module. The app,
bridge, Core, Runtime and ordinary IPC module cannot link it; module-boundary checks
enforce this. `AgentVaultWebHostLink` implements Core's `WebSessionExecutor` port. The
production broker still composes no web host.

Each host generation completes an empty probe checked against the configured code
requirement and kernel UID before receiving credentials. Core alone mints a
`WebStartAuthority`; after the probe, its callback rechecks the run, epoch, phase,
deadline and live grant. Binding and writing then happen without another suspension.
A run stays bound to that generation, and connection loss reports only its affected runs.

Absolute link budgets include probing: start 15 s, classify 10 s, end 2 s, show-human
5 s, frame and input 2 s each. Configuration checks these paths, including credential
access and cleanup, against the read client's 30 s budget. Core independently owns
start/classify deadline tasks; dispatch is also capped by grant expiry. A late host
reply ends any context it created. Unconfirmed teardown invalidates the generation.
The host listener's peer loss is terminal: running handlers are cancelled, later results
are dropped and no replacement peer is accepted. The future host must also suppress
late context creation after teardown starts.

Read-peer invalidation cancels tracked handler tasks. Keys are reserved before task
creation, so finish-before-register and invalidate-before-register leave no retained
handles. Admin handlers always finish, preserving lifecycle journals and uncertain
outcome semantics.

`HumanFrame` and bounded typed `HumanInputBatch` are App-safe data contracts. The host
port exposes show/frame/input for a preexisting `HumanStepID`; this does not yet provide
an authenticated human-app relay or native rendering. Those remain U3/U4 work. No MCP
human-input or generic browser operation was added.

Text events and web credentials exclude Unicode Cc/Cf control and format scalars,
including ZWJ, LRM and BOM. Separators such as U+2028 remain accepted within the byte
limits. Named key events carry Enter/Tab separately.

## Production layout

`deploy/ipc/agentvault_installer.py` implements this layout. Reference config/plist templates
remain for tests. Sandbox installation has been tested; privileged host installation has not.

| Item | Value |
| --- | --- |
| Code identifiers | `dev.agentvault.broker`, `dev.agentvault.bridge`, `dev.agentvault.app` |
| Team | Bite Technology Limited Developer ID, `3JWAQ92CB4` |
| Mach services | `dev.agentvault.broker.read` and `dev.agentvault.broker.admin`, system bootstrap |
| LaunchDaemon | `dev.agentvault.broker`. `Program` only, no arguments. Runs as `_agentvault`. Umask 077. |
| Configuration | `/Library/Application Support/AgentVault/config.json`, root:wheel 0644 |
| Private data | `/private/var/db/agent-vault`, `_agentvault` 0700 |

The configuration file contains `{ "ipc": IPCConfiguration, "approvalPublicKey":
base64 X9.63 }`. The private data directory holds `keychain.password` and
`state-integrity.key` (32 random bytes each, owner-read-only 0400) and the broker's
`broker.lock`.

The installer first copies all three programs into protected staging and verifies publisher,
role, hardened runtime and exact code hash. It verifies the approval key against the fingerprint
read from the app, validates existing ownership and account state, and uses descriptor-relative
no-follow traversal and atomic installation. Seeds are never overwritten. A journal supports
retry after interruption. Changing code pins, paired UID or approval key requires separate
explicit options. Uninstall preserves the dedicated account and private data. See
[installation instructions and limits](INSTALLATION.md).

## Verification

Run these from the repository root on macOS in a logged-in GUI session:

```sh
swift test
python3 scripts/verify-xpc.py --evidence /tmp/xpc-evidence.json
python3 scripts/verify-xpc-mutations.py
```

`verify-xpc.py` does these steps:

1. Copies the fixture binaries and signs each copy ad hoc with its own identifier.
2. Signs a separate impostor build with the bridge's and the broker's identifiers.
3. Bootstraps three temporary `gui/<uid>` launch agents. Their plists are in a private
   temporary directory, and their labels contain a random run ID: the genuine broker, a
   broker that allows only `uid+1`, and the impostor broker.
4. Runs the scenarios.
5. Boots out exactly those labels, confirms they are gone and deletes the directory.

The scenarios confirm these results:

- The bridge reads, and the broker binds the bridge's kernel UID.
- The app completes snapshot, begin and authorize, and a replayed authorization is
  refused.
- The bridge cannot call the admin service, and the app cannot call the read service.
- A copied bridge signing identifier is refused, because its cdhash differs.
- Oversized requests, unknown keys, unknown operations and `null` values get fixed codes.
- An admin selector sent on the read service is not dispatched.
- With 12 concurrent calls on one connection, the 8 beyond the limit of four get `busy`.
- The broker refuses an unexpected UID.
- The bridge and the app both refuse a spoofed broker.
- A production configuration in a user-owned file is refused.
- Only the genuine broker's handlers run.

`verify-xpc-mutations.py` works on a scratch copy of the tree. It disables one defense at
a time and requires the matching scenarios to fail. Without the server's UID check, the
server's code requirements, the client's broker requirement, probe gating or the
concurrency gate, the matching scenarios fail. With only the listener requirement or only
the connection requirement removed, every scenario still passes. Each server layer
therefore enforces on its own.

Results on 13 October 2026, Apple Swift 6.2.4, macOS 15:

- Early IPC checkpoint: 61 tests passed (26 Core, 35 IPC); later integrated and review-fix
  results are recorded in [the verification record](verification/review-checkpoint.json).
- `verify-xpc.py`: 18 of 18 scenarios passed. All temporary labels were removed.
- `verify-xpc-mutations.py`: all 7 mutations behaved as expected.
- `swift build -c release` succeeded.
- The replacement Python installer passes its unit suite, guard mutations and signed-payload
  sandbox checks. Those checks simulate account creation and launchd and do not establish a
  working privileged installation.

## Unproven

- Separation by UID at runtime. Every verified process ran as the same user. The `uid+1`
  scenario shows that the broker rejects a UID it does not expect. It does not show that
  a dedicated `_agentvault` broker resists same-user inspection. That needs the
  privileged install, which remains a release gate.
- `.privileged` lookup and the Developer ID requirements against real signed builds and
  the installed LaunchDaemon.
- Code-requirement behaviour across `exec` or PID reuse beyond what XPC's per-message
  check provides. The tests do not cover this.
- Handler timeouts. A handler that never returns holds its in-flight slot. The root's
  handlers must bound their own work.
- Copying the genuine bridge binary yields the bridge's cdhash and signature. A code
  requirement identifies code, not the agent that runs it. Grants must stay bound to the
  paired UID and principal.
