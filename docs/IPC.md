# Broker IPC

`AgentVaultIPC` connects three programs over XPC on macOS: the broker, the MCP bridge
and the human app. The same closed wire and handlers also run over kernel-authenticated
Unix sockets for the Linux service; see [Unix-socket transport](#unix-socket-transport). The bridge may use only the read service. The app may use only the admin
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
| `openHumanStep` | `requestID`, `accountID`, `stepEpoch`, `humanStepKind` |
| `recover`, `prune` | none |

`authorize` takes a 36-character UUID string and a signature of 8–72 bytes. That range
covers both DER and raw P-256 signatures.

Each reply is a JSON object with exactly one key: `readReply`, `snapshot`, `challenge`,
`adminReply`, `humanFrame`, `humanReply` or `error`. Each method accepts only its own kinds plus `error`. The server
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

`VaultXPCServer(configuration:limits:read:snapshot:begin:authorize:continuation:connectionClosed:)`
takes async handlers. Read and snapshot receive the bound kernel UID; human administration
receives the server-minted `AdminConnection`:

- `(UInt32, ReadRequest) -> ReadReply`
- `(UInt32) -> AdminSnapshot`
- `(AdminConnection, AdminRequest) -> AdminChallenge`. Throw `AdminRejection(status:)` to send an
  `AdminReply` instead. Any other error becomes `unavailable`.
- `(AdminConnection, UUID, Data) -> AdminReply`
- `(AdminConnection, ContinuationRequest) -> ContinuationReply`
- `(AdminConnection) -> Void` when that connection closes

`VaultReadClient.perform(_:)` returns a `ReadReply`. `VaultAdminClient` has these operations:

- `snapshot()`
- `begin(_:)`, which returns `.challenge(AdminChallenge)` or `.rejected(AdminReply)`
- `authorize(id:signature:)`
- `continueHuman(_:)`

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

`HumanFrame` and bounded typed `HumanInputBatch` are App-safe contracts. U3/U4 relay
them over the existing admin connection's `continueHuman` selector. Its separate lane
allows two calls per connection and four globally, preserving the admin handler reserve.
Each accepted connection has one server-minted UUID; invalidation marks it closed before
the asynchronous cleanup callback. Signed opens bind a preexisting run, account, step epoch
and kind; the returned lease belongs to that connection. Snapshot replies include the
available `humanSteps`. No MCP human-input or generic browser operation was added.

Continuation requests have exact keys: `frame` uses `operation`, `lease`, `after`;
`input` uses `operation`, `lease`, `batch`, `frame`, `events`; `finish`, `cancel` and `close`
use only `operation`, `lease`. Requests are capped at 8192 bytes, input at 32 events and
text at 64 bytes per event. Frame/input authority is checked before and after host calls;
sequences, served-frame dimensions and pacing are enforced per lease. Finish/Cancel checks
synchronous liveness at admission. Admitted work completes under its own deadline.
The app validates the JPEG's actual raster dimensions before rendering and drains input
acknowledgments before Finish. Full integration with the real host remains unverified.

`AgentVaultWebHost` now implements that wire as a separate executable, with a four-run
table, once-only run IDs and a shared launch barrier before target creation. Its bounded
nonblocking CDP writer cannot hold the state lock while a browser stops reading. The
production service/plist/pins and installed system-domain host link remain unverified;
the broker still configures no host. Other product targets are forbidden from linking
the host executable, in addition to its dependency exclusions.

Text events and web credentials exclude Unicode Cc/Cf control and format scalars,
including ZWJ, LRM and BOM. Separators such as U+2028 remain accepted within the byte
limits. Named key events carry Enter/Tab separately.

## Unix-socket transport

`VaultSocketServer`, `VaultSocketReadClient` and `VaultSocketAdminClient` carry the same
closed `ReadRequest`, `AdminRequest`, authorize and continuation messages as XPC. Both
transports call one `BrokerHandlers` value, built by the daemon's `BrokerComposition` from
`ReadOperations`, `Administration` and `ContinuationOperations`. Permission logic stays in
the broker; the transport adds no grant, approval or pairing rule of its own.

`SocketConfiguration` replaces code requirements with kernel UIDs:

| Field | Meaning |
| --- | --- |
| `read.path`, `admin.path` | Absolute socket paths, at most 103 bytes, portable characters only. |
| `read.clientUID` | The only peer UID the read socket serves: the agent's OS account. |
| `admin.clientUID` | The only peer UID the admin socket serves: the controller's OS account. |
| `read.group`, `admin.group` | Group of each socket file, which is mode 0660. Defense in depth only. |
| `brokerUID` | The only socket peer UID a client accepts as the broker. |
| `development` | Allows equal UIDs and group 0 for single-user tests. |

Production requires three distinct non-root UIDs. An agent that shares the controller's
UID could read administrative snapshots; it would still need the pinned controller's
signature for any mutation. The installed file is `/etc/agent-vault/sockets.json` and must be
root-owned and not group/other writable, in a directory with the same property.

Identity and framing:

- The server reads the peer UID with `SO_PEERCRED` on Linux and `getpeereid` on macOS
  before it reads any byte, and closes a connection whose UID does not match its endpoint.
  A refused peer sees the stream end. On Linux, a peer that already wrote bytes sees a reset
  instead, because the server closes without reading them.
  Clients check the broker UID the same way before writing any byte. No request field
  names a UID or a connection. A small C target, `CAgentVaultSocket`, isolates these calls.
- A request frame is `length:u32be | id:u32be | opcode:u8 | body`; a reply is
  `length:u32be | id:u32be | body`. The ID only matches replies; it carries no authority.
  Read and admin opcodes are disjoint. An opcode from the other role, an unknown opcode or
  a duplicate in-flight ID closes the connection without a reply. An ID is in flight from
  the moment its request is read until its reply, error replies included, has been written
  in full or dropped, not merely until its handler returns. The clients never reuse an ID on
  a connection; a peer that reuses one at the instant its reply is written can be closed.
- A body above `maxRequestBytes` is refused from the header with `request_too_large`, and
  the connection is closed. A malformed body gets the same fixed codes as XPC and the
  connection stays usable.
- An idle connection stays open. Once a frame starts, it must complete within 5 seconds.
  A reply write must complete within 5 seconds. Client calls have one monotonic deadline
  covering connect, write and reply. `EINTR`, partial reads and partial writes recompute the
  remaining time from that deadline. Every read and write attempt first checks the deadline
  and the server's stop signal, so a peer that always has bytes ready cannot outlast either,
  and a client call that expired while queued is never sent. The accept loop checks stop
  before each accept. Writes use `MSG_NOSIGNAL` or `SO_NOSIGPIPE`.

Capacity and lifetime:

- Connection, per-connection and per-service limits are the `IPCLimits` values used by XPC,
  with the same separate admin and continuation lanes. Excess connections are closed.
- Every reply, including `busy` and other error replies, counts against the per-connection
  backlog from the moment it is queued until it is written or dropped. The
  `maxInFlightPerConnection` threshold pauses admission; already admitted handlers may still
  enqueue their replies. A conservative queued-reply bound is `R + H + 1`, where `R` is that
  threshold, `H` is the bounded per-connection handler capacity, and the extra reply covers
  terminal oversized-frame rejection. One complete request frame may also be read ahead of
  admission. A handler keeps its connection and service capacity until its reply is written
  or dropped. While the backlog meets the threshold the reader waits. A peer that
  stops reading its replies therefore stops being served, and the first reply write that
  misses its deadline closes the connection; requests it had sent but the server had not
  read get no reply, and the client reports `timeout` or `connection_failed` for them.
- A read handler is cancelled when its connection ends. Admin handlers run to completion;
  their reply is dropped if the connection is gone, and the client reports `timeout` or
  `connection_failed` for an unknown outcome. Nothing retries a mutation.
- Each admin connection gets an `AdminConnection` minted at accept. Its liveness is cleared
  when the connection ends, before the broker's closed callback runs. A continuation lease
  therefore needs the client's one persistent connection; after a reconnect it needs a new
  signed open. The connection's slot stays taken until the closed callback finishes, so
  reconnecting cannot outrun the broker's cleanup.
- Only a connection's writer queue closes its descriptor, after the reader thread exits.
  `stop()` wakes every thread, closes listeners and peers, and returns only after every
  descriptor is closed and every handler task has finished.

Socket files:

- The socket directory and every ancestor must be a real directory owned by root or the
  broker UID. The directory itself must not be group/other writable. An ancestor may be
  writable only with the sticky bit, as `/tmp` is.
- Each socket path has a lock file, `<path>.lock`, mode 0600 and owned by the broker UID. A
  server takes an exclusive `flock` on it before it checks the path and holds it until stop,
  so a second broker starting on the same path fails `unavailable` and cannot replace or
  unlink the first one's socket. A lock file that is not a regular file owned by the broker
  UID fails `invalid_configuration`. Lock files stay after stop.
- Under that lock, an existing path is replaced only if it is a socket owned by the broker
  UID that refuses connections. A live socket fails `unavailable`. Any other file fails
  `invalid_configuration` and is left in place.
- The socket's device and inode are recorded right after `bind()`. Mode 0660 and the group
  are set before `listen()`. A failed start and `stop()` unlink a socket only while it still
  has that recorded identity, and stop unlinks it before releasing the lock.

The Linux `agent-vault-broker` validates `sockets.json` for the broker role and then exits
with `custody_unavailable`. Vault key custody through a systemd encrypted credential is the
next delivery unit. There is no fallback secret store. The Linux MCP bridge is built with
portable bounded stdio and the read-only Unix-socket client. It uses fixed installed socket
configuration and the same four MCP tools as macOS. This does not establish a serving Linux
daemon, installed UID separation or systemd key custody.

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

- The Unix-socket transport on an installed Linux host. Tests run both roles under one UID,
  with denied UIDs simulated by configuration. Dedicated broker, agent and controller
  accounts, systemd units and socket directory provisioning have not been run.

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
