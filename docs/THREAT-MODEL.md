# Threat model and measured guarantees

The separate portable codec under `Packages/VaultCore` is a new development unit. Its
current scope is signed immutable encrypted records with trusted fixture keys; it proves
no cloud enrollment/sync, native Linux isolation, recovery/revocation or browser integration.
The [multi-platform design](design/multiplatform/DESIGN.md) describes the new target and
explicit limitations. Existing implemented macOS boundaries below remain in force until
a separately reviewed migration; cloud login must never become vault decryption authority.

The synthetic U1 extension adds controller-signed membership, a bounded session-local fork
latch and stateless current-head revision authorization. It requires exact recipient
membership and validates every encapsulation before opening. Actual macOS/Linux checks pass
55 tests and agree on 150 pinned signature cases. Bidirectional reader-only exchange,
signature-flip refusal/restoration, 20 policy controls and separate low-order-key removal
are recorded in the [U1 evidence](verification/membership-u1.json). Three AI model reviews
accept that synthetic checkpoint; they are not a security certification.
These RAM checkpoints provide neither durable rollback protection nor global freshness.
The root app still does not link this fixture-only package.

The controls package also has a writable alias under the container's evidence mount.
Its read-only package mount is not hostile-container isolation; whole-copy snapshots detect
changes afterwards. Canary scans cover finite known synthetic encodings, and reader custody
checks are lexical over separately pinned source. The M10 scanner is scoped to a captured
step. In these runs its canary appears inside the named test interval, which is a measured
observation rather than a general enforcement guarantee. Native backend masking additionally
requires manual confirmation that the mutant source was compiled. A recorded cleanup gate
must be completed before further harness feature growth.

The root build's fixture-only maintenance guard rejects the portable package through
direct or transitive dependencies and checks declared compiler source paths by filesystem
identity, including dependency targets. Queries enforce pins and isolate resolved JSON from
normal fetch diagnostics. It trusts SwiftPM's metadata and does not detect copied/renamed
implementations, trace arbitrary compiler plugins or constrain a hostile maintainer.
It is not an OS sandbox or a runtime credential boundary.
The directory anchor does not authenticate fixture contents. A leftover ignored .build
directory after a local move can hide a renamed fixture from the local path check.
Clean CI checkouts refuse a missing anchor. The token/symlink manifest scan covers the
default Package.swift only; semantic graph checks use SwiftPM's selected manifest.

The prototype AVSEAL01 version 1 format exposes record length, identifiers, ancestry and
recipient metadata. It has no padding or explicit data-key commitment. An authorized
writer is not proven to give every recipient a consistent plaintext. A reviewed successor
format is a gate before persistent real-password storage or cross-user sharing. Current
LoginItem plaintext is for trusted service code only; aggregate redaction does not hide
an explicitly read password property or guarantee memory erasure. See the design's
[format limits and storage gate](design/multiplatform/DESIGN.md#format-limits-and-storage-gate).

Agent Vault exposes fixed read-only operations and safe metadata. No MCP operation returns a
password, PIN, token, cookie, raw page, profile path, CDP endpoint, arbitrary URL, executable
recipe or script. Every invocation checks a live account/action grant, reserves attempt budget,
and checks authority again after credential access and before returning output.

## Installed design

The intended production broker runs as the hidden `_agentvault` user. Root owns its signed
executable and configuration. Its private directory, explicit Keychain database and metadata
integrity key belong to that dedicated UID. Startup refuses root, equal broker/client UIDs,
unsafe ownership, permissive files, invalid code requirements or another live broker owner.

Read and admin are separate XPC services. Both endpoints check Apple Developer ID, exact code
hash, role identifier and kernel effective UID. Clients complete an empty authenticated probe
before transmitting any request, including enrollment credentials. A copied genuine bridge
shares its original code identity; permissions belong to the paired OS user and bridge, not
to an individual model, chat or host name.

Admin mutations require a single-use challenge signed by the human app's protected
P-256 key. Its digest binds operation metadata, challenge ID, random nonce and expiry.
Credential bytes and credential-content hashes are excluded from that digest. The broker
freezes the actual request privately and verifies the configured public key. The app
recomputes the digest from its request before allowing a signature and
requests fresh device-owner authentication for every signature and refuses unprotected or
unverifiable keys. Public-key registration is a trusted installation ceremony; the public key
alone is not hardware attestation. The approval key never stores service credentials.

## Verification limits

The dedicated-UID installation, real protected-key signing and notarization have not passed
runtime verification. Same-UID signed fixtures demonstrate code and role rejection, not OS
filesystem or process-memory isolation. **Do not enroll production passwords or PINs until the
remaining gates in IMPLEMENTATION-PLAN.md pass.** The legacy `agent-vault` developer CLI runs
Core in its own user process and retains no same-user confinement guarantee; it is excluded
from distribution review bundles.

The old WebKit engine and its same-process continuation view have been removed. Selected
headless-host tests use isolated contexts, fixed origins/recipes and a native image/input
relay. Synthetic U5 tests join the real host, authenticated XPC and app model. Browser accounts
and actions remain disabled in production. Installed continuation, live GitHub selectors
and CAPTCHA compatibility are unverified.

The selected headless path now has an authenticated host wire and Core port, tested
with synthetic XPC peers. Credentials are withheld until an empty host probe passes code
and UID checks and Core rechecks live authority immediately before dispatch. Run losses
are scoped to the connection generation; start/classify waits have Core-owned deadlines.
Initial read cancellation ends its browser run, including late contexts; admin handlers
continue to completion. Terminal host-peer loss prevents replacement peers and drops late
results. Host teardown prevents late context creation. App-safe frame/input types and native
JPEG validation do not establish an installed human relay or OS isolation.

The separate U2 executable now implements fixed Chromium workflows over private pipes,
with no TCP debugging endpoint. A serial nonblocking writer enforces each call's deadline
outside the state lock; teardown kills only its spawned process group. Run admission waits
for confirmed paused auto-attach. Exact-origin/phase gates and a CSP delivered with each
document constrain the fixture's page traffic. They are not OS-enforced egress: Chromium's
browser and network utility processes are unsandboxed. Same-UID loopback and renderer
sandbox observations do not establish the installed daemon, whole-process network policy,
signed distribution or live GitHub workflow. The production broker still composes no host.

Human continuation uses a server-minted connection UUID and synchronous liveness flag.
A signed open names the exact run, account, step epoch and kind. Relay calls check the
grant and lease; Finish/Cancel refuses an already closed connection before its delayed
cleanup callback. Admitted admin work retains its completion semantics. Separate bounded
continuation capacity preserves admin capacity. ImageIO checks JPEG type, count, dimensions
and orientation; this trusts the OS decoder. Finish drains input acknowledgments and late
polling cannot overwrite its result. U5 exercises host-to-app-model integration on a synthetic
origin under the same UID; visible GUI, protected-key and installed multi-UID proof remain open.

Browser signals use a handle that pins its spawned leader until reaping. The reaper kills
remaining group members before releasing the ID. Watcher failure triggers kill-and-wait;
EINTR retries. Unconfirmed waits disable signals without reporting successful cleanup,
potentially retaining a zombie until host exit. This controls only the owned process group;
a compromised child escaping that group is not confined by the handle.

## Trusted parties and exclusions

The OS, protected installer, selected publisher, authenticated human app, broker and fixed
service endpoints are trusted. Root/administrator compromise, replaced installation policy,
compromised signing authority plus a root-approved update, and a compromised broker are outside
the guarantee. A service receiving credentials can misuse them or encode them into permitted
output fields; typed schemas are not a proof of information-flow noninterference.

Revocation cancels pending approvals and tears down local session state. It cannot recall an
external request already dispatched. A fixed HTTP operation refuses cancellation after
dispatch. A browser cancellation ends its owned context, without claiming to undo an
external request. An unreadable final policy state suppresses output and invalidates
any adapter session. Operations are read-only; future writes require provider idempotency and
an explicit uncertain-outcome/reconciliation design.

## Storage, retention and resources

Enrollment, rotation and deletion persist intent before mutating Keychain, retain item IDs
across interruption, and recover under the daemon's exclusive owner lease. No automatic
migration reads a user's existing Keychain or version-1 developer state. Production metadata
requires an HMAC with an independent broker-only key and refuses unsigned downgrade. The latest
audit history is bounded metadata: 256 reserved administration entries and 744 invocation
entries in schema 3. Agent traffic cannot evict the administration partition; administration
traffic can still evict older administration entries. No-op recovery emits no administration
entries. Startup recovery retries keep a representative start until global completion or
genuine administrative account cleanup, rollback or recovery completes; intent and failure
records alone cannot reset it. Repeated failure
and uncertain outcomes for the same account are coalesced until a real lifecycle transition.
Alternating those failure kinds does not reset their representatives. This applies across broker
restarts because the representatives live in the persisted administration history. They retain
the first observation, not an exact retry count or most recent failure timestamp. Repeated denials
and unapproved-request events for the same client/account/action are coalesced until a real reservation or terminal
event resets that tuple. They are representative events, not exact attempt counts. Invocation
overflow evicts the oldest entry from the registered client with the largest retained history,
using the oldest entry across tied clients. With at most 128 registered clients, a client that
has accumulated five entries retains at least its latest five while it remains registered;
unused capacity is shared. One client's successful flood cannot erase another client's smaller
history. This floor applies while the registered population is stable; trusted administration
can prune clients and change that population. Unregistered callers do not create entries or
retention partitions, and existing history from pruned clients is evicted first under pressure. Completed calls remain subject to
this bounded retention. HMAC detects modification, not replay of an older
authentic snapshot or deletion by a privileged attacker; audit is not an immutable witness.

The MCP transport bounds input before SDK parsing: 64 KiB per line, depth 64, 16 queued and
outstanding requests, strict JSON-RPC envelopes and duplicate-key/ID refusal. Notifications
are limited to 8 KiB and 64/second with a burst of 16. Output is capped at 1 MiB with a write
deadline. XPC bounds request/reply sizes, connections and concurrent handler calls. The pinned
Swift SDK and dependencies are inventoried, not independently audited.

Read traffic has 32 handler slots and administration has four independent slots. Cheap empty
authentication probes do not consume those handler slots. Pending invocation approvals have
a 120-second lifetime; waiting resumes report that approval is still required. The dedicated
broker's explicit Keychain is unlocked with its private seed before every access, including
after sleep or an explicit lock. Its lock policy stays unchanged. The native settings-change
probe blocked inside Security.framework; no GUI dialog was observed. The settings change was
removed. No Keychain
setting or search list is changed.

Synchronous credential operations run off the broker actor with at most four actual operations
and no waiting queue. Reads reserve at most three slots, leaving one slot available to lifecycle
writes even when agent reads stall. After authorization checks, a read slot is reserved in the
same synchronous metadata transaction before consuming approval or attempt budget. A capacity
refusal leaves both intact for retry; an admitted attempt spends budget even if credential
access fails. Unused reservations are released when their metadata transaction fails, and each
reservation can start only one read. Calls have a five-second deadline; a timed-out operation
retains its slot and pending-write guard until it really finishes. Late results are discarded. Uncertain writes
retain lifecycle journals and cannot race recovery or another mutation. This keeps metadata
revocation responsive to a stalled credential store; it does not cancel an operation inside
Security.framework. The private database password remains in broker memory for explicit unlocks.

Recovery first closes admission for new credential invocations and lifecycle mutations, then
asynchronously drains existing credential workers and lifecycle mutations before reading their
journals. This drain is bounded by the credential-operation timeout (five seconds by default),
so continuous read traffic cannot starve maintenance. A drain timeout returns busy and preserves
the journals and actual-worker tracking. Metadata and revocation stay responsive; the admission
gate is released whenever recovery exits, including cancellation or failure.

Swift/Foundation may copy immutable credential buffers and strings. The design does not claim
complete RAM zeroization. Native tests use unique synthetic namespaces and delete only their
own entries; real credentials and business evidence are never fixtures. Without the explicit
`AGENT_VAULT_KEYCHAIN_TEST=1` opt-in, the two native storage tests are reported as skipped rather
than passed.
