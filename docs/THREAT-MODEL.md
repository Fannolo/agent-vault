# Threat model and measured guarantees

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

The controlled WebKit library passed real loopback hostile-page tests. It uses ephemeral,
separate data stores and fixed origins/recipes. It is not linked into the production daemon
or human app: a system LaunchDaemon cannot present its human continuation view. Browser
accounts and actions remain disabled in production. Live GitHub web selectors and CAPTCHA
continuation are unverified.

## Trusted parties and exclusions

The OS, protected installer, selected publisher, authenticated human app, broker and fixed
service endpoints are trusted. Root/administrator compromise, replaced installation policy,
compromised signing authority plus a root-approved update, and a compromised broker are outside
the guarantee. A service receiving credentials can misuse them or encode them into permitted
output fields; typed schemas are not a proof of information-flow noninterference.

Revocation cancels pending approvals and tears down local session state. It cannot recall an
external request already dispatched. Cancellation after dispatch is refused rather than
claiming the work stopped. An unreadable final policy state suppresses output and invalidates
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
entries. Startup recovery retries keep a representative start until completion; repeated failure
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
