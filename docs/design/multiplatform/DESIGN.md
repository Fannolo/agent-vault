# Native multi-platform Agent Vault

21 October 2026. Selected architecture; implementation proceeds in bounded reviewed units.
Existing macOS app remains a development implementation. Nothing in this document enables
cloud signup, live synchronization or generic website login before those units exist.

## User outcome

An agent visits Amazon and sees that it is logged out. It asks the local vault whether
it may use a corresponding account. The vault checks the authenticated client and human
grant, privately selects/fills an approved account in the trusted browser, handles required
human authentication, and returns login status. The agent continues normal website work.
It never receives password text, cookies, a browser profile or a debugging connection.

Linux and macOS each run their own native password manager, local broker and private
browser. Linux does not depend on a Mac. A cloud account provides signup/login and encrypted
own-device synchronization. Passwords are encrypted before upload and decrypted only in
trusted enrolled clients. Cross-user sharing is a separate collection/permission feature;
Windows can implement the same protocol later and is not a macOS/Linux delivery gate.

Broad website grants include submissions, messages, payments, deletion and account-security
changes, as explicitly chosen by the user. They remain client/account/site/time bound.
Credential sync never implicitly transfers local agent grants or client pairings.

## Architecture and ownership

One portable Swift core owns the encrypted record format and, in subsequent units, the
membership/checkpoint and conflict rules. Native platform adapters own human interaction,
protected local keys, installation and kernel-authenticated administrative/agent endpoints.
macOS reuses SwiftUI/XPC/Security work. Linux requires its own native UI, protected service
identity, peer credentials and installed browser/process/network containment. Swift alone
does not make those macOS adapters portable.

The cloud reference service authenticates users and stores ciphertext; it has no vault
decrypt endpoint. A cloud login or account reset must not enroll an encryption device or
recover vault keys. Initial device enrollment creates local signing and encryption keys.
New devices require controller-approved, transcript-bound pairing through trusted human UI.
A pinned recovery kit restores lost devices separately from cloud account recovery. Losing
all trusted devices and recovery material means losing access to the encrypted vault.

Each immutable item revision uses a fresh random data key. Its full username, password and
site metadata are encrypted once; standard HPKE wraps that key to each intended device or
recovery recipient. The author signs the complete canonical ciphertext and envelope set.
One device controls a signed membership lineage; independent item writers use immutable
version ancestry and retain conflicts instead of server-timestamp overwrites. This is a
custom application protocol over library cryptography, requiring external assessment.

An existing signed recipient set cannot be edited to add a device. A future separately
signed envelope-grant object must bind unchanged ciphertext and verified membership.
The first codec deliberately implements no such extension or mutable recipient slot.

The public agent API remains small: discover account availability for an owned tab,
request private authentication, check status, operate a current session and close it.
The broker derives origin/tab/document identity from its trusted host. An arbitrary
caller-provided CDP endpoint is not eligible for private filling. Existing unrestricted
third-party browser integrations require a separate trust design; they are not silently
supported by this proposal.

## Threat boundaries

Cloud transport authentication and vault decryption are separate. Treat cloud objects,
directories and timestamps as adversarial. Device pairing must defeat server key
substitution; local pinned checkpoints detect previously observed rollback. A new/recovered
device without recent trusted state cannot prove the server has supplied the latest history.
Signatures do not prevent withholding, partitioning or every fork. Signed client updates
and supply-chain controls are also necessary; an attacker controlling trusted client code
can steal plaintext when it is unlocked.

Revoked devices cannot be made to forget previously decrypted data. Exclude them from new
envelopes and rotate affected current item keys; separately revoke website sessions/change
credentials when needed. Offline grants have bounded leases and cannot promise immediate
remote revocation while disconnected. A headless Linux machine needs a trusted local human
path or a paired controller, which may itself run Linux. No terminal/env password fallback.

Native services must protect against the agent's OS identity, not merely use a desktop
keyring readable by that same user. Linux Secret Service alone specifies no access-control
boundary. Root/kernel, trusted broker/admin compromise and receiving-site compromise remain
explicit limitations. A website receiving a password can reflect it into visible text or
images; bounded controls/redaction do not prove universal secret non-disclosure. Prompt
injection can misuse account authority even without revealing the password.

## First unit: portable sealed-revision codec

`Packages/VaultCore` is a standalone trusted-service library with no executable product.
It does not change the root package, app, broker, bridge, MCP tools or live Keychain.
Exact dependency: Swift Crypto 5.0.3, with its resolved revision retained in the lockfile.
The library uses ChaChaPoly, Curve25519 signing/agreement, HPKE and SHA256; no custom cipher
or manual nonce counter. Swift Crypto uses platform cryptography on macOS and includes
BoringSSL on Linux; this choice avoids an additional native-library build, not all C code.

The unit seals/opens a bounded login record using trusted fixture context and recipient
keys, and admits immutable signed bytes into an in-memory duplicate/conflict log. Callers
supply pinned expected author trust; a record's self-described signing key is not membership
authority. Membership-head bytes are opaque expected context in this unit. No real device
enrollment, recovery-kit derivation, persistent sync state or freshness proof is implied.

The public operation hides key generation, sealing, recipient wrapping and signing. No
caller-supplied data key, nonce, HPKE sender context or add-recipient method. Opening verifies
canonical structure and pinned-author signature, compares expected context and only then
decrypts. Errors contain fixed case names. Secret-bearing values have redacted descriptions;
Swift memory wiping/absence of every hidden copy is not a claim.

### AVSEAL01 format contract

Numeric tags below are single bytes; counts and variable lengths are big-endian UInt32.
Identifiers are 16 bytes. Membership head and parent hashes are 32 bytes. The signed message:

1. Eight ASCII bytes `AVSEAL01`; version 1, suite 1, record kind 1.
2. Vault, item and revision IDs; membership head; 32-byte Ed25519 author public key.
3. Parent count followed by sorted unique parent hashes.
4. Payload nonce (12 bytes), ciphertext length, ciphertext, authentication tag (16 bytes).
5. Recipient count followed by sorted unique recipient entries. Sort role then raw key.
   Each entry: role (1 device, 2 recovery), 32-byte X25519 public key, 32-byte HPKE
   encapsulation, 48-byte wrapped data key including its authentication tag.

Append a 64-byte Ed25519 signature over exactly that signed message. Reject trailing bytes.
Payload associated data is the prefix through the parent section. HPKE info is ASCII
`agent-vault-sealed-revision-v1`, a zero byte, then suite byte 1. HPKE associated data is
payload associated data, SHA256(nonce || ciphertext-length || ciphertext || tag), role
and recipient agreement public key. Use a fresh HPKE sender once per wrapped 32-byte key.

Inside the encrypted payload: version 1, kind 1, length-prefixed UTF-8 username, raw password
bytes, origin count and sorted unique length-prefixed ASCII origin strings. This codec
does not establish browser origin authorization by accepting a string. Later policy adapters
must validate actual website origin/cookie/identity-provider scope.

Bounds: plaintext payload at most 262144 bytes; username at most 1024 bytes; password at
most 4096 bytes; at most 32 origins of at most 256 ASCII bytes each; 1–32 recipients;
0–16 parents. Check counts and lengths against limits and remaining input before allocation.
Unknown versions/roles, bad UTF-8, duplicates, unsorted lists, truncation and trailing bytes
fail closed. Fixed error cases: malformed, badSignature, badAuthentication, unexpectedIdentity
and conflict. The in-memory log never decrypts records or treats a signature as freshness.

A parent hash means SHA256 of the entire canonical encoded parent record, including its
signature. Exact-byte retries therefore have the same digest. This codec only carries
those hashes: resolving parents, validating ancestry, checking membership and pinning a
checkpoint belong to the next unit. There is no lineage or freshness API yet.

### Format limits and storage gate

Version 1 remains a synthetic development format. It has no padding: the server can infer
the combined encoded length of username, password and origins, and length changes between
revisions. Vault/item/revision identifiers, membership head, ancestry, author, recipient
roles/keys, counts and ciphertext lengths are visible. Encryption does not hide traffic
timing, object access or membership metadata from the service.

Version 1 also has no explicit data-key commitment. A signature authenticates the author's
chosen envelopes; it does not prove every recipient receives a key yielding the same
plaintext. A malicious authorized author can always withhold or corrupt a recipient's
wrap. A reviewed key-commitment construction addresses ambiguous-key decryption, not that
availability attack. Do not claim the current format provides multi-writer consistency.

Before non-fixture persistent storage or sharing, specify and independently review a
successor format with a version change, explicit data-key commitment and canonical bucketed
padding. Test malformed padding, commitment mismatch and recipient equivocation across
platforms. Do not retrofit changed bytes under version 1 or treat this codec's passing
tests as approval for real-password cloud storage. The first membership unit may use
synthetic records while that format gate is open.

LoginItem is a plaintext value inside the trusted service library. Its aggregate
description/mirror is redacted, but reading or dumping its public password property
reveals bytes. No app or MCP product links this library. A redacted secret wrapper and
scoped access must be designed before connecting service adapters; neither Swift Data
nor such a wrapper guarantees erasure or prevents trusted code deliberately reading it.

### Evidence required for this unit

Run the same behavior/hostile-input tests on native macOS and actual Linux aarch64 Docker.
Exchange unchanged synthetic ciphertext in both directions and open with two device keys
and a recovery key, rejecting an unrelated key. Test valid-signature wrong-context records,
tampered AEAD, recipient swaps/roles, canonical/size failures and duplicate/conflict behavior.
Capture output and reject synthetic secret/key leakage; deliberately planted logging and
signature-bypass defects must be detected. Freeze source/dependency/container digests;
review that exact implementation independently and rerun after material corrections.
Reject low-order recipient and encapsulated X25519 keys, including non-canonical/top-bit
encodings, rather than relying on a dependency's length-only public-key constructor.
Test Ed25519 S+L rejection, nonzero-start Data slices, exact UTF-8/BOM preservation and
admission of exchanged records into the pinned-author log on both platforms. HPKE input
validation follows [RFC 9180 section 7.1.4](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.4).

Passing this unit proves portable codec behavior only. It does not prove signup, cloud
sync, installed isolation, device membership/revocation, website login or production safety.

## Subsequent delivery units

The first group's accepted [membership design](MEMBERSHIP.md) separates an integration
guard/verification unit, session-local membership plus stateless authorization, and a later
retained-revision store. Its membership digest hashes the signed body without its signature;
the AVSEAL01 parent/revision digest above still hashes the complete immutable record.
Accepted design does not imply these units are implemented.

1. Signed membership, local encrypted database, pinned checkpoints and explicit conflicts.
   Resolve the successor-format storage gate above before persisting real credentials;
   define authenticated deletion/tombstones and parent resolution in this unit.
2. Native setup/unlock/import/approval adapters and installed identity boundaries on both OSes.
3. Maintained cloud signup/login, ciphertext sync, new-device pairing and recovery; local
   self-hosted tests before isolated staging, with malicious-server fixtures.
4. Private browser containment and discovery-first authentication, then continuing generic
   operation, human challenge/takeover, expiry and uncertain external-effect handling.
5. Linux-to-Linux headless approval/unlock; migration from the existing app's own Keychain
   namespace to one authoritative encrypted store; required file-transfer capabilities.
6. Supported live-provider workflow and actual signed/notarized/macOS and packaged/Linux
   distribution, upgrade/recovery/uninstall, plus external human security assessment.
7. Cross-user sharing in separate collections: explicit invitations, writer/reader roles,
   independently authenticated recipient keys, revocation/rekeying and recipient-consistency
   tests. Own-device synchronization does not imply this capability is implemented.

Each unit requires independent AI review of frozen source, meaningful positive and
negative runtime checks, retained private evidence and fresh review after material changes.
AI agreement, a signed build and a cryptographic primitive's assessment establish different
facts; none certifies the complete password manager.

## Synthesis and reconciliation

Base: independent candidate A, shared portable Swift core and per-recipient HPKE revisions.
Candidate B agrees on a shared Swift kernel and native authority but uses libsodium and a
shared epoch wrapping key. The cross-judge chose A (16/20 versus 15/20), chiefly for delivery
cost in this repository, and treated cryptographic strength as a tie. Rubric scores are
design judgments, not security measurements. B uses random 192-bit nonces, not shared nonce
counters; the retained distinction is common epoch-key authority and rotation cost.

Adopt B's exact-byte retries, recipient-envelope swap tests and isolation from root products.
Keep A's one-use per-recipient HPKE context and controller-signed device admission. Explicitly
omit future recipient-extension objects from unit one and use the current compatible crypto
pin rather than the older API probe. Both designs preserve malicious-server freshness and
endpoint-compromise limits. Frozen candidates, hashes and full Grok review remain private in
`verification-logs/multiplatform-design/`. No production verdict is inferred from that review.
