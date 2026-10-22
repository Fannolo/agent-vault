# Membership lineage and revision authorization

Design accepted on 21 October 2026 after two independent Opus 5.5 review rounds and root
review. Corrected U0 source passes its native/Linux and guard/runner checks after review
fixes. Opus 5.5 and Grok 4.7 accept the bounded unit. Opus also accepts the applied small
hardening follow-up. Its final current-source runtime checks pass.
The [U0 evidence](../../verification/membership-u0.json) records current and initial results.
The synthetic U1 implementation is now present in the separate package. Early checks pass
55 tests on macOS and Linux, with agreement on all 150 pinned signature cases. Complete U1
exchange, controls and final review remain pending. Cloud synchronization, durable rollback
protection and product readiness remain later work.

The reviewed design is candidate A v2, SHA256
`ec01875ba9fa13fd762f150004fa39d66e107a7511b37bd214ca79649895c539`, with the text-only
constraints below. The existing AVSEAL01 codec remains unchanged and fixture-only.

## Trust and key separation

One immutable controller signing key governs membership. One distinct immutable writer
signing key authors revisions. Genesis also pins that writer's agreement key. Readers and
recovery recipients have decryption capability without membership or writing authority.
A successor may disable and later re-enable the same writer. Rotation, new writer
identities, controller transfer, remote pairing and recovery of authority are later units.

The controller mints signed genesis from trusted local fixture inputs and returns its bytes
and a typed anchor containing the vault ID and genesis body digest. The writer input is a
public key. Validators receive an independently established typed anchor and untrusted
genesis bytes. Reader setup constructs only that reader's own agreement private key; it
never constructs controller/writer signing keys or calls the all-authority fixture helper.
There is no server-derived anchor decoder or tautological local writer possession proof.

A producer validates its own output through a separate verifier session to obtain the
checkpoint used to mint successors. A typed anchor records a trusted bootstrap decision;
it does not authenticate a human or implement a device-enrollment protocol.

## AVMEMB01 encoding

All integers are unsigned big endian. Fields are exact-width, with no optional fields,
extensions, implicit padding or trailing bytes:

```text
record = body || controllerSignature[64]
body =
    "AVMEMB01"[8] || version:u8=1 || suite:u8=1 || kind:u8=1 ||
    vaultID[16] || sequence:u64 || parentMembershipDigest[32] ||
    controllerSigningKey[32] || writerSigningKey[32] || memberCount:u32 ||
    member[memberCount]
member = role:u8 || capability:u8 || agreementKey[32]
```

The body prefix is 135 bytes. Each member is 34 bytes. There are 1–32 members, giving body
sizes 169–1,223 and full-record sizes 233–1,287 bytes. Bound before copying, validate the
count and exact remaining length before allocation, and require canonical re-encoding.
Nonzero-start Data slices must work.

Closed member combinations are device reader `(1,1)`, device writer `(1,3)` and recovery
recipient `(2,5)`. At least one device is required. Genesis requires exactly one writer;
successors permit zero or one. Rows sort strictly by role then agreement key. Reusing an
agreement key across roles is forbidden. Member X25519 coordinates must be canonical
unsigned little-endian values below `2^255-19` and pass the existing zero-DH check.

The controller signs the complete body. Membership identity is `SHA256(body)`, excluding
the signature. Every received signature is verified, including duplicate candidates.
Different valid signatures over one body have one identity. The first signed representation
is retained. This accommodates randomized signing; a native CryptoKit probe produced two
different valid signatures for the same message/key. The probe establishes that native
behavior only. Cross-platform implementation tests remain required.

Revision identity stays `SHA256(full canonical AVSEAL01 record)`, including its signature.
Membership and revision digests use distinct types. Neither is a password fingerprint.

## Session-local lineage

Genesis has sequence zero and a zero parent. Initialization checks the independently pinned
body digest, vault/sequence/parent, signature and member policy before installing state.

Advance order is structural parse, anchored vault/controller identity, pinned controller
signature, lineage classification, semantic member policy, capacity, then one synchronous
commit. No callback or suspension occurs between validation and state replacement.

- A valid old body duplicate returns the current checkpoint and never rolls it back.
- A different authenticated body at an observed sequence latches a membership fork.
- An authenticated immediate successor with a parent different from the current head
  latches a signed-lineage contradiction before semantic policy or capacity checks.
- A sequence gap returns `missingPredecessor` without inventing missing history.
- An ordinary invalid input leaves state unchanged. An invalid signature never poisons it.

A changed controller header is rejected as a foreign authority namespace before signature
verification or latching. A changed writer under the pinned controller remains a statement
inside the supported namespace. This intentional distinction limits which statements count
as lineage evidence; it does not promise detection of every malformed controller statement.

Keep both full signed records in the one bounded latch. Once latched, advance, authorize
and open fail; diagnostics may read the retained checkpoint/evidence. A wrong-parent pair
does not prove that its missing alternative parent exists. Semantically invalid statements
rejected before a supported body was accepted are not retained, so detection can depend
on arrival order. No-op successors with unchanged recipients are valid.

History retains 256 snapshots including genesis with no eviction. Signed history bytes are
at most 329,472; a separately reserved evidence pair adds at most 2,574. Object overhead and
bounded transient buffers are additional. Contradictions still latch at capacity; duplicate
receipts still succeed. Arithmetic and conversions remain checked.

The checkpoint is observed RAM state. Restarting from genesis loses prior observations.
Neither signatures nor this checkpoint prove freshness, reveal withholding, compare every
partition or prevent restoration of an older durable image.

## Stateless revision policy

`authorize` parses existing AVSEAL01 bytes, checks caller-expected vault/item/revision IDs,
verifies the pinned writer, checks the current membership head and active write capability,
requires the complete recipient set to equal validated membership, and validates every
encapsulated key, including unselected envelopes. It returns a digest and `authorizedAt`
checkpoint receipt. It retains no revision, parent graph, item head or revision-ID registry.

`openAtCurrentMembership` reauthorizes the supplied bytes, checks the requesting recipient
is a current decrypting member, then calls unchanged `openRevision` with independently
expected context and author. A receipt is never accepted as opening authority.

Every membership advance currently makes old-head records unavailable through this policy,
even after adding a reader. A limitation-pin test must preserve that explicit behavior.
Future historical opening requires review of the entire successive membership path,
creation/admission rules and removal/re-addition behavior. Raw decryption with previously
held keys remains possible; policy cannot erase plaintext or old keys.

Complete recipient matching does not prove every wrap carries a consistent or usable data
key. A malicious authorized writer can withhold, corrupt or disclose content. A controller
can enroll an attacker or sign contradictions. Version 1 still lacks padding and explicit
data-key commitment.

## Delivery and acceptance gates

U0 implements the semantic fixture-only integration guard, unchanged codec baselines on
Mac/Linux, and raw open-side validation-removal control. It does not rerun exchange. The
Linux control must detect the removed check; native backend masking is reported separately.
All commands, source/helper/log/artifact hashes, mutation/restoration and owned-container
cleanup are bound to the evidence. Original codec and verifier files stay unchanged.

The guard scans the default Package.swift, Sources, Tests and actual root target paths, with semantic
dependency/product checks and source/symlink checks. Unrelated generated output and root
manifest maintenance remain supported. Existing graph assertions are retained; the overall
entry point explicitly refuses optimized Python rather than silently disabling them. New
semantic helper checks use explicit failures and are tested under both interpreter modes.
Dependency checks must include the full resolved tree: an innocuous wrapper package must
not transitively introduce the fixture package. Direct `describe` dependencies alone are
insufficient. Alias and canonical-path checks apply at every resolved dependency node.
Queries force the lockfile's pinned versions. Resolved-tree JSON uses an owned private
output file so normal fetch diagnostics do not corrupt it. Dependency target directories
and declared source files are checked by filesystem identity against the fixture subtree;
this catches renamed targets and symlink/case aliases without rejecting safe ancestor
packages or scanning unrelated dependency comments. This trusts SwiftPM metadata and
does not trace arbitrary compiler plugins or provide a hostile-maintainer sandbox.
SwiftPM's graph describes its selected manifest, including a version-specific manifest.
The lexical and symlink manifest scan covers only the default Package.swift file.

The fixture anchor must be a directory. The guard does not authenticate that directory's
contents. An ignored .build directory left after a local move can hide the relocation
when a renamed wrapper uses the moved sources. A clean checkout refuses an absent anchor.
The separate codec recorder also requires the exact package files and frozen digest.

U1 adds membership and stateless authorization. All original 21 codec tests must still pass
unchanged in the combined package on both platforms. New code must not add extension
members to Data, existing VaultCore internal types or Crypto types that could shadow old
codec calls. Add a mechanical reader-fixture custody check; the validation helper's fresh
random X25519 probe is allowed because it is not an authority key.

U1 also requires the pinned 150-case Wycheproof Ed25519 corpus, exact expected outcomes on
both backends, separate reader-only bidirectional exchange, hostile grammar/policy/fork
tests and attributable compiled controls. Signature cofactor edge coverage is separately
recorded; a stronger agreement gate blocks independent multiwriter authority. Exact corrupt
exchange failure markers belong to that exchange unit. Broader marker/parser infrastructure
is not part of U0.

U2 requires its own review before retaining revisions, resolving parents, tracking conflicts
or handling revision-ID equivocation. Durable storage, tombstones, real pairing, native
custody and browser integration remain later work. Persistent real passwords and sharing
remain blocked on a reviewed successor format with padding/key commitment and the required
durable authority/storage policies. Software Curve25519 keys do not become hardware-backed
merely because they are used through a native library.
