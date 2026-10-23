# VaultPersistence

Standalone synchronous local commit/pin kernel for opaque, already-encrypted state and
immutable opaque signed-object bytes. No root product depends on it. It does not implement
record encryption, signature verification, history validation, enrollment authorization,
head maps, grants, effect dispatch, sync or a password store.

A future trusted repository validates the cryptography, complete admitted inventory and
history before calling this kernel. The kernel hashes exact frames/objects and checks its
SQL inventory totals; those checks alone cannot authenticate a replacement inventory.
`SignedObject` is an opaque byte container, not a verified-authority capability.

## Ownership and calling contract

`VaultKernel` owns one private SQLite connection and a process-lifetime `flock` lease on
one stable inode. It is deliberately non-Sendable. Keep it in one Swift isolation domain;
never call it concurrently from unchecked legacy code. Calls are synchronous and contain
no network work or suspension. The connection and transaction stages never escape.

```swift
let store = try VaultKernel.openExisting(root: privateRoot, custody: protectedPin)
let expected = store.head
// Trusted repository validates history and seals outside the transaction.
let acknowledged = try store.commit(expecting: expected, next: sealedFrame, adding: objects)
// Only now may the repository release an external effect or publish a head.
```

`create` is a separate first-install operation requiring a private empty storage namespace
and a custody slot already provisioned as `.unenrolled`. Ordinary open never provisions
custody, creates missing files, rebuilds schema or supplies an empty state. Interrupted
creation stays locked for an independently authorized enrollment/recovery flow.

`VaultCustodyPin` is a bounded synchronous protected-custody port. Implementations must
make each compare-and-set atomic and durable before returning. The store cannot enforce
that promise or make the adapter non-rollback. There are no keys or raw-secret getters.
Paths are trusted installation inputs, never agent-supplied destinations.

## Transaction and recovery

A commit checks the expected generation, begins `IMMEDIATE`, verifies lease identity and
current head, inserts new objects and replaces the exact state in one transaction. It
persists pending `(old,new)`, commits SQLite, finishes stable `new`, then returns. Exact
object duplicates are idempotent; conflicting stored bytes and digest substitution fail
closed. Deterministic limit/stale-head refusals preserve state. SQLite write, commit or
custody uncertainty blocks the current instance until reopen; no success is guessed.

| Retained pin | Database state | Ordinary open |
| --- | --- | --- |
| Stable X | X | Open |
| Pending old/new | new | Finish pin, then open |
| Pending old/new | old | Abort pending, retain old; never replay |
| Stable new | old | Lock |
| Any enrolled pin | Third/missing/corrupt state | Lock |
| Unenrolled/enrolling | Any | Lock |

No admitted-object deletion or GC exists. Default kernel/test bounds are 1 MiB per object,
16 MiB state, 10,000 objects and 512 MiB total object bytes. `KernelLimits` permits explicit
bounded configuration. These are refusal budgets, not final product lifetime capacity.

## SQLite and filesystem boundary

SQLite is the platform system dependency, linked through a small C API shim. It is not a
vendored or exact-source-pinned SQLite build. The only explicit package dependency is
swift-crypto **5.0.3**, used for SHA-256; Package.resolved records its transitive resolution.
No SQLCipher, alternate store or copied record codec is included.

Settings are checked after configuration: DELETE journal, synchronous EXTRA, fullfsync ON
(effective on macOS), foreign keys ON, trusted_schema OFF, temp_store MEMORY, extensions
OFF and defensive mode ON. On builds with `OMIT_LOAD_EXTENSION`, the compile option is
the evidence for extensions being unavailable; that build rejects the extension db_config
opcode itself. Other unsupported configuration is an error.

Roots require canonical paths, effective-UID ownership and mode 0700, with protected
ancestry. Database, lease and existing journal require owner, regular-file, single-link,
0600 checks. The lease path must continue to name the locked inode. SQLite journals inherit
the private database mode. A cold unfinished journal can remain after a read-only reopen;
the next successful write removes it. No journal is manually discarded. No plaintext
search index, plaintext bound to SQL, backup API or disk-backed temp-store is introduced.
Freed pages can retain old ciphertext; there is no secure-deletion claim.

The boundary assumes a local filesystem, protected directory ancestry, cooperating single
owner, trusted custody adapter and honest OS/filesystem synchronization. Same-UID/root
attackers, lying fsync/storage, network filesystems and rollback of both data and custody
are outside the guarantee. A process SIGKILL is not a power-cut test.

## Native proof and parent Linux handoff

`Scripts/verify.py` imports **scripts/verify-webhost-link-mutations.py** from the enclosing
repository. Every build, test and probe goes through that canonical `run_owned`; each child
has a recorded owned process group. No blanket kills or process-name matching exist.
Crash probes use self-SIGKILL. Timeout (`None`) always fails. A failed build stops testing;
`--skip-build` follows a successful build only.

```sh
python3 -B Packages/VaultPersistence/Scripts/verify.py \
  --scratch verification-logs/durable-vault-kernel/dev-build \
  --evidence verification-logs/durable-vault-kernel/fresh-run --controls
```

Use a fresh evidence directory. Existing dependency checkouts can be reused; automatic
resolution is disabled. Parent owns independent native Linux CI; no VM, container,
OrbStack, service account or installed custody is required by this synthetic package.
Linux needs Swift 6.2+ and platform sqlite3 development headers/library. Inspect returned
OS, SDK where applicable, compiler, SQLite header/runtime/source IDs, library image,
compile options and actual settings. Do not infer Linux results from macOS builds.

Proof includes missing/corrupt enrolled files and pins, unsafe paths/modes/link counts,
lease replacement, third/stable rollback mismatch, pending resolution, table/state/object
and inventory tamper, duplicate/digest conflicts, capacity refusal and custody failures.
Separate processes cover a four-way lease race and five cuts: before pending, after
pending, after DB commit, after stable pin, after return. The runner decodes actual pin
artifacts and compares every recovered state/object byte and inventory total to exact old
or new fixtures. Synthetic bytes are **not encrypted** and contain no real credentials.

RLIMIT_FSIZE induces a real EFBIG write failure during commit. Pin adapter tests include before/after persistence failures and a real failing
`fsync(-1)` (EBADF) seam. The latter is deliberately test-only, not a disk-fsync failure.
Three compiled controls omit flock, create a missing DB on ordinary open, and acknowledge
without finishing the stable pin. Each must fail its named assertion, restore exact source
bytes, build again and pass its target. Full tests run again after controls.

`VaultPersistenceTestSupport` and `VaultPersistenceProbe` are test-only targets, not library
products or installed custody. The separate file pin uses write/fsync/rename/directory
fsync and assumes its directory is retained outside vault rollback. Its checksum detects
accidental damage, not malicious replacement. It is not installed Linux/macOS custody.

Open gates: independent Linux execution and review; actual SQLite ENOSPC, mid-transaction write and disk-fsync
faults; power-loss/VM filesystem behavior; installed dedicated-UID custody, backup/restore
scope and enrollment; authority/inventory validation; record format/auth acceptance;
head-map/capacity/retention design; broker migration/effect journal; browser/cloud flows;
signing and notarization. File wrong-owner refusal is exercised through a real foreign-owned
root; changing test database ownership across UIDs is not measured. This unit clears none
of those product gates and claims no production readiness or certification.
