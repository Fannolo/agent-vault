# VaultRecord

Synthetic committed-record codec, unit 1 of the password-ready vault work. It implements
candidate A §5 record kinds 1 (login), 2 (API token) and 3 (encrypted tombstone), as
corrected by root `SYNTHESIS.md`, `SERVICE-TAGS.md` and the proposed `SIGNATURE-PROFILE.md`.
The wire format is not approved or frozen. No product depends on this package, and it must
not receive real credentials until the format, parity and review gates pass.

Kind 4 (encrypted head snapshot) is reserved and refused. Collection protocol, store,
membership transitions, export, enrollment and cloud authority are outside this package.

## Construction

```text
record = P || u32(len(E)) || E || Ed25519(P || u32(len(E)) || E)
```

- `P` is the public `AVREC002` header: kind, vault, item, revision, membership body ID,
  author key and 0–16 strictly ascending parent body IDs.
- `E` is a complete AWS Encryption SDK message format v2 body, suite 0x0478, with one final
  frame. The profile fixes the encryption context, the `av-hpke-2` key provider and frame
  length 524,288. Each recipient gets one RFC 9180 base-mode HPKE wrap of the 32-byte DK.
- The payload is `u32(L) || logical || zeros`, padded to the smallest bucket from 512 bytes.
- `RevisionBodyID` hashes the signed body. It excludes the signature. `TransportDigest`
  hashes the whole record.

The unsigned 0x0478 suite does not authenticate a sender against other DK holders. The outer
signature is the only sender-authentication barrier. The codec verifies it under an
independently supplied `RecordAuthority` before any unwrap. Verification uses the vendored
BoringSSL `ED25519_verify` of swift-crypto 5.0.3 on every platform. The codec first checks
the A/R encodings and small-order values, and requires S < L. The OS verifier is never the
protocol predicate.

Kinds 1–3 reach at most the 32,768-byte bucket. The largest valid record is 37,780 bytes,
with 16 parents and 32 recipients. Records with a larger frame are refused before
decryption.

## Interface

```swift
let sealed = try RecordSealer.seal(content, identity: identity, authority: authority, author: writerKey)
let verified = try ParsedRecord(bytes).verify(under: authority, item: itemID, revision: revisionID)
try verified.open(as: recipientKey) { content in /* borrowed; secrets are SecretBytes */ }
```

The interface has no plaintext getter, no signing or verification oracle, no injectable DK
or RNG, and no credential content hash. `open` calls its closure only after every check
succeeds: signature, authority, exact recipient set, all X25519 keys (selected and
unselected), HPKE, commitment, header tag, frame tag, padding and schema. Errors are fixed
`RecordError` codes.

`SecretBytes` clears only its own allocation. Swift `Data` and arrays, the crypto libraries
and callers can leave transient copies. This package does not claim to erase them.

## Tests

Run `swift test` from this directory, or run the private owned verifier recorded with this
unit's evidence. The tests use publicly known synthetic keys and values.

For the parent's Linux byte exchange, the following test-only switches write or read a
private JSON file of public ciphertext. Each switch is enabled only by its environment
variable.

- `AV_RECORD_EXCHANGE_WRITE=/new/path swift test --filter exchangeProducer`
- `AV_RECORD_EXCHANGE_READ=/path swift test --filter exchangeReader`
- `AV_RECORD_REFERENCE_WRITE=/new/path swift test --filter awsReferenceProducer`: writes
  synthetic DKs for the AWS reference decryptor.

Standard output carries case names, public identities and pass markers only.
