import Crypto
import Foundation
import Testing
@_spi(SecretReveal) import VaultSecret
@testable import VaultRecord

// Publicly known synthetic test material only; never suitable for real credentials.
let syntheticCanary = "AV_RECORD_SYNTHETIC_CANARY_3B9E51A4"

func key<T>(_ seed: UInt8, _ make: (Data) throws -> T) -> T {
    try! make(Data(SHA256.hash(data: Data("AV/record-test-key/\(seed)".utf8))))
}

/// Deterministic synthetic writer, two devices, recovery and an unrelated key.
struct Fixture {
    let author = key(1) { try Curve25519.Signing.PrivateKey(rawRepresentation: $0) }
    let otherAuthor = key(2) { try Curve25519.Signing.PrivateKey(rawRepresentation: $0) }
    let device1 = key(11) { try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: $0) }
    let device2 = key(12) { try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: $0) }
    let recovery = key(13) { try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: $0) }
    let unrelated = key(14) { try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: $0) }
    let vaultID = try! VaultID(Data(repeating: 0xa1, count: 16))
    let membership = try! MembershipBodyID(Data(repeating: 0xb2, count: 32))
    let itemID = try! ItemID(Data(repeating: 0xc3, count: 16))
    let revisionID = try! RevisionID(Data(repeating: 0xd4, count: 16))

    var recipientKeys: [RecipientKey] {
        [RecipientKey(role: .device, privateKey: device1), RecipientKey(role: .device, privateKey: device2),
         RecipientKey(role: .recovery, privateKey: recovery)]
    }

    var recipients: RecipientSet {
        try! RecipientSet(recipientKeys.map { try Recipient(role: $0.role, publicKey: $0.privateKey.publicKey.rawRepresentation) })
    }

    func authority(vault: VaultID? = nil, membership: MembershipBodyID? = nil,
                   author: Data? = nil, recipients: RecipientSet? = nil) -> RecordAuthority {
        try! RecordAuthority(vaultID: vault ?? vaultID, membershipBodyID: membership ?? self.membership,
                             authorEd25519: author ?? self.author.publicKey.rawRepresentation,
                             recipients: recipients ?? self.recipients)
    }

    var identity: RevisionIdentity { try! RevisionIdentity(itemID: itemID, revisionID: revisionID, parents: []) }

    func seal(_ content: RecordContent, identity: RevisionIdentity? = nil) throws -> SealedRecord {
        try RecordSealer.seal(content, identity: identity ?? self.identity, authority: authority(), author: author)
    }

    func verify(_ bytes: Data, authority: RecordAuthority? = nil) throws -> VerifiedRecord {
        try ParsedRecord(bytes).verify(under: authority ?? self.authority(), item: itemID, revision: revisionID)
    }
}

func secret(_ text: String) -> SecretBytes { secret(Array(text.utf8)) }
func secret(_ bytes: [UInt8]) -> SecretBytes {
    var copy = bytes
    return try! SecretBytes(consuming: &copy)
}

func bytes(_ value: SecretBytes) -> [UInt8] { value.withUnsafeBytes { Array($0) } }

func login(title: String = "Synthetic title", username: Username = .value(secret("synthetic-user")),
           password: String = syntheticCanary, origins: [String] = ["https://example.invalid"]) -> RecordContent {
    .login(try! LoginContent(title: title.isEmpty ? .empty : .value(secret(title)), username: username,
                             password: secret(password), origins: origins.map { try CanonicalOrigin($0) }))
}

/// Counts content callbacks. Every refusal test asserts zero.
final class Callbacks: @unchecked Sendable {
    private(set) var count = 0
    func open(_ record: VerifiedRecord, as recipient: RecipientKey) throws {
        try record.open(as: recipient) { _ in count += 1 }
    }
}

func expectRefusal(_ expected: RecordError, sourceLocation: SourceLocation = #_sourceLocation,
                   _ body: () throws -> Void) {
    do {
        try body()
        Issue.record("expected \(expected), got success", sourceLocation: sourceLocation)
    } catch let error as RecordError {
        #expect(error == expected, sourceLocation: sourceLocation)
    } catch {
        Issue.record("unexpected error type", sourceLocation: sourceLocation)
    }
}

/// Parses, verifies under the fixture authority and opens as `recipient`, counting callbacks.
func expectOpenRefusal(_ expected: RecordError, _ fixture: Fixture, _ record: Data, as recipient: RecipientKey? = nil,
                       authority: RecordAuthority? = nil, sourceLocation: SourceLocation = #_sourceLocation) {
    let callbacks = Callbacks()
    expectRefusal(expected, sourceLocation: sourceLocation) {
        let verified = try fixture.verify(record, authority: authority)
        try callbacks.open(verified, as: recipient ?? fixture.recipientKeys[0])
    }
    #expect(callbacks.count == 0, sourceLocation: sourceLocation)
}

// MARK: - TEST ONLY hostile construction

/// Rebuilds a record from explicit parts, the same steps as `RecordSealer.seal`, with
/// per-step overrides. Per crypto review R3, the header tag and frame are always computed
/// under DK1 after the final H, and the writer signature over the final body, so each
/// fixture reaches the gate it targets. Not a production resealing API.
struct HostileRecord {
    var kind: UInt8 = RecordKind.login.rawValue
    var vault: Data
    var item: Data
    var revision: Data
    var membership: Data
    var author: Data
    var parents: [Data] = []
    var logical: [UInt8]
    var padded: [UInt8]? = nil
    var dataKey = SymmetricKey(size: .bits256)
    var messageID = randomBytes(32)
    var commitment: Data? = nil
    var context: [UInt8]? = nil
    var recipients: [Recipient]
    /// Replaces the HPKE entry at an index: (headerHash, messageID, commitment) -> EDK.
    var edk: [Int: (Data, Data, Data) throws -> ESDK.EncryptedDataKey] = [:]
    var mutateHeaderTag: (inout Data) -> Void = { _ in }
    var mutateBody: (inout Data) -> Void = { _ in }
    var signer: Curve25519.Signing.PrivateKey

    init(_ fixture: Fixture, content: RecordContent) {
        vault = fixture.vaultID.rawValue
        item = fixture.itemID.rawValue
        revision = fixture.revisionID.rawValue
        membership = fixture.membership.rawValue
        author = fixture.author.publicKey.rawRepresentation
        kind = content.kind.rawValue
        logical = Payload.logical(content)
        recipients = fixture.recipients.members
        signer = fixture.author
    }

    var headerBytes: Data {
        var writer = ByteWriter()
        writer.raw(RecordFormat.magic)
        writer.u8(2)
        writer.u8(1)
        writer.u8(kind)
        writer.raw(vault)
        writer.raw(item)
        writer.raw(revision)
        writer.raw(membership)
        writer.raw(author)
        writer.u8(UInt8(parents.count))
        for parent in parents { writer.raw(parent) }
        return writer.data
    }

    func message() throws -> Data {
        let header = headerBytes
        let headerHash = sha256(header)
        let keys = ESDK.derive(dataKey: dataKey, messageID: messageID)
        let stored = commitment ?? keys.commitment
        var edks: [ESDK.EncryptedDataKey] = []
        for (index, recipient) in recipients.enumerated() {
            if let replacement = edk[index] {
                edks.append(try replacement(headerHash, messageID, stored))
            } else {
                edks.append(try ESDK.wrap(dataKey, for: recipient, headerHash: headerHash, messageID: messageID,
                                          commitment: stored))
            }
        }
        let esdkHeader = ESDK.header(messageID: messageID, context: context ?? ESDK.context(headerHash: headerHash),
                                     edks: edks, commitment: stored)
        var tag = try ESDK.headerTag(key: keys.encryption, header: esdkHeader)
        mutateHeaderTag(&tag)
        let (ciphertext, frameTag) = try ESDK.sealFrame(key: keys.encryption, messageID: messageID,
                                                        padded: padded ?? Payload.pad(logical))
        var body = ESDK.body(header: esdkHeader, headerTag: tag, ciphertext: ciphertext, frameTag: frameTag)
        mutateBody(&body)
        return body
    }

    func build() throws -> Data {
        try RecordSealer.signRecord(header: headerBytes, message: message(), author: signer).bytes
    }
}

/// Offsets of E's fields for the fixture shape (no parents, `n` recipients).
struct Layout {
    let parents: Int
    let recipients: Int
    var p: Int { 124 + 32 * parents }
    var e: Int { p + 4 }
    var header: Int { 156 + 128 * recipients }
    var commitment: Int { e + header - 32 }
    var headerTag: Int { e + header }
    var frame: Int { headerTag + 16 }
    var ciphertext: Int { frame + 24 }
    func edk(_ index: Int) -> Int { e + 1 + 2 + 32 + 2 + 80 + 2 + 128 * index }
}

// MARK: - TEST ONLY RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305

/// Independent of the library HPKE implementation: only X25519, HKDF and ChaChaPoly
/// primitives. `dh` may be supplied to model an unchecked zero-DH backend.
struct ManualHPKE {
    let key: SymmetricKey
    let nonce: ChaChaPoly.Nonce
    let sharedSecret: Data

    static let kemSuite = Data("KEM".utf8) + Data([0, 0x20])
    static let hpkeSuite = Data("HPKE".utf8) + Data([0, 0x20, 0, 1, 0, 3])

    init(dh: Data, encapsulation: Data, recipient: Data, info: Data) throws {
        func extract(_ suite: Data, salt: Data = Data(), _ label: String, _ ikm: Data = Data()) -> Data {
            let labeled = Data("HPKE-v1".utf8) + suite + Data(label.utf8) + ikm
            return Data(HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: labeled), salt: salt))
        }
        func expand(_ suite: Data, _ prk: Data, _ label: String, _ info: Data, _ count: Int) -> Data {
            let labeled = Data([UInt8(count >> 8), UInt8(truncatingIfNeeded: count)]) + Data("HPKE-v1".utf8) + suite
                + Data(label.utf8) + info
            return HKDF<SHA256>.expand(pseudoRandomKey: prk, info: labeled, outputByteCount: count)
                .withUnsafeBytes { Data($0) }
        }
        let eae = extract(Self.kemSuite, "eae_prk", dh)
        sharedSecret = expand(Self.kemSuite, eae, "shared_secret", encapsulation + recipient, 32)
        let context = Data([0]) + extract(Self.hpkeSuite, "psk_id_hash") + extract(Self.hpkeSuite, "info_hash", info)
        let secret = extract(Self.hpkeSuite, salt: sharedSecret, "secret")
        key = SymmetricKey(data: expand(Self.hpkeSuite, secret, "key", context, 32))
        nonce = try ChaChaPoly.Nonce(data: expand(Self.hpkeSuite, secret, "base_nonce", context, 12))
    }

    static func dh(_ privateKey: Curve25519.KeyAgreement.PrivateKey, _ publicKey: Data) throws -> Data {
        try privateKey.sharedSecretFromKeyAgreement(with: .init(rawRepresentation: publicKey)).withUnsafeBytes { Data($0) }
    }

    func seal(_ plaintext: Data, aad: Data) throws -> Data {
        let box = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce, authenticating: aad)
        return box.ciphertext + box.tag
    }

    func open(_ ciphertext: Data, aad: Data) throws -> Data {
        try ChaChaPoly.open(.init(nonce: nonce, ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16)),
                            using: key, authenticating: aad)
    }
}

/// Spec-text recomputation of the project's HPKE binding; does not call `ESDK.hpkeInfo`.
func specInfo(headerHash: Data, messageID: Data) -> Data { Data("AV/HPKE/2".utf8) + Data([0]) + headerHash + messageID }
func specAAD(headerHash: Data, messageID: Data, commitment: Data, role: UInt8, recipient: Data) -> Data {
    headerHash + messageID + commitment + Data([role]) + recipient
}

func unhex(_ text: String) -> Data {
    let characters = Array(text.utf8)
    precondition(characters.count.isMultiple(of: 2))
    return Data(stride(from: 0, to: characters.count, by: 2).map {
        UInt8(String(decoding: characters[$0..<($0 + 2)], as: UTF8.self), radix: 16)!
    })
}

func flip(_ data: inout Data, at offset: Int, mask: UInt8 = 1) {
    data[data.startIndex + offset] ^= mask
}

/// Emits one public line for the owned harness. Never called with secret material.
func emitPublic(_ line: String) {
    FileHandle.standardOutput.write(Data((line + "\n").utf8))
}

#if os(Linux)
let platformName = "linux"
#else
let platformName = "macos"
#endif
