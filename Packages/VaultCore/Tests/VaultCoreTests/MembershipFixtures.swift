import Crypto
import Foundation
import Testing
@testable import VaultCore

// Publicly known synthetic authority material for producer and policy tests only. Reader code
// must never reference this file. Keys are built inside called functions, never by a global.

let membershipPolicyVaultID = Data(repeating: 0x6E, count: 16)

let membershipPolicyItem = LoginItem(username: "synthetic-user", password: Data(fixtureCanary.utf8),
                                     origins: ["https://example.invalid"])

func membershipAgreementKey(_ seed: UInt8) throws -> Curve25519.KeyAgreement.PrivateKey {
    try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: seed, count: 32))
}

func membershipSigningKey(_ seed: UInt8) throws -> Curve25519.Signing.PrivateKey {
    try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: seed, count: 32))
}

func membershipRow(_ kind: MemberKind, _ key: Curve25519.KeyAgreement.PublicKey) -> MembershipRow {
    MembershipRow(role: kind.role, capability: kind.capability, agreementKey: key.rawRepresentation)
}

func membershipRows(_ rows: [MembershipRow]) -> [MembershipRow] {
    rows.sorted { $0.sortKey.lexicographicallyPrecedes($1.sortKey) }
}

struct MembershipAuthority: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    var description: String { "MembershipAuthority(<redacted>)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: [:]) }

    static let controllerSeed: UInt8 = 0xC1
    static let writerSigningSeed: UInt8 = 0xC2
    static let writerAgreementSeed: UInt8 = 0xC3
    static let foreignSigningSeed: UInt8 = 0xC4
    static let otherWriterSigningSeed: UInt8 = 0xC5

    let vaultID: VaultID
    let controller: Curve25519.Signing.PrivateKey
    let writer: Curve25519.Signing.PrivateKey
    let writerAgreement: Curve25519.KeyAgreement.PrivateKey

    init(vaultID: Data = membershipPolicyVaultID) throws {
        self.vaultID = try VaultID(vaultID)
        controller = try membershipSigningKey(Self.controllerSeed)
        writer = try membershipSigningKey(Self.writerSigningSeed)
        writerAgreement = try membershipAgreementKey(Self.writerAgreementSeed)
    }

    var writerRow: MembershipRow { membershipRow(.writer, writerAgreement.publicKey) }

    func writerMember() throws -> FixtureMember { try .writer(writerAgreement.publicKey) }

    func genesis(_ members: [FixtureMember]) throws -> (record: Data, anchor: FixtureTrustAnchor) {
        try FixtureController.genesis(vaultID: vaultID, controller: controller, writer: writer.publicKey, members: members)
    }

    /// A verifier session over freshly minted genesis, with the writer plus `members`.
    func session(_ members: [FixtureMember]) throws -> (session: FixtureMembershipSession, genesis: Data) {
        let minted = try genesis([writerMember()] + members)
        return (try FixtureMembershipSession(anchor: minted.anchor, genesis: minted.record), minted.record)
    }

    func successor(_ checkpoint: MembershipCheckpoint, _ members: [FixtureMember]) throws -> Data {
        try FixtureController.successor(after: checkpoint, members: members, controller: controller)
    }

    /// Mints and advances; returns the accepted record.
    @discardableResult
    func advance(_ session: FixtureMembershipSession, _ members: [FixtureMember]) throws -> Data {
        let record = try successor(session.checkpoint, members)
        guard case .advanced = try session.advance(record) else { throw MembershipPolicyError.malformed }
        return record
    }

    /// Unvalidated successor body bound to the checkpoint, for hostile signed inputs.
    func body(after checkpoint: MembershipCheckpoint, rows: [MembershipRow], sequence: UInt64? = nil) -> MembershipBody {
        MembershipBody(vaultID: vaultID.bytes, sequence: sequence ?? checkpoint.sequence + 1, parent: checkpoint.head.bytes,
                       controllerKey: controller.publicKey.rawRepresentation, writerKey: writer.publicKey.rawRepresentation,
                       rows: membershipRows(rows))
    }

    func signed(_ body: MembershipBody, by key: Curve25519.Signing.PrivateKey? = nil) throws -> Data {
        let bytes = body.encoded
        return bytes + (try (key ?? controller).signature(for: bytes))
    }

    func context(_ session: FixtureMembershipSession, revision: UInt8 = 0x31, item: UInt8 = 0x21) throws -> RevisionContext {
        try RevisionContext(vaultID: vaultID.bytes, itemID: Data(repeating: item, count: 16),
                            revisionID: Data(repeating: revision, count: 16), membershipHead: session.checkpoint.head.bytes)
    }

    func seal(_ context: RevisionContext, _ recipients: [(RecipientRole, Curve25519.KeyAgreement.PublicKey)],
              author: Curve25519.Signing.PrivateKey? = nil, parents: [Data] = [],
              item: LoginItem = membershipPolicyItem) throws -> Data {
        try sealRevision(context: context, parents: parents, author: author ?? writer,
                         recipients: recipients.map { try RevisionRecipient(role: $0.0, publicKey: $0.1) }, item: item)
    }

    func resign(_ record: SealedRecord) throws -> Data {
        var record = record
        record.signature = try writer.signature(for: record.signedMessage)
        return record.encoded
    }

    /// Exact recipients with one unselected envelope's encapsulation replaced by a low-order
    /// encoding. Its wrap is a genuine zero-DH wrap of the data key, so only validation stops it.
    func lowOrderEncapsulationRecord(_ context: RevisionContext,
                                     _ recipients: [(RecipientRole, Curve25519.KeyAgreement.PublicKey)],
                                     lowOrderFor target: Data, encoding: Data) throws -> Data {
        let dataKey = SymmetricKey(size: .bits256)
        var record = SealedRecord(context: context, author: writer.publicKey.rawRepresentation, parents: [], nonce: Data(),
                                  ciphertext: Data(), tag: Data(), envelopes: [], signature: Data())
        let payload = try ChaChaPoly.seal(membershipPolicyItem.encode(), using: dataKey, authenticating: record.payloadAAD)
        record.nonce = payload.nonce.withUnsafeBytes { Data($0) }
        record.ciphertext = payload.ciphertext
        record.tag = payload.tag
        for (role, key) in recipients {
            let publicKey = key.rawRepresentation
            let aad = record.wrapAAD(role: role, publicKey: publicKey)
            if publicKey == target {
                let schedule = try MembershipZeroDHSchedule(encapsulatedKey: encoding, recipientKey: publicKey)
                record.envelopes.append(Envelope(role: role, publicKey: publicKey, encapsulatedKey: encoding,
                                                 ciphertext: try schedule.seal(dataKey, aad: aad)))
            } else {
                var sender = try HPKE.Sender(recipientKey: key, ciphersuite: .Curve25519_SHA256_ChachaPoly,
                                             info: SealedRecord.hpkeInfo)
                let wrap = try dataKey.withUnsafeBytes { try sender.seal($0, authenticating: aad) }
                record.envelopes.append(Envelope(role: role, publicKey: publicKey,
                                                 encapsulatedKey: sender.encapsulatedKey, ciphertext: wrap))
            }
        }
        record.envelopes.sort { $0.sortKey.lexicographicallyPrecedes($1.sortKey) }
        return try resign(record)
    }
}

/// Comparable snapshot of everything a rejected input must leave unchanged.
struct MembershipSessionState: Equatable {
    let checkpoint: MembershipCheckpoint
    let history: [Data]
    let membership: ActiveMembership
    let evidence: [Data]?

    init(_ session: FixtureMembershipSession) {
        checkpoint = session.checkpoint
        history = session.history
        membership = session.membership
        evidence = session.forkEvidence.map { [$0.firstRecord, $0.secondRecord] }
    }
}

func expectPolicyError(_ expected: MembershipPolicyError, sourceLocation: SourceLocation = #_sourceLocation,
                       _ operation: () throws -> Void) {
    do {
        try operation()
        Issue.record("Expected fixed membership error", sourceLocation: sourceLocation)
    } catch let actual as MembershipPolicyError {
        #expect(actual == expected, sourceLocation: sourceLocation)
    } catch {
        Issue.record("Unexpected error type; details suppressed", sourceLocation: sourceLocation)
    }
}

/// Records at most one issue: wrong outcome, or any change to head, history, membership or evidence.
func expectRejectedUnchanged(_ expected: MembershipPolicyError, _ session: FixtureMembershipSession,
                             sourceLocation: SourceLocation = #_sourceLocation, _ operation: () throws -> Void) {
    let before = MembershipSessionState(session)
    do {
        try operation()
        Issue.record("Expected fixed membership error", sourceLocation: sourceLocation)
    } catch let actual as MembershipPolicyError {
        if actual != expected {
            #expect(actual == expected, sourceLocation: sourceLocation)
        } else if MembershipSessionState(session) != before {
            Issue.record("Rejected input changed session state", sourceLocation: sourceLocation)
        }
    } catch {
        Issue.record("Unexpected error type; details suppressed", sourceLocation: sourceLocation)
    }
}

/// Records at most one issue unless the operation latches exactly this pair, keeps the checkpoint,
/// and leaves the session terminal for further membership input.
func expectForkLatch(_ kind: MembershipForkEvidence.Kind, _ session: FixtureMembershipSession,
                     first: Data, second: Data, probe: Data,
                     sourceLocation: SourceLocation = #_sourceLocation, _ operation: () throws -> Void) {
    let checkpoint = session.checkpoint
    let history = session.history
    do {
        try operation()
        Issue.record("Expected membership fork latch", sourceLocation: sourceLocation)
        return
    } catch let actual as MembershipPolicyError {
        guard actual == .membershipFork else {
            #expect(actual == .membershipFork, sourceLocation: sourceLocation)
            return
        }
    } catch {
        Issue.record("Unexpected error type; details suppressed", sourceLocation: sourceLocation)
        return
    }
    let exact = session.forkEvidence?.kind == kind && session.forkEvidence?.firstRecord == first
        && session.forkEvidence?.secondRecord == second && session.checkpoint == checkpoint && session.history == history
    let terminal: Bool
    do {
        _ = try session.advance(probe)
        terminal = false
    } catch {
        terminal = (error as? MembershipPolicyError) == .membershipFork
    }
    let unchanged = session.forkEvidence?.firstRecord == first && session.forkEvidence?.secondRecord == second
        && session.checkpoint == checkpoint
    if !(exact && terminal && unchanged) {
        Issue.record("Fork latch evidence, checkpoint or terminal state differs", sourceLocation: sourceLocation)
    }
}

// u = 0, 1, two order-eight points, p-1, p, p+1; plus their high-bit aliases. Same public
// encodings as the frozen codec's low-order regression, copied under a new name.
func membershipLowOrderEncodings() -> [Data] {
    let representatives = [
        Data(count: 32),
        Data([1]) + Data(count: 31),
        MembershipExchangeOracle.hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        MembershipExchangeOracle.hex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        Data([0xec]) + Data(repeating: 0xff, count: 30) + Data([0x7f]),
        Data([0xed]) + Data(repeating: 0xff, count: 30) + Data([0x7f]),
        Data([0xee]) + Data(repeating: 0xff, count: 30) + Data([0x7f]),
    ]
    return representatives + representatives.map {
        var alias = $0
        alias[31] |= 0x80
        return alias
    }
}

// TEST ONLY: RFC 9180 base-mode key schedule from DH = 0 and the public transcript, copied from
// the frozen codec regression so a low-order wrap is genuine on both backends.
struct MembershipZeroDHSchedule {
    let key: SymmetricKey
    let nonce: ChaChaPoly.Nonce

    init(encapsulatedKey: Data, recipientKey: Data) throws {
        let kemSuite = Data("KEM".utf8) + Data([0, 0x20])
        let hpkeSuite = Data("HPKE".utf8) + Data([0, 0x20, 0, 1, 0, 3])
        func extract(suite: Data, salt: Data = Data(), label: String, input: Data = Data()) -> SymmetricKey {
            let labeled = Data("HPKE-v1".utf8) + suite + Data(label.utf8) + input
            return SymmetricKey(data: HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: labeled), salt: salt))
        }
        func expand(suite: Data, prk: SymmetricKey, label: String, info: Data, count: Int) -> SymmetricKey {
            let labeled = Data([UInt8(count >> 8), UInt8(truncatingIfNeeded: count)]) +
                Data("HPKE-v1".utf8) + suite + Data(label.utf8) + info
            return HKDF<SHA256>.expand(pseudoRandomKey: prk, info: labeled, outputByteCount: count)
        }
        let eae = extract(suite: kemSuite, label: "eae_prk", input: Data(count: 32))
        let shared = expand(suite: kemSuite, prk: eae, label: "shared_secret",
                            info: encapsulatedKey + recipientKey, count: 32)
        let pskIDHash = extract(suite: hpkeSuite, label: "psk_id_hash")
        let infoHash = extract(suite: hpkeSuite, label: "info_hash", input: SealedRecord.hpkeInfo)
        let context = Data([0]) + pskIDHash.withUnsafeBytes { Data($0) } + infoHash.withUnsafeBytes { Data($0) }
        let secret = extract(suite: hpkeSuite, salt: shared.withUnsafeBytes { Data($0) }, label: "secret")
        key = expand(suite: hpkeSuite, prk: secret, label: "key", info: context, count: 32)
        let baseNonce = expand(suite: hpkeSuite, prk: secret, label: "base_nonce", info: context, count: 12)
        nonce = try baseNonce.withUnsafeBytes { try ChaChaPoly.Nonce(data: $0) }
    }

    func open(_ ciphertext: Data, aad: Data) throws -> Data {
        let box = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16))
        return try ChaChaPoly.open(box, using: key, authenticating: aad)
    }

    func seal(_ keyToWrap: SymmetricKey, aad: Data) throws -> Data {
        let box = try keyToWrap.withUnsafeBytes {
            try ChaChaPoly.seal($0, using: key, nonce: nonce, authenticating: aad)
        }
        return box.ciphertext + box.tag
    }
}
