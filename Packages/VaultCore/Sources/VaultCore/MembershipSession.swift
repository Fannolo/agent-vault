import Crypto
import Foundation

/// Synchronous session-local membership lineage. Holds no private key. Calls must be
/// serialized; there is no suspension between validation and state replacement.
public final class FixtureMembershipSession: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "FixtureMembershipSession(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }

    /// Genesis included; sequences 0 through 255. Never evicted.
    static let historyCapacity = 256

    let anchor: FixtureTrustAnchor
    let authority: MembershipAuthorityPins
    let controller: Curve25519.Signing.PublicKey
    let writer: Curve25519.Signing.PublicKey
    /// First-seen full signed record per accepted sequence; index equals sequence.
    private(set) var history: [Data]
    private(set) var membership: ActiveMembership
    public private(set) var checkpoint: MembershipCheckpoint
    public private(set) var forkEvidence: MembershipForkEvidence?

    public init(anchor: FixtureTrustAnchor, genesis: Data) throws {
        let record = try MembershipRecord.parse(genesis)
        guard MembershipDigest(body: record.bodyBytes) == anchor.genesis else { throw MembershipPolicyError.anchorMismatch }
        let body = record.body
        guard body.vaultID == anchor.vaultID.bytes, body.sequence == 0, body.parent == Data(count: 32) else {
            throw MembershipPolicyError.anchorMismatch
        }
        // Safe only because the whole body matched the independently trusted digest above.
        guard let controller = try? Curve25519.Signing.PublicKey(rawRepresentation: body.controllerKey),
              controller.isValidSignature(record.signature, for: record.bodyBytes) else {
            throw MembershipPolicyError.badMembershipSignature
        }
        guard let writer = try? Curve25519.Signing.PublicKey(rawRepresentation: body.writerKey),
              body.writerKey != body.controllerKey else { throw MembershipPolicyError.malformed }
        let membership = try MembershipPolicy.validate(rows: body.rows, pinnedWriterAgreement: nil)
        guard let writerAgreementKey = membership.writerAgreementKey else { throw MembershipPolicyError.malformed }
        let authority = MembershipAuthorityPins(vaultID: anchor.vaultID, controllerKey: body.controllerKey,
                                                writerKey: body.writerKey, writerAgreementKey: writerAgreementKey)
        self.anchor = anchor
        self.authority = authority
        self.controller = controller
        self.writer = writer
        self.history = [record.encoded]
        self.membership = membership
        self.checkpoint = MembershipCheckpoint(sequence: 0, head: anchor.genesis, authority: authority)
        self.forkEvidence = nil
    }

    /// Order: structure, namespace, signature, lineage, semantic policy, capacity, commit.
    /// Every thrown error leaves state unchanged except establishing the fork latch.
    public func advance(_ input: Data) throws -> MembershipAdvance {
        guard forkEvidence == nil else { throw MembershipPolicyError.membershipFork }
        let record = try MembershipRecord.parse(input)
        let body = record.body
        guard body.vaultID == authority.vaultID.bytes, body.controllerKey == authority.controllerKey else {
            throw MembershipPolicyError.anchorMismatch
        }
        guard controller.isValidSignature(record.signature, for: record.bodyBytes) else {
            throw MembershipPolicyError.badMembershipSignature
        }
        if let index = MembershipSequence.historyIndex(of: body.sequence, current: checkpoint.sequence) {
            let retained = history[index]
            if retained.prefix(retained.count - MembershipBody.signatureSize) == record.bodyBytes {
                return .duplicate(checkpoint)
            }
            try latch(.observedSequence, first: retained, second: record.encoded)
        }
        let next = try MembershipSequence.successor(after: checkpoint.sequence)
        guard body.sequence == next else { throw MembershipPolicyError.missingPredecessor }
        guard body.parent == checkpoint.head.bytes else {
            try latch(.signedLineageContradiction, first: history[history.count - 1], second: record.encoded)
        }
        guard body.writerKey == authority.writerKey else { throw MembershipPolicyError.unsupportedAuthorityChange }
        let membership = try MembershipPolicy.validate(rows: body.rows, pinnedWriterAgreement: authority.writerAgreementKey)
        guard history.count < Self.historyCapacity else { throw MembershipPolicyError.capacityExceeded }
        let advanced = MembershipCheckpoint(sequence: next, head: MembershipDigest(body: record.bodyBytes),
                                            authority: authority)
        history.append(record.encoded)
        self.membership = membership
        checkpoint = advanced
        return .advanced(advanced)
    }

    private func latch(_ kind: MembershipForkEvidence.Kind, first: Data, second: Data) throws -> Never {
        forkEvidence = MembershipForkEvidence(kind: kind, first: first, second: second)
        throw MembershipPolicyError.membershipFork
    }
}

@available(*, unavailable)
extension FixtureMembershipSession: Sendable {}
