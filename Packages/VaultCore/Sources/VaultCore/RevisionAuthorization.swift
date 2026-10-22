import Crypto
import Foundation

/// Stateless policy over unchanged AVSEAL01 bytes. Nothing about a revision is retained.
extension FixtureMembershipSession {
    public func authorize(_ record: Data, itemID: Data, revisionID: Data) throws -> AuthorizedRevision {
        try authorizedAtCurrentHead(record, itemID: itemID, revisionID: revisionID)
    }

    /// Reauthorizes the supplied bytes, then opens with the independently pinned context and writer.
    /// The recipient key is used for this call only and is not retained.
    public func openAtCurrentMembership(
        _ record: Data, itemID: Data, revisionID: Data,
        role: RecipientRole,
        recipient: Curve25519.KeyAgreement.PrivateKey
    ) throws -> LoginItem {
        let receipt = try authorizedAtCurrentHead(record, itemID: itemID, revisionID: revisionID)
        guard membership.recipients.contains(Data([role.rawValue]) + recipient.publicKey.rawRepresentation) else {
            throw MembershipPolicyError.unauthorizedRecipient
        }
        let expected = try RevisionContext(vaultID: anchor.vaultID.bytes, itemID: itemID, revisionID: revisionID,
                                           membershipHead: receipt.authorizedAt.head.bytes)
        return try openRevision(record, expected: expected, author: writer, role: role, recipient: recipient)
    }

    private func authorizedAtCurrentHead(_ record: Data, itemID: Data, revisionID: Data) throws -> AuthorizedRevision {
        guard forkEvidence == nil else { throw MembershipPolicyError.membershipFork }
        guard itemID.count == 16, revisionID.count == 16 else { throw VaultError.malformed }
        let parsed = try SealedRecord.parse(record)
        let context = parsed.context
        guard context.vaultID == anchor.vaultID.bytes, context.itemID == itemID,
              context.revisionID == revisionID else { throw VaultError.unexpectedIdentity }
        try parsed.verify(author: writer)
        guard context.membershipHead == checkpoint.head.bytes else { throw MembershipPolicyError.staleMembership }
        guard membership.writerActive else { throw MembershipPolicyError.unauthorizedAuthor }
        guard parsed.envelopes.map(\.sortKey) == membership.recipients else {
            throw MembershipPolicyError.recipientSetMismatch
        }
        for envelope in parsed.envelopes {
            do {
                try validateX25519PublicKey(Curve25519.KeyAgreement.PublicKey(rawRepresentation: envelope.encapsulatedKey))
            } catch {
                throw MembershipPolicyError.invalidEncapsulation
            }
        }
        return AuthorizedRevision(digest: RevisionDigest(record: record), authorizedAt: checkpoint)
    }
}
