import Crypto
import Foundation

/// Trusted local synthetic minting. The writer is a public key from the same trusted fixture
/// source; this type cannot verify that provenance. Minting never advances any session.
public enum FixtureController {
    public static func genesis(
        vaultID: VaultID,
        controller: Curve25519.Signing.PrivateKey,
        writer: Curve25519.Signing.PublicKey,
        members: [FixtureMember]
    ) throws -> (record: Data, anchor: FixtureTrustAnchor) {
        let controllerKey = controller.publicKey.rawRepresentation
        let writerKey = writer.rawRepresentation
        guard controllerKey != writerKey else { throw MembershipPolicyError.malformed }
        let rows = try canonicalRows(members)
        _ = try MembershipPolicy.validate(rows: rows, pinnedWriterAgreement: nil)
        let body = MembershipBody(vaultID: vaultID.bytes, sequence: 0, parent: Data(count: 32),
                                  controllerKey: controllerKey, writerKey: writerKey, rows: rows).encoded
        let record = try sign(body, with: controller)
        return (record, FixtureTrustAnchor(vaultID: vaultID, genesis: MembershipDigest(body: body)))
    }

    /// A stale checkpoint can still be signed; the receiving session's lineage rules decide.
    public static func successor(
        after checkpoint: MembershipCheckpoint,
        members: [FixtureMember],
        controller: Curve25519.Signing.PrivateKey
    ) throws -> Data {
        let pins = checkpoint.authority
        guard controller.publicKey.rawRepresentation == pins.controllerKey else {
            throw MembershipPolicyError.anchorMismatch
        }
        let rows = try canonicalRows(members)
        _ = try MembershipPolicy.validate(rows: rows, pinnedWriterAgreement: pins.writerAgreementKey)
        let sequence = try MembershipSequence.successor(after: checkpoint.sequence)
        let body = MembershipBody(vaultID: pins.vaultID.bytes, sequence: sequence, parent: checkpoint.head.bytes,
                                  controllerKey: pins.controllerKey, writerKey: pins.writerKey, rows: rows).encoded
        return try sign(body, with: controller)
    }

    private static func canonicalRows(_ members: [FixtureMember]) throws -> [MembershipRow] {
        guard (1...MembershipBody.memberLimit).contains(members.count) else { throw MembershipPolicyError.malformed }
        let rows = members.map(\.row).sorted { $0.sortKey.lexicographicallyPrecedes($1.sortKey) }
        guard strictlySorted(rows.map(\.sortKey)) else { throw MembershipPolicyError.malformed }
        return rows
    }

    private static func sign(_ body: Data, with controller: Curve25519.Signing.PrivateKey) throws -> Data {
        let signature: Data
        do {
            signature = try controller.signature(for: body)
        } catch {
            throw MembershipPolicyError.membershipSigningFailed
        }
        guard signature.count == MembershipBody.signatureSize,
              controller.publicKey.isValidSignature(signature, for: body) else {
            throw MembershipPolicyError.membershipSigningFailed
        }
        return body + signature
    }
}
