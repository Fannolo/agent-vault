import Crypto
import Foundation

struct Envelope {
    var role: RecipientRole
    var publicKey: Data
    var encapsulatedKey: Data
    var ciphertext: Data
    var sortKey: Data { Data([role.rawValue]) + publicKey }
}

struct SealedRecord {
    static let magic = Data("AVSEAL01".utf8)
    static let hpkeInfo = Data("agent-vault-sealed-revision-v1".utf8) + Data([0, 1])
    static let maximumSize = 8 + 3 + 48 + 32 + 32 + 4 + 16 * 32 + 12 + 4 + 262144 + 16 + 4 + 32 * 113 + 64

    var context: RevisionContext
    var author: Data
    var parents: [Data]
    var nonce: Data
    var ciphertext: Data
    var tag: Data
    var envelopes: [Envelope]
    var signature: Data

    var payloadAAD: Data {
        var writer = BinaryWriter()
        writer.bytes(Self.magic)
        writer.bytes(Data([1, 1, 1]))
        writer.bytes(context.vaultID)
        writer.bytes(context.itemID)
        writer.bytes(context.revisionID)
        writer.bytes(context.membershipHead)
        writer.bytes(author)
        writer.count(parents.count)
        for parent in parents { writer.bytes(parent) }
        return writer.data
    }

    var payloadSection: Data {
        var writer = BinaryWriter()
        writer.bytes(nonce)
        writer.field(ciphertext)
        writer.bytes(tag)
        return writer.data
    }

    func wrapAAD(role: RecipientRole, publicKey: Data) -> Data {
        payloadAAD + Data(SHA256.hash(data: payloadSection)) + Data([role.rawValue]) + publicKey
    }

    var signedMessage: Data {
        var writer = BinaryWriter()
        writer.bytes(payloadAAD)
        writer.bytes(payloadSection)
        writer.count(envelopes.count)
        for envelope in envelopes {
            writer.bytes(envelope.sortKey)
            writer.bytes(envelope.encapsulatedKey)
            writer.bytes(envelope.ciphertext)
        }
        return writer.data
    }

    var encoded: Data { signedMessage + signature }

    func verify(author trustedAuthor: Curve25519.Signing.PublicKey) throws {
        guard trustedAuthor.isValidSignature(signature, for: signedMessage) else {
            throw VaultError.badSignature
        }
        guard author == trustedAuthor.rawRepresentation else { throw VaultError.unexpectedIdentity }
    }

    static func parse(_ data: Data) throws -> SealedRecord {
        guard data.count <= maximumSize else { throw VaultError.malformed }
        var reader = BinaryReader(data)
        guard try reader.bytes(8) == magic, try reader.byte() == 1,
              try reader.byte() == 1, try reader.byte() == 1 else { throw VaultError.malformed }
        let context = try RevisionContext(vaultID: reader.bytes(16), itemID: reader.bytes(16),
                                          revisionID: reader.bytes(16), membershipHead: reader.bytes(32))
        let author = try reader.bytes(32)
        let parentCount = try reader.count(maximum: 16)
        var parents: [Data] = []
        for _ in 0..<parentCount { parents.append(try reader.bytes(32)) }
        guard strictlySorted(parents) else { throw VaultError.malformed }
        let nonce = try reader.bytes(12)
        let ciphertext = try reader.field(maximum: 262144)
        let tag = try reader.bytes(16)
        let recipientCount = try reader.count(maximum: 32)
        guard recipientCount > 0 else { throw VaultError.malformed }
        var envelopes: [Envelope] = []
        for _ in 0..<recipientCount {
            guard let role = RecipientRole(rawValue: try reader.byte()) else { throw VaultError.malformed }
            envelopes.append(try Envelope(role: role, publicKey: reader.bytes(32),
                                          encapsulatedKey: reader.bytes(32), ciphertext: reader.bytes(48)))
        }
        guard strictlySorted(envelopes.map(\.sortKey)) else { throw VaultError.malformed }
        let signature = try reader.bytes(64)
        try reader.finish()
        let record = SealedRecord(context: context, author: author, parents: parents, nonce: nonce,
                                  ciphertext: ciphertext, tag: tag, envelopes: envelopes, signature: signature)
        guard record.encoded == data else { throw VaultError.malformed }
        return record
    }
}
