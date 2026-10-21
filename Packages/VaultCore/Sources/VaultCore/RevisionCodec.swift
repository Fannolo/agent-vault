import Crypto
import Foundation

/// Creates one immutable record. Recipient membership is supplied by trusted fixture callers.
public func sealRevision(
    context: RevisionContext,
    parents: [Data] = [],
    author: Curve25519.Signing.PrivateKey,
    recipients: [RevisionRecipient],
    item: LoginItem
) throws -> Data {
    guard parents.count <= 16, parents.allSatisfy({ $0.count == 32 }),
          (1...32).contains(recipients.count) else { throw VaultError.malformed }
    let parents = parents.sorted { $0.lexicographicallyPrecedes($1) }
    let recipients = recipients.sorted {
        (Data([$0.role.rawValue]) + $0.publicKey.rawRepresentation)
            .lexicographicallyPrecedes(Data([$1.role.rawValue]) + $1.publicKey.rawRepresentation)
    }
    guard strictlySorted(parents), strictlySorted(recipients.map {
        Data([$0.role.rawValue]) + $0.publicKey.rawRepresentation
    }) else { throw VaultError.malformed }
    let plaintext = try item.encode()
    do {
        let dataKey = SymmetricKey(size: .bits256)
        var record = SealedRecord(context: context, author: author.publicKey.rawRepresentation,
                                  parents: parents, nonce: Data(), ciphertext: Data(), tag: Data(),
                                  envelopes: [], signature: Data())
        let payload = try ChaChaPoly.seal(plaintext, using: dataKey, authenticating: record.payloadAAD)
        record.nonce = payload.nonce.withUnsafeBytes { Data($0) }
        record.ciphertext = payload.ciphertext
        record.tag = payload.tag
        for recipient in recipients {
            var sender = try HPKE.Sender(recipientKey: recipient.publicKey,
                                         ciphersuite: .Curve25519_SHA256_ChachaPoly,
                                         info: SealedRecord.hpkeInfo)
            let publicKey = recipient.publicKey.rawRepresentation
            let wrap = try dataKey.withUnsafeBytes {
                try sender.seal($0, authenticating: record.wrapAAD(role: recipient.role, publicKey: publicKey))
            }
            record.envelopes.append(Envelope(role: recipient.role, publicKey: publicKey,
                                             encapsulatedKey: sender.encapsulatedKey, ciphertext: wrap))
        }
        record.signature = try author.signature(for: record.signedMessage)
        return record.encoded
    } catch {
        throw VaultError.badAuthentication
    }
}

/// The author and all expected context fields must come from trusted caller state, never this record.
public func openRevision(
    _ bytes: Data,
    expected: RevisionContext,
    author: Curve25519.Signing.PublicKey,
    role: RecipientRole,
    recipient: Curve25519.KeyAgreement.PrivateKey
) throws -> LoginItem {
    let record = try SealedRecord.parse(bytes)
    try record.verify(author: author)
    guard record.context == expected else { throw VaultError.unexpectedIdentity }
    let publicKey = recipient.publicKey.rawRepresentation
    guard let envelope = record.envelopes.first(where: { $0.role == role && $0.publicKey == publicKey }) else {
        throw VaultError.badAuthentication
    }
    let plaintext: Data
    do {
        let encapsulatedKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: envelope.encapsulatedKey)
        try validateX25519PublicKey(encapsulatedKey)
        var receiver = try HPKE.Recipient(privateKey: recipient, ciphersuite: .Curve25519_SHA256_ChachaPoly,
                                          info: SealedRecord.hpkeInfo, encapsulatedKey: envelope.encapsulatedKey)
        let keyBytes = try receiver.open(envelope.ciphertext, authenticating: record.wrapAAD(role: role, publicKey: publicKey))
        guard keyBytes.count == 32 else { throw VaultError.badAuthentication }
        let payload = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: record.nonce),
                                              ciphertext: record.ciphertext, tag: record.tag)
        plaintext = try ChaChaPoly.open(payload, using: SymmetricKey(data: keyBytes), authenticating: record.payloadAAD)
    } catch {
        throw VaultError.badAuthentication
    }
    return try LoginItem.decode(plaintext)
}
