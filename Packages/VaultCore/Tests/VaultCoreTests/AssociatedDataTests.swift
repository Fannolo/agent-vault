import Crypto
import Foundation
import Testing
@testable import VaultCore

// Build an authenticated record with deliberately inconsistent inner content. Only test code
// can choose a data key, override AAD, or assemble ciphertext and wraps in separate stages.
private func syntheticRecord(_ fixture: Fixture, plaintext: Data, context: RevisionContext? = nil,
                             payloadAAD: Data? = nil, info: Data? = nil) throws -> Data {
    var record = SealedRecord(context: context ?? fixture.context, author: fixture.author.publicKey.rawRepresentation,
                              parents: [], nonce: Data(), ciphertext: Data(), tag: Data(), envelopes: [], signature: Data())
    let key = SymmetricKey(size: .bits256)
    let payload = try ChaChaPoly.seal(plaintext, using: key, authenticating: payloadAAD ?? record.payloadAAD)
    record.nonce = payload.nonce.withUnsafeBytes { Data($0) }
    record.ciphertext = payload.ciphertext
    record.tag = payload.tag
    let keyBytes = key.withUnsafeBytes { Data($0) }
    for recipient in try fixture.recipients {
        var sender = try HPKE.Sender(recipientKey: recipient.publicKey, ciphersuite: .Curve25519_SHA256_ChachaPoly,
                                     info: info ?? SealedRecord.hpkeInfo)
        let publicKey = recipient.publicKey.rawRepresentation
        let wrap = try sender.seal(keyBytes, authenticating: record.wrapAAD(role: recipient.role, publicKey: publicKey))
        record.envelopes.append(Envelope(role: recipient.role, publicKey: publicKey,
                                         encapsulatedKey: sender.encapsulatedKey, ciphertext: wrap))
    }
    record.envelopes.sort { $0.sortKey.lexicographicallyPrecedes($1.sortKey) }
    return try fixture.resign(record)
}

@Test func payloadAuthenticationCheckedAfterValidWraps() throws {
    let fixture = try Fixture()
    let original = try SealedRecord.parse(fixture.seal())
    for context in try [fixture.changedContext(vault: 9), fixture.changedContext(item: 9),
                        fixture.changedContext(revision: 9), fixture.changedContext(head: 9)] {
        let bytes = try syntheticRecord(fixture, plaintext: fixture.item.encode(), context: context, payloadAAD: original.payloadAAD)
        expectError(.badAuthentication) { _ = try fixture.open(bytes, expected: context) }
    }
    let wrongInfo = try syntheticRecord(fixture, plaintext: fixture.item.encode(), info: Data("incorrect-domain".utf8))
    expectError(.badAuthentication) { _ = try fixture.open(wrongInfo) }
}

@Test func authenticatedMalformedPlaintextStaysMalformed() throws {
    let fixture = try Fixture()
    let valid = try fixture.item.encode()
    var invalidUTF8 = valid
    invalidUTF8[6] = 0xFF
    for plaintext in [invalidUTF8, valid + Data([0]), Data([2, 1]), Data(count: 262144)] {
        let bytes = try syntheticRecord(fixture, plaintext: plaintext)
        expectError(.malformed) { _ = try fixture.open(bytes) }
    }
}

@Test func wireLayoutAndAADMatchContract() throws {
    let fixture = try Fixture()
    let parents = [Data(repeating: 5, count: 32), Data(repeating: 6, count: 32)]
    let bytes = try fixture.seal(parents: parents)
    let record = try SealedRecord.parse(bytes)
    var header = Data("AVSEAL01".utf8) + Data([1, 1, 1])
    header += fixture.context.vaultID + fixture.context.itemID + fixture.context.revisionID
    header += fixture.context.membershipHead + fixture.author.publicKey.rawRepresentation
    header += Data([0, 0, 0, 2]) + parents[0] + parents[1]
    #expect(header == record.payloadAAD)
    #expect(bytes.prefix(header.count) == header)
    #expect(SealedRecord.hpkeInfo == Data("agent-vault-sealed-revision-v1\0\u{1}".utf8))
    let count = record.ciphertext.count
    let countBytes = Data([UInt8(count >> 24), UInt8(truncatingIfNeeded: count >> 16),
                           UInt8(truncatingIfNeeded: count >> 8), UInt8(truncatingIfNeeded: count)])
    let payload = record.nonce + countBytes + record.ciphertext + record.tag
    let envelope = try #require(record.envelopes.first)
    let expectedAAD = header + Data(SHA256.hash(data: payload)) + Data([envelope.role.rawValue]) + envelope.publicKey
    #expect(record.wrapAAD(role: envelope.role, publicKey: envelope.publicKey) == expectedAAD)
    var expectedBytes = header + payload + Data([0, 0, 0, 3])
    for recipient in record.envelopes {
        #expect(recipient.publicKey.count == 32 && recipient.encapsulatedKey.count == 32 && recipient.ciphertext.count == 48)
        expectedBytes += Data([recipient.role.rawValue]) + recipient.publicKey + recipient.encapsulatedKey + recipient.ciphertext
    }
    #expect(expectedBytes == record.signedMessage)
    #expect(fixture.author.publicKey.isValidSignature(Data(bytes.suffix(64)), for: expectedBytes))
    #expect(bytes == expectedBytes + record.signature)
}

@Test func maximumRecipientCountRoundTrips() throws {
    let fixture = try Fixture()
    let keys = try (1...32).map {
        try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: UInt8($0), count: 32))
    }
    let recipients = try keys.map { try RevisionRecipient(role: .device, publicKey: $0.publicKey) }
    let bytes = try sealRevision(context: fixture.context, author: fixture.author, recipients: recipients, item: fixture.item)
    #expect(try SealedRecord.parse(bytes).envelopes.count == 32)
    for key in keys { #expect(fixture.matches(try fixture.open(bytes, recipient: key))) }
}
