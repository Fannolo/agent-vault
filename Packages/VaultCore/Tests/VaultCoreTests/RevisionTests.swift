import Crypto
import Foundation
import Testing
@testable import VaultCore

@Test func allRecipientsAndUnrelatedKey() throws {
    let fixture = try Fixture()
    let bytes = try fixture.seal()
    for device in fixture.devices { #expect(fixture.matches(try fixture.open(bytes, recipient: device))) }
    #expect(fixture.matches(try fixture.open(bytes, role: .recovery, recipient: fixture.recovery)))
    expectError(.badAuthentication) { _ = try fixture.open(bytes, recipient: fixture.unrelated) }
    expectError(.badAuthentication) { _ = try fixture.open(bytes, role: .device, recipient: fixture.recovery) }
    #expect(bytes.range(of: Data(fixtureCanary.utf8)) == nil)
}

@Test func freshNonceEncapsulationAndDataKey() throws {
    let fixture = try Fixture()
    let first = try SealedRecord.parse(fixture.seal())
    let second = try SealedRecord.parse(fixture.seal(context: fixture.changedContext(revision: 9)))
    #expect(first.nonce != second.nonce)
    #expect(zip(first.envelopes, second.envelopes).allSatisfy { $0.encapsulatedKey != $1.encapsulatedKey })
    // Unwrap both keys only inside the test, then compare booleans so diagnostics cannot disclose them.
    func unwrap(_ record: SealedRecord) throws -> Data {
        let envelope = try #require(record.envelopes.first { $0.publicKey == fixture.devices[0].publicKey.rawRepresentation })
        var receiver = try HPKE.Recipient(privateKey: fixture.devices[0], ciphersuite: .Curve25519_SHA256_ChachaPoly,
                                          info: SealedRecord.hpkeInfo, encapsulatedKey: envelope.encapsulatedKey)
        return try receiver.open(envelope.ciphertext, authenticating: record.wrapAAD(role: .device, publicKey: envelope.publicKey))
    }
    let keysDiffer = try unwrap(first) != unwrap(second)
    #expect(keysDiffer)
}

@Test func signatureCheckedBeforeIdentityAndDecryption() throws {
    let fixture = try Fixture()
    var bytes = try fixture.seal()
    bytes[bytes.count - 1] ^= 1
    expectError(.badSignature) { _ = try fixture.open(bytes) }
    expectError(.badSignature) { _ = try fixture.open(bytes, recipient: fixture.unrelated) }
    expectError(.badSignature) { _ = try fixture.open(bytes, expected: fixture.changedContext(vault: 9)) }
    var record = try SealedRecord.parse(fixture.seal())
    record.envelopes[0].ciphertext[0] ^= 1
    expectError(.badSignature) { _ = try fixture.open(record.encoded) }
    let otherAuthor = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x61, count: 32))
    let stranger = try sealRevision(context: fixture.context, author: otherAuthor, recipients: fixture.recipients, item: fixture.item)
    expectError(.badSignature) { _ = try fixture.open(stranger) }
}

@Test func resignedPayloadAndEnvelopeTampering() throws {
    let fixture = try Fixture()
    let original = try SealedRecord.parse(fixture.seal())
    for field in 0..<3 {
        var record = original
        switch field {
        case 0: record.ciphertext[0] ^= 1
        case 1: record.nonce[0] ^= 1
        default: record.tag[0] ^= 1
        }
        expectError(.badAuthentication) { _ = try fixture.open(fixture.resign(record)) }
    }
    var swapped = original
    let first = swapped.envelopes[0]
    swapped.envelopes[0].encapsulatedKey = swapped.envelopes[1].encapsulatedKey
    swapped.envelopes[0].ciphertext = swapped.envelopes[1].ciphertext
    swapped.envelopes[1].encapsulatedKey = first.encapsulatedKey
    swapped.envelopes[1].ciphertext = first.ciphertext
    for device in fixture.devices {
        expectError(.badAuthentication) { _ = try fixture.open(fixture.resign(swapped), recipient: device) }
    }
    var substituted = original
    let index = try #require(substituted.envelopes.firstIndex { $0.role == .recovery })
    substituted.envelopes[index].publicKey = fixture.unrelated.publicKey.rawRepresentation
    expectError(.badAuthentication) {
        _ = try fixture.open(fixture.resign(substituted), role: .recovery, recipient: fixture.unrelated)
    }
    var roleChanged = original
    roleChanged.envelopes[index].role = .device
    roleChanged.envelopes.sort { $0.sortKey.lexicographicallyPrecedes($1.sortKey) }
    expectError(.badAuthentication) {
        _ = try fixture.open(fixture.resign(roleChanged), role: .device, recipient: fixture.recovery)
    }
}

@Test func contextComparisonsAndTransplantBinding() throws {
    let fixture = try Fixture()
    let original = try SealedRecord.parse(fixture.seal())
    let contexts = try [fixture.changedContext(vault: 9), fixture.changedContext(item: 9),
                        fixture.changedContext(revision: 9), fixture.changedContext(head: 9)]
    for context in contexts {
        expectError(.unexpectedIdentity) { _ = try fixture.open(original.encoded, expected: context) }
        var transplanted = original
        transplanted.context = context
        let bytes = try fixture.resign(transplanted)
        expectError(.unexpectedIdentity) { _ = try fixture.open(bytes) }
        expectError(.badAuthentication) { _ = try fixture.open(bytes, expected: context) }
    }
    var parentsChanged = original
    parentsChanged.parents = [Data(repeating: 9, count: 32)]
    expectError(.badAuthentication) { _ = try fixture.open(fixture.resign(parentsChanged)) }
    let otherRevision = try SealedRecord.parse(fixture.seal(context: fixture.changedContext(revision: 8)))
    var envelopeTransplant = original
    envelopeTransplant.envelopes = otherRevision.envelopes
    expectError(.badAuthentication) { _ = try fixture.open(fixture.resign(envelopeTransplant)) }
}

@Test func logPinsAuthorsAndVaultAndStoresExactBytes() throws {
    let fixture = try Fixture()
    var log = try RevisionLog(vaultID: fixture.context.vaultID, trustedAuthors: [fixture.author.publicKey])
    let bytes = try fixture.seal()
    #expect(log.accept(bytes) == .inserted)
    #expect(log.accept(bytes) == .duplicate)
    let conflict = try fixture.seal()
    #expect(bytes != conflict)
    #expect(log.accept(conflict) == .conflict)
    #expect(log.accept(bytes) == .duplicate)
    let another = try fixture.seal(context: fixture.changedContext(revision: 8))
    #expect(log.accept(another) == .inserted)
    let otherVault = try fixture.seal(context: fixture.changedContext(vault: 9))
    #expect(log.accept(otherVault) == .rejected)
    let stranger = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x61, count: 32))
    let strangerBytes = try sealRevision(context: fixture.changedContext(revision: 9), author: stranger,
                                        recipients: fixture.recipients, item: fixture.item)
    #expect(log.accept(strangerBytes) == .rejected)
    var empty = try RevisionLog(vaultID: fixture.context.vaultID, trustedAuthors: [])
    #expect(empty.accept(bytes) == .rejected)
    var other = try RevisionLog(vaultID: Data(repeating: 9, count: 16), trustedAuthors: [fixture.author.publicKey])
    #expect(other.accept(bytes) == .rejected)
    var badSignature = bytes
    badSignature[badSignature.count - 1] ^= 1
    #expect(log.accept(badSignature) == .rejected)
    #expect(log.accept(bytes + Data([0])) == .rejected)
}

@Test func secretDescriptionsAreRedacted() throws {
    let fixture = try Fixture()
    #expect(String(reflecting: fixture.context) == "RevisionContext(<redacted>)")
    #expect(String(reflecting: try fixture.recipients[0]) == "RevisionRecipient(<redacted>)")
    var log = try RevisionLog(vaultID: fixture.context.vaultID, trustedAuthors: [fixture.author.publicKey])
    #expect(log.accept(try fixture.seal()) == .inserted)
    #expect(String(reflecting: log) == "RevisionLog(<redacted>)")
    #expect(Mirror(reflecting: log).children.isEmpty)
    let rendered = [String(describing: fixture.item), String(reflecting: fixture.item)]
    #expect(rendered.allSatisfy { $0 == "LoginItem(<redacted>)" })
    #expect(Mirror(reflecting: fixture.item).children.isEmpty)
    var dumped = ""
    dump(fixture.item, to: &dumped)
    #expect(!dumped.contains(fixtureCanary))
    #expect(!dumped.contains(fixture.item.username))
    for error in [VaultError.malformed, .badSignature, .badAuthentication, .unexpectedIdentity, .conflict] {
        #expect(error.localizedDescription == error.rawValue)
        #expect(String(describing: error) == error.rawValue)
        #expect(String(reflecting: error) == error.rawValue)
    }
}
