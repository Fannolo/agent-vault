import Crypto
import Foundation
import Testing
@testable import VaultCore

private func publicHex(_ text: String) throws -> Data {
    let characters = Array(text.utf8)
    try #require(characters.count.isMultiple(of: 2))
    return try Data(stride(from: 0, to: characters.count, by: 2).map {
        try #require(UInt8(String(decoding: characters[$0..<($0 + 2)], as: UTF8.self), radix: 16))
    })
}

// u = 0, 1, two order-eight points, p-1, p, p+1; plus RFC 7748 high-bit aliases.
// The order-eight encodings also occur in swift-crypto's pinned x25519_test.json.
private func lowOrderEncodings() throws -> [Data] {
    let representatives = try [
        Data(count: 32),
        Data([1]) + Data(count: 31),
        publicHex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        publicHex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        Data([0xec]) + Data(repeating: 0xff, count: 30) + Data([0x7f]),
        Data([0xed]) + Data(repeating: 0xff, count: 30) + Data([0x7f]),
        Data([0xee]) + Data(repeating: 0xff, count: 30) + Data([0x7f])
    ]
    return representatives + representatives.map {
        var alias = $0
        alias[31] |= 0x80
        return alias
    }
}

// TEST ONLY: RFC 9180 base-mode key schedule from DH = 0 and public transcript.
// No recipient private key or sender context is an input to this witness.
private struct PublicZeroDHSchedule {
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

private func syntheticPayload(_ fixture: Fixture, key: SymmetricKey) throws -> SealedRecord {
    var record = SealedRecord(context: fixture.context, author: fixture.author.publicKey.rawRepresentation,
                              parents: [], nonce: Data(), ciphertext: Data(), tag: Data(), envelopes: [], signature: Data())
    let payload = try ChaChaPoly.seal(fixture.item.encode(), using: key, authenticating: record.payloadAAD)
    record.nonce = payload.nonce.withUnsafeBytes { Data($0) }
    record.ciphertext = payload.ciphertext
    record.tag = payload.tag
    return record
}

private func unvalidatedLowOrderRecord(_ fixture: Fixture, recipientKey: Curve25519.KeyAgreement.PublicKey) throws -> Data {
    let dataKey = SymmetricKey(size: .bits256)
    var record = try syntheticPayload(fixture, key: dataKey)
    let publicKey = recipientKey.rawRepresentation
    let encapsulatedKey: Data
    let wrap: Data
    #if os(Linux)
    // Pinned swift-crypto/BoringSSL ignores the zero-DH failure. Exercise that primitive.
    var sender = try HPKE.Sender(recipientKey: recipientKey, ciphersuite: .Curve25519_SHA256_ChachaPoly,
                                 info: SealedRecord.hpkeInfo)
    encapsulatedKey = sender.encapsulatedKey
    wrap = try dataKey.withUnsafeBytes {
        try sender.seal($0, authenticating: record.wrapAAD(role: .device, publicKey: publicKey))
    }
    #else
    // Native CryptoKit can reject already. Model the unchecked primitive explicitly:
    // every clamped ephemeral scalar times these low-order inputs gives zero DH.
    encapsulatedKey = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
    let unchecked = try PublicZeroDHSchedule(encapsulatedKey: encapsulatedKey, recipientKey: publicKey)
    wrap = try unchecked.seal(dataKey, aad: record.wrapAAD(role: .device, publicKey: publicKey))
    #endif
    record.envelopes = [Envelope(role: .device, publicKey: publicKey,
                                 encapsulatedKey: encapsulatedKey, ciphertext: wrap)]
    return try fixture.resign(record)
}

private func recoverUsingPublicInformation(_ bytes: Data) throws -> LoginItem {
    let record = try SealedRecord.parse(bytes)
    let envelope = try #require(record.envelopes.first)
    let schedule = try PublicZeroDHSchedule(encapsulatedKey: envelope.encapsulatedKey, recipientKey: envelope.publicKey)
    let dataKey = try schedule.open(envelope.ciphertext,
                                   aad: record.wrapAAD(role: envelope.role, publicKey: envelope.publicKey))
    let payload = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: record.nonce),
                                          ciphertext: record.ciphertext, tag: record.tag)
    return try LoginItem.decode(ChaChaPoly.open(payload, using: SymmetricKey(data: dataKey), authenticating: record.payloadAAD))
}

@Test func lowOrderRecipientValidationPreventsPublicRecovery() throws {
    let fixture = try Fixture()
    let encodings = try lowOrderEncodings()
    #expect(encodings.count == 14)
    for encoding in encodings {
        let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: encoding)
        let vulnerable = try unvalidatedLowOrderRecord(fixture, recipientKey: publicKey)
        let recovered = try recoverUsingPublicInformation(vulnerable)
        let recoveredCanary = fixture.matches(recovered)
        #expect(recoveredCanary)
        for role in [RecipientRole.device, .recovery] {
            expectError(.malformed) {
                _ = try RevisionRecipient(role: role, publicKey: publicKey)
            }
            expectError(.malformed) {
                let recipient = try RevisionRecipient(role: role, publicKey: publicKey)
                _ = try sealRevision(context: fixture.context, author: fixture.author, recipients: [recipient], item: fixture.item)
            }
        }
    }
}

@Test func lowOrderEncapsulationRejectedAfterSignatureAndContext() throws {
    let fixture = try Fixture()
    let publicKey = fixture.devices[0].publicKey.rawRepresentation
    for encapsulatedKey in try lowOrderEncodings() {
        let dataKey = SymmetricKey(size: .bits256)
        var record = try syntheticPayload(fixture, key: dataKey)
        let schedule = try PublicZeroDHSchedule(encapsulatedKey: encapsulatedKey, recipientKey: publicKey)
        let wrap = try schedule.seal(dataKey, aad: record.wrapAAD(role: .device, publicKey: publicKey))
        record.envelopes = [Envelope(role: .device, publicKey: publicKey, encapsulatedKey: encapsulatedKey, ciphertext: wrap)]
        let bytes = try fixture.resign(record)
        // This wrap and payload authenticate under zero DH; AEAD alone cannot reject them.
        let recoveredCanary = fixture.matches(try recoverUsingPublicInformation(bytes))
        #expect(recoveredCanary)
        expectError(.badAuthentication) { _ = try fixture.open(bytes) }
        expectError(.unexpectedIdentity) { _ = try fixture.open(bytes, expected: fixture.changedContext(head: 9)) }
        var badSignature = bytes
        badSignature[badSignature.count - 1] ^= 1
        expectError(.badSignature) { _ = try fixture.open(badSignature) }
        expectError(.badSignature) { _ = try fixture.open(badSignature, expected: fixture.changedContext(head: 9)) }
    }
}
