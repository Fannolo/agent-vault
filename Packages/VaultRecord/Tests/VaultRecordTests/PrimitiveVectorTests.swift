import Crypto
import Foundation
import Testing
@testable import VaultRecord

/// RFC 9180 Appendix A.2.1 (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, base).
/// RFC text SHA-256 f45a8b7c30231b26d668b1e8168074e5ab514b174d656b67e859895117f1f8f6.
@Test func rfc9180BaseVectorForSelectedSuite() throws {
    let info = unhex("4f6465206f6e2061204772656369616e2055726e")
    let skE = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: unhex("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600"))
    let skR = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: unhex("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb"))
    let pkR = unhex("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a")
    let enc = unhex("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a")
    #expect(skE.publicKey.rawRepresentation == enc)
    #expect(skR.publicKey.rawRepresentation == pkR)
    let schedule = try ManualHPKE(dh: ManualHPKE.dh(skE, pkR), encapsulation: enc, recipient: pkR, info: info)
    #expect(schedule.sharedSecret == unhex("0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7"))
    #expect(schedule.key.withUnsafeBytes { Data($0) } == unhex("ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91"))
    #expect(schedule.nonce.withUnsafeBytes { Data($0) } == unhex("5c4d98150661b848853b547f"))
    let pt = unhex("4265617574792069732074727574682c20747275746820626561757479")
    let aad = unhex("436f756e742d30")
    let ct = unhex("1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28")
    #expect(try schedule.seal(pt, aad: aad) == ct)
    var library = try HPKE.Recipient(privateKey: skR, ciphersuite: .Curve25519_SHA256_ChachaPoly, info: info, encapsulatedKey: enc)
    #expect(try library.open(ct, authenticating: aad) == pt)
}

/// Spec-text HKDF-SHA512 key schedule (AWS transitive requirements), written independently
/// of `ESDK.derive`.
func specCommitment(dataKey: Data, messageID: Data) -> (encryption: Data, commitment: Data) {
    let prk = HKDF<SHA512>.extract(inputKeyMaterial: SymmetricKey(data: dataKey), salt: messageID)
    let encryption = HKDF<SHA512>.expand(pseudoRandomKey: prk, info: Data([0x04, 0x78]) + Data("DERIVEKEY".utf8), outputByteCount: 32)
    let commitment = HKDF<SHA512>.expand(pseudoRandomKey: prk, info: Data("COMMITKEY".utf8), outputByteCount: 32)
    return (encryption.withUnsafeBytes { Data($0) }, commitment.withUnsafeBytes { Data($0) })
}

/// Our wraps open under the independent RFC 9180 schedule with spec-text info/AAD, the DK
/// matches the stored commitment, and the header tag and frame open with spec-derived Kenc.
@Test func sealedWrapsOpenUnderIndependentSchedule() throws {
    let fixture = Fixture()
    let record = try fixture.seal(login())
    let parsed = try ParsedRecord(record.bytes)
    let headerHash = Data(SHA256.hash(data: parsed.headerBytes))
    var keys: Set<Data> = []
    for edk in parsed.message.edks {
        let holder = fixture.recipientKeys.first { $0.publicKey == edk.recipient }!
        let schedule = try ManualHPKE(dh: ManualHPKE.dh(holder.privateKey, edk.encapsulation), encapsulation: edk.encapsulation,
                                      recipient: edk.recipient, info: specInfo(headerHash: headerHash, messageID: parsed.message.messageID))
        let dataKey = try schedule.open(edk.wrapped, aad: specAAD(headerHash: headerHash, messageID: parsed.message.messageID,
                                                                  commitment: parsed.message.commitment, role: edk.role,
                                                                  recipient: edk.recipient))
        keys.insert(dataKey)
        let derived = specCommitment(dataKey: dataKey, messageID: parsed.message.messageID)
        #expect(derived.commitment == parsed.message.commitment)
        let key = SymmetricKey(data: derived.encryption)
        _ = try AES.GCM.open(.init(nonce: .init(data: Data(count: 12)), ciphertext: Data(), tag: parsed.message.headerTag),
                             using: key, authenticating: parsed.message.header)
        let frameAAD = parsed.message.messageID + Data("AWSKMSEncryptionClient Final Frame".utf8) + Data([0, 0, 0, 1])
            + Data([0, 0, 0, 0, 0, 0, 0x02, 0x00])
        let padded = try AES.GCM.open(.init(nonce: .init(data: Data(count: 11) + Data([1])), ciphertext: parsed.message.ciphertext,
                                            tag: parsed.message.frameTag), using: key, authenticating: frameAAD)
        #expect(padded.count == 512)
    }
    #expect(keys.count == 1)
}

/// Reverse direction: a wrap sealed by the independent schedule opens through the record API.
@Test func independentlySealedWrapOpensThroughRecordAPI() throws {
    let fixture = Fixture()
    var hostile = HostileRecord(fixture, content: login())
    let recipient = hostile.recipients[1]
    let dataKey = hostile.dataKey
    hostile.edk[1] = { headerHash, messageID, commitment in
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let enc = ephemeral.publicKey.rawRepresentation
        let schedule = try ManualHPKE(dh: ManualHPKE.dh(ephemeral, recipient.publicKey), encapsulation: enc,
                                      recipient: recipient.publicKey, info: specInfo(headerHash: headerHash, messageID: messageID))
        let wrapped = try dataKey.withUnsafeBytes {
            try schedule.seal(Data($0), aad: specAAD(headerHash: headerHash, messageID: messageID, commitment: commitment,
                                                     role: recipient.role.rawValue, recipient: recipient.publicKey))
        }
        return ESDK.EncryptedDataKey(role: recipient.role.rawValue, recipient: recipient.publicKey, encapsulation: enc, wrapped: wrapped)
    }
    let record = try hostile.build()
    let holder = fixture.recipientKeys.first { $0.publicKey == recipient.publicKey }!
    try fixture.verify(record).open(as: holder) { opened in
        guard case .login = opened else { Issue.record("shape"); return }
    }
}
