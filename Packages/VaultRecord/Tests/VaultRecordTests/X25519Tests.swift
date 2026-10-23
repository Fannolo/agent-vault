import Crypto
import Foundation
import Testing
@testable import VaultRecord

/// u = 0, 1, the two order-eight points, p−1, p, p+1, each with its high-bit alias (RFC 7748).
/// The order-eight encodings also occur in swift-crypto's pinned x25519_test.json.
let lowOrderX25519: [Data] = {
    let representatives = [
        Data(count: 32),
        Data([1]) + Data(count: 31),
        unhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        unhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        Data([0xec]) + Data(repeating: 0xff, count: 30) + Data([0x7f]),
        Data([0xed]) + Data(repeating: 0xff, count: 30) + Data([0x7f]),
        Data([0xee]) + Data(repeating: 0xff, count: 30) + Data([0x7f]),
    ]
    return representatives + representatives.map { var alias = $0; alias[31] |= 0x80; return alias }
}()

/// Every field value p … 2^255 − 1 (top bit clear), i.e. noncanonical aliases of u = 0 … 18.
let fieldAliasesX25519: [Data] = (0xed...0xff).map { Data([UInt8($0)]) + Data(repeating: 0xff, count: 30) + Data([0x7f]) }

func zeroDHWrap(dataKey: SymmetricKey, encapsulation: Data, recipient: Recipient, headerHash: Data, messageID: Data,
                commitment: Data) throws -> ESDK.EncryptedDataKey {
    let schedule = try ManualHPKE(dh: Data(count: 32), encapsulation: encapsulation, recipient: recipient.publicKey,
                                  info: specInfo(headerHash: headerHash, messageID: messageID))
    let wrapped = try dataKey.withUnsafeBytes {
        try schedule.seal(Data($0), aad: specAAD(headerHash: headerHash, messageID: messageID, commitment: commitment,
                                                 role: recipient.role.rawValue, recipient: recipient.publicKey))
    }
    return ESDK.EncryptedDataKey(role: recipient.role.rawValue, recipient: recipient.publicKey,
                                 encapsulation: encapsulation, wrapped: wrapped)
}

@Test func lowOrderAndNoncanonicalRecipientKeysRefusedAtAuthority() throws {
    #expect(lowOrderX25519.count == 14)
    #expect(fieldAliasesX25519.count == 19)
    let valid = Fixture().device1.publicKey.rawRepresentation
    var aliasOfValid = valid
    aliasOfValid[31] |= 0x80
    for encoding in lowOrderX25519 + fieldAliasesX25519 + [aliasOfValid] {
        for role in [RecipientRole.device, .recovery] {
            #expect(throws: RecordError.invalidKey) { _ = try Recipient(role: role, publicKey: encoding) }
        }
    }
    #expect(throws: RecordError.invalidKey) { _ = try Recipient(role: .device, publicKey: valid.prefix(31)) }
    _ = try Recipient(role: .device, publicKey: valid)
}

/// The authority boundary refuses bad recipient keys; a record naming one instead of the
/// authority's key is an exact-set refusal.
@Test func recordWithAliasedRecipientKeyIsExactSetRefusal() throws {
    let fixture = Fixture()
    var hostile = HostileRecord(fixture, content: login())
    let original = hostile.recipients[0]
    var alias = original.publicKey
    alias[31] |= 0x80
    hostile.edk[0] = { headerHash, messageID, commitment in
        let good = try ESDK.wrap(SymmetricKey(size: .bits256), for: original, headerHash: headerHash, messageID: messageID,
                                 commitment: commitment)
        return ESDK.EncryptedDataKey(role: good.role, recipient: alias, encapsulation: good.encapsulation, wrapped: good.wrapped)
    }
    expectOpenRefusal(.unexpectedAuthority, fixture, try hostile.build())
}

/// Selected low-order encapsulation: the zero-DH wrap is recoverable from public data alone
/// (witness), yet the record is refused before any unwrap or callback.
@Test func lowOrderSelectedEncapsulationRefused() throws {
    let fixture = Fixture()
    for encapsulation in lowOrderX25519 {
        var hostile = HostileRecord(fixture, content: login())
        let recipient = hostile.recipients[0]
        let dataKey = hostile.dataKey
        hostile.edk[0] = { try zeroDHWrap(dataKey: dataKey, encapsulation: encapsulation, recipient: recipient,
                                          headerHash: $0, messageID: $1, commitment: $2) }
        let record = try hostile.build()
        let parsed = try ParsedRecord(record)
        let edk = parsed.message.edks[0]
        let witness = try ManualHPKE(dh: Data(count: 32), encapsulation: edk.encapsulation, recipient: edk.recipient,
                                     info: specInfo(headerHash: sha256(parsed.headerBytes), messageID: parsed.message.messageID))
        let recovered = try witness.open(edk.wrapped, aad: specAAD(
            headerHash: sha256(parsed.headerBytes), messageID: parsed.message.messageID,
            commitment: parsed.message.commitment, role: edk.role, recipient: edk.recipient))
        #expect(recovered == dataKey.withUnsafeBytes { Data($0) })
        let key = fixture.recipientKeys.first { $0.publicKey == recipient.publicKey }!
        expectOpenRefusal(.invalidKey, fixture, record, as: key)
    }
}

/// Unselected entries are checked too: one bad encapsulation refuses the record for every
/// recipient, including those whose own wrap is valid. The selected unwrap never touches it.
@Test func lowOrderUnselectedEncapsulationRefusedForEveryone() throws {
    let fixture = Fixture()
    for encapsulation in lowOrderX25519 + fieldAliasesX25519 {
        var hostile = HostileRecord(fixture, content: login())
        let recipient = hostile.recipients[2]
        let dataKey = hostile.dataKey
        hostile.edk[2] = { try zeroDHWrap(dataKey: dataKey, encapsulation: encapsulation, recipient: recipient,
                                          headerHash: $0, messageID: $1, commitment: $2) }
        let record = try hostile.build()
        for key in fixture.recipientKeys where key.publicKey != recipient.publicKey {
            expectOpenRefusal(.invalidKey, fixture, record, as: key)
        }
    }
}

/// High-bit alias of a genuine ephemeral key, with a wrap computed for the aliased bytes in
/// the KEM context. The profile's canonical check refuses it before unwrap.
@Test func noncanonicalEncapsulationAliasRefused() throws {
    let fixture = Fixture()
    for index in [0, 2] {
        var hostile = HostileRecord(fixture, content: login())
        let recipient = hostile.recipients[index]
        let dataKey = hostile.dataKey
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        var alias = ephemeral.publicKey.rawRepresentation
        alias[31] |= 0x80
        hostile.edk[index] = { headerHash, messageID, commitment in
            let schedule = try ManualHPKE(dh: ManualHPKE.dh(ephemeral, recipient.publicKey), encapsulation: alias,
                                          recipient: recipient.publicKey,
                                          info: specInfo(headerHash: headerHash, messageID: messageID))
            let wrapped = try dataKey.withUnsafeBytes {
                try schedule.seal(Data($0), aad: specAAD(headerHash: headerHash, messageID: messageID,
                                                         commitment: commitment, role: recipient.role.rawValue,
                                                         recipient: recipient.publicKey))
            }
            return ESDK.EncryptedDataKey(role: recipient.role.rawValue, recipient: recipient.publicKey,
                                         encapsulation: alias, wrapped: wrapped)
        }
        let record = try hostile.build()
        for key in fixture.recipientKeys { expectOpenRefusal(.invalidKey, fixture, record, as: key) }
    }
}

/// Library observation only (not an assertion of backend policy): does the platform HPKE
/// recipient accept the aliased encapsulation? Either way the profile refuses above.
@Test func aliasWitnessObservation() throws {
    let fixture = Fixture()
    let recipient = try Recipient(role: .device, publicKey: fixture.device1.publicKey.rawRepresentation)
    let ephemeral = Curve25519.KeyAgreement.PrivateKey()
    var alias = ephemeral.publicKey.rawRepresentation
    alias[31] |= 0x80
    let info = Data("alias-witness".utf8)
    let schedule = try ManualHPKE(dh: ManualHPKE.dh(ephemeral, recipient.publicKey), encapsulation: alias,
                                  recipient: recipient.publicKey, info: info)
    let wrapped = try schedule.seal(Data(repeating: 7, count: 32), aad: Data())
    var opened = false
    if var library = try? HPKE.Recipient(privateKey: fixture.device1, ciphersuite: .Curve25519_SHA256_ChachaPoly,
                                          info: info, encapsulatedKey: alias) {
        opened = (try? library.open(wrapped, authenticating: Data())) == Data(repeating: 7, count: 32)
    }
    emitPublic("AV_RECORD_ALIAS_WITNESS platform=\(platformName) library_hpke_opened_alias=\(opened)")
}
