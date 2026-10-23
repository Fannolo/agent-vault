import Crypto
import Foundation
import Testing
@testable import VaultRecord

private func set(_ data: Data, _ offset: Int, _ bytes: [UInt8]) -> Data {
    var copy = data
    copy.replaceSubrange(offset..<(offset + bytes.count), with: bytes)
    return copy
}

private func be32(_ value: UInt32) -> [UInt8] { [UInt8(value >> 24), UInt8(truncatingIfNeeded: value >> 16),
                                                  UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)] }

/// Every truncation, every one-byte extension and wrong fixed values fail the bounded parse.
@Test func truncationAndTrailingBytes() throws {
    let record = try Fixture().seal(.tombstone).bytes
    for length in 0..<record.count {
        expectRefusal(.malformed) { _ = try ParsedRecord(record.prefix(length)) }
    }
    expectRefusal(.malformed) { _ = try ParsedRecord(record + Data([0])) }
    expectRefusal(.malformed) { _ = try ParsedRecord(Data(count: RecordFormat.maximumRecordBytes + 1)) }
}

@Test func fixedPublicFieldsAndCounts() throws {
    let fixture = Fixture()
    let record = try fixture.seal(.tombstone).bytes
    let l = Layout(parents: 0, recipients: 3)
    var cases: [Data] = [
        set(record, 0, Array("AVREC003".utf8)), set(record, 8, [3]), set(record, 9, [2]),
        set(record, 10, [0]), set(record, 10, [5]), set(record, 10, [0xff]),
        set(record, 11, [UInt8](repeating: 0, count: 16)), set(record, 27, [UInt8](repeating: 0, count: 16)),
        set(record, 43, [UInt8](repeating: 0, count: 16)), set(record, 59, [UInt8](repeating: 0, count: 32)),
        set(record, 123, [17]), set(record, 123, [1]),
        set(record, l.p, be32(UInt32(record.count))), set(record, l.p, be32(0xffff_ffff)),
        set(record, l.e, [1]), set(record, l.e + 1, [0x04, 0x78 ^ 1]), set(record, l.e + 1, [0x01, 0x78]),
        set(record, l.e + 35, [0, 81]), set(record, l.e + 35, [0xff, 0xff]),
        set(record, l.e + 37, [0, 2]), set(record, l.e + 39, [0, 11]),
        set(record, l.e + 39 + 2, Array("AV-context".utf8)),
        set(record, l.e + 117, [0, 0]), set(record, l.e + 117, [0, 33]), set(record, l.e + 117, [0xff, 0xff]),
        set(record, l.e + 117, [0, 2]), set(record, l.e + 117, [0, 4]),
        set(record, l.e + 117, [0, 10]),
    ]
    let firstEDK = l.e + 119
    cases += [
        set(record, firstEDK, [0, 10]), set(record, firstEDK + 2, Array("av-hpke-3".utf8)),
        set(record, firstEDK + 11, [0, 32]), set(record, firstEDK + 13, [3]), set(record, firstEDK + 13, [0]),
        set(record, firstEDK + 46, [0, 79]),
        set(record, l.commitment - 5, [1]), set(record, l.commitment - 4, be32(262_144)),
        set(record, l.frame, be32(0xffff_fffe)), set(record, l.frame + 4, be32(2)), set(record, l.frame + 4, be32(0)),
        set(record, l.frame + 8, [UInt8](repeating: 0, count: 12)), set(record, l.frame + 19, [2]),
        set(record, l.frame + 20, be32(511)), set(record, l.frame + 20, be32(1024)), set(record, l.frame + 20, be32(0)),
        set(record, l.frame + 20, be32(65_536)), set(record, l.frame + 20, be32(0xffff_ffff)),
    ]
    for (index, bytes) in cases.enumerated() {
        let callbacks = Callbacks()
        expectRefusal(.malformed) { _ = try ParsedRecord(bytes) }
        #expect(callbacks.count == 0, "case \(index)")
    }
}

/// Validly signed records with unsorted/duplicate parents or recipient entries.
@Test func signedNoncanonicalOrderIsMalformed() throws {
    let fixture = Fixture()
    let a = Data(repeating: 1, count: 32), b = Data(repeating: 2, count: 32)
    for parents in [[b, a], [a, a], [Data(count: 32)], Array(repeating: a, count: 17)] {
        var hostile = HostileRecord(fixture, content: login())
        hostile.parents = parents
        expectRefusal(.malformed) { _ = try ParsedRecord(try hostile.build()) }
    }
    var ordered = HostileRecord(fixture, content: login())
    ordered.parents = [a, b]
    _ = try ParsedRecord(try ordered.build())
    var swapped = HostileRecord(fixture, content: login())
    swapped.recipients = [swapped.recipients[1], swapped.recipients[0], swapped.recipients[2]]
    expectRefusal(.malformed) { _ = try ParsedRecord(try swapped.build()) }
    var duplicated = HostileRecord(fixture, content: login())
    duplicated.recipients = [duplicated.recipients[0], duplicated.recipients[0], duplicated.recipients[2]]
    expectRefusal(.malformed) { _ = try ParsedRecord(try duplicated.build()) }
}

/// A frame larger than 32 KiB cannot be a canonical kind 1–3 payload; refused at parse.
@Test func kindOneToThreeBucketBoundIsEnforcedBeforeDecryption() throws {
    let fixture = Fixture()
    var hostile = HostileRecord(fixture, content: .tombstone)
    hostile.padded = [0, 0, 0, 2, 2, 3] + [UInt8](repeating: 0, count: 65_536 - 6)
    expectRefusal(.malformed) { _ = try ParsedRecord(try hostile.build()) }
}

/// Generic ESDK layer: one full 524,288-byte final frame parses and authenticates when the
/// caller's bucket bound allows it. Not a valid unit record.
@Test func genericESDKFullFinalFrame() throws {
    let dataKey = SymmetricKey(size: .bits256)
    let messageID = randomBytes(32)
    let headerHash = sha256(Data("generic".utf8))
    let keys = ESDK.derive(dataKey: dataKey, messageID: messageID)
    let recipient = try Recipient(role: .device, publicKey: Fixture().device1.publicKey.rawRepresentation)
    let edk = try ESDK.wrap(dataKey, for: recipient, headerHash: headerHash, messageID: messageID, commitment: keys.commitment)
    let header = ESDK.header(messageID: messageID, context: ESDK.context(headerHash: headerHash), edks: [edk],
                             commitment: keys.commitment)
    let plaintext = [UInt8](repeating: 0x33, count: 524_288)
    let (ciphertext, tag) = try ESDK.sealFrame(key: keys.encryption, messageID: messageID, padded: plaintext)
    let message = ESDK.body(header: header, headerTag: try ESDK.headerTag(key: keys.encryption, header: header),
                            ciphertext: ciphertext, frameTag: tag)
    expectRefusal(.malformed) { _ = try ESDK.parse(message, maximumBucket: Payload.maximumBucketForKinds1To3) }
    let parsed = try ESDK.parse(message, maximumBucket: 524_288)
    #expect(Array(try ESDK.decrypt(parsed, dataKey: dataKey)) == plaintext)
}
