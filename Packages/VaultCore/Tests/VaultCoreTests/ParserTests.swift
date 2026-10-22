import Crypto
import Foundation
import Testing
@testable import VaultCore

@Test func malformedHeadersLengthsAndTruncation() throws {
    let fixture = try Fixture()
    let bytes = try fixture.seal()
    for length in 0..<bytes.count {
        expectError(.malformed) { _ = try fixture.open(Data(bytes.prefix(length))) }
    }
    expectError(.malformed) { _ = try fixture.open(bytes + Data([0])) }
    expectError(.malformed) { _ = try fixture.open(Data(repeating: 0, count: SealedRecord.maximumSize + 1)) }
    for offset in [0, 8, 9, 10] {
        var bad = bytes
        bad[offset] = 0xFF
        expectError(.malformed) { _ = try fixture.open(bad) }
    }
    let record = try SealedRecord.parse(bytes)
    // Fixed header through author = 123 bytes. Parent count is the next UInt32.
    for (offset, value) in [(123, UInt32(17)), (139, UInt32(262145)), (139, UInt32.max),
                            (143 + record.ciphertext.count + 16, UInt32(0)),
                            (143 + record.ciphertext.count + 16, UInt32(33))] {
        var bad = bytes
        bad.replaceSubrange(offset..<(offset + 4), with: [UInt8(value >> 24), UInt8(truncatingIfNeeded: value >> 16),
                                                        UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)])
        expectError(.malformed) { _ = try fixture.open(bad) }
    }
    var unknownRole = bytes
    unknownRole[143 + record.ciphertext.count + 16 + 4] = 3
    expectError(.malformed) { _ = try fixture.open(unknownRole) }
    var shortKey = bytes
    shortKey.remove(at: 143 + record.ciphertext.count + 16 + 4 + 1)
    expectError(.malformed) { _ = try fixture.open(shortKey) }
    expectError(.malformed) {
        _ = try RevisionContext(vaultID: Data(count: 15), itemID: Data(count: 16),
                                revisionID: Data(count: 16), membershipHead: Data(count: 32))
    }
}

@Test func signedNoncanonicalParentsAndRecipientsAreMalformed() throws {
    let fixture = try Fixture()
    let parents = [Data(repeating: 1, count: 32), Data(repeating: 2, count: 32)]
    let original = try SealedRecord.parse(fixture.seal(parents: parents.reversed()))
    #expect(original.parents == parents)
    #expect(original.encoded == (try SealedRecord.parse(original.encoded)).encoded)
    var record = original
    record.parents.reverse()
    expectError(.malformed) { _ = try fixture.open(fixture.resign(record)) }
    record = original
    record.parents[1] = record.parents[0]
    expectError(.malformed) { _ = try fixture.open(fixture.resign(record)) }
    record = original
    record.envelopes.reverse()
    expectError(.malformed) { _ = try fixture.open(fixture.resign(record)) }
    record = original
    record.envelopes[1] = record.envelopes[0]
    expectError(.malformed) { _ = try fixture.open(fixture.resign(record)) }
    var log = try RevisionLog(vaultID: fixture.context.vaultID, trustedAuthors: [fixture.author.publicKey])
    #expect(log.accept(try fixture.resign(record)) == .rejected)
}

@Test func sealInputBoundsAndCanonicalOrdering() throws {
    let fixture = try Fixture()
    func seal(_ item: LoginItem = LoginItem(username: "", password: Data(), origins: []),
              parents: [Data] = [], recipients: [RevisionRecipient]? = nil) throws {
        _ = try sealRevision(context: fixture.context, parents: parents, author: fixture.author,
                             recipients: recipients ?? fixture.recipients, item: item)
    }
    expectError(.malformed) { try seal(parents: [Data(count: 31)]) }
    expectError(.malformed) { try seal(parents: Array(repeating: Data(count: 32), count: 17)) }
    expectError(.malformed) { try seal(parents: [Data(count: 32), Data(count: 32)]) }
    expectError(.malformed) { try seal(recipients: []) }
    expectError(.malformed) { try seal(recipients: Array(repeating: fixture.recipients[0], count: 33)) }
    expectError(.malformed) { try seal(recipients: [fixture.recipients[0], fixture.recipients[0]]) }
    for item in [LoginItem(username: String(repeating: "a", count: 1025), password: Data(), origins: []),
                 LoginItem(username: String(repeating: "é", count: 513), password: Data(), origins: []),
                 LoginItem(username: "", password: Data(count: 4097), origins: []),
                 LoginItem(username: "", password: Data(), origins: (0..<33).map { "https://\($0).invalid" }),
                 LoginItem(username: "", password: Data(), origins: [String(repeating: "a", count: 257)]),
                 LoginItem(username: "", password: Data(), origins: ["é"]),
                 LoginItem(username: "", password: Data(), origins: ["a", "a"])] {
        expectError(.malformed) { try seal(item) }
    }
    let boundary = LoginItem(username: String(repeating: "a", count: 1024), password: Data(repeating: 0xF1, count: 4096),
                             origins: (0..<32).map { String(format: "%03d", $0) + String(repeating: "a", count: 253) })
    let bytes = try sealRevision(context: fixture.context, parents: (0..<16).map { Data(repeating: UInt8($0), count: 32) },
                                 author: fixture.author, recipients: fixture.recipients.reversed(), item: boundary)
    let opened = try fixture.open(bytes)
    let matches = opened.username == boundary.username && opened.password == boundary.password && opened.origins == boundary.origins
    #expect(matches)
    let sorted = try SealedRecord.parse(bytes)
    #expect(strictlySorted(sorted.envelopes.map(\.sortKey)))
}

@Test func plaintextParserBoundsUTF8AndCanonicalOrigins() throws {
    var writer = BinaryWriter()
    writer.bytes(Data([1, 1]))
    writer.field(Data([0xFF]))
    writer.field(Data())
    writer.count(0)
    expectError(.malformed) { _ = try LoginItem.decode(writer.data) }
    let valid = try LoginItem(username: "", password: Data([0xFF, 0]), origins: ["b", "a"]).encode()
    let parsed = try LoginItem.decode(valid)
    #expect(parsed.origins == ["a", "b"])
    for length in 0..<valid.count {
        expectError(.malformed) { _ = try LoginItem.decode(Data(valid.prefix(length))) }
    }
    expectError(.malformed) { _ = try LoginItem.decode(valid + Data([0])) }
    expectError(.malformed) { _ = try LoginItem.decode(Data(count: 262145)) }
    for offset in [0, 1] {
        var bad = valid
        bad[offset] = 2
        expectError(.malformed) { _ = try LoginItem.decode(bad) }
    }
    for origins in [[Data("b".utf8), Data("a".utf8)], [Data("a".utf8), Data("a".utf8)], [Data([0x80])]] {
        var bad = BinaryWriter()
        bad.bytes(Data([1, 1]))
        bad.field(Data())
        bad.field(Data())
        bad.count(origins.count)
        for origin in origins { bad.field(origin) }
        expectError(.malformed) { _ = try LoginItem.decode(bad.data) }
    }
    for (offset, count) in [(2, 1025), (6, 4097), (12, 33), (16, 257)] {
        var bad = valid
        var length = BinaryWriter()
        length.count(count)
        bad.replaceSubrange(offset..<(offset + 4), with: length.data)
        expectError(.malformed) { _ = try LoginItem.decode(bad) }
    }
}
