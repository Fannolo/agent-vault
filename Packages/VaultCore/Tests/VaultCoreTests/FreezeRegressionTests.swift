import Crypto
import Foundation
import Testing
@testable import VaultCore

@Test func ed25519ScalarPlusOrderRejectedByOpenAndLog() throws {
    let fixture = try Fixture()
    let bytes = try fixture.seal()
    var malleated = bytes
    // Ed25519 group order L, little endian. Add only to signature S, never R/message.
    let order: [UInt8] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                         0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14] +
                        Array(repeating: 0, count: 15) + [0x10]
    var carry: UInt16 = 0
    for index in 0..<32 {
        let offset = malleated.count - 32 + index
        let sum = UInt16(malleated[offset]) + UInt16(order[index]) + carry
        malleated[offset] = UInt8(truncatingIfNeeded: sum)
        carry = sum >> 8
    }
    try #require(carry == 0)
    #expect(malleated.prefix(bytes.count - 32) == bytes.prefix(bytes.count - 32))
    #expect(malleated != bytes)
    expectError(.badSignature) { _ = try fixture.open(malleated) }
    var log = try RevisionLog(vaultID: fixture.context.vaultID, trustedAuthors: [fixture.author.publicKey])
    #expect(log.accept(malleated) == .rejected)
    #expect(log.accept(bytes) == .inserted)
    #expect(log.accept(malleated) == .rejected)
    #expect(log.accept(bytes) == .duplicate)
}

@Test func nonzeroStartSlicesOpenAndLogInsertDuplicateConflict() throws {
    let fixture = try Fixture()
    let bytes = try fixture.seal()
    let prefixCount = 4096
    let padded = Data(repeating: 0xa5, count: prefixCount) + bytes
    let slice = padded.dropFirst(prefixCount)
    try #require(slice.startIndex == prefixCount)
    #expect(fixture.matches(try fixture.open(slice)))
    var log = try RevisionLog(vaultID: fixture.context.vaultID, trustedAuthors: [fixture.author.publicKey])
    #expect(log.accept(slice) == .inserted)
    #expect(log.accept(slice) == .duplicate)
    #expect(log.accept(bytes) == .duplicate)
    let conflictingBytes = try fixture.seal()
    let conflictPadded = Data(repeating: 0x5a, count: prefixCount) + conflictingBytes
    let conflictSlice = conflictPadded.dropFirst(prefixCount)
    try #require(conflictSlice.startIndex == prefixCount)
    #expect(fixture.matches(try fixture.open(conflictSlice)))
    #expect(log.accept(conflictSlice) == .conflict)
    #expect(log.accept(slice) == .duplicate)
}

@Test func bomPrefixedUsernamePreservesExactUTF8() throws {
    let fixture = try Fixture()
    let original = Data([0xef, 0xbb, 0xbf]) + Data("synthetic-user".utf8)
    let item = LoginItem(username: String(decoding: original, as: UTF8.self),
                         password: fixture.item.password, origins: fixture.item.origins)
    let decoded = try LoginItem.decode(item.encode())
    let decodedBytesMatch = Data(decoded.username.utf8) == original
    #expect(decodedBytesMatch)
    let bytes = try sealRevision(context: fixture.context, author: fixture.author, recipients: fixture.recipients, item: item)
    for device in fixture.devices {
        let opened = try fixture.open(bytes, recipient: device)
        let openedBytesMatch = Data(opened.username.utf8) == original
        #expect(openedBytesMatch)
    }
}
