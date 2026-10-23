import Crypto
import Foundation
import Testing
@testable import VaultRecord

@Test func independentlySuppliedAuthorityIsRequired() throws {
    let fixture = Fixture()
    let record = try fixture.seal(login()).bytes
    let wrongVault = try VaultID(Data(repeating: 0x0e, count: 16))
    let wrongMembership = try MembershipBodyID(Data(repeating: 0x0f, count: 32))
    expectOpenRefusal(.unexpectedAuthority, fixture, record, authority: fixture.authority(vault: wrongVault))
    expectOpenRefusal(.unexpectedAuthority, fixture, record, authority: fixture.authority(membership: wrongMembership))
    expectOpenRefusal(.badSignature, fixture, record,
                      authority: fixture.authority(author: fixture.otherAuthor.publicKey.rawRepresentation))
    // Recipient set: missing, extra, and role-swapped members are exact-set refusals.
    let members = fixture.recipients.members
    let missing = try RecipientSet(Array(members.dropLast()))
    let extra = try RecipientSet(members + [Recipient(role: .device, publicKey: fixture.unrelated.publicKey.rawRepresentation)])
    let swapped = try RecipientSet(members.map {
        try Recipient(role: $0.role == .device ? .recovery : .device, publicKey: $0.publicKey)
    })
    for set in [missing, extra, swapped] {
        expectOpenRefusal(.unexpectedAuthority, fixture, record, authority: fixture.authority(recipients: set))
    }
    // Expected item and revision.
    let parsed = try ParsedRecord(record)
    let otherItem = try ItemID(Data(repeating: 0x55, count: 16))
    let otherRevision = try RevisionID(Data(repeating: 0x66, count: 16))
    expectRefusal(.unexpectedAuthority) { _ = try parsed.verify(under: fixture.authority(), item: otherItem, revision: fixture.revisionID) }
    expectRefusal(.unexpectedAuthority) { _ = try parsed.verify(under: fixture.authority(), item: fixture.itemID, revision: otherRevision) }
}

/// Valid signatures by the expected author over records claiming another context.
@Test func validlySignedWrongContextIsRefused() throws {
    let fixture = Fixture()
    var vault = HostileRecord(fixture, content: login())
    vault.vault = Data(repeating: 0x0e, count: 16)
    var membership = HostileRecord(fixture, content: login())
    membership.membership = Data(repeating: 0x0f, count: 32)
    var item = HostileRecord(fixture, content: login())
    item.item = Data(repeating: 0x55, count: 16)
    var revision = HostileRecord(fixture, content: login())
    revision.revision = Data(repeating: 0x66, count: 16)
    var claimedAuthor = HostileRecord(fixture, content: login())
    claimedAuthor.author = fixture.otherAuthor.publicKey.rawRepresentation // signed by the real author
    var recipients = HostileRecord(fixture, content: login())
    recipients.recipients = Array(fixture.recipients.members.prefix(2))
    for hostile in [vault, membership, item, revision, claimedAuthor, recipients] {
        expectOpenRefusal(.unexpectedAuthority, fixture, try hostile.build())
    }
}

/// The record's self-declared author never selects its own authority.
@Test func selfDeclaredAuthorCannotAuthenticate() throws {
    let fixture = Fixture()
    var hostile = HostileRecord(fixture, content: login())
    hostile.author = fixture.otherAuthor.publicKey.rawRepresentation
    hostile.signer = fixture.otherAuthor
    let record = try hostile.build()
    expectOpenRefusal(.badSignature, fixture, record)
    // Only an authority that independently names the other key accepts it.
    let other = fixture.authority(author: fixture.otherAuthor.publicKey.rawRepresentation)
    _ = try ParsedRecord(record).verify(under: other, item: fixture.itemID, revision: fixture.revisionID)
}

@Test func sealRefusesAuthorKeyOutsideAuthority() throws {
    let fixture = Fixture()
    #expect(throws: RecordError.unexpectedAuthority) {
        _ = try RecordSealer.seal(login(), identity: fixture.identity, authority: fixture.authority(), author: fixture.otherAuthor)
    }
}

@Test func recipientSetShape() throws {
    let fixture = Fixture()
    let device = try Recipient(role: .device, publicKey: fixture.device1.publicKey.rawRepresentation)
    #expect(throws: RecordError.malformed) { _ = try RecipientSet([]) }
    #expect(throws: RecordError.malformed) { _ = try RecipientSet([device, device]) }
    #expect(throws: RecordError.malformed) {
        _ = try RecipientSet([device, try Recipient(role: .recovery, publicKey: device.publicKey)])
    }
    let many = (0..<33).map { index in
        try! Recipient(role: .device, publicKey: key(UInt8(150 + index)) {
            try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: $0)
        }.publicKey.rawRepresentation)
    }
    #expect(throws: RecordError.malformed) { _ = try RecipientSet(many) }
    let full = try RecipientSet(Array(many.prefix(32)))
    #expect(full.members.map(\.sortKey) == full.members.map(\.sortKey).sorted { $0.lexicographicallyPrecedes($1) })
}

@Test func reservedSnapshotKindIsRefused() throws {
    let fixture = Fixture()
    var hostile = HostileRecord(fixture, content: .tombstone)
    hostile.kind = 4
    expectRefusal(.unsupported) { _ = try ParsedRecord(try hostile.build()) }
}

@Test func bodyIDExcludesSignatureAndTransportDigestIncludesIt() throws {
    let fixture = Fixture()
    let record = try fixture.seal(login())
    let body = record.bytes.dropLast(64)
    #expect(record.bodyID.rawValue == Data(SHA256.hash(data: Data("AV/revision/2".utf8) + Data([0]) + body)))
    #expect(record.transportDigest.rawValue == Data(SHA256.hash(data: record.bytes)))
    // Fresh seals of equal content differ (fresh DK, messageID and HPKE randomness).
    #expect(try fixture.seal(login()).bodyID != record.bodyID)
}
