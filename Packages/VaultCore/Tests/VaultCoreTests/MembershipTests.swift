import Crypto
import Foundation
import Testing
@testable import VaultCore

// Two public signatures over the exchange genesis body, generated on 22 October 2026 by native
// macOS CryptoKit through swift-crypto 5.0.3 (c2cbadd7263439d8015189668f96ff5b5be565ce) with two
// identical FixtureController.genesis calls. Both backends must accept both.
let membershipAlternativeGenesisSignatures = [
    MembershipExchangeOracle.hex("e1a32fb3ba45f8120e5eceba2bb05cab43451cb4b9b2a439437bc1a2fb692522364babe792379f48db03ef0e2f7a75d57276ea6e7be3a53d1bc3c88e87052e0e"),
    MembershipExchangeOracle.hex("ffa421b983ee5b8bbbb4281bb22dfe6be22626a3f2d10ce3a0309b72a9c1d8403eb5783ebc3f2695294df58c296a3b1c8d107b7f7aed513383ec592042d98a08"),
]

private func body(_ record: Data) -> Data { Data(record.prefix(record.count - 64)) }

private func bigEndian(_ value: UInt32) -> Data {
    Data([UInt8(value >> 24), UInt8(truncatingIfNeeded: value >> 16), UInt8(truncatingIfNeeded: value >> 8),
          UInt8(truncatingIfNeeded: value)])
}

/// Genesis [writer, A], then add B at sequence 1. Returns the session at head 1.
private struct MembershipLineageFixture {
    let authority: MembershipAuthority
    let readerA: Curve25519.KeyAgreement.PublicKey
    let readerB: Curve25519.KeyAgreement.PublicKey
    let session: FixtureMembershipSession
    let genesis: Data
    let addReader: Data
    let h0: MembershipCheckpoint

    init() throws {
        authority = try MembershipAuthority()
        readerA = try membershipAgreementKey(0xE0).publicKey
        readerB = try membershipAgreementKey(0xE1).publicKey
        let created = try authority.session([.reader(readerA)])
        session = created.session
        genesis = created.genesis
        h0 = session.checkpoint
        addReader = try authority.advance(session, [authority.writerMember(), .reader(readerA), .reader(readerB)])
    }

    var rowsA: [MembershipRow] { [authority.writerRow, membershipRow(.reader, readerA)] }

    func replay(_ records: [Data]) throws -> FixtureMembershipSession {
        let replayed = try FixtureMembershipSession(anchor: session.anchor, genesis: genesis)
        for record in records { _ = try replayed.advance(record) }
        return replayed
    }
}

@Test func membershipWireLayoutMatchesContract() throws {
    let authority = try MembershipAuthority()
    let readers = try (0..<31).map { try FixtureMember.reader(membershipAgreementKey(0xE0 + UInt8($0)).publicKey) }
    let minimum = try authority.genesis([authority.writerMember()]).record
    let maximum = try authority.genesis([authority.writerMember()] + readers).record
    #expect(minimum.count == 233 && maximum.count == 1_287)
    #expect(MembershipBody.prefixSize == 135 && MembershipBody.minimumRecordSize == 233
            && MembershipBody.maximumRecordSize == 1_287)
    for record in [minimum, maximum] {
        let count = (record.count - 199) / 34
        #expect(record.prefix(8) == Data("AVMEMB01".utf8))
        #expect(Array(record[8..<11]) == [1, 1, 1])
        #expect(record[11..<27] == authority.vaultID.bytes)
        #expect(record[27..<35] == Data(count: 8))
        #expect(record[35..<67] == Data(count: 32))
        #expect(record[67..<99] == authority.controller.publicKey.rawRepresentation)
        #expect(record[99..<131] == authority.writer.publicKey.rawRepresentation)
        #expect(record[131..<135] == bigEndian(UInt32(count)))
        let rows = (0..<count).map { Data(record[(135 + 34 * $0)..<(169 + 34 * $0)]) }
        #expect(strictlySorted(rows.map { $0.prefix(1) + $0.suffix(32) }))
        #expect(rows.filter { $0 == Data([1, 3]) + authority.writerAgreement.publicKey.rawRepresentation }.count == 1)
        #expect(record.count - 64 == 135 + 34 * count)
        #expect(authority.controller.publicKey.isValidSignature(record.suffix(64), for: body(record)))
        let parsed = try MembershipRecord.parse(record)
        #expect(parsed.bodyBytes == body(record) && parsed.signature == record.suffix(64) && parsed.encoded == record)
        #expect(MembershipDigest(body: parsed.bodyBytes).bytes == Data(SHA256.hash(data: body(record))))
    }
}

@Test func membershipBodyIdentityIgnoresSignatureRandomization() throws {
    let authority = try MembershipExchangeProducer.authority()
    let minted = try MembershipExchangeProducer.genesis(authority)
    #expect(minted.anchor.genesis.bytes == MembershipExchangeOracle.genesisDigest)
    #expect(minted.anchor.vaultID.bytes == MembershipExchangeOracle.vaultID)
    let records = membershipAlternativeGenesisSignatures.map { body(minted.record) + $0 }
    #expect(records[0] != records[1])
    #expect(records.allSatisfy { authority.controller.publicKey.isValidSignature($0.suffix(64), for: body($0)) })
    let anchor = try MembershipExchangeOracle.anchor()
    let first = try FixtureMembershipSession(anchor: anchor, genesis: records[0])
    let second = try FixtureMembershipSession(anchor: anchor, genesis: records[1])
    #expect(first.checkpoint == second.checkpoint && first.checkpoint.head == minted.anchor.genesis)
    #expect(try first.advance(records[1]) == .duplicate(first.checkpoint))
    #expect(try first.advance(minted.record) == .duplicate(first.checkpoint))
    #expect(first.history == [records[0]])
    var invalid = records[1]
    invalid[invalid.count - 1] ^= 0x01
    expectRejectedUnchanged(.badMembershipSignature, first) { _ = try first.advance(invalid) }
    expectPolicyError(.badMembershipSignature) { _ = try FixtureMembershipSession(anchor: anchor, genesis: invalid) }
    #expect(first.history == [records[0]])
}

@Test func membershipBootstrapRejectsUntrustedGenesis() throws {
    let authority = try MembershipAuthority()
    let reader = try FixtureMember.reader(membershipAgreementKey(0xE0).publicKey)
    let minted = try authority.genesis([authority.writerMember(), reader])
    _ = try FixtureMembershipSession(anchor: minted.anchor, genesis: minted.record)
    let otherVault = FixtureTrustAnchor(vaultID: try VaultID(Data(repeating: 0x6F, count: 16)), genesis: minted.anchor.genesis)
    expectPolicyError(.anchorMismatch) { _ = try FixtureMembershipSession(anchor: otherVault, genesis: minted.record) }
    let otherDigest = FixtureTrustAnchor(vaultID: authority.vaultID, genesis: MembershipDigest(body: Data("other".utf8)))
    expectPolicyError(.anchorMismatch) { _ = try FixtureMembershipSession(anchor: otherDigest, genesis: minted.record) }
    let foreign = try membershipSigningKey(MembershipAuthority.foreignSigningSeed)
    let replacement = try FixtureController.genesis(vaultID: authority.vaultID, controller: foreign,
                                                    writer: authority.writer.publicKey,
                                                    members: [authority.writerMember(), reader])
    expectPolicyError(.anchorMismatch) { _ = try FixtureMembershipSession(anchor: minted.anchor, genesis: replacement.record) }

    // Each body below is pinned exactly, so only its own genesis rule can reject it.
    func pinned(_ body: MembershipBody, signer: Curve25519.Signing.PrivateKey? = nil) throws {
        let anchor = FixtureTrustAnchor(vaultID: authority.vaultID, genesis: MembershipDigest(body: body.encoded))
        _ = try FixtureMembershipSession(anchor: anchor, genesis: authority.signed(body, by: signer))
    }
    let rows = try MembershipRecord.parse(minted.record).body.rows
    let base = MembershipBody(vaultID: authority.vaultID.bytes, sequence: 0, parent: Data(count: 32),
                              controllerKey: authority.controller.publicKey.rawRepresentation,
                              writerKey: authority.writer.publicKey.rawRepresentation, rows: rows)
    try pinned(base)
    var shape = base
    shape.sequence = 1
    expectPolicyError(.anchorMismatch) { try pinned(shape) }
    shape = base
    shape.parent = Data(repeating: 1, count: 32)
    expectPolicyError(.anchorMismatch) { try pinned(shape) }
    shape = base
    shape.vaultID = Data(repeating: 0x6F, count: 16)
    expectPolicyError(.anchorMismatch) { try pinned(shape) }
    expectPolicyError(.badMembershipSignature) { try pinned(base, signer: foreign) }
    shape = base
    shape.writerKey = shape.controllerKey
    expectPolicyError(.malformed) { try pinned(shape) }
    shape = base
    shape.rows = rows.filter { $0.capability != MemberKind.writer.capability }
    expectPolicyError(.malformed) { try pinned(shape) }
    shape = base
    shape.rows = membershipRows(rows + [membershipRow(.writer, try membershipAgreementKey(0xE1).publicKey)])
    expectPolicyError(.malformed) { try pinned(shape) }
    shape = base
    shape.rows = membershipRows(rows + [MembershipRow(role: 1, capability: 1, agreementKey: Data(count: 32))])
    expectPolicyError(.invalidMemberKey) { try pinned(shape) }
}

@Test func membershipMintingRejectsInvalidAuthority() throws {
    let authority = try MembershipAuthority()
    let reader = try FixtureMember.reader(membershipAgreementKey(0xE0).publicKey)
    let writer = try authority.writerMember()
    func mint(_ members: [FixtureMember], writerKey: Curve25519.Signing.PublicKey? = nil) throws {
        _ = try FixtureController.genesis(vaultID: authority.vaultID, controller: authority.controller,
                                          writer: writerKey ?? authority.writer.publicKey, members: members)
    }
    expectPolicyError(.malformed) { try mint([writer, reader], writerKey: authority.controller.publicKey) }
    expectPolicyError(.malformed) { try mint([reader]) }
    expectPolicyError(.malformed) { try mint([]) }
    expectPolicyError(.malformed) { try mint([writer, reader, reader]) }
    expectPolicyError(.malformed) { try mint([writer, .writer(membershipAgreementKey(0xE1).publicKey)]) }
    expectPolicyError(.malformed) { try mint([writer, .recovery(authority.writerAgreement.publicKey)]) }
    expectPolicyError(.malformed) { try mint([writer] + (0..<32).map { try FixtureMember.reader(membershipAgreementKey(0xE0 + UInt8($0)).publicKey) }) }
    expectPolicyError(.malformed) { _ = try VaultID(Data(count: 15)) }
    expectPolicyError(.malformed) { _ = try FixtureTrustAnchor(compiledVaultID: Data(count: 16), genesisBodyDigest: Data(count: 31)) }
    expectPolicyError(.malformed) { _ = try MembershipDigest(pinned: Data(count: 33)) }
    let (session, _) = try authority.session([reader])
    let checkpoint = session.checkpoint
    let foreign = try membershipSigningKey(MembershipAuthority.foreignSigningSeed)
    expectPolicyError(.anchorMismatch) {
        _ = try FixtureController.successor(after: checkpoint, members: [writer, reader], controller: foreign)
    }
    expectPolicyError(.unsupportedAuthorityChange) {
        _ = try authority.successor(checkpoint, [.writer(membershipAgreementKey(0xE1).publicKey), reader])
    }
    expectPolicyError(.malformed) { _ = try authority.successor(checkpoint, [.recovery(membershipAgreementKey(0xD5).publicKey)]) }
    let minted = try authority.successor(checkpoint, [reader])
    #expect(try MembershipRecord.parse(minted).body.sequence == 1)
    #expect(session.checkpoint == checkpoint && session.history.count == 1)
}

@Test func membershipHostileStructureIsMalformedWithoutState() throws {
    let fixture = try MembershipLineageFixture()
    let session = fixture.session
    let next = try fixture.authority.successor(session.checkpoint, [fixture.authority.writerMember(), .reader(fixture.readerA)])
    for length in 0..<next.count {
        expectRejectedUnchanged(.malformed, session) { _ = try session.advance(Data(next.prefix(length))) }
    }
    for length in 0..<fixture.genesis.count {
        expectPolicyError(.malformed) {
            _ = try FixtureMembershipSession(anchor: session.anchor, genesis: Data(fixture.genesis.prefix(length)))
        }
    }
    expectRejectedUnchanged(.malformed, session) { _ = try session.advance(next + Data([0])) }
    expectRejectedUnchanged(.malformed, session) { _ = try session.advance(Data(count: 1_288)) }
    expectRejectedUnchanged(.malformed, session) { _ = try session.advance(Data(count: 4 * 1024 * 1024)) }
    for offset in [0, 7, 8, 9, 10] {
        var bad = next
        bad[offset] ^= 0xFF
        expectRejectedUnchanged(.malformed, session) { _ = try session.advance(bad) }
    }
    for count in [UInt32(0), 1, 3, 33, .max] {
        var bad = next
        bad.replaceSubrange(131..<135, with: bigEndian(count))
        expectRejectedUnchanged(.malformed, session) { _ = try session.advance(bad) }
    }
    var reversed = fixture.authority.body(after: session.checkpoint, rows: fixture.rowsA)
    reversed.rows.reverse()
    expectRejectedUnchanged(.malformed, session) { _ = try session.advance(fixture.authority.signed(reversed)) }
    var repeated = reversed
    repeated.rows = [fixture.rowsA[1], fixture.rowsA[1]]
    expectRejectedUnchanged(.malformed, session) { _ = try session.advance(fixture.authority.signed(repeated)) }
    for (role, capability) in [(UInt8(0), UInt8(1)), (3, 1), (1, 0), (1, 2), (1, 5), (2, 1), (2, 3), (1, 7)] {
        let rows = [fixture.authority.writerRow, MembershipRow(role: role, capability: capability,
                                                               agreementKey: fixture.readerA.rawRepresentation)]
        let record = try fixture.authority.signed(fixture.authority.body(after: session.checkpoint, rows: rows))
        #expect(try MembershipRecord.parse(record).body.rows.count == 2)
        expectRejectedUnchanged(.malformed, session) { _ = try session.advance(record) }
    }
    let hostileSlice = (Data(repeating: 0x5A, count: 4096) + next + Data([0])).dropFirst(4096)
    expectRejectedUnchanged(.malformed, session) { _ = try session.advance(hostileSlice) }
    let slice = (Data(repeating: 0xA5, count: 4096) + next).dropFirst(4096)
    try #require(slice.startIndex == 4096)
    let result = try session.advance(slice)
    #expect(result == .advanced(session.checkpoint) && session.checkpoint.sequence == 2)
    #expect(session.history.last == next && session.history.last?.startIndex == 0)
}

@Test func membershipMemberPolicyAndKeyHostility() throws {
    let fixture = try MembershipLineageFixture()
    let authority = fixture.authority
    let session = fixture.session
    let recovery = try membershipAgreementKey(0xD5).publicKey
    let writer = authority.writerRow
    func next(_ rows: [MembershipRow]) throws -> Data { try authority.signed(authority.body(after: session.checkpoint, rows: rows)) }
    for (role, capability) in [(UInt8(1), UInt8(0)), (1, 2), (1, 4), (1, 5), (1, 7), (2, 0), (2, 1), (2, 3),
                               (2, 7), (0, 1), (3, 5), (255, 255)] {
        let row = MembershipRow(role: role, capability: capability, agreementKey: fixture.readerA.rawRepresentation)
        expectRejectedUnchanged(.malformed, session) { _ = try session.advance(next([writer, row])) }
    }
    expectRejectedUnchanged(.malformed, session) { _ = try session.advance(next([membershipRow(.recovery, recovery)])) }
    expectRejectedUnchanged(.malformed, session) { _ = try session.advance(next([writer, membershipRow(.writer, fixture.readerA)])) }
    expectRejectedUnchanged(.malformed, session) {
        _ = try session.advance(next([writer, membershipRow(.reader, fixture.readerA), membershipRow(.recovery, fixture.readerA)]))
    }
    expectRejectedUnchanged(.malformed, session) {
        _ = try session.advance(next([writer, MembershipRow(role: 3, capability: 1, agreementKey: Data(count: 32))]))
    }
    let lowOrder = membershipLowOrderEncodings()
    #expect(lowOrder.count == 14)
    for encoding in lowOrder {
        let row = MembershipRow(role: 1, capability: 1, agreementKey: encoding)
        expectRejectedUnchanged(.invalidMemberKey, session) { _ = try session.advance(next([writer, row])) }
        let key = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: encoding)
        expectPolicyError(.invalidMemberKey) { _ = try FixtureMember.reader(key) }
        expectPolicyError(.invalidMemberKey) { _ = try FixtureMember.recovery(key) }
    }
    var highBitAlias = fixture.readerA.rawRepresentation
    highBitAlias[31] |= 0x80
    let nonLowOrderNoncanonical = [highBitAlias,
                                   Data([0xf6]) + Data(repeating: 0xff, count: 30) + Data([0x7f]),
                                   Data(repeating: 0xff, count: 31) + Data([0x7f])]
    for encoding in nonLowOrderNoncanonical {
        #expect(!MembershipPolicy.isCanonicalCoordinate(encoding))
        let key = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: encoding)
        #expect((try? RevisionRecipient(role: .device, publicKey: key)) != nil)
        let row = MembershipRow(role: 1, capability: 1, agreementKey: encoding)
        expectRejectedUnchanged(.invalidMemberKey, session) { _ = try session.advance(next([writer, row])) }
        expectPolicyError(.invalidMemberKey) { _ = try FixtureMember.reader(key) }
    }
    #expect(MembershipPolicy.isCanonicalCoordinate(Data([0xec]) + Data(repeating: 0xff, count: 30) + Data([0x7f])))
    var changedHeader = authority.body(after: session.checkpoint, rows: fixture.rowsA)
    changedHeader.writerKey = try membershipSigningKey(MembershipAuthority.otherWriterSigningSeed).publicKey.rawRepresentation
    expectRejectedUnchanged(.unsupportedAuthorityChange, session) { _ = try session.advance(authority.signed(changedHeader)) }
    changedHeader.rows = membershipRows([writer, MembershipRow(role: 3, capability: 1, agreementKey: Data(count: 32))])
    expectRejectedUnchanged(.unsupportedAuthorityChange, session) { _ = try session.advance(authority.signed(changedHeader)) }
    let otherWriterAgreement = try membershipAgreementKey(0xE2).publicKey
    expectRejectedUnchanged(.unsupportedAuthorityChange, session) {
        _ = try session.advance(next([membershipRow(.writer, otherWriterAgreement), membershipRow(.reader, fixture.readerA)]))
    }
    let accepted = try next([writer, membershipRow(.reader, fixture.readerA), membershipRow(.recovery, recovery)])
    #expect(try session.advance(accepted) == .advanced(session.checkpoint))
    #expect(session.checkpoint.sequence == 2 && session.membership.recipients.count == 3)
}

@Test func membershipWriterDisableRetainOmitAndReenable() throws {
    let fixture = try MembershipLineageFixture()
    let authority = fixture.authority
    let session = fixture.session
    let reader = try FixtureMember.reader(fixture.readerA)
    let writerAgreement = authority.writerAgreement.publicKey.rawRepresentation
    try authority.advance(session, [.reader(authority.writerAgreement.publicKey), reader])
    #expect(!session.membership.writerActive && session.membership.recipients.contains(Data([1]) + writerAgreement))
    try authority.advance(session, [reader])
    #expect(!session.membership.writerActive && session.membership.recipients == [Data([1]) + fixture.readerA.rawRepresentation])
    let otherWriter = try authority.signed(authority.body(after: session.checkpoint, rows: [
        membershipRow(.writer, try membershipAgreementKey(0xE2).publicKey), membershipRow(.reader, fixture.readerA)]))
    expectRejectedUnchanged(.unsupportedAuthorityChange, session) { _ = try session.advance(otherWriter) }
    try authority.advance(session, [authority.writerMember(), reader])
    #expect(session.membership.writerActive && session.membership.writerAgreementKey == writerAgreement)
    #expect(session.checkpoint.sequence == 4)
}

@Test func membershipContiguousLineageAndDuplicates() throws {
    let fixture = try MembershipLineageFixture()
    let authority = fixture.authority
    let session = fixture.session
    let remove = try authority.advance(session, [authority.writerMember(), .reader(fixture.readerA)])
    let records = [fixture.genesis, fixture.addReader, remove]
    for index in 1..<records.count {
        #expect(records[index][35..<67] == Data(SHA256.hash(data: body(records[index - 1]))))
        #expect(try MembershipRecord.parse(records[index]).body.sequence == UInt64(index))
    }
    let head = session.checkpoint
    #expect(head.sequence == 2 && head.head == MembershipDigest(body: body(remove)))
    for record in records { #expect(try session.advance(record) == .duplicate(head)) }
    let resigned = body(fixture.addReader) + (try authority.controller.signature(for: body(fixture.addReader)))
    #expect(try session.advance(resigned) == .duplicate(head))
    #expect(session.history == records)
    var tampered = fixture.addReader
    tampered[tampered.count - 1] ^= 0x01
    expectRejectedUnchanged(.badMembershipSignature, session) { _ = try session.advance(tampered) }
    let gap = try authority.signed(authority.body(after: head, rows: fixture.rowsA, sequence: 4))
    expectRejectedUnchanged(.missingPredecessor, session) { _ = try session.advance(gap) }
    var fullRecordParent = authority.body(after: head, rows: fixture.rowsA)
    fullRecordParent.parent = Data(SHA256.hash(data: remove))
    let contradiction = try authority.signed(fullRecordParent)
    expectForkLatch(.signedLineageContradiction, session, first: remove, second: contradiction, probe: remove) {
        _ = try session.advance(contradiction)
    }
}

@Test func membershipObservedSequenceForksAndPoisoningResistance() throws {
    let fixture = try MembershipLineageFixture()
    let authority = fixture.authority
    let h1 = fixture.session.checkpoint
    let remove = try authority.advance(fixture.session, [authority.writerMember(), .reader(fixture.readerA)])
    let prefix = [fixture.addReader, remove]
    var genesisVariant = MembershipBody(vaultID: authority.vaultID.bytes, sequence: 0, parent: Data(count: 32),
                                        controllerKey: authority.controller.publicKey.rawRepresentation,
                                        writerKey: authority.writer.publicKey.rawRepresentation,
                                        rows: membershipRows(fixture.rowsA + [membershipRow(.reader, fixture.readerB)]))
    var changedWriter = authority.body(after: fixture.h0, rows: fixture.rowsA)
    changedWriter.writerKey = try membershipSigningKey(MembershipAuthority.otherWriterSigningSeed).publicKey.rawRepresentation
    let unknownRole = authority.body(after: fixture.h0, rows: [authority.writerRow,
                                                                MembershipRow(role: 3, capability: 1, agreementKey: Data(count: 32))])
    let lowOrderMember = authority.body(after: h1, rows: [authority.writerRow,
                                                          MembershipRow(role: 1, capability: 1, agreementKey: Data(count: 32))])
    let variants: [(MembershipBody, Data)] = [(genesisVariant, fixture.genesis), (changedWriter, fixture.addReader),
                                              (unknownRole, fixture.addReader), (lowOrderMember, remove)]
    for (variant, retained) in variants {
        let session = try fixture.replay(prefix)
        let record = try authority.signed(variant)
        expectForkLatch(.observedSequence, session, first: retained, second: record, probe: remove) {
            _ = try session.advance(record)
        }
    }
    let clean = try fixture.replay(prefix)
    let foreign = try membershipSigningKey(MembershipAuthority.foreignSigningSeed)
    expectRejectedUnchanged(.badMembershipSignature, clean) { _ = try clean.advance(authority.signed(changedWriter, by: foreign)) }
    genesisVariant.vaultID = Data(repeating: 0x6F, count: 16)
    expectRejectedUnchanged(.anchorMismatch, clean) { _ = try clean.advance(authority.signed(genesisVariant)) }
    var foreignController = changedWriter
    foreignController.controllerKey = foreign.publicKey.rawRepresentation
    expectRejectedUnchanged(.anchorMismatch, clean) { _ = try clean.advance(authority.signed(foreignController, by: foreign)) }
    #expect(clean.forkEvidence == nil)

    let latched = try fixture.replay(prefix)
    let firstFork = try authority.signed(unknownRole)
    expectForkLatch(.observedSequence, latched, first: fixture.addReader, second: firstFork, probe: remove) {
        _ = try latched.advance(firstFork)
    }
    expectPolicyError(.membershipFork) { _ = try latched.advance(authority.signed(lowOrderMember)) }
    expectPolicyError(.membershipFork) { _ = try latched.authorize(Data(), itemID: Data(), revisionID: Data()) }
    expectPolicyError(.membershipFork) {
        _ = try latched.openAtCurrentMembership(Data(), itemID: Data(), revisionID: Data(), role: .device,
                                                recipient: membershipAgreementKey(0xE0))
    }
    #expect(latched.forkEvidence?.firstRecord == fixture.addReader && latched.forkEvidence?.secondRecord == firstFork)
    #expect(latched.checkpoint.sequence == 2)
}

@Test func membershipLineageContradictionAndGaps() throws {
    let fixture = try MembershipLineageFixture()
    let authority = fixture.authority
    let probe = try authority.successor(fixture.session.checkpoint, [authority.writerMember(), .reader(fixture.readerA)])
    var random = authority.body(after: fixture.session.checkpoint, rows: fixture.rowsA)
    random.parent = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
    var semanticallyInvalid = random
    semanticallyInvalid.rows = [authority.writerRow, MembershipRow(role: 3, capability: 1, agreementKey: Data(count: 32))]
    var changedWriter = random
    changedWriter.writerKey = try membershipSigningKey(MembershipAuthority.otherWriterSigningSeed).publicKey.rawRepresentation
    for variant in [random, semanticallyInvalid, changedWriter] {
        let session = try fixture.replay([fixture.addReader])
        let record = try authority.signed(variant)
        expectForkLatch(.signedLineageContradiction, session, first: fixture.addReader, second: record, probe: probe) {
            _ = try session.advance(record)
        }
    }
    let session = try fixture.replay([fixture.addReader])
    var gap = random
    gap.sequence = 3
    expectRejectedUnchanged(.missingPredecessor, session) { _ = try session.advance(authority.signed(gap)) }
    gap.sequence = .max
    expectRejectedUnchanged(.missingPredecessor, session) { _ = try session.advance(authority.signed(gap)) }
    #expect(session.forkEvidence == nil)
}

@Test func membershipHistoryCapacityAndAtomicity() throws {
    let authority = try MembershipAuthority()
    let reader = try FixtureMember.reader(membershipAgreementKey(0xE0).publicKey)
    let members = [try authority.writerMember(), reader]
    let (session, genesis) = try authority.session([reader])
    var records = [genesis]
    for _ in 1..<FixtureMembershipSession.historyCapacity { records.append(try authority.advance(session, members)) }
    #expect(FixtureMembershipSession.historyCapacity == 256 && session.history.count == 256)
    #expect(session.checkpoint.sequence == 255)
    #expect(256 * MembershipBody.maximumRecordSize == 329_472)
    #expect(258 * MembershipBody.maximumRecordSize == 332_046)
    let full = session.checkpoint
    let next = try authority.successor(full, members)
    expectRejectedUnchanged(.capacityExceeded, session) { _ = try session.advance(next) }
    for index in [0, 1, 128, 255] { #expect(try session.advance(records[index]) == .duplicate(full)) }
    #expect(session.history == records)

    func replay() throws -> FixtureMembershipSession {
        let replayed = try FixtureMembershipSession(anchor: session.anchor, genesis: genesis)
        for record in records.dropFirst() { _ = try replayed.advance(record) }
        return replayed
    }
    let observed = try replay()
    var fork = authority.body(after: full, rows: [authority.writerRow], sequence: 100)
    fork.parent = Data(SHA256.hash(data: body(records[99])))
    let forkRecord = try authority.signed(fork)
    expectForkLatch(.observedSequence, observed, first: records[100], second: forkRecord, probe: next) {
        _ = try observed.advance(forkRecord)
    }
    #expect((observed.forkEvidence?.firstRecord.count ?? 0) + (observed.forkEvidence?.secondRecord.count ?? 0)
            <= 2 * MembershipBody.maximumRecordSize)
    let lineage = try replay()
    var wrongParent = authority.body(after: full, rows: [authority.writerRow, reader.row])
    wrongParent.parent = MembershipExchangeOracle.nonexistentParent
    let wrongParentRecord = try authority.signed(wrongParent)
    expectForkLatch(.signedLineageContradiction, lineage, first: records[255], second: wrongParentRecord, probe: next) {
        _ = try lineage.advance(wrongParentRecord)
    }
    // A withheld successor raises no freshness alarm: the observed head still authorizes.
    let context = try authority.context(session)
    let revision = try authority.seal(context, [(.device, authority.writerAgreement.publicKey),
                                                (.device, try membershipAgreementKey(0xE0).publicKey)])
    #expect(try session.authorize(revision, itemID: context.itemID, revisionID: context.revisionID).authorizedAt == full)
}

@Test func membershipSequenceArithmeticIsChecked() throws {
    #expect(try MembershipSequence.successor(after: 254) == 255)
    expectPolicyError(.sequenceExhausted) { _ = try MembershipSequence.successor(after: .max) }
    #expect(MembershipSequence.historyIndex(of: 5, current: 5) == 5)
    #expect(MembershipSequence.historyIndex(of: 6, current: 5) == nil)
    #expect(MembershipSequence.historyIndex(of: .max, current: 5) == nil)
    #expect(MembershipSequence.historyIndex(of: .max, current: .max) == Int(exactly: UInt64.max))
}

// Focused single-assertion tests used by the compiled controls.

@Test func membershipForgedSuccessorIsRejectedUnchanged() throws {
    let fixture = try MembershipLineageFixture()
    let forged = try fixture.authority.signed(fixture.authority.body(after: fixture.session.checkpoint, rows: fixture.rowsA),
                                              by: membershipSigningKey(MembershipAuthority.foreignSigningSeed))
    expectRejectedUnchanged(.badMembershipSignature, fixture.session) { _ = try fixture.session.advance(forged) }
}

@Test func membershipSignedGapIsMissingPredecessor() throws {
    let fixture = try MembershipLineageFixture()
    let checkpoint = fixture.session.checkpoint
    let gap = try fixture.authority.signed(fixture.authority.body(after: checkpoint, rows: fixture.rowsA,
                                                                   sequence: checkpoint.sequence + 2))
    expectRejectedUnchanged(.missingPredecessor, fixture.session) { _ = try fixture.session.advance(gap) }
}

@Test func membershipObservedSequenceForkLatches() throws {
    let fixture = try MembershipLineageFixture()
    let members = [try fixture.authority.writerMember(), try FixtureMember.reader(fixture.readerA)]
    let fork = try fixture.authority.successor(fixture.h0, members)
    let probe = try fixture.authority.successor(fixture.session.checkpoint, members)
    expectForkLatch(.observedSequence, fixture.session, first: fixture.addReader, second: fork, probe: probe) {
        _ = try fixture.session.advance(fork)
    }
}

@Test func membershipWrongParentLatchesLineageContradiction() throws {
    let fixture = try MembershipLineageFixture()
    var contradiction = fixture.authority.body(after: fixture.session.checkpoint, rows: [
        fixture.authority.writerRow, MembershipRow(role: 3, capability: 1, agreementKey: fixture.readerA.rawRepresentation)])
    contradiction.parent = MembershipExchangeOracle.nonexistentParent
    let record = try fixture.authority.signed(contradiction)
    let probe = try fixture.authority.successor(fixture.session.checkpoint, [fixture.authority.writerMember(), .reader(fixture.readerA)])
    expectForkLatch(.signedLineageContradiction, fixture.session, first: fixture.addReader, second: record, probe: probe) {
        _ = try fixture.session.advance(record)
    }
}

@Test func membershipChangedWriterAtObservedSequenceLatches() throws {
    let fixture = try MembershipLineageFixture()
    var changed = fixture.authority.body(after: fixture.h0, rows: fixture.rowsA + [membershipRow(.reader, fixture.readerB)])
    changed.writerKey = try membershipSigningKey(MembershipAuthority.otherWriterSigningSeed).publicKey.rawRepresentation
    let fork = try fixture.authority.signed(changed)
    let probe = try fixture.authority.successor(fixture.session.checkpoint, [fixture.authority.writerMember(), .reader(fixture.readerA)])
    expectForkLatch(.observedSequence, fixture.session, first: fixture.addReader, second: fork, probe: probe) {
        _ = try fixture.session.advance(fork)
    }
}
