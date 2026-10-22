import Crypto
import Foundation
import Testing
@testable import VaultCore

/// Genesis [writer, reader A, recovery], optionally with reader B, plus one session.
private struct RevisionPolicyFixture {
    let authority: MembershipAuthority
    let readerA: Curve25519.KeyAgreement.PrivateKey
    let readerB: Curve25519.KeyAgreement.PrivateKey
    let recovery: Curve25519.KeyAgreement.PrivateKey
    let unrelated: Curve25519.KeyAgreement.PrivateKey
    let session: FixtureMembershipSession

    init(withB: Bool = false) throws {
        authority = try MembershipAuthority()
        readerA = try membershipAgreementKey(0xE0)
        readerB = try membershipAgreementKey(0xE1)
        recovery = try membershipAgreementKey(0xD5)
        unrelated = try membershipAgreementKey(0xD6)
        session = try authority.session(try Self.members(readerA, readerB, recovery, withB: withB)).session
    }

    static func members(_ readerA: Curve25519.KeyAgreement.PrivateKey, _ readerB: Curve25519.KeyAgreement.PrivateKey,
                        _ recovery: Curve25519.KeyAgreement.PrivateKey, withB: Bool) throws -> [FixtureMember] {
        try [.reader(readerA.publicKey), .recovery(recovery.publicKey)] + (withB ? [.reader(readerB.publicKey)] : [])
    }

    func members(withB: Bool, writer: Bool = true) throws -> [FixtureMember] {
        try (writer ? [authority.writerMember()] : [.reader(authority.writerAgreement.publicKey)])
            + Self.members(readerA, readerB, recovery, withB: withB)
    }

    func recipients(withB: Bool) -> [(RecipientRole, Curve25519.KeyAgreement.PublicKey)] {
        [(.device, authority.writerAgreement.publicKey), (.device, readerA.publicKey), (.recovery, recovery.publicKey)]
            + (withB ? [(.device, readerB.publicKey)] : [])
    }

    func seal(withB: Bool = false, revision: UInt8 = 0x31,
              recipients: [(RecipientRole, Curve25519.KeyAgreement.PublicKey)]? = nil,
              author: Curve25519.Signing.PrivateKey? = nil, parents: [Data] = []) throws -> (record: Data, context: RevisionContext) {
        let context = try authority.context(session, revision: revision)
        return (try authority.seal(context, recipients ?? self.recipients(withB: withB), author: author, parents: parents), context)
    }

    func authorize(_ sealed: (record: Data, context: RevisionContext)) throws -> AuthorizedRevision {
        try session.authorize(sealed.record, itemID: sealed.context.itemID, revisionID: sealed.context.revisionID)
    }

    func open(_ sealed: (record: Data, context: RevisionContext), _ key: Curve25519.KeyAgreement.PrivateKey,
              role: RecipientRole = .device) throws -> Bool {
        let item = try session.openAtCurrentMembership(sealed.record, itemID: sealed.context.itemID,
                                                       revisionID: sealed.context.revisionID, role: role, recipient: key)
        return item.username == membershipPolicyItem.username && item.password == membershipPolicyItem.password
            && item.origins == membershipPolicyItem.origins
    }
}

@Test func revisionAuthorizationIdentityAndCapability() throws {
    let fixture = try RevisionPolicyFixture()
    let sealed = try fixture.seal()
    let receipt = try fixture.authorize(sealed)
    #expect(receipt.digest.bytes == Data(SHA256.hash(data: sealed.record)))
    #expect(receipt.authorizedAt == fixture.session.checkpoint)
    let repeated = try fixture.authorize(sealed)
    #expect(repeated.digest == receipt.digest && repeated.authorizedAt == receipt.authorizedAt)
    #expect(try fixture.open(sealed, fixture.readerA))
    #expect(try fixture.open(sealed, fixture.recovery, role: .recovery))
    #expect(try fixture.open(sealed, fixture.authority.writerAgreement))
    let other = Data(repeating: 0x7A, count: 16)
    expectError(.unexpectedIdentity) {
        _ = try fixture.session.authorize(sealed.record, itemID: other, revisionID: sealed.context.revisionID)
    }
    expectError(.unexpectedIdentity) {
        _ = try fixture.session.authorize(sealed.record, itemID: sealed.context.itemID, revisionID: other)
    }
    let foreignVault = try RevisionContext(vaultID: other, itemID: sealed.context.itemID, revisionID: sealed.context.revisionID,
                                           membershipHead: sealed.context.membershipHead)
    let foreignRecord = try fixture.authority.seal(foreignVault, fixture.recipients(withB: false))
    expectError(.unexpectedIdentity) { _ = try fixture.authorize((foreignRecord, sealed.context)) }
    expectError(.malformed) { _ = try fixture.session.authorize(sealed.record, itemID: Data(count: 15), revisionID: other) }
    expectError(.malformed) { _ = try fixture.session.authorize(sealed.record, itemID: other, revisionID: Data(count: 17)) }
    expectError(.malformed) { _ = try fixture.authorize((Data(), sealed.context)) }
    for signer in [try membershipSigningKey(MembershipAuthority.foreignSigningSeed), fixture.authority.controller,
                   try membershipSigningKey(MembershipAuthority.otherWriterSigningSeed)] {
        expectError(.badSignature) { _ = try fixture.authorize(fixture.seal(author: signer)) }
    }
    var relabelled = try SealedRecord.parse(sealed.record)
    relabelled.author = fixture.authority.controller.publicKey.rawRepresentation
    expectError(.unexpectedIdentity) { _ = try fixture.authorize((fixture.authority.resign(relabelled), sealed.context)) }
    // U1 pins the missing U2 guarantee: distinct records reusing one revision ID both authorize.
    let twin = try fixture.seal()
    #expect(twin.record != sealed.record && twin.context == sealed.context)
    #expect(try fixture.authorize(twin).digest != receipt.digest)
    let orphan = try fixture.seal(parents: [Data(repeating: 0x99, count: 32), Data(repeating: 0x9A, count: 32)])
    #expect(try fixture.open(orphan, fixture.readerA))
    try fixture.authority.advance(fixture.session, fixture.members(withB: false, writer: false))
    let disabled = try fixture.seal()
    expectPolicyError(.unauthorizedAuthor) { _ = try fixture.authorize(disabled) }
}

@Test func revisionAuthorizationCheckOrder() throws {
    let fixture = try RevisionPolicyFixture(withB: true)
    let stale = try fixture.seal(withB: true)
    var foreignBadSignature = try fixture.authority.seal(
        RevisionContext(vaultID: Data(repeating: 0x7A, count: 16), itemID: stale.context.itemID,
                        revisionID: stale.context.revisionID, membershipHead: stale.context.membershipHead),
        fixture.recipients(withB: true))
    foreignBadSignature[foreignBadSignature.count - 1] ^= 0x01
    expectError(.unexpectedIdentity) { _ = try fixture.authorize((foreignBadSignature, stale.context)) }
    try fixture.authority.advance(fixture.session, fixture.members(withB: true, writer: false))
    var staleBadSignature = stale.record
    staleBadSignature[staleBadSignature.count - 1] ^= 0x01
    expectError(.badSignature) { _ = try fixture.authorize((staleBadSignature, stale.context)) }
    expectPolicyError(.staleMembership) { _ = try fixture.authorize(stale) }
    let incomplete = try fixture.seal(recipients: Array(fixture.recipients(withB: true).dropLast()))
    expectPolicyError(.unauthorizedAuthor) { _ = try fixture.authorize(incomplete) }
    try fixture.authority.advance(fixture.session, fixture.members(withB: true))
    let context = try fixture.authority.context(fixture.session)
    let lowOrderMissing = try fixture.authority.lowOrderEncapsulationRecord(
        context, Array(fixture.recipients(withB: true).dropLast()),
        lowOrderFor: fixture.authority.writerAgreement.publicKey.rawRepresentation, encoding: Data(count: 32))
    expectPolicyError(.recipientSetMismatch) { _ = try fixture.authorize((lowOrderMissing, context)) }
    expectPolicyError(.unauthorizedRecipient) {
        _ = try fixture.open((try fixture.authority.seal(context, fixture.recipients(withB: true)), context), fixture.unrelated)
    }
}

@Test func revisionRecipientSetMustMatchExactly() throws {
    let fixture = try RevisionPolicyFixture(withB: true)
    let full = try fixture.seal(withB: true)
    #expect(try fixture.open(full, fixture.readerA))
    let complete = fixture.recipients(withB: true)
    var alias = fixture.readerA.publicKey.rawRepresentation
    alias[31] |= 0x80
    let aliasKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: alias)
    let mismatched: [[(RecipientRole, Curve25519.KeyAgreement.PublicKey)]] = [
        Array(complete.dropLast()),
        complete + [(.device, fixture.unrelated.publicKey)],
        complete.map { $0.1.rawRepresentation == fixture.recovery.publicKey.rawRepresentation ? (.device, $0.1) : $0 },
        complete.map { $0.1.rawRepresentation == fixture.readerA.publicKey.rawRepresentation
            ? (.device, aliasKey) : $0 },
    ]
    for recipients in mismatched {
        let sealed = try fixture.seal(recipients: recipients)
        expectPolicyError(.recipientSetMismatch) { _ = try fixture.authorize(sealed) }
        expectPolicyError(.recipientSetMismatch) { _ = try fixture.open(sealed, fixture.readerA) }
    }
    var lowOrderRecipient = try SealedRecord.parse(full.record)
    lowOrderRecipient.envelopes.append(Envelope(role: .device, publicKey: Data(count: 32),
                                                encapsulatedKey: lowOrderRecipient.envelopes[0].encapsulatedKey,
                                                ciphertext: lowOrderRecipient.envelopes[0].ciphertext))
    lowOrderRecipient.envelopes.sort { $0.sortKey.lexicographicallyPrecedes($1.sortKey) }
    let lowOrder = (try fixture.authority.resign(lowOrderRecipient), full.context)
    expectPolicyError(.recipientSetMismatch) { _ = try fixture.authorize(lowOrder) }
    try fixture.authority.advance(fixture.session, fixture.members(withB: false))
    let old = try fixture.seal(withB: true)
    expectPolicyError(.recipientSetMismatch) { _ = try fixture.authorize(old) }
}

@Test func revisionEveryEncapsulationIsValidated() throws {
    let fixture = try RevisionPolicyFixture()
    let context = try fixture.authority.context(fixture.session)
    let writerKey = fixture.authority.writerAgreement.publicKey.rawRepresentation
    for encoding in membershipLowOrderEncodings() {
        let record = try fixture.authority.lowOrderEncapsulationRecord(context, fixture.recipients(withB: false),
                                                                        lowOrderFor: writerKey, encoding: encoding)
        let parsed = try SealedRecord.parse(record)
        let envelope = try #require(parsed.envelopes.first { $0.publicKey == writerKey })
        let schedule = try MembershipZeroDHSchedule(encapsulatedKey: envelope.encapsulatedKey, recipientKey: writerKey)
        let recoveredKey = try schedule.open(envelope.ciphertext, aad: parsed.wrapAAD(role: .device, publicKey: writerKey))
        #expect(recoveredKey.count == 32)
        let rawOpen = try openRevision(record, expected: context, author: fixture.authority.writer.publicKey,
                                       role: .device, recipient: fixture.readerA)
        #expect(rawOpen.password == membershipPolicyItem.password)
        expectPolicyError(.invalidEncapsulation) { _ = try fixture.authorize((record, context)) }
        expectPolicyError(.invalidEncapsulation) { _ = try fixture.open((record, context), fixture.readerA) }
    }
}

@Test func revisionCurrentHeadLimitationAndRequestingRecipient() throws {
    let fixture = try RevisionPolicyFixture()
    let h0 = try fixture.seal(revision: 0x40)
    let receipt = try fixture.authorize(h0)
    let genesisHead = fixture.session.checkpoint
    #expect(try fixture.open(h0, fixture.readerA))
    try fixture.authority.advance(fixture.session, fixture.members(withB: true))
    expectPolicyError(.staleMembership) { _ = try fixture.open(h0, fixture.readerA) }
    #expect(receipt.authorizedAt == genesisHead && receipt.authorizedAt.sequence == 0)
    let h1 = try fixture.seal(withB: true, revision: 0x41)
    #expect(try fixture.open(h1, fixture.readerA))
    #expect(try fixture.open(h1, fixture.readerB))
    try fixture.authority.advance(fixture.session, fixture.members(withB: false))
    let h2 = try fixture.seal(revision: 0x42)
    expectPolicyError(.unauthorizedRecipient) { _ = try fixture.open(h2, fixture.readerB) }
    expectPolicyError(.staleMembership) { _ = try fixture.open(h1, fixture.readerB) }
    expectPolicyError(.unauthorizedRecipient) { _ = try fixture.open(h2, fixture.readerA, role: .recovery) }
    expectPolicyError(.unauthorizedRecipient) { _ = try fixture.open(h2, fixture.recovery, role: .device) }
    expectPolicyError(.unauthorizedRecipient) { _ = try fixture.open(h2, fixture.unrelated) }
    try fixture.authority.advance(fixture.session, fixture.members(withB: false, writer: false))
    let h3 = try fixture.seal(revision: 0x43)
    expectPolicyError(.unauthorizedAuthor) { _ = try fixture.authorize(h3) }
    try fixture.authority.advance(fixture.session, fixture.members(withB: false))
    expectPolicyError(.staleMembership) { _ = try fixture.authorize(h3) }
    expectPolicyError(.staleMembership) { _ = try fixture.authorize(h2) }
    // Policy cannot erase previously held keys: the raw codec still opens old ciphertext.
    let raw = try openRevision(h1.record, expected: h1.context, author: fixture.authority.writer.publicKey,
                               role: .device, recipient: fixture.readerB)
    #expect(raw.password == membershipPolicyItem.password)
}

@Test func revisionMaliciousWriterBounds() throws {
    let fixture = try RevisionPolicyFixture(withB: true)
    let sealed = try fixture.seal(withB: true)
    var corruptWrap = try SealedRecord.parse(sealed.record)
    let index = try #require(corruptWrap.envelopes.firstIndex { $0.publicKey == fixture.readerB.publicKey.rawRepresentation })
    corruptWrap.envelopes[index].ciphertext[0] ^= 0x01
    let wrap = (try fixture.authority.resign(corruptWrap), sealed.context)
    _ = try fixture.authorize(wrap)
    expectError(.badAuthentication) { _ = try fixture.open(wrap, fixture.readerB) }
    #expect(try fixture.open(wrap, fixture.readerA))
    var corruptPayload = try SealedRecord.parse(sealed.record)
    corruptPayload.ciphertext[0] ^= 0x01
    let payload = (try fixture.authority.resign(corruptPayload), sealed.context)
    _ = try fixture.authorize(payload)
    expectError(.badAuthentication) { _ = try fixture.open(payload, fixture.readerA) }
}

@Test func membershipDiagnosticsAreRedacted() throws {
    let fixture = try RevisionPolicyFixture()
    let sealed = try fixture.seal()
    let receipt = try fixture.authorize(sealed)
    let member = try FixtureMember.reader(fixture.readerA.publicKey)
    let latched = try fixture.authority.session([member]).session
    let fork = try fixture.authority.signed(MembershipBody(
        vaultID: fixture.authority.vaultID.bytes, sequence: 0, parent: Data(count: 32),
        controllerKey: fixture.authority.controller.publicKey.rawRepresentation,
        writerKey: fixture.authority.writer.publicKey.rawRepresentation, rows: [fixture.authority.writerRow]))
    expectPolicyError(.membershipFork) { _ = try latched.advance(fork) }
    let evidence = try #require(latched.forkEvidence)
    let checkpoint = fixture.session.checkpoint
    let values: [(Any, String)] = [
        (fixture.session.anchor.vaultID, "VaultID"), (checkpoint.head, "MembershipDigest"), (receipt.digest, "RevisionDigest"),
        (fixture.session.anchor, "FixtureTrustAnchor"), (member, "FixtureMember"), (checkpoint, "MembershipCheckpoint"),
        (receipt, "AuthorizedRevision"), (evidence, "MembershipForkEvidence"), (fixture.session, "FixtureMembershipSession"),
        (fixture.authority, "MembershipAuthority"),
    ]
    let forbidden = [fixtureCanary, membershipPolicyItem.username] + [
        fixture.authority.vaultID.bytes, checkpoint.head.bytes, receipt.digest.bytes,
        fixture.authority.controller.publicKey.rawRepresentation, fixture.authority.writer.publicKey.rawRepresentation,
        fixture.readerA.publicKey.rawRepresentation, fixture.authority.controller.rawRepresentation,
    ].flatMap { [MembershipExchangeTrace.hex($0), MembershipExchangeTrace.hex($0).uppercased(), $0.base64EncodedString()] }
    func clean(_ text: String) -> Bool { !forbidden.contains { text.contains($0) } }
    for (value, name) in values {
        #expect(String(describing: value) == name + "(<redacted>)")
        #expect(String(reflecting: value) == name + "(<redacted>)")
        #expect(Mirror(reflecting: value).children.isEmpty)
        var dumped = ""
        dump(value, to: &dumped)
        #expect(clean(dumped))
    }
    for value in [MembershipAdvance.duplicate(checkpoint), .advanced(checkpoint)] {
        var dumped = ""
        dump(value, to: &dumped)
        #expect(clean(String(describing: value)) && clean(String(reflecting: value)) && clean(dumped))
    }
    let errors: [MembershipPolicyError] = [
        .malformed, .anchorMismatch, .badMembershipSignature, .unsupportedAuthorityChange, .invalidMemberKey,
        .missingPredecessor, .membershipFork, .sequenceExhausted, .capacityExceeded, .staleMembership,
        .unauthorizedAuthor, .unauthorizedRecipient, .recipientSetMismatch, .invalidEncapsulation, .membershipSigningFailed,
    ]
    #expect(Set(errors.map(\.rawValue)).count == 15)
    for error in errors {
        #expect(error.localizedDescription == error.rawValue)
        #expect(String(describing: error) == error.rawValue && String(reflecting: error) == error.rawValue)
    }
}

// Focused single-assertion tests used by the compiled controls.

@Test func revisionStaleAfterNoOpSuccessor() throws {
    let fixture = try RevisionPolicyFixture()
    let stale = try fixture.seal()
    try fixture.authority.advance(fixture.session, fixture.members(withB: false))
    expectPolicyError(.staleMembership) { _ = try fixture.authorize(stale) }
}

@Test func revisionFromDisabledWriterIsUnauthorized() throws {
    let fixture = try RevisionPolicyFixture()
    try fixture.authority.advance(fixture.session, fixture.members(withB: false, writer: false))
    let sealed = try fixture.seal()
    expectPolicyError(.unauthorizedAuthor) { _ = try fixture.authorize(sealed) }
}

@Test func revisionMissingRecipientIsRejected() throws {
    let fixture = try RevisionPolicyFixture(withB: true)
    let missing = try fixture.seal(recipients: fixture.recipients(withB: false))
    expectPolicyError(.recipientSetMismatch) { _ = try fixture.authorize(missing) }
}

@Test func revisionUnselectedLowOrderEncapsulationIsRejected() throws {
    let fixture = try RevisionPolicyFixture()
    let context = try fixture.authority.context(fixture.session)
    let record = try fixture.authority.lowOrderEncapsulationRecord(
        context, fixture.recipients(withB: false),
        lowOrderFor: fixture.authority.writerAgreement.publicKey.rawRepresentation, encoding: membershipLowOrderEncodings()[2])
    expectPolicyError(.invalidEncapsulation) { _ = try fixture.authorize((record, context)) }
}

@Test func revisionPolicyOpenReturnsSyntheticItem() throws {
    let fixture = try RevisionPolicyFixture()
    let sealed = try fixture.seal()
    #expect(try fixture.open(sealed, fixture.readerA))
    #expect(try fixture.open(sealed, fixture.recovery, role: .recovery))
}
