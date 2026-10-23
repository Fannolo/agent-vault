import Crypto
import Foundation
import Testing
@testable import VaultRecord

// Full AVREC002 cases, not CCTV primitive messages. Expectations come from private
// deterministic affine arithmetic checked independently against RFC8032 section 6.
// A=[a]B+T, R=[r]B+T, exact order(T)=8; both A and R have order 8L.
// h=LE(SHA512(R||A||body)) mod L, S=(r+h*a) mod L. The exact equation
// holds iff (1+h) mod 8 == 0. Both cases pass the cofactored equation.
// No key enrollment, production signing, subgroup-validation or security-proof claim.

private func mixedOrderPreconditions(_ parsed: ParsedRecord, challenge expected: Data) throws {
    let fixture = Fixture()
    let correctBody = parsed.signed == MixedOrderFixture.body
    let correctDigest = hex(SHA256.hash(data: parsed.signed)) == MixedOrderFixture.bodySHA256
    let correctAuthor = parsed.header.author == MixedOrderFixture.author
    let correctContext = parsed.message.contextValue == Data(hex(SHA256.hash(data: parsed.headerBytes)).utf8)
    let correctBinding = parsed.header.vaultID == fixture.vaultID && parsed.header.itemID == fixture.itemID
        && parsed.header.revisionID == fixture.revisionID && parsed.header.membershipBodyID == fixture.membership
        && parsed.header.parents.isEmpty && parsed.header.kind == .login
    let correctRecipients = parsed.message.edks.map(\.sortKey) == fixture.recipients.members.map(\.sortKey)
    #expect(correctBody && correctDigest && correctAuthor && correctContext && correctBinding && correctRecipients)
    #expect(SignatureProfile.screensPoint(MixedOrderFixture.author))
    #expect(SignatureProfile.screensPoint(parsed.signature.prefix(32)))
    #expect(SignatureProfile.scalarIsReduced(parsed.signature.suffix(32)))
    let correctChallenge = Data(challenge(Data(parsed.signature.prefix(32)), MixedOrderFixture.author, parsed.signed)) == expected
    #expect(correctChallenge)
    for edk in parsed.message.edks {
        try validateX25519(edk.recipient)
        try validateX25519(edk.encapsulation)
    }
}

@Test func mixedOrderFullRecordAcceptsAndOpensForThreeHolders() throws {
    let fixture = Fixture()
    let parsed = try ParsedRecord(MixedOrderFixture.acceptRecord)
    try mixedOrderPreconditions(parsed, challenge: MixedOrderFixture.acceptChallenge)
    // Exact torsion cancellation in the selected reduced-h equation.
    #expect(MixedOrderFixture.acceptChallenge[0] % 8 == 7)
    let result = outcome(parsed.signature, parsed.signed, MixedOrderFixture.author)
    #expect(result.effective && result.rawPinned)
    let authority = fixture.authority(author: MixedOrderFixture.author)
    let verified = try parsed.verify(under: authority, item: fixture.itemID, revision: fixture.revisionID)
    let bodyIdentityMatches = verified.bodyID.rawValue == sha256(RecordFormat.bodyDomain, parsed.signed)
    let transportMatches = verified.transportDigest.rawValue == sha256(MixedOrderFixture.acceptRecord)
    #expect(bodyIdentityMatches && transportMatches)
    var callbacks = 0
    for holder in fixture.recipientKeys {
        try verified.open(as: holder) { content in
            let exact = sameContent(content, login())
            #expect(exact, "mixed-order accepted payload differs")
            callbacks += 1
        }
    }
    #expect(callbacks == 3)
    emitPublic("AV_RECORD_MIXED full_accept platform=\(platformName) \(result) payload_exact=true callbacks=\(callbacks)")
}

@Test func mixedOrderFullRecordRejectsCofactoredOnlyBeforeOpen() throws {
    let fixture = Fixture()
    let parsed = try ParsedRecord(MixedOrderFixture.rejectRecord)
    try mixedOrderPreconditions(parsed, challenge: MixedOrderFixture.rejectChallenge)
    #expect(MixedOrderFixture.rejectChallenge[0] % 8 != 7)
    let sameBodyAsAccepted = parsed.signed == Data(MixedOrderFixture.acceptRecord.dropLast(64))
    #expect(sameBodyAsAccepted)
    let result = outcome(parsed.signature, parsed.signed, MixedOrderFixture.author)
    #expect(!result.effective && !result.rawPinned)
    // Preflight the otherwise identical rejected body independently of the signature gate:
    // spec-text HPKE info/AAD, manual RFC9180 schedule, commitment, final H authentication,
    // final-frame authentication and exact canonical padded payload for every holder.
    // This is a test witness, not an alternate production open or authority capability.
    let headerHash = Data(SHA256.hash(data: parsed.headerBytes))
    var preflightExact = 0
    for holder in fixture.recipientKeys {
        let edk = try #require(parsed.message.edks.first { $0.recipient == holder.publicKey && $0.role == holder.role.rawValue })
        let schedule = try ManualHPKE(dh: ManualHPKE.dh(holder.privateKey, edk.encapsulation),
                                      encapsulation: edk.encapsulation, recipient: edk.recipient,
                                      info: specInfo(headerHash: headerHash, messageID: parsed.message.messageID))
        let dk = try schedule.open(edk.wrapped, aad: specAAD(headerHash: headerHash, messageID: parsed.message.messageID,
                                                            commitment: parsed.message.commitment, role: edk.role,
                                                            recipient: edk.recipient))
        let keys = specCommitment(dataKey: dk, messageID: parsed.message.messageID)
        let commitmentMatches = keys.commitment == parsed.message.commitment
        #expect(commitmentMatches)
        let key = SymmetricKey(data: keys.encryption)
        _ = try AES.GCM.open(.init(nonce: .init(data: Data(count: 12)), ciphertext: Data(), tag: parsed.message.headerTag),
                             using: key, authenticating: parsed.message.header)
        // This fixture uses the 512-byte final frame, sequence 1, 64-bit content length.
        let aad = parsed.message.messageID + Data("AWSKMSEncryptionClient Final Frame".utf8)
            + Data([0, 0, 0, 1]) + Data([0, 0, 0, 0, 0, 0, 2, 0])
        let padded = try AES.GCM.open(.init(nonce: .init(data: Data(count: 11) + Data([1])),
                                            ciphertext: parsed.message.ciphertext, tag: parsed.message.frameTag),
                                     using: key, authenticating: aad)
        let paddedMatches = padded == Data(Payload.pad(Payload.logical(login())))
        let decodedMatches = sameContent(try Payload.decode(padded, kind: .login), login())
        #expect(paddedMatches && decodedMatches)
        preflightExact += 1
    }
    #expect(preflightExact == 3)
    let authority = fixture.authority(author: MixedOrderFixture.author)
    var totalCallbacks = 0
    for holder in fixture.recipientKeys {
        let callbacks = Callbacks()
        expectRefusal(.badSignature) {
            let verified = try parsed.verify(under: authority, item: fixture.itemID, revision: fixture.revisionID)
            try callbacks.open(verified, as: holder)
        }
        #expect(callbacks.count == 0)
        totalCallbacks += callbacks.count
    }
    #expect(totalCallbacks == 0)
    emitPublic("AV_RECORD_MIXED full_reject platform=\(platformName) \(result) preflight_exact=\(preflightExact) refusal=badSignature callbacks=\(totalCallbacks)")
}
