import Crypto
import Foundation
import Testing
@_spi(SecretReveal) import VaultSecret
@testable import VaultRecord

// Every fixture here carries a valid writer signature over its final body and, per crypto
// review R3, a header tag and frame computed under DK1 after the final H.

@Test func hostileBuilderBaselineOpens() throws {
    let fixture = Fixture()
    let record = try HostileRecord(fixture, content: login()).build()
    for key in fixture.recipientKeys {
        try fixture.verify(record).open(as: key) { _ in }
    }
}

/// Changed stored commitment, selected HPKE AAD consistent with it: unwrap succeeds, the
/// recomputed commitment differs.
@Test func alteredCommitmentWithConsistentWrapAADFailsCommitment() throws {
    let fixture = Fixture()
    var hostile = HostileRecord(fixture, content: login())
    hostile.commitment = randomBytes(32)
    let record = try hostile.build()
    for key in fixture.recipientKeys { expectOpenRefusal(.commitmentMismatch, fixture, record, as: key) }
}

/// R3 fixture 1: reader 2's wrap holds DK2 under the stored DK1 commitment.
@Test func alternateDataKeyInSecondWrap() throws {
    let fixture = Fixture()
    var hostile = HostileRecord(fixture, content: login())
    let recipient = fixture.recipients.members[1]
    hostile.edk[1] = { headerHash, messageID, commitment in
        try ESDK.wrap(SymmetricKey(size: .bits256), for: recipient, headerHash: headerHash, messageID: messageID,
                      commitment: commitment)
    }
    let record = try hostile.build()
    let index = fixture.recipientKeys.firstIndex { $0.publicKey == recipient.publicKey }!
    for (position, key) in fixture.recipientKeys.enumerated() {
        if position == index {
            expectOpenRefusal(.commitmentMismatch, fixture, record, as: key)
        } else {
            try fixture.verify(record).open(as: key) { _ in }
        }
    }
}

/// R3 fixture 2 and the documented limitation: a canonical but corrupt wrap for another
/// recipient is undetectable to the unaffected readers.
@Test func corruptUnselectedWrapIsUndetectableToOthers() throws {
    let fixture = Fixture()
    var hostile = HostileRecord(fixture, content: login())
    let recipient = fixture.recipients.members[2]
    let dataKey = hostile.dataKey
    hostile.edk[2] = { headerHash, messageID, commitment in
        let good = try ESDK.wrap(dataKey, for: recipient, headerHash: headerHash, messageID: messageID,
                                 commitment: commitment)
        var wrapped = good.wrapped
        flip(&wrapped, at: 47)
        return ESDK.EncryptedDataKey(role: good.role, recipient: good.recipient, encapsulation: good.encapsulation,
                                     wrapped: wrapped)
    }
    let record = try hostile.build()
    let affected = fixture.recipientKeys.firstIndex { $0.publicKey == recipient.publicKey }!
    for (position, key) in fixture.recipientKeys.enumerated() {
        if position == affected {
            expectOpenRefusal(.wrapAuthentication, fixture, record, as: key)
        } else {
            try fixture.verify(record).open(as: key) { _ in }
        }
    }
}

/// A wrap bound to the other role, or to another record's P hash, fails HPKE AAD/info.
@Test func wrapBindingToRoleAndHeaderHash() throws {
    let fixture = Fixture()
    for variant in 0..<3 {
        var hostile = HostileRecord(fixture, content: login())
        let recipient = fixture.recipients.members[0]
        let dataKey = hostile.dataKey
        hostile.edk[0] = { headerHash, messageID, commitment in
            let pk = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipient.publicKey)
            let otherHash = sha256(Data("other P".utf8))
            let info = variant == 1 ? specInfo(headerHash: otherHash, messageID: messageID)
                                    : specInfo(headerHash: headerHash, messageID: messageID)
            let aad = specAAD(headerHash: variant == 2 ? otherHash : headerHash, messageID: messageID, commitment: commitment,
                              role: variant == 0 ? 2 : recipient.role.rawValue, recipient: recipient.publicKey)
            var sender = try HPKE.Sender(recipientKey: pk, ciphersuite: .Curve25519_SHA256_ChachaPoly, info: info)
            let wrapped = try dataKey.withUnsafeBytes { try sender.seal($0, authenticating: aad) }
            return ESDK.EncryptedDataKey(role: recipient.role.rawValue, recipient: recipient.publicKey,
                                         encapsulation: sender.encapsulatedKey, wrapped: wrapped)
        }
        let record = try hostile.build()
        let key = fixture.recipientKeys.first { $0.publicKey == recipient.publicKey }!
        expectOpenRefusal(.wrapAuthentication, fixture, record, as: key)
    }
}

@Test func headerTagFrameTagAndCiphertextFlips() throws {
    let fixture = Fixture()
    let layout = Layout(parents: 0, recipients: 3)
    var header = HostileRecord(fixture, content: login())
    header.mutateHeaderTag = { flip(&$0, at: 0) }
    expectOpenRefusal(.headerAuthentication, fixture, try header.build())
    for offset in [layout.ciphertext - layout.e, layout.ciphertext - layout.e + 511, layout.ciphertext - layout.e + 512] {
        var frame = HostileRecord(fixture, content: login())
        frame.mutateBody = { flip(&$0, at: offset) }
        expectOpenRefusal(.frameAuthentication, fixture, try frame.build())
    }
}

/// P/context and messageID mismatches reach their gates under a valid signature.
@Test func contextAndMessageBindings() throws {
    let fixture = Fixture()
    var context = HostileRecord(fixture, content: login())
    context.context = ESDK.context(headerHash: sha256(Data("not this P".utf8)))
    expectRefusal(.malformed) { _ = try ParsedRecord(try context.build()) }
    var uppercase = HostileRecord(fixture, content: login())
    var bytes = ESDK.context(headerHash: sha256(uppercase.headerBytes))
    bytes = bytes.map { (0x61...0x66).contains($0) ? $0 - 0x20 : $0 }
    uppercase.context = bytes
    expectRefusal(.malformed) { _ = try ParsedRecord(try uppercase.build()) }
    // Header messageID differs from the one bound into wraps and the KDF salt.
    var message = HostileRecord(fixture, content: login())
    message.mutateBody = { flip(&$0, at: 3) }
    expectOpenRefusal(.wrapAuthentication, fixture, try message.build())
}

private func authenticatedPayload(_ fixture: Fixture, kind: RecordKind = .login, _ logical: [UInt8]? = nil,
                                  padded: [UInt8]? = nil) throws -> Data {
    var hostile = HostileRecord(fixture, content: login())
    hostile.kind = kind.rawValue
    if let logical { hostile.logical = logical }
    hostile.padded = padded
    return try hostile.build()
}

@Test func authenticatedBadPaddingAndLength() throws {
    let fixture = Fixture()
    let logical = Payload.logical(.tombstone)
    var nonzero = Payload.pad(logical)
    nonzero[511] = 1
    var inflated = ByteWriter()
    inflated.u32(UInt32(logical.count))
    inflated.raw(logical)
    inflated.raw([UInt8](repeating: 0, count: 1024 - 6))
    var long = Payload.pad(logical)
    long[3] = 3 // claims a trailing byte that is really padding
    var short = Payload.pad(logical)
    short[3] = 1
    var huge = Payload.pad(logical)
    huge[0] = 0xff
    var exact = Payload.pad(logical)
    exact[2] = 0x01
    exact[3] = 0xfc // L = 508 fills the bucket; the extra logical zeros are not padding
    for padded in [nonzero, inflated.bytes, long, short, huge, exact] {
        expectOpenRefusal(.invalidPayload, fixture,
                          try authenticatedPayload(fixture, kind: .tombstone, logical, padded: padded))
    }
}

@Test func authenticatedKindAndVersionMismatch() throws {
    let fixture = Fixture()
    let loginLogical = Payload.logical(login())
    // Public kind 2 / 3 with a login payload, public kind 1 with a tombstone payload.
    expectOpenRefusal(.invalidPayload, fixture, try authenticatedPayload(fixture, kind: .apiToken, loginLogical))
    expectOpenRefusal(.invalidPayload, fixture, try authenticatedPayload(fixture, kind: .tombstone, loginLogical))
    expectOpenRefusal(.invalidPayload, fixture, try authenticatedPayload(fixture, kind: .login, Payload.logical(.tombstone)))
    var version = loginLogical
    version[0] = 3
    expectOpenRefusal(.invalidPayload, fixture, try authenticatedPayload(fixture, version))
    // Inner kind differs but the remaining bytes are schema-valid for the public kind.
    for innerKind: UInt8 in [1, 2, 4] {
        expectOpenRefusal(.invalidPayload, fixture, try authenticatedPayload(fixture, kind: .tombstone, [2, innerKind]))
    }
    var token = Payload.logical(.apiToken(try APITokenContent(title: .empty, token: secret([0x41]), service: .github)))
    token[1] = 1
    expectOpenRefusal(.invalidPayload, fixture, try authenticatedPayload(fixture, kind: .apiToken, token))
    expectOpenRefusal(.invalidPayload, fixture, try authenticatedPayload(fixture, kind: .tombstone, [3, 3]))
}

private func loginLogical(title: [UInt8] = [], usernameTag: UInt8 = 0, username: [UInt8]? = nil,
                          password: [UInt8] = Array(syntheticCanary.utf8), origins: [[UInt8]] = [],
                          trailing: [UInt8] = [], passwordLength: UInt32? = nil) -> [UInt8] {
    var writer = ByteWriter()
    writer.u8(2)
    writer.u8(1)
    writer.f16(title)
    writer.u8(usernameTag)
    if let username { writer.f16(username) }
    writer.u32(passwordLength ?? UInt32(password.count))
    writer.raw(password)
    writer.u8(UInt8(origins.count))
    for origin in origins { writer.f16(origin) }
    writer.raw(trailing)
    return writer.bytes
}

@Test func authenticatedBrowserNumericHostsAreRefused() throws {
    let fixture = Fixture()
    for origin in ["https://0x7f000001", "https://0x7f.1", "https://example.1",
                   "https://example.0xff", "https://example.0x", "https://example.09"] {
        let logical = loginLogical(origins: [Array(origin.utf8)])
        expectOpenRefusal(.invalidPayload, fixture, try authenticatedPayload(fixture, logical))
    }
}

@Test func authenticatedSchemaViolations() throws {
    let fixture = Fixture()
    let control = loginLogical()
    try fixture.verify(try authenticatedPayload(fixture, control)).open(as: fixture.recipientKeys[0]) { _ in }
    let a = Array("https://a.invalid".utf8), b = Array("https://b.invalid".utf8)
    let cases: [[UInt8]] = [
        loginLogical(usernameTag: 2),
        loginLogical(usernameTag: 2, username: []),
        loginLogical(usernameTag: 0, username: []), // absent tag followed by a stray field
        loginLogical(usernameTag: 1, username: [0xc3]),
        loginLogical(usernameTag: 1, username: [UInt8](repeating: 0x61, count: 1025)),
        loginLogical(title: [0xf4, 0x90, 0x80, 0x80]),
        loginLogical(title: [UInt8](repeating: 0x61, count: 1025)),
        loginLogical(password: []),
        loginLogical(password: [UInt8](repeating: 1, count: 16385)),
        loginLogical(password: [1], passwordLength: 2),
        loginLogical(origins: [b, a]),
        loginLogical(origins: [a, a]),
        loginLogical(origins: [Array("https://A.invalid".utf8)]),
        loginLogical(origins: [Array("https://a.invalid:443".utf8)]),
        loginLogical(origins: Array(repeating: a, count: 33)),
        loginLogical(trailing: [0]),
    ]
    for logical in cases {
        expectOpenRefusal(.invalidPayload, fixture, try authenticatedPayload(fixture, logical))
    }
}

/// SERVICE-TAGS.md: only 0x0001 is admitted; 0, 2 and 0xffff fail with zero callbacks.
@Test func unknownServiceTagsRefusedUnderRealCrypto() throws {
    let fixture = Fixture()
    func token(_ tag: UInt16, tokenLength: Int = 1) -> [UInt8] {
        var writer = ByteWriter()
        writer.u8(2)
        writer.u8(2)
        writer.u16(0)
        writer.f32([UInt8](repeating: 0x41, count: tokenLength))
        writer.u16(tag)
        return writer.bytes
    }
    try fixture.verify(try authenticatedPayload(fixture, kind: .apiToken, token(1))).open(as: fixture.recipientKeys[1]) { opened in
        guard case .apiToken(let value) = opened else { Issue.record("shape"); return }
        #expect(bytes(value.token) == [0x41])
    }
    for tag: UInt16 in [0, 2, 0xffff] {
        expectOpenRefusal(.invalidPayload, fixture, try authenticatedPayload(fixture, kind: .apiToken, token(tag)))
    }
    expectOpenRefusal(.invalidPayload, fixture, try authenticatedPayload(fixture, kind: .apiToken, token(1, tokenLength: 0)))
    expectOpenRefusal(.invalidPayload, fixture, try authenticatedPayload(fixture, kind: .apiToken, token(1, tokenLength: 16385)))
    expectOpenRefusal(.invalidPayload, fixture, try authenticatedPayload(fixture, kind: .apiToken, token(1) + [0]))
}

/// A recipient holding DK alters plaintext and rebuilds every inner tag and wrap, but
/// cannot produce the writer signature.
@Test func recipientForgedMessageFailsBeforeUnwrap() throws {
    let fixture = Fixture()
    let original = try fixture.seal(login())
    var forged = HostileRecord(fixture, content: login(password: "forged-\(syntheticCanary)"))
    forged.signer = fixture.otherAuthor
    expectOpenRefusal(.badSignature, fixture, try forged.build())
    // Old writer signature transplanted onto the rebuilt body.
    let rebuilt = try HostileRecord(fixture, content: login(password: "forged")).build()
    let transplant = rebuilt.prefix(rebuilt.count - 64) + original.bytes.suffix(64)
    expectOpenRefusal(.badSignature, fixture, Data(transplant))
    // Corrupt signature on a known, otherwise identical body: no duplicate shortcut.
    var corrupt = original.bytes
    flip(&corrupt, at: corrupt.count - 1)
    expectOpenRefusal(.badSignature, fixture, corrupt)
}
