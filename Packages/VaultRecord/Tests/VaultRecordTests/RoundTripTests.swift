import Crypto
import Foundation
import Testing
@_spi(SecretReveal) import VaultSecret
@testable import VaultRecord

/// Opens `record` as every fixture recipient and returns each recipient's view of the content.
func openAll(_ fixture: Fixture, _ record: SealedRecord) throws -> [RecordContent] {
    let verified = try fixture.verify(record.bytes)
    #expect(verified.bodyID == record.bodyID)
    #expect(verified.transportDigest == record.transportDigest)
    return try fixture.recipientKeys.map { key in try verified.open(as: key) { $0 } }
}

func expectLogin(_ content: RecordContent, title: [UInt8], username: Username, password: [UInt8], origins: [String],
                 sourceLocation: SourceLocation = #_sourceLocation) {
    guard case .login(let login) = content else {
        Issue.record("not a login", sourceLocation: sourceLocation)
        return
    }
    switch (login.title, title.isEmpty) {
    case (.empty, true): break
    case (.value(let value), false): #expect(bytes(value) == title, sourceLocation: sourceLocation)
    default: Issue.record("title state differs", sourceLocation: sourceLocation)
    }
    switch (login.username, username) {
    case (.absent, .absent), (.empty, .empty): break
    case (.value(let got), .value(let want)): #expect(got.matches(want), sourceLocation: sourceLocation)
    default: Issue.record("username state differs", sourceLocation: sourceLocation)
    }
    #expect(bytes(login.password) == password, sourceLocation: sourceLocation)
    #expect(login.origins.map(\.ascii) == origins, sourceLocation: sourceLocation)
}

@Test func absentEmptyAndPresentUsernamesStayDistinctForEveryRecipient() throws {
    let fixture = Fixture()
    for username in [Username.absent, .empty, .value(secret("synthetic-user"))] {
        let record = try fixture.seal(login(username: username))
        for content in try openAll(fixture, record) {
            expectLogin(content, title: Array("Synthetic title".utf8), username: username,
                        password: Array(syntheticCanary.utf8), origins: ["https://example.invalid"])
        }
    }
    // Absent and empty differ in authenticated bytes, not only in the decoded enum.
    #expect(Payload.logical(login(username: .absent)) != Payload.logical(login(username: .empty)))
}

@Test func exactUTF8BytesBOMAndNonASCIIArePreserved() throws {
    let fixture = Fixture()
    let title = [0xef, 0xbb, 0xbf] + Array("Café e\u{301} 🔐".utf8)
    let user = [0xef, 0xbb, 0xbf] + Array("ユーザー".utf8)
    let password: [UInt8] = [0x00, 0xff, 0x80, 0x0a] + Array(syntheticCanary.utf8)
    let content = RecordContent.login(try LoginContent(title: .value(secret(title)), username: .value(secret(user)),
                                                       password: secret(password), origins: []))
    for opened in try openAll(fixture, try fixture.seal(content)) {
        expectLogin(opened, title: title, username: .value(secret(user)), password: password, origins: [])
    }
}

@Test func emptyTitleAndAPITokenRoundTrip() throws {
    let fixture = Fixture()
    let token: [UInt8] = Array("ghp_synthetic_\(syntheticCanary)".utf8)
    let content = RecordContent.apiToken(try APITokenContent(title: .empty, token: secret(token), service: .github))
    for opened in try openAll(fixture, try fixture.seal(content)) {
        guard case .apiToken(let value) = opened, case .empty = value.title else {
            Issue.record("token shape differs")
            continue
        }
        #expect(bytes(value.token) == token)
        #expect(value.service == .github)
    }
}

@Test func githubMinimalPayloadMatchesReviewBytes() throws {
    let content = RecordContent.apiToken(try APITokenContent(title: .empty, token: secret([0x41]), service: .github))
    var logical = Payload.logical(content)
    #expect(logical == [0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x41, 0x00, 0x01])
    let padded = Payload.pad(logical)
    #expect(padded.count == 512)
    #expect(Array(padded.prefix(15)) == [0x00, 0x00, 0x00, 0x0b] + logical)
    #expect(padded.dropFirst(15).allSatisfy { $0 == 0 })
    wipe(&logical)
}

@Test func tombstoneUsesSmallestBucket() throws {
    let fixture = Fixture()
    let record = try fixture.seal(.tombstone)
    #expect(Payload.pad(Payload.logical(.tombstone)).count == 512)
    #expect(record.bytes.count == 124 + 4 + 156 + 128 * 3 + 16 + 40 + 512 + 64)
    for opened in try openAll(fixture, record) {
        guard case .tombstone = opened else { Issue.record("not a tombstone"); continue }
    }
}

@Test func secretAndTitleLimits() throws {
    let fixture = Fixture()
    let maximum = [UInt8](repeating: 0x5a, count: SecretBytes.maximumBytes)
    let longText = [UInt8](repeating: 0x61, count: 1024)
    let content = RecordContent.login(try LoginContent(title: .value(secret(longText)), username: .value(secret(longText)),
                                                       password: secret(maximum), origins: []))
    for opened in try openAll(fixture, try fixture.seal(content)) {
        expectLogin(opened, title: longText, username: .value(secret(longText)), password: maximum, origins: [])
    }
    let oneByte = RecordContent.apiToken(try APITokenContent(title: .empty, token: secret([1]), service: .github))
    _ = try openAll(fixture, try fixture.seal(oneByte))
    let tooLong = [UInt8](repeating: 0x61, count: 1025)
    #expect(throws: RecordError.invalidContent) {
        _ = try LoginContent(title: .value(secret(tooLong)), username: .absent, password: secret("x"), origins: [])
    }
    #expect(throws: RecordError.invalidContent) {
        _ = try LoginContent(title: .empty, username: .value(secret(tooLong)), password: secret("x"), origins: [])
    }
    #expect(throws: RecordError.invalidContent) {
        _ = try LoginContent(title: .value(secret([0xc0, 0x80])), username: .absent, password: secret("x"), origins: [])
    }
    #expect(throws: RecordError.invalidContent) {
        _ = try APITokenContent(title: .value(secret([0xed, 0xa0, 0x80])), token: secret("x"), service: .github)
    }
}

@Test func originsAreCanonicalSortedAndUnique() throws {
    for valid in ["https://example.invalid", "https://xn--bcher-kva.example", "https://a.b:8443", "https://a1-b.c"] {
        #expect((try? CanonicalOrigin(valid)) != nil, "\(valid)")
    }
    for invalid in ["http://example.invalid", "https://Example.invalid", "https://example.invalid/",
                    "https://example.invalid:443", "https://example.invalid:0443", "https://example.invalid:",
                    "https://user@example.invalid", "https://example.invalid.", "https://-a.example",
                    "https://0x7f000001", "https://0x7f.1", "https://example.1",
                    "https://example.0xff", "https://example.0x", "https://example.09",
                    "https://1.2.3.4", "https://[::1]", "https://example.invalid?x", "https://exa mple.invalid",
                    "https://example.invalid:65536", "https://" + String(repeating: "a", count: 64) + ".invalid"] {
        #expect(throws: RecordError.invalidContent, "\(invalid)") { _ = try CanonicalOrigin(invalid) }
    }
    let sorted = try LoginContent(title: .empty, username: .absent, password: secret("x"),
                                  origins: [try CanonicalOrigin("https://b.invalid"), try CanonicalOrigin("https://a.invalid")])
    #expect(sorted.origins.map(\.ascii) == ["https://a.invalid", "https://b.invalid"])
    #expect(throws: RecordError.invalidContent) {
        _ = try LoginContent(title: .empty, username: .absent, password: secret("x"),
                             origins: [try CanonicalOrigin("https://a.invalid"), try CanonicalOrigin("https://a.invalid")])
    }
}

/// Every reachable bucket at, just below and just above its boundary.
@Test func reachableBucketBoundaries() throws {
    let fixture = Fixture()
    let overhead = 2 + 2 + 4 + 2 // version, kind, empty title, F32 header, service tag
    for bucket in [512, 1024, 2048, 4096, 8192, 16384] {
        for logical in [bucket - 5, bucket - 4, bucket - 3] {
            let tokenLength = logical - overhead
            guard (1...SecretBytes.maximumBytes).contains(tokenLength) else { continue }
            let token = [UInt8](repeating: 0x54, count: tokenLength)
            let content = RecordContent.apiToken(try APITokenContent(title: .empty, token: secret(token), service: .github))
            let record = try fixture.seal(content)
            let expected = Payload.buckets.first { $0 >= 4 + logical }!
            let parsed = try ParsedRecord(record.bytes)
            #expect(parsed.message.ciphertext.count == expected)
            for opened in try openAll(fixture, record) {
                guard case .apiToken(let value) = opened else { Issue.record("shape"); continue }
                #expect(bytes(value.token) == token)
            }
        }
    }
    #expect(Payload.bucket(forLogicalCount: 32764) == 32768)
    #expect(Payload.bucket(forLogicalCount: 32765) == 65536)
}

func maximumLogin() throws -> RecordContent {
    let text = [UInt8](repeating: 0x61, count: 1024)
    let origins = try (0..<32).map { index -> CanonicalOrigin in
        let tail = String(format: "%02d", index) + String(repeating: "d", count: 54)
        let host = [String(repeating: "a", count: 63), String(repeating: "b", count: 63),
                    String(repeating: "c", count: 63), tail].joined(separator: ".")
        return try CanonicalOrigin("https://" + host)
    }
    #expect(origins.allSatisfy { $0.ascii.utf8.count == 256 })
    return .login(try LoginContent(title: .value(secret(text)), username: .value(secret(text)),
                                   password: secret([UInt8](repeating: 0x70, count: 16384)), origins: origins))
}

/// Largest kind 1–3 record: 26,700 logical bytes → B = 32,768; 16 parents, 32 recipients.
@Test func maximumReachableRecordIs37780Bytes() throws {
    let fixture = Fixture()
    let content = try maximumLogin()
    #expect(Payload.logical(content).count == 26_700)
    let keys = (0..<32).map { index in
        RecipientKey(role: index < 31 ? .device : .recovery,
                     privateKey: key(UInt8(100 + index)) { try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: $0) })
    }
    let set = try RecipientSet(keys.map { try Recipient(role: $0.role, publicKey: $0.publicKey) })
    let authority = fixture.authority(recipients: set)
    let parents = (1...16).map { try! RevisionBodyID(Data(repeating: UInt8($0), count: 32)) }
    let identity = try RevisionIdentity(itemID: fixture.itemID, revisionID: fixture.revisionID, parents: parents.reversed())
    let record = try RecordSealer.seal(content, identity: identity, authority: authority, author: fixture.author)
    #expect(record.bytes.count == 37_780)
    let verified = try ParsedRecord(record.bytes).verify(under: authority, item: fixture.itemID, revision: fixture.revisionID)
    #expect(verified.parents == parents)
    for recipient in [keys[0], keys[17], keys[31]] {
        try verified.open(as: recipient) { opened in
            guard case .login(let login) = opened else { Issue.record("shape"); return }
            #expect(bytes(login.password) == [UInt8](repeating: 0x70, count: 16384))
            #expect(login.origins.count == 32)
        }
    }
    #expect(throws: RecordError.invalidContent) {
        _ = try RevisionIdentity(itemID: fixture.itemID, revisionID: fixture.revisionID,
                                 parents: parents + [try RevisionBodyID(Data(repeating: 0x77, count: 32))])
    }
}

@Test func nonzeroStartSlicesParseAndOpen() throws {
    let fixture = Fixture()
    let record = try fixture.seal(login())
    let framed = Data([0xaa, 0xbb, 0xcc]) + record.bytes + Data([0xdd])
    let slice = framed[framed.startIndex + 3..<framed.endIndex - 1]
    #expect(slice.startIndex != 0)
    let verified = try fixture.verify(slice)
    #expect(verified.bodyID == record.bodyID)
    try verified.open(as: fixture.recipientKeys[2]) { opened in
        expectLogin(opened, title: Array("Synthetic title".utf8), username: .value(secret("synthetic-user")),
                    password: Array(syntheticCanary.utf8), origins: ["https://example.invalid"])
    }
}

@Test func unrelatedKeyAndWrongRoleAreNotRecipients() throws {
    let fixture = Fixture()
    let verified = try fixture.verify(try fixture.seal(login()).bytes)
    let callbacks = Callbacks()
    expectRefusal(.notRecipient) { try callbacks.open(verified, as: RecipientKey(role: .device, privateKey: fixture.unrelated)) }
    expectRefusal(.notRecipient) { try callbacks.open(verified, as: RecipientKey(role: .recovery, privateKey: fixture.device1)) }
    #expect(callbacks.count == 0)
}

@Test func redactedDescriptions() throws {
    let content = login()
    for text in [String(describing: content), String(reflecting: content), "\(RecipientKey(role: .device, privateKey: Fixture().device1))"] {
        #expect(!text.contains(syntheticCanary))
        #expect(text.contains("redacted"))
    }
    #expect(String(describing: RecordError.badSignature) == "badSignature")
}
