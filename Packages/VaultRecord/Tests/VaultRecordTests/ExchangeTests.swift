import Crypto
import Foundation
import Testing
@_spi(SecretReveal) import VaultSecret
@testable import VaultRecord

// TEST ONLY byte producer/reader for the parent's native ↔ Linux exchange and the AWS
// reference decryptor. Enabled only by an explicit output/input path. Files hold public
// ciphertext; the reference file additionally holds synthetic test DKs. Stdout carries only
// case names, public identities and pass markers.

private let environment = ProcessInfo.processInfo.environment

struct ExchangeCase: Sendable {
    let name: String
    let content: @Sendable () throws -> RecordContent
}

let exchangeCases: [ExchangeCase] = [
    ExchangeCase(name: "login_absent_username") { login(username: .absent) },
    ExchangeCase(name: "login_empty_username") { login(username: .empty, origins: []) },
    ExchangeCase(name: "login_bom_non_ascii") {
        .login(try LoginContent(title: .value(secret([0xef, 0xbb, 0xbf] + Array("Café 🔐".utf8))),
                                username: .value(secret([0xef, 0xbb, 0xbf] + Array("ユーザー".utf8))),
                                password: secret([0x00, 0xff] + Array(syntheticCanary.utf8)),
                                origins: [try CanonicalOrigin("https://a.invalid:8443"), try CanonicalOrigin("https://b.invalid")]))
    },
    ExchangeCase(name: "login_maximum_fields") { try maximumLogin() },
    ExchangeCase(name: "token_github_minimal") { .apiToken(try APITokenContent(title: .empty, token: secret([0x41]), service: .github)) },
    ExchangeCase(name: "token_github_bucket_512") {
        .apiToken(try APITokenContent(title: .empty, token: secret([UInt8](repeating: 0x54, count: 498)), service: .github))
    },
    ExchangeCase(name: "token_github_bucket_1024") {
        .apiToken(try APITokenContent(title: .value(secret("Synthetic token")),
                                      token: secret([UInt8](repeating: 0x54, count: 499 - 15)), service: .github))
    },
    ExchangeCase(name: "token_github_maximum") {
        .apiToken(try APITokenContent(title: .empty, token: secret([UInt8](repeating: 0x55, count: 16384)), service: .github))
    },
    ExchangeCase(name: "tombstone") { .tombstone },
]

func exchangeIdentity(_ index: Int) -> RevisionIdentity {
    try! RevisionIdentity(itemID: ItemID(Data(repeating: UInt8(0x10 + index), count: 16)),
                          revisionID: RevisionID(Data(repeating: UInt8(0x40 + index), count: 16)),
                          parents: index == 0 ? [] : [try RevisionBodyID(Data(repeating: UInt8(index), count: 32))])
}

func sameContent(_ left: RecordContent, _ right: RecordContent) -> Bool {
    func text(_ a: RecordText, _ b: RecordText) -> Bool {
        switch (a, b) {
        case (.empty, .empty): true
        case (.value(let x), .value(let y)): x.matches(y)
        default: false
        }
    }
    switch (left, right) {
    case (.tombstone, .tombstone): return true
    case (.apiToken(let a), .apiToken(let b)): return text(a.title, b.title) && a.token.matches(b.token) && a.service == b.service
    case (.login(let a), .login(let b)):
        let user: Bool
        switch (a.username, b.username) {
        case (.absent, .absent), (.empty, .empty): user = true
        case (.value(let x), .value(let y)): user = x.matches(y)
        default: user = false
        }
        return text(a.title, b.title) && user && a.password.matches(b.password) && a.origins == b.origins
    default: return false
    }
}

func writePrivate(_ data: Data, to path: String) throws {
    guard FileManager.default.createFile(atPath: path, contents: nil, attributes: [.posixPermissions: 0o600]),
          let handle = FileHandle(forWritingAtPath: path) else { throw RecordError.invalidContent }
    try handle.write(contentsOf: data)
    try handle.close()
}

private let writeExchange = environment["AV_RECORD_EXCHANGE_WRITE"]
private let readExchange = environment["AV_RECORD_EXCHANGE_READ"]
private let writeReference = environment["AV_RECORD_REFERENCE_WRITE"]

@Test(.enabled(if: writeExchange != nil)) func exchangeProducer() throws {
    let path = try #require(writeExchange)
    #expect(!FileManager.default.fileExists(atPath: path))
    let fixture = Fixture()
    var records: [[String: String]] = []
    for (index, item) in exchangeCases.enumerated() {
        let identity = exchangeIdentity(index)
        let sealed = try fixture.seal(try item.content(), identity: identity)
        records.append(["name": item.name, "bytes": hex(sealed.bytes), "body_id": hex(sealed.bodyID.rawValue),
                        "transport_digest": hex(sealed.transportDigest.rawValue)])
        emitPublic("AV_RECORD_EXCHANGE_WRITE platform=\(platformName) case=\(item.name) bytes=\(sealed.bytes.count) "
                   + "body_id=\(hex(sealed.bodyID.rawValue))")
    }
    let document: [String: Any] = ["schema": "av-record-exchange-v1", "producer": platformName, "records": records]
    try writePrivate(try JSONSerialization.data(withJSONObject: document, options: [.sortedKeys]), to: path)
}

@Test(.enabled(if: readExchange != nil)) func exchangeReader() throws {
    let path = try #require(readExchange)
    let document = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path))) as? [String: Any])
    #expect(document["schema"] as? String == "av-record-exchange-v1")
    let records = try #require(document["records"] as? [[String: String]])
    #expect(records.map { $0["name"] } == exchangeCases.map(\.name))
    let fixture = Fixture()
    for (index, record) in records.enumerated() {
        let bytes = unhex(try #require(record["bytes"]))
        let identity = exchangeIdentity(index)
        let parsed = try ParsedRecord(bytes)
        let verified = try parsed.verify(under: fixture.authority(), item: identity.itemID, revision: identity.revisionID)
        #expect(hex(verified.bodyID.rawValue) == record["body_id"])
        #expect(hex(verified.transportDigest.rawValue) == record["transport_digest"])
        #expect(verified.parents == identity.parents)
        let expected = try exchangeCases[index].content()
        var opened = 0
        for key in fixture.recipientKeys {
            try verified.open(as: key) { content in
                #expect(sameContent(content, expected), "\(exchangeCases[index].name)")
                opened += 1
            }
        }
        let callbacks = Callbacks()
        expectRefusal(.notRecipient) { try callbacks.open(verified, as: RecipientKey(role: .device, privateKey: fixture.unrelated)) }
        #expect(opened == 3 && callbacks.count == 0)
        emitPublic("AV_RECORD_EXCHANGE_READ platform=\(platformName) producer=\(document["producer"] as? String ?? "?") "
                   + "case=\(exchangeCases[index].name) body_id=\(hex(verified.bodyID.rawValue)) bucket=\(parsed.message.ciphertext.count) "
                   + "recipients_opened=\(opened) PASS")
    }
}

/// DK recovered by the independent RFC 9180 schedule with spec-text info/AAD, never by the
/// package's open path.
private func referenceEntry(_ name: String, record: Data, holder: RecipientKey, expectedPadded: [UInt8]) throws -> [String: Any] {
    let parsed = try ParsedRecord(record)
    let headerHash = Data(SHA256.hash(data: parsed.headerBytes))
    let edk = try #require(parsed.message.edks.first { $0.recipient == holder.publicKey })
    let schedule = try ManualHPKE(dh: ManualHPKE.dh(holder.privateKey, edk.encapsulation), encapsulation: edk.encapsulation,
                                  recipient: edk.recipient, info: specInfo(headerHash: headerHash, messageID: parsed.message.messageID))
    let dataKey = try schedule.open(edk.wrapped, aad: specAAD(headerHash: headerHash, messageID: parsed.message.messageID,
                                                              commitment: parsed.message.commitment, role: edk.role,
                                                              recipient: edk.recipient))
    let message = record[(record.startIndex + parsed.headerBytes.count + 4)..<(record.endIndex - 64)]
    return ["name": name, "e": hex(message), "dk": hex(dataKey), "padded": hex(expectedPadded),
            "message_id": hex(parsed.message.messageID), "context_value": String(decoding: parsed.message.contextValue, as: UTF8.self),
            "commitment": hex(parsed.message.commitment), "selected_key_info": hex([edk.role] + Array(edk.recipient)),
            "key_infos": parsed.message.edks.map { hex([$0.role] + Array($0.recipient)) }]
}

@Test(.enabled(if: writeReference != nil)) func awsReferenceProducer() throws {
    let path = try #require(writeReference)
    #expect(!FileManager.default.fileExists(atPath: path))
    let fixture = Fixture()
    var entries: [[String: Any]] = []
    for (index, item) in exchangeCases.enumerated() {
        let content = try item.content()
        let record = try fixture.seal(content, identity: exchangeIdentity(index)).bytes
        for holder in [fixture.recipientKeys[0], fixture.recipientKeys[2]] {
            entries.append(try referenceEntry(item.name + "_role\(holder.role.rawValue)", record: record, holder: holder,
                                              expectedPadded: Payload.pad(Payload.logical(content))))
        }
    }
    // 32 recipients, 16 parents, maximum login.
    let keys = (0..<32).map { RecipientKey(role: $0 < 31 ? .device : .recovery,
                                          privateKey: key(UInt8(100 + $0)) { try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: $0) }) }
    let authority = fixture.authority(recipients: try RecipientSet(keys.map { try Recipient(role: $0.role, publicKey: $0.publicKey) }))
    let identity = try RevisionIdentity(itemID: fixture.itemID, revisionID: fixture.revisionID,
                                        parents: (1...16).map { try RevisionBodyID(Data(repeating: UInt8($0), count: 32)) })
    let maximum = try maximumLogin()
    let largest = try RecordSealer.seal(maximum, identity: identity, authority: authority, author: fixture.author).bytes
    #expect(largest.count == 37_780)
    entries.append(try referenceEntry("maximum_record_32_recipients", record: largest, holder: keys[31],
                                      expectedPadded: Payload.pad(Payload.logical(maximum))))
    // Generic ESDK layer: one full 524,288-byte final frame (not a valid unit record).
    let dataKey = SymmetricKey(size: .bits256)
    let messageID = randomBytes(32)
    let headerHash = sha256(Data("generic full frame".utf8))
    let derived = ESDK.derive(dataKey: dataKey, messageID: messageID)
    let recipient = try Recipient(role: .device, publicKey: fixture.device1.publicKey.rawRepresentation)
    let edk = try ESDK.wrap(dataKey, for: recipient, headerHash: headerHash, messageID: messageID, commitment: derived.commitment)
    let header = ESDK.header(messageID: messageID, context: ESDK.context(headerHash: headerHash), edks: [edk], commitment: derived.commitment)
    let plaintext = (0..<524_288).map { UInt8(truncatingIfNeeded: $0 &* 31) }
    let (ciphertext, tag) = try ESDK.sealFrame(key: derived.encryption, messageID: messageID, padded: plaintext)
    let full = ESDK.body(header: header, headerTag: try ESDK.headerTag(key: derived.encryption, header: header),
                         ciphertext: ciphertext, frameTag: tag)
    entries.append(["name": "generic_full_final_frame_524288", "e": hex(full), "dk": hex(dataKey.withUnsafeBytes { Data($0) }),
                    "padded": hex(plaintext), "message_id": hex(messageID), "context_value": hex(headerHash),
                    "commitment": hex(derived.commitment), "selected_key_info": hex([1] + Array(recipient.publicKey)),
                    "key_infos": [hex([1] + Array(recipient.publicKey))]])
    let document: [String: Any] = ["schema": "av-record-aws-reference-v1", "producer": platformName, "cases": entries]
    try writePrivate(try JSONSerialization.data(withJSONObject: document, options: [.sortedKeys]), to: path)
    emitPublic("AV_RECORD_REFERENCE_WRITE platform=\(platformName) cases=\(entries.count)")
}
