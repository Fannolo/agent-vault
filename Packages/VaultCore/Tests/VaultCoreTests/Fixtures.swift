import Crypto
import Foundation
import Testing
@testable import VaultCore

// Publicly known synthetic test material; never suitable for real credentials.
let fixtureCanary = "AV_UNIT1_SYNTHETIC_CANARY_7F92C6D0"

struct Fixture: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    var description: String { "Fixture(<redacted>)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: [:]) }
    let author: Curve25519.Signing.PrivateKey
    let devices: [Curve25519.KeyAgreement.PrivateKey]
    let recovery: Curve25519.KeyAgreement.PrivateKey
    let unrelated: Curve25519.KeyAgreement.PrivateKey
    let context: RevisionContext

    init() throws {
        author = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x11, count: 32))
        devices = try [0x21, 0x31].map {
            try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: UInt8($0), count: 32))
        }
        recovery = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 0x41, count: 32))
        unrelated = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 0x51, count: 32))
        context = try RevisionContext(vaultID: Data(repeating: 1, count: 16), itemID: Data(repeating: 2, count: 16),
                                      revisionID: Data(repeating: 3, count: 16), membershipHead: Data(repeating: 4, count: 32))
    }

    var recipients: [RevisionRecipient] {
        get throws {
            try devices.map { try RevisionRecipient(role: .device, publicKey: $0.publicKey) } +
            [RevisionRecipient(role: .recovery, publicKey: recovery.publicKey)]
        }
    }
    var item: LoginItem {
        LoginItem(username: "synthetic-user", password: Data(fixtureCanary.utf8),
                  origins: ["https://example.invalid", "https://login.example.invalid"])
    }
    func seal(context: RevisionContext? = nil, parents: [Data] = []) throws -> Data {
        try sealRevision(context: context ?? self.context, parents: parents, author: author, recipients: recipients, item: item)
    }
    func open(_ bytes: Data, expected: RevisionContext? = nil, role: RecipientRole = .device,
              recipient: Curve25519.KeyAgreement.PrivateKey? = nil) throws -> LoginItem {
        try openRevision(bytes, expected: expected ?? context, author: author.publicKey,
                         role: role, recipient: recipient ?? devices[0])
    }
    func matches(_ item: LoginItem) -> Bool {
        item.username == self.item.username && item.password == self.item.password && item.origins == self.item.origins
    }
    func resign(_ record: SealedRecord) throws -> Data {
        var record = record
        record.signature = try author.signature(for: record.signedMessage)
        return record.encoded
    }
    func changedContext(vault: UInt8 = 1, item: UInt8 = 2, revision: UInt8 = 3, head: UInt8 = 4) throws -> RevisionContext {
        try RevisionContext(vaultID: Data(repeating: vault, count: 16), itemID: Data(repeating: item, count: 16),
                            revisionID: Data(repeating: revision, count: 16), membershipHead: Data(repeating: head, count: 32))
    }
}

func expectError(_ expected: VaultError, _ operation: () throws -> Void,
                 sourceLocation: SourceLocation = #_sourceLocation) {
    do {
        try operation()
        Issue.record("Expected fixed codec error", sourceLocation: sourceLocation)
    } catch let actual as VaultError {
        #expect(actual == expected, sourceLocation: sourceLocation)
    } catch {
        Issue.record("Unexpected error type; details suppressed", sourceLocation: sourceLocation)
    }
}

/// Cross-platform runner entry point. Environment variables contain filesystem paths only.
@Test func fixtureExchange() throws {
    let fixture = try Fixture()
    let environment = ProcessInfo.processInfo.environment
    let fresh = try fixture.seal()
    let bytes: Data
    if let path = environment["AV_TEST_READ_FIXTURE"] {
        bytes = try Data(contentsOf: URL(fileURLWithPath: path))
    } else {
        bytes = fresh
    }
    var log = try RevisionLog(vaultID: fixture.context.vaultID, trustedAuthors: [fixture.author.publicKey])
    #expect(log.accept(bytes) == .inserted)
    #expect(log.accept(bytes) == .duplicate)
    for device in fixture.devices { #expect(fixture.matches(try fixture.open(bytes, recipient: device))) }
    #expect(fixture.matches(try fixture.open(bytes, role: .recovery, recipient: fixture.recovery)))
    expectError(.badAuthentication) { _ = try fixture.open(bytes, recipient: fixture.unrelated) }
    if let path = environment["AV_TEST_WRITE_FIXTURE"] {
        #expect(fresh.range(of: Data(fixtureCanary.utf8)) == nil)
        try fresh.write(to: URL(fileURLWithPath: path), options: .atomic)
    }
}
