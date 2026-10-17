import AgentVaultCore
import Foundation
import Testing

func privateDirectory() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("agent-vault-tests-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                            attributes: [.posixPermissions: 0o700])
    return root
}

@Test func metadataSurvivesReopenAndHasPrivatePermissions() throws {
    let root = try privateDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let id = UUID()
    try FileStateStore(directory: root).transaction { $0.clients.append(.init(id: id)) }
    let stored = try FileStateStore(directory: root).transaction { $0.clients.map(\.id) }
    #expect(stored == [id])
    let attributes = try FileManager.default.attributesOfItem(atPath: root.appendingPathComponent("state.json").path)
    #expect(attributes[.posixPermissions] as? Int == 0o600)
}

@Test func corruptStateFailsClosedAndIsPreserved() throws {
    let root = try privateDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("state.json")
    let bytes = Data("broken JSON".utf8)
    try bytes.write(to: path)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
    #expect(throws: VaultError.stateUnavailable) { try FileStateStore(directory: root).transaction { $0.accounts } }
    #expect(try Data(contentsOf: path) == bytes)
}

@Test func existingPermissiveFileIsRefused() throws {
    let root = try privateDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("state.json")
    try JSONEncoder().encode(VaultState()).write(to: path)
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path.path)
    #expect(throws: VaultError.stateUnavailable) { try FileStateStore(directory: root).transaction { $0.accounts } }
}

@Test func stateAndDirectorySymlinksAreRefused() throws {
    let root = try privateDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("state.json")
    try FileManager.default.createSymbolicLink(at: path, withDestinationURL: root.appendingPathComponent("elsewhere"))
    #expect(throws: VaultError.stateUnavailable) { try FileStateStore(directory: root).transaction { $0.accounts } }
    let link = root.appendingPathComponent("linked-root")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: root)
    #expect(throws: VaultError.stateUnavailable) { try FileStateStore(directory: link) }
}

@Test func separateStoreInstancesSerializeUpdates() async throws {
    let root = try privateDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let first = try FileStateStore(directory: root), second = try FileStateStore(directory: root)
    try await withThrowingTaskGroup(of: Void.self) { group in
        for i in 0..<30 {
            group.addTask {
                try (i.isMultiple(of: 2) ? first : second).transaction { $0.clients.append(.init()) }
            }
        }
        try await group.waitForAll()
    }
    #expect(try first.transaction { $0.clients.count } == 30)
}

@Test(.enabled(if: ProcessInfo.processInfo.environment["AGENT_VAULT_KEYCHAIN_TEST"] == "1",
               "Set AGENT_VAULT_KEYCHAIN_TEST=1 to run the isolated native Keychain fixture"))
func nativeKeychainRoundTripWhenExplicitlyEnabled() throws {
    let store = KeychainStore(namespace: "io.agent-vault.test.\(UUID())")
    let id = UUID(), value = Data("SYNTHETIC-only-keychain-fixture".utf8)
    defer { try? store.delete(for: id) }
    try store.save(value, for: id)
    #expect(try store.load(for: id) == value)
    #expect(throws: VaultError.secretUnavailable) { try store.save(value, for: id) }
    try store.delete(for: id)
    #expect(throws: VaultError.secretUnavailable) { try store.load(for: id) }
}

@Test func snapshotsDoNotRewriteMetadata() throws {
    let root = try privateDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try FileStateStore(directory: root)
    try store.transaction { $0.clients.append(.init()) }
    let path = root.appendingPathComponent("state.json").path
    let before = try FileManager.default.attributesOfItem(atPath: path)
    _ = try store.snapshot()
    let after = try FileManager.default.attributesOfItem(atPath: path)
    #expect(before[.systemFileNumber] as? NSNumber == after[.systemFileNumber] as? NSNumber)
    #expect(before[.modificationDate] as? Date == after[.modificationDate] as? Date)
}

@Test func capacityLimitsLeaveRoomForRevocation() async throws {
    let root = try privateDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try FileStateStore(directory: root)
    let client = UUID(), account = UUID()
    let time = Date()
    try store.transaction { state in
        state.clients = [.init(id: client)] + (1..<VaultState.maxClients).map { _ in .init() }
        state.accounts = [.init(id: account, service: .demo)] + (1..<VaultState.maxAccounts).map { _ in .init(service: .demo) }
        state.grants = (0..<VaultState.maxGrants).map { _ in
            Grant(clientID: client, accountID: account, action: .demoStatus,
                  expiresAt: time.addingTimeInterval(3600), callLimit: 20)
        }
        for _ in 0..<1000 {
            state.record(client: client, account: account, action: .demoStatus,
                         outcome: "response_suppressed", at: time)
        }
    }
    let broker = Broker(state: store, secrets: MemorySecrets())
    await #expect(throws: VaultError.stateUnavailable) {
        _ = try await broker.grant(clientID: client, accountID: account, duration: 30, callLimit: 1)
    }
    try await broker.revokeClient(client)
    #expect(try store.snapshot().grants.allSatisfy(\.revoked))
    #expect(try Data(contentsOf: root.appendingPathComponent("state.json")).count < 1_048_576)
}

@Test func authenticatedMetadataRejectsTamperingWrongKeyAndUnsignedFallback() throws {
    let root = try privateDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let key = Data(repeating: 0x42, count: 32)
    let store = try FileStateStore(directory: root, integrityKey: key)
    let client = UUID()
    try store.transaction { $0.clients.append(.init(id: client)) }
    #expect(try FileStateStore(directory: root, integrityKey: key).snapshot().clients.map(\.id) == [client])
    #expect(throws: VaultError.stateUnavailable) {
        _ = try FileStateStore(directory: root, integrityKey: Data(repeating: 0x43, count: 32)).snapshot()
    }
    let path = root.appendingPathComponent("state.json")
    var envelope = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: path)) as? [String: Any])
    envelope["payload"] = try JSONEncoder().encode(VaultState()).base64EncodedString()
    try JSONSerialization.data(withJSONObject: envelope).write(to: path)
    #expect(throws: VaultError.stateUnavailable) { _ = try store.snapshot() }
    // A valid plain state must not become a downgrade path in integrity mode.
    try JSONEncoder().encode(VaultState()).write(to: path)
    #expect(throws: VaultError.stateUnavailable) { _ = try store.snapshot() }
}

@Test(.enabled(if: ProcessInfo.processInfo.environment["AGENT_VAULT_KEYCHAIN_TEST"] == "1",
               "Set AGENT_VAULT_KEYCHAIN_TEST=1 to run the isolated private Keychain fixture"))
func privateKeychainRoundTripUsesOnlyExplicitDatabaseWhenEnabled() throws {
    let root = try privateDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let password = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })
    let path = root.appendingPathComponent("broker.keychain-db")
    let store = try PrivateKeychainStore(path: path, password: password)
    let id = UUID(), value = Data("SYNTHETIC-private-keychain".utf8)
    defer { try? store.delete(for: id) }
    try store.save(value, for: id)
    #expect(try store.load(for: id) == value)
    try store.lockForSyntheticTest()
    #expect(try store.load(for: id) == value)
    let reopened = try PrivateKeychainStore(path: path, password: password)
    #expect(try reopened.load(for: id) == value)
    try reopened.delete(for: id)
    #expect(throws: VaultError.secretUnavailable) { _ = try store.load(for: id) }
}
