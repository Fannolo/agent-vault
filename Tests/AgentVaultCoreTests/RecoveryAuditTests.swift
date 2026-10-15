import AgentVaultCore
import Dispatch
import Foundation
import Testing

private func recoveryAuditBytes(_ events: [AuditEvent]) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    return try encoder.encode(events)
}

private final class RetryingRecoverySecrets: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private let gate = DispatchSemaphore(value: 0)
    private var items: [UUID: Data] = [:]
    private var failDeletes = true
    private var stallNext = false
    private var started = 0
    private var completed = 0
    var starts: Int { lock.withLock { started } }
    var finishes: Int { lock.withLock { completed } }
    func allowDeletes(_ allow: Bool) { lock.withLock { failDeletes = !allow } }
    func stallNextDelete() { lock.withLock { stallNext = true } }
    func release() { gate.signal() }
    func save(_ value: Data, for id: UUID) throws { lock.withLock { items[id] = value } }
    func load(for id: UUID) throws -> Data {
        try lock.withLock {
            guard let value = items[id] else { throw VaultError.secretUnavailable }
            return value
        }
    }
    func delete(for id: UUID) throws {
        let stalled = lock.withLock {
            started += 1
            let value = stallNext; stallNext = false
            return value
        }
        defer { lock.withLock { completed += 1 } }
        if stalled { gate.wait() }
        try lock.withLock {
            guard !failDeletes else { throw VaultError.secretUnavailable }
            items.removeValue(forKey: id)
        }
    }
    func waitForStarts(_ count: Int) async throws { try await waitFor { self.starts >= count } }
    func waitForFinishes(_ count: Int) async throws { try await waitFor { self.finishes >= count } }
    private func waitFor(_ condition: () -> Bool) async throws {
        let deadline = ContinuousClock.now + .seconds(5)
        while !condition() {
            guard ContinuousClock.now < deadline else { throw VaultError.stateUnavailable }
            try await Task.sleep(for: .milliseconds(1))
        }
    }
}

@Test func repeatedNoOpRecoveryAcrossBrokerRestartsPreservesAdministrationHistory() async throws {
    let root = try privateDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let state = try FileStateStore(directory: root), secrets = MemorySecrets()
    let setup = Broker(state: state, secrets: secrets)
    let account = try await setup.enroll(service: .demo, credential: Data("SYNTHETIC-no-op-recovery".utf8))
    let client = try await setup.registerClient()
    _ = try await setup.grant(clientID: client.id, accountID: account.id, duration: 60, callLimit: 1)
    let before = try recoveryAuditBytes(state.snapshot().adminAudit)
    let metadataBefore = try Data(contentsOf: root.appendingPathComponent("state.json"))
    for _ in 0..<130 {
        let reopened = try FileStateStore(directory: root)
        try await Broker(state: reopened, secrets: secrets).recoverInterruptedLifecycle()
    }
    #expect(try recoveryAuditBytes(FileStateStore(directory: root).snapshot().adminAudit) == before)
    #expect(try Data(contentsOf: root.appendingPathComponent("state.json")) == metadataBefore)
}

@Test func persistentRecoveryFailuresAcrossBrokerRestartsRetainOriginalAuditAndFailureEvidence() async throws {
    let root = try privateDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let state = try FileStateStore(directory: root), secrets = RetryingRecoverySecrets()
    let setup = Broker(state: state, secrets: secrets)
    let account = try await setup.enroll(service: .demo, credential: Data("SYNTHETIC-recovery-original".utf8))
    let client = try await setup.registerClient()
    _ = try await setup.grant(clientID: client.id, accountID: account.id, duration: 60, callLimit: 1)
    let original = try state.snapshot().adminAudit
    let originalBytes = try recoveryAuditBytes(original)
    let retired = UUID()
    try secrets.save(Data("SYNTHETIC-recovery-retired".utf8), for: retired)
    // A persisted retirement journal left behind by an interrupted process.
    try state.transaction { $0.accounts[0].retiredCredentialID = retired }
    defer { secrets.release() }
    for attempt in 0..<130 {
        let reopened = try FileStateStore(directory: root)
        let broker = Broker(state: reopened, secrets: secrets, secretIOPolicy: try .init(timeout: 2))
        if attempt == 1 || attempt == 3 {
            secrets.stallNextDelete()
            let expected = secrets.starts + 1
            let recovery = Task { try await broker.recoverInterruptedLifecycle() }
            try await secrets.waitForStarts(expected)
            await #expect(throws: VaultError.secretUnavailable) { try await recovery.value }
            secrets.release()
            try await secrets.waitForFinishes(expected)
        } else {
            await #expect(throws: VaultError.secretUnavailable) { try await broker.recoverInterruptedLifecycle() }
        }
    }
    let failed = try FileStateStore(directory: root).snapshot()
    #expect(try recoveryAuditBytes(Array(failed.adminAudit.prefix(original.count))) == originalBytes)
    #expect(failed.adminAudit.count == original.count + 3)
    #expect(failed.adminAudit.filter { $0.outcome == "recovery_started" }.count == 1)
    #expect(failed.adminAudit.filter { $0.accountID == account.id && $0.outcome == "recovery_failed" }.count == 1)
    #expect(failed.adminAudit.filter { $0.accountID == account.id && $0.outcome == "recovery_uncertain" }.count == 1)
    #expect(failed.accounts[0].retiredCredentialID == retired)
    #expect(failed.audit.isEmpty)

    secrets.allowDeletes(true)
    try await Broker(state: try FileStateStore(directory: root), secrets: secrets).recoverInterruptedLifecycle()
    #expect(try state.snapshot().accounts[0].retiredCredentialID == nil)
    #expect(try state.snapshot().adminAudit.contains { $0.outcome == "retirement_recovered" })
    // Real progress ends the representative's episode. A later failed retirement
    // on the same account must leave new evidence rather than being hidden.
    secrets.allowDeletes(false)
    let later = Broker(state: try FileStateStore(directory: root), secrets: secrets)
    await #expect(throws: VaultError.secretUnavailable) {
        try await later.rotate(accountID: account.id, credential: Data("SYNTHETIC-later-rotation".utf8))
    }
    await #expect(throws: VaultError.secretUnavailable) { try await later.recoverInterruptedLifecycle() }
    let final = try FileStateStore(directory: root).snapshot()
    #expect(final.adminAudit.filter { $0.accountID == account.id && $0.outcome == "recovery_failed" }.count == 2)
    #expect(try recoveryAuditBytes(Array(final.adminAudit.prefix(original.count))) == originalBytes)
    #expect(final.adminAudit.count < VaultState.maxAdministrationAudit)
}
