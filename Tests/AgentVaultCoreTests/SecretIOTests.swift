@testable import AgentVaultCore
import Dispatch
import Foundation
import Testing

private final class StallingSecrets: SecretStore, @unchecked Sendable {
    enum Kind: Hashable, Sendable { case save, load, delete }
    private let lock = NSLock()
    private let gate = DispatchSemaphore(value: 0)
    private var items: [UUID: Data] = [:]
    private var stalls: [Kind: Int] = [:]
    private var started = 0
    private var completed = 0
    func stall(_ kind: Kind, count: Int = 1) { lock.withLock { stalls[kind] = count } }
    var starts: Int { lock.withLock { started } }
    var finishes: Int { lock.withLock { completed } }
    var ids: Set<UUID> { lock.withLock { Set(items.keys) } }
    func release(_ count: Int = 1) { for _ in 0..<count { gate.signal() } }
    private func wait(_ kind: Kind) -> Bool {
        let blocked = lock.withLock {
            guard stalls[kind, default: 0] > 0 else { return false }
            stalls[kind, default: 0] -= 1; started += 1
            return true
        }
        if blocked { gate.wait() }
        return blocked
    }
    private func finished(_ blocked: Bool) { if blocked { lock.withLock { completed += 1 } } }
    func save(_ value: Data, for id: UUID) throws {
        let blocked = wait(.save)
        defer { finished(blocked) }
        lock.withLock { items[id] = value }
    }
    func load(for id: UUID) throws -> Data {
        let value = try lock.withLock {
            guard let value = items[id] else { throw VaultError.secretUnavailable }
            return value
        }
        let blocked = wait(.load)
        defer { finished(blocked) }
        return value
    }
    func delete(for id: UUID) throws {
        let blocked = wait(.delete)
        defer { finished(blocked) }
        _ = lock.withLock { items.removeValue(forKey: id) }
    }
    func waitForStarts(_ count: Int) async throws { try await waitFor { self.starts >= count } }
    func waitForFinishes(_ count: Int) async throws { try await waitFor { self.finishes >= count } }
    private func waitFor(_ predicate: () -> Bool) async throws {
        let end = ContinuousClock.now + .seconds(2)
        while !predicate() {
            guard ContinuousClock.now < end else { throw VaultError.stateUnavailable }
            try await Task.sleep(for: .milliseconds(1))
        }
    }
}

private struct IOFixture {
    let state: MemoryState
    let store: StallingSecrets
    let broker: Broker
    let account: Account
    let client: ClientRecord
    let grant: Grant
    let adapter: CountingAdapter
    static func make(timeout: TimeInterval = 1) async throws -> Self {
        let state = MemoryState(), store = StallingSecrets(), adapter = CountingAdapter()
        let broker = Broker(state: state, secrets: store, adapter: adapter, secretIOPolicy: try .init(timeout: timeout))
        let account = try await broker.enroll(service: .demo, credential: Data("SYNTHETIC-original".utf8))
        let client = try await broker.registerClient()
        let grant = try await broker.grant(clientID: client.id, accountID: account.id, duration: 3600, callLimit: 100)
        return .init(state: state, store: store, broker: broker, account: account, client: client, grant: grant, adapter: adapter)
    }
}

private func recoverWhenReady(_ broker: Broker) async throws {
    let end = ContinuousClock.now + .seconds(2)
    while true {
        do { try await broker.recoverInterruptedLifecycle(); return }
        catch VaultError.busy {
            guard ContinuousClock.now < end else { throw VaultError.stateUnavailable }
            try await Task.sleep(for: .milliseconds(1))
        }
    }
}

@Test func blockedSecretReadCannotBlockRevocationOrMetadataSnapshots() async throws {
    let f = try await IOFixture.make(timeout: 2)
    f.store.stall(.load)
    defer { f.store.release(4) }
    DispatchQueue.global().asyncAfter(deadline: .now() + 1) { f.store.release() }
    let run = Task { try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus) }
    try await f.store.waitForStarts(1)
    let start = ContinuousClock.now
    try await f.broker.revokeGrant(f.grant.id)
    #expect(try await f.broker.snapshot().grants.first { $0.id == f.grant.id }?.revoked == true)
    #expect(ContinuousClock.now - start < .milliseconds(250))
    #expect(f.store.finishes == 0)
    f.store.release()
    await #expect(throws: VaultError.denied) { _ = try await run.value }
    #expect(await f.adapter.calls == 0)
}

@Test func timeoutDoesNotFreeCapacityOrQueueMoreSynchronousWork() async throws {
    let f = try await IOFixture.make(timeout: 0.5)
    f.store.stall(.load, count: SecretIOExecutor.capacity)
    defer { f.store.release(4) }
    let runs = (0..<SecretIOExecutor.capacity).map { _ in
        Task { try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus) }
    }
    try await f.store.waitForStarts(4)
    for run in runs { await #expect(throws: VaultError.secretUnavailable) { _ = try await run.value } }
    for _ in 0..<20 {
        await #expect(throws: VaultError.busy) {
            _ = try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)
        }
    }
    #expect(f.store.starts == 4)
    #expect(f.store.finishes == 0)
    #expect(await f.adapter.calls == 0)
    await #expect(throws: VaultError.busy) { try await f.broker.recoverInterruptedLifecycle() }
    f.store.release(4)
    try await f.store.waitForFinishes(4)
    try await recoverWhenReady(f.broker)
    #expect(try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus) == .demoReady)
}

@Test func lateEnrollmentWriteStaysTrackedUntilSafeRecovery() async throws {
    let state = MemoryState(), store = StallingSecrets()
    let broker = Broker(state: state, secrets: store, secretIOPolicy: try .init(timeout: 0.5))
    store.stall(.save)
    defer { store.release(4) }
    let enrollment = Task { try await broker.enroll(service: .demo, credential: Data("SYNTHETIC-late".utf8)) }
    try await store.waitForStarts(1)
    await #expect(throws: VaultError.secretUnavailable) { _ = try await enrollment.value }
    let account = try #require(state.snapshot().accounts.first)
    #expect(account.lifecycle == .enrolling)
    #expect(store.ids.isEmpty)
    #expect(try state.snapshot().adminAudit.contains { $0.outcome == "enrollment_uncertain" })
    #expect(try !state.snapshot().adminAudit.contains { $0.outcome == "enrollment_aborted" })
    await #expect(throws: VaultError.busy) { try await broker.deleteAccount(account.id) }
    await #expect(throws: VaultError.busy) { try await broker.recoverInterruptedLifecycle() }
    store.release()
    try await store.waitForFinishes(1)
    #expect(store.ids == [account.credentialID])
    try await recoverWhenReady(broker)
    #expect(store.ids.isEmpty)
    #expect(try state.snapshot().accounts.isEmpty)
}

@Test func lateRotationWriteCannotRaceRollbackDeletionOrRecovery() async throws {
    let f = try await IOFixture.make(timeout: 0.5)
    f.store.stall(.save)
    defer { f.store.release(4) }
    await #expect(throws: VaultError.secretUnavailable) {
        try await f.broker.rotate(accountID: f.account.id, credential: Data("SYNTHETIC-late-stage".utf8))
    }
    let journal = try f.state.snapshot().accounts[0]
    #expect(journal.lifecycle == .rotating)
    #expect(journal.stagedCredentialID != nil)
    #expect(f.store.ids == [f.account.credentialID])
    await #expect(throws: VaultError.busy) { try await f.broker.deleteAccount(f.account.id) }
    await #expect(throws: VaultError.busy) { try await f.broker.recoverInterruptedLifecycle() }
    f.store.release()
    try await f.store.waitForFinishes(1)
    #expect(f.store.ids.count == 2)
    try await recoverWhenReady(f.broker)
    #expect(f.store.ids == [f.account.credentialID])
    #expect(try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus) == .demoReady)
}

@Test func lateDeletionKeepsItsJournalAndSnapshotAvailable() async throws {
    let f = try await IOFixture.make(timeout: 0.5)
    f.store.stall(.delete)
    defer { f.store.release(4) }
    await #expect(throws: VaultError.secretUnavailable) { try await f.broker.deleteAccount(f.account.id) }
    #expect(try await f.broker.snapshot().accounts[0].lifecycle == .deleting)
    #expect(try f.state.snapshot().grants[0].revoked)
    await #expect(throws: VaultError.busy) { try await f.broker.recoverInterruptedLifecycle() }
    f.store.release()
    try await f.store.waitForFinishes(1)
    try await recoverWhenReady(f.broker)
    #expect(try f.state.snapshot().accounts.isEmpty)
    #expect(f.store.ids.isEmpty)
}

@Test func rotationWhileReadWaitsPreventsDispatchWithTheOldCredential() async throws {
    let f = try await IOFixture.make(timeout: 2)
    f.store.stall(.load)
    defer { f.store.release(4) }
    let run = Task { try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus) }
    try await f.store.waitForStarts(1)
    try await f.broker.rotate(accountID: f.account.id, credential: Data("SYNTHETIC-replacement".utf8))
    f.store.release()
    await #expect(throws: VaultError.denied) { _ = try await run.value }
    #expect(await f.adapter.calls == 0)
    #expect(try f.state.snapshot().accounts[0].credentialID != f.account.credentialID)
}

@Test(arguments: [StallingSecrets.Kind.save, .delete])
private func blockedLifecycleIOCannotBlockClientRevocationOrSnapshot(_ kind: StallingSecrets.Kind) async throws {
    let f = try await IOFixture.make(timeout: 2)
    f.store.stall(kind)
    defer { f.store.release(4) }
    DispatchQueue.global().asyncAfter(deadline: .now() + 1) { f.store.release() }
    let operation = Task {
        if kind == .save { try await f.broker.rotate(accountID: f.account.id, credential: Data("SYNTHETIC-new".utf8)) }
        else { try await f.broker.deleteAccount(f.account.id) }
    }
    try await f.store.waitForStarts(1)
    let start = ContinuousClock.now
    try await f.broker.revokeClient(f.client.id)
    #expect(try await f.broker.snapshot().clients.first { $0.id == f.client.id }?.revoked == true)
    #expect(ContinuousClock.now - start < .milliseconds(250))
    #expect(f.store.finishes == 0)
    f.store.release()
    try await operation.value
}

@Test func lateRetirementCannotLoseItsJournalOrAllowASecondRotation() async throws {
    let f = try await IOFixture.make(timeout: 0.5)
    f.store.stall(.delete)
    defer { f.store.release(4) }
    await #expect(throws: VaultError.secretUnavailable) {
        try await f.broker.rotate(accountID: f.account.id, credential: Data("SYNTHETIC-new".utf8))
    }
    let journal = try f.state.snapshot().accounts[0]
    #expect(journal.lifecycle == .active)
    #expect(journal.retiredCredentialID == f.account.credentialID)
    #expect(journal.credentialID != f.account.credentialID)
    await #expect(throws: VaultError.busy) {
        try await f.broker.rotate(accountID: f.account.id, credential: Data("SYNTHETIC-another".utf8))
    }
    await #expect(throws: VaultError.busy) { try await f.broker.recoverInterruptedLifecycle() }
    f.store.release()
    try await f.store.waitForFinishes(1)
    try await recoverWhenReady(f.broker)
    #expect(try f.state.snapshot().accounts[0].retiredCredentialID == nil)
    #expect(f.store.ids == [journal.credentialID])
}
