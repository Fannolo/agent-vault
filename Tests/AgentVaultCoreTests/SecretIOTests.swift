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
        let end = ContinuousClock.now + .seconds(5)
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
    static func make(timeout: TimeInterval = 1, webSessions: (any WebSessionExecutor)? = nil) async throws -> Self {
        let state = MemoryState(), store = StallingSecrets(), adapter = CountingAdapter()
        // Build the synchronous fake's known state before attaching the short I/O
        // deadline. Setup must not time out before the operation under test starts.
        let account = Account(service: .demo), client = ClientRecord()
        let grant = Grant(clientID: client.id, accountID: account.id, action: .demoStatus,
                          expiresAt: Date().addingTimeInterval(3600), callLimit: 100)
        try store.save(Data("SYNTHETIC-original".utf8), for: account.credentialID)
        try state.transaction { $0.accounts = [account]; $0.clients = [client]; $0.grants = [grant] }
        let broker = Broker(state: state, secrets: store, adapter: adapter, webSessions: webSessions,
                            secretIOPolicy: try .init(timeout: timeout))
        return .init(state: state, store: store, broker: broker, account: account, client: client, grant: grant, adapter: adapter)
    }
}

private final class PermitCommitFailingState: StateStore, @unchecked Sendable {
    private let store = MemoryState()
    private let lock = NSLock()
    private var failuresRemaining = 0
    func failPermitCommits(_ count: Int) { lock.withLock { failuresRemaining = count } }
    func transaction<T>(_ body: (inout VaultState) throws -> T) throws -> T {
        try store.transaction { state in
            let before = state.grants.map(\.callsUsed).reduce(0, +)
            let result = try body(&state)
            let after = state.grants.map(\.callsUsed).reduce(0, +)
            let fail = lock.withLock {
                guard after > before, failuresRemaining > 0 else { return false }
                failuresRemaining -= 1
                return true
            }
            if fail { throw VaultError.stateUnavailable }
            return result
        }
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
    let f = try await IOFixture.make(timeout: 2)
    f.store.stall(.load, count: SecretIOExecutor.readCapacity)
    defer { f.store.release(4) }
    let runs = (0..<SecretIOExecutor.readCapacity).map { _ in
        Task { try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus) }
    }
    try await f.store.waitForStarts(SecretIOExecutor.readCapacity)
    for run in runs { await #expect(throws: VaultError.secretUnavailable) { _ = try await run.value } }
    for _ in 0..<20 {
        await #expect(throws: VaultError.busy) {
            _ = try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)
        }
    }
    #expect(f.store.starts == SecretIOExecutor.readCapacity)
    #expect(f.store.finishes == 0)
    #expect(await f.adapter.calls == 0)
    #expect(try f.state.snapshot().grants.first { $0.id == f.grant.id }?.callsUsed == SecretIOExecutor.readCapacity)
    await #expect(throws: VaultError.busy) { try await f.broker.recoverInterruptedLifecycle() }
    f.store.release(SecretIOExecutor.readCapacity)
    try await f.store.waitForFinishes(SecretIOExecutor.readCapacity)
    try await recoverWhenReady(f.broker)
    #expect(try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus) == .demoReady)
}

@Test func busyReadAdmissionPreservesTheApprovedRequestAndItsBudget() async throws {
    let f = try await IOFixture.make(timeout: 2)
    let approvedClient = try await f.broker.registerClient()
    let approvedGrant = try await f.broker.grant(clientID: approvedClient.id, accountID: f.account.id,
        duration: 300, callLimit: 1, requiresApproval: true)
    guard case .approvalRequired(let request) = try await f.broker.run(clientID: approvedClient.id,
        accountID: f.account.id, action: .demoStatus)
    else { Issue.record("Missing approval request"); return }
    try await f.broker.approveInvocation(request)
    let before = try f.state.snapshot().audit.count
    f.store.stall(.load, count: SecretIOExecutor.readCapacity)
    defer { f.store.release(SecretIOExecutor.capacity) }
    let runs = (0..<SecretIOExecutor.readCapacity).map { _ in
        Task { try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus) }
    }
    try await f.store.waitForStarts(SecretIOExecutor.readCapacity)
    for run in runs { await #expect(throws: VaultError.secretUnavailable) { _ = try await run.value } }
    for _ in 0..<20 {
        await #expect(throws: VaultError.busy) { _ = try await f.broker.resume(request.uuid, clientID: approvedClient.id) }
    }
    let blocked = try f.state.snapshot()
    #expect(blocked.grants.first { $0.id == approvedGrant.id }?.callsUsed == 0)
    #expect(blocked.pending.first { $0.id == request }?.status == .approved)
    #expect(blocked.audit.count == before + SecretIOExecutor.readCapacity * 2)
    #expect(await f.adapter.calls == 0)
    f.store.release(SecretIOExecutor.readCapacity)
    try await f.store.waitForFinishes(SecretIOExecutor.readCapacity)
    try await recoverWhenReady(f.broker)
    #expect(try await f.broker.resume(request.uuid, clientID: approvedClient.id) == .demoReady)
    #expect(try f.state.snapshot().grants.first { $0.id == approvedGrant.id }?.callsUsed == 1)
    #expect(try f.state.snapshot().pending.first { $0.id == request }?.status == .consumed)
    await #expect(throws: VaultError.denied) { _ = try await f.broker.resume(request.uuid, clientID: approvedClient.id) }
    #expect(await f.adapter.calls == 1)
}

@Test func stalledReadsLeaveAdministrationCredentialCapacityAvailable() async throws {
    let f = try await IOFixture.make(timeout: 2)
    f.store.stall(.load, count: SecretIOExecutor.readCapacity)
    defer { f.store.release(SecretIOExecutor.capacity) }
    let runs = (0..<SecretIOExecutor.readCapacity).map { _ in
        Task { try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus) }
    }
    try await f.store.waitForStarts(SecretIOExecutor.readCapacity)
    for run in runs { await #expect(throws: VaultError.secretUnavailable) { _ = try await run.value } }
    let replacement = try await f.broker.enroll(service: .demo, credential: Data("SYNTHETIC-new-account".utf8))
    try await f.broker.rotate(accountID: f.account.id, credential: Data("SYNTHETIC-replacement".utf8))
    try await f.broker.deleteAccount(replacement.id)
    #expect(f.store.finishes == 0)
    #expect(f.store.ids.count == 1)
    #expect(f.store.ids != [f.account.credentialID])
    #expect(try f.state.snapshot().accounts.map(\.lifecycle) == [.active])
    f.store.release(SecretIOExecutor.readCapacity)
    try await f.store.waitForFinishes(SecretIOExecutor.readCapacity)
    try await recoverWhenReady(f.broker)
    #expect(await f.adapter.calls == 0)
}

@Test func busyCredentialAdmissionPreservesAWebApprovalForRetry() async throws {
    let host = ScriptedWebHost(start: [.humanStep(.mfa)])
    let f = try await IOFixture.make(timeout: 2, webSessions: host)
    let account = try await f.broker.enroll(service: .githubWeb, credential: syntheticWebCredential)
    let grant = try await f.broker.grant(clientID: f.client.id, accountID: account.id,
                                       duration: 300, callLimit: 1, requiresApproval: true)
    guard case .approvalRequired(let request) = try await f.broker.run(clientID: f.client.id,
        accountID: account.id, action: .githubWebProfile) else { Issue.record("No approval"); return }
    try await f.broker.approveInvocation(request)
    f.store.stall(.load, count: SecretIOExecutor.readCapacity)
    defer { f.store.release(SecretIOExecutor.capacity) }
    let reads = (0..<SecretIOExecutor.readCapacity).map { _ in
        Task { try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus) }
    }
    try await f.store.waitForStarts(SecretIOExecutor.readCapacity)
    for _ in 0..<20 {
        await #expect(throws: VaultError.busy) { _ = try await f.broker.resume(request.uuid, clientID: f.client.id) }
    }
    let blocked = try f.state.snapshot()
    #expect(blocked.grants.first { $0.id == grant.id }?.callsUsed == 0)
    #expect(blocked.pending.first { $0.id == request }?.status == .approved)
    #expect(host.startCount == 0)
    #expect(!blocked.audit.contains { $0.accountID == account.id && $0.outcome == "reserved" })
    f.store.release(SecretIOExecutor.readCapacity)
    for read in reads { #expect(try await read.value == .demoReady) }
    guard case .humanStepRequired(let run) = try await f.broker.resume(request.uuid, clientID: f.client.id)
    else { Issue.record("No browser run"); return }
    #expect(try f.state.snapshot().grants.first { $0.id == grant.id }?.callsUsed == 1)
    #expect(try f.state.snapshot().pending.first { $0.id == request }?.status == .consumed)
    #expect(host.startCount == 1)
    try await f.broker.cancel(run.uuid, clientID: f.client.id)
}

@Test(arguments: [true, false])
func refusedHostAdmissionDoesNotLeakCredentialReadCapacity(hostAvailable: Bool) async throws {
    let host = ScriptedWebHost(start: [.humanStep(.mfa)])
    let f = try await IOFixture.make(timeout: 2, webSessions: hostAvailable ? host : nil)
    let account = try await f.broker.enroll(service: .githubWeb, credential: syntheticWebCredential)
    let grant = try await f.broker.grant(clientID: f.client.id, accountID: account.id, duration: 300, callLimit: 1)
    let active: BrowserRunID?
    if hostAvailable {
        guard case .humanStepRequired(let run) = try await f.broker.run(clientID: f.client.id,
            accountID: account.id, action: .githubWebProfile) else { Issue.record("No browser run"); return }
        active = run
    } else { active = nil }
    let other = try await f.broker.registerClient()
    let gated = try await f.broker.grant(clientID: other.id, accountID: account.id,
                                       duration: 300, callLimit: 1, requiresApproval: true)
    let approval: ApprovalID?
    if hostAvailable {
        guard case .approvalRequired(let request) = try await f.broker.run(clientID: other.id,
            accountID: account.id, action: .githubWebProfile) else { Issue.record("No approval"); return }
        try await f.broker.approveInvocation(request)
        approval = request
    } else { approval = nil }
    for _ in 0..<20 {
        await #expect(throws: hostAvailable ? VaultError.busy : .upstreamUnavailable) {
            if let approval { _ = try await f.broker.resume(approval.uuid, clientID: other.id) }
            else { _ = try await f.broker.run(clientID: other.id, accountID: account.id, action: .githubWebProfile) }
        }
    }
    let state = try f.state.snapshot()
    #expect(state.grants.first { $0.id == gated.id }?.callsUsed == 0)
    #expect(state.grants.first { $0.id == grant.id }?.callsUsed == (hostAvailable ? 1 : 0))
    if let approval { #expect(state.pending.first { $0.id == approval }?.status == .approved) }
    else { #expect(state.pending.isEmpty) }
    f.store.stall(.load, count: SecretIOExecutor.readCapacity)
    defer { f.store.release(SecretIOExecutor.capacity) }
    let reads = (0..<SecretIOExecutor.readCapacity).map { _ in
        Task { try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus) }
    }
    try await f.store.waitForStarts(SecretIOExecutor.readCapacity)
    f.store.release(SecretIOExecutor.readCapacity)
    for read in reads { #expect(try await read.value == .demoReady) }
    if let active { try await f.broker.cancel(active.uuid, clientID: f.client.id) }
}

@Test func rotationIntentEndsAWebRunBeforeAnUncertainCredentialWrite() async throws {
    let host = ScriptedWebHost(start: [.humanStep(.mfa)])
    let f = try await IOFixture.make(timeout: 2, webSessions: host)
    let account = try await f.broker.enroll(service: .githubWeb, credential: syntheticWebCredential)
    _ = try await f.broker.grant(clientID: f.client.id, accountID: account.id, duration: 300, callLimit: 1)
    guard case .humanStepRequired(let run) = try await f.broker.run(clientID: f.client.id,
        accountID: account.id, action: .githubWebProfile) else { Issue.record("No browser run"); return }
    f.store.stall(.save)
    defer { f.store.release(SecretIOExecutor.capacity) }
    let rotation = Task { try await f.broker.rotate(accountID: account.id,
        credential: Data("synthetic-user\nSYNTHETIC-next".utf8)) }
    try await f.store.waitForStarts(1)
    #expect(!host.contextOpen(run))
    #expect(host.endCount(run) == 1)
    await #expect(throws: VaultError.secretUnavailable) { try await rotation.value }
    #expect(try f.state.snapshot().accounts.first { $0.id == account.id }?.lifecycle == .rotating)
    #expect(!host.contextOpen(run))
    #expect(await f.broker.scheduledDeadlineCount == 0)
    f.store.release()
    try await f.store.waitForFinishes(1)
    try await recoverWhenReady(f.broker)
}

@Test func readReservationsAreSingleUseAndUnusedReservationsReleaseCapacity() async throws {
    let store = StallingSecrets()
    let executor = SecretIOExecutor(store: store, policy: .standard)
    let account = UUID(), credential = UUID()
    try store.save(Data("SYNTHETIC-reservation".utf8), for: credential)
    do {
        let reservations = try (0..<SecretIOExecutor.readCapacity).map { _ in try executor.reserveRead(account: account) }
        #expect(throws: VaultError.busy) { try executor.reserveRead(account: account) }
        #expect(!executor.isIdle)
        withExtendedLifetime(reservations) {}
    }
    #expect(executor.isIdle)
    let reservation = try executor.reserveRead(account: account)
    #expect(try await reservation.load(id: credential) == Data("SYNTHETIC-reservation".utf8))
    await #expect(throws: SecretIOFailure.self) { _ = try await reservation.load(id: credential) }
    #expect(executor.isIdle)
}

@Test func administrationReserveDoesNotIncreaseTheFourActualOperationLimit() async throws {
    let store = StallingSecrets()
    let executor = SecretIOExecutor(store: store, policy: try .init(timeout: 2))
    let account = UUID(), credential = UUID()
    try store.save(Data("SYNTHETIC-four-slots".utf8), for: credential)
    store.stall(.load, count: SecretIOExecutor.readCapacity)
    store.stall(.save)
    defer { store.release(SecretIOExecutor.capacity) }
    let reservations = try (0..<SecretIOExecutor.readCapacity).map { _ in try executor.reserveRead(account: account) }
    let reads = reservations.map { reservation in Task { try await reservation.load(id: credential) } }
    try await store.waitForStarts(SecretIOExecutor.readCapacity)
    let write = Task { try await executor.save(Data("SYNTHETIC-write".utf8), id: UUID(), account: account) }
    try await store.waitForStarts(SecretIOExecutor.capacity)
    do {
        try await executor.save(Data("SYNTHETIC-refused".utf8), id: UUID(), account: account)
        Issue.record("A fifth actual operation was admitted")
    } catch SecretIOFailure.notStarted {}
    #expect(throws: VaultError.busy) { try executor.reserveRead(account: account) }
    for read in reads { await #expect(throws: SecretIOFailure.self) { _ = try await read.value } }
    await #expect(throws: SecretIOFailure.self) { try await write.value }
    #expect(store.starts == SecretIOExecutor.capacity)
    #expect(store.finishes == 0)
    #expect(executor.hasPendingWrite(account: account))
    #expect(!executor.isIdle)
    store.release(SecretIOExecutor.capacity)
    try await store.waitForFinishes(SecretIOExecutor.capacity)
}

@Test func failedPermitCommitReleasesItsReadReservationWithoutSpendingBudget() async throws {
    let state = PermitCommitFailingState(), secrets = StallingSecrets(), adapter = CountingAdapter()
    let broker = Broker(state: state, secrets: secrets, adapter: adapter, secretIOPolicy: try .init(timeout: 2))
    let account = try await broker.enroll(service: .demo, credential: Data("SYNTHETIC-commit-failure".utf8))
    var approved: [(client: UUID, request: ApprovalID)] = []
    for _ in 0..<SecretIOExecutor.readCapacity {
        let client = try await broker.registerClient()
        _ = try await broker.grant(clientID: client.id, accountID: account.id, duration: 300,
                                   callLimit: 1, requiresApproval: true)
        guard case .approvalRequired(let request) = try await broker.run(clientID: client.id,
            accountID: account.id, action: .demoStatus)
        else { Issue.record("Missing approval request"); return }
        try await broker.approveInvocation(request)
        approved.append((client.id, request))
    }
    state.failPermitCommits(SecretIOExecutor.capacity)
    for _ in 0..<SecretIOExecutor.capacity {
        await #expect(throws: VaultError.stateUnavailable) {
            _ = try await broker.resume(approved[0].request.uuid, clientID: approved[0].client)
        }
    }
    #expect(try state.snapshot().grants.allSatisfy { $0.callsUsed == 0 })
    #expect(try state.snapshot().pending.allSatisfy { $0.status == .approved })
    #expect(try !state.snapshot().audit.contains { $0.outcome == "reserved" })
    #expect(await adapter.calls == 0)
    secrets.stall(.load, count: SecretIOExecutor.readCapacity)
    defer { secrets.release(SecretIOExecutor.capacity) }
    let runs = approved.map { item in Task { try await broker.resume(item.request.uuid, clientID: item.client) } }
    try await secrets.waitForStarts(SecretIOExecutor.readCapacity)
    secrets.release(SecretIOExecutor.readCapacity)
    for run in runs { #expect(try await run.value == .demoReady) }
    #expect(try state.snapshot().grants.allSatisfy { $0.callsUsed == 1 })
    #expect(try state.snapshot().pending.allSatisfy { $0.status == .consumed })
    #expect(await adapter.calls == SecretIOExecutor.readCapacity)
}

@Test func lateEnrollmentWriteStaysTrackedUntilSafeRecovery() async throws {
    let state = MemoryState(), store = StallingSecrets()
    let broker = Broker(state: state, secrets: store, secretIOPolicy: try .init(timeout: 2))
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
    let f = try await IOFixture.make(timeout: 2)
    f.store.stall(.save)
    defer { f.store.release(4) }
    let rotation = Task { try await f.broker.rotate(accountID: f.account.id, credential: Data("SYNTHETIC-late-stage".utf8)) }
    try await f.store.waitForStarts(1)
    await #expect(throws: VaultError.secretUnavailable) { try await rotation.value }
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
    let f = try await IOFixture.make(timeout: 2)
    f.store.stall(.delete)
    defer { f.store.release(4) }
    let deletion = Task { try await f.broker.deleteAccount(f.account.id) }
    try await f.store.waitForStarts(1)
    await #expect(throws: VaultError.secretUnavailable) { try await deletion.value }
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
    let f = try await IOFixture.make(timeout: 2)
    f.store.stall(.delete)
    defer { f.store.release(4) }
    let rotation = Task { try await f.broker.rotate(accountID: f.account.id, credential: Data("SYNTHETIC-new".utf8)) }
    try await f.store.waitForStarts(1)
    await #expect(throws: VaultError.secretUnavailable) { try await rotation.value }
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
