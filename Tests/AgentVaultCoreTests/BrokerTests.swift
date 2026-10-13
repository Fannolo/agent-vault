import AgentVaultCore
import Foundation
import Testing

@Test func approvedActionReturnsOnlyTypedResult() async throws {
    let f = try await Fixture.make()
    let result = try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)
    #expect(result == .demoReady)
    #expect(f.secrets.reads == 1)
    let data = try f.state.transaction { try JSONEncoder().encode($0) }
    #expect(!String(decoding: data, as: UTF8.self).contains("SYNTHETIC-only-token"))
}

@Test func missingGrantCannotReadCredential() async throws {
    let f = try await Fixture.make()
    await #expect(throws: VaultError.denied) {
        _ = try await f.broker.run(clientID: UUID(), accountID: f.account.id, action: .demoStatus)
    }
    #expect(f.secrets.reads == 0)
}

@Test func wrongAccountAndActionAreDenied() async throws {
    let f = try await Fixture.make()
    await #expect(throws: VaultError.denied) {
        _ = try await f.broker.run(clientID: f.client.id, accountID: UUID(), action: .demoStatus)
    }
    await #expect(throws: VaultError.denied) {
        _ = try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .githubProfile)
    }
    #expect(f.secrets.reads == 0)
}

@Test func expiryIsCheckedAtEachCall() async throws {
    let f = try await Fixture.make()
    f.clock.advance(60)
    await #expect(throws: VaultError.denied) {
        _ = try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)
    }
    #expect(try await f.broker.availableAccounts(clientID: f.client.id).isEmpty)
    #expect(f.secrets.reads == 0)
}

@Test func revocationTakesEffectImmediately() async throws {
    let f = try await Fixture.make()
    try await f.broker.revokeGrant(f.grant.id)
    await #expect(throws: VaultError.denied) {
        _ = try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)
    }
    #expect(f.secrets.reads == 0)
}

@Test func clientRevocationBlocksEveryGrant() async throws {
    let f = try await Fixture.make()
    try await f.broker.revokeClient(f.client.id)
    await #expect(throws: VaultError.denied) {
        _ = try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)
    }
    #expect(try await f.broker.availableAccounts(clientID: f.client.id).isEmpty)
}

@Test func concurrentCallsCannotExceedBudget() async throws {
    let f = try await Fixture.make(calls: 3)
    let completed = await withTaskGroup(of: Bool.self, returning: Int.self) { group in
        for _ in 0..<30 {
            group.addTask {
                (try? await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)) != nil
            }
        }
        var count = 0
        for await success in group { if success { count += 1 } }
        return count
    }
    #expect(completed == 3)
    #expect(f.secrets.reads == 3)
}

actor PausedAdapter: ServiceAdapter {
    private var started = false
    private var startedWaiter: CheckedContinuation<Void, Never>?
    private var releaseWaiter: CheckedContinuation<Void, Never>?
    func execute(service: Service, credential: Data) async throws -> OperationResult {
        started = true
        startedWaiter?.resume()
        await withCheckedContinuation { releaseWaiter = $0 }
        return .demoReady
    }
    func waitUntilStarted() async {
        if !started { await withCheckedContinuation { startedWaiter = $0 } }
    }
    func release() { releaseWaiter?.resume(); releaseWaiter = nil }
}

@Test func revokedInflightRequestSuppressesOutput() async throws {
    let adapter = PausedAdapter()
    let f = try await Fixture.make(adapter: adapter)
    let task = Task { try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus) }
    await adapter.waitUntilStarted()
    try await f.broker.revokeGrant(f.grant.id)
    await adapter.release()
    await #expect(throws: VaultError.denied) { _ = try await task.value }
    #expect(try f.state.snapshot().audit.filter { $0.outcome == "response_suppressed" }.count == 1)
}

struct FailingAdapter: ServiceAdapter {
    func execute(service: Service, credential: Data) async throws -> OperationResult {
        throw NSError(domain: "SYNTHETIC-only-token", code: 1)
    }
}

@Test func failedAttemptConsumesBudgetAndReturnsStableError() async throws {
    let f = try await Fixture.make(calls: 1, adapter: FailingAdapter())
    await #expect(throws: VaultError.upstreamUnavailable) {
        _ = try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)
    }
    #expect(try f.state.snapshot().audit.filter { $0.outcome == "failed" }.count == 1)
    await #expect(throws: VaultError.denied) {
        _ = try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)
    }
}

@Test func invalidGrantLimitsAreRejected() async throws {
    let f = try await Fixture.make()
    for seconds in [0, -1, 86_401, Double.infinity, Double.nan] {
        await #expect(throws: VaultError.invalidInput) {
            _ = try await f.broker.grant(clientID: f.client.id, accountID: f.account.id,
                                       duration: seconds, callLimit: 1)
        }
    }
}

final class DelayedState: StateStore, @unchecked Sendable {
    private let inner: MemoryState
    private let clock: Clock
    private let advanceOnCall: Int
    private let lock = NSLock()
    private var calls = 0
    init(inner: MemoryState, clock: Clock, advanceOnCall: Int) {
        self.inner = inner; self.clock = clock; self.advanceOnCall = advanceOnCall
    }
    func transaction<T>(_ body: (inout VaultState) throws -> T) throws -> T {
        let advance = lock.withLock { calls += 1; return calls == advanceOnCall }
        if advance { clock.advance(61) }
        return try inner.transaction(body)
    }
}

@Test func expiryAfterLockWaitPreventsSecretRead() async throws {
    let f = try await Fixture.make()
    let state = DelayedState(inner: f.state, clock: f.clock, advanceOnCall: 1)
    let broker = Broker(state: state, secrets: f.secrets, now: { f.clock.now() })
    await #expect(throws: VaultError.denied) {
        _ = try await broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)
    }
    #expect(f.secrets.reads == 0)
}

@Test func expiryAfterCompletionLockWaitSuppressesResponse() async throws {
    let f = try await Fixture.make()
    let state = DelayedState(inner: f.state, clock: f.clock, advanceOnCall: 4)
    let adapter = CountingAdapter()
    let broker = Broker(state: state, secrets: f.secrets, adapter: adapter, now: { f.clock.now() })
    await #expect(throws: VaultError.denied) {
        _ = try await broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)
    }
    #expect(f.secrets.reads == 1)
    #expect(await adapter.calls == 1)
}

struct DelayedSecrets: SecretStore {
    let inner: MemorySecrets
    let clock: Clock
    func save(_ value: Data, for id: UUID) throws { try inner.save(value, for: id) }
    func load(for id: UUID) throws -> Data { clock.advance(61); return try inner.load(for: id) }
    func delete(for id: UUID) throws { try inner.delete(for: id) }
}

actor CountingAdapter: ServiceAdapter {
    private(set) var calls = 0
    func execute(service: Service, credential: Data) async throws -> OperationResult {
        calls += 1
        return .demoReady
    }
}

@Test func expiryWhileKeychainBlocksPreventsProviderDispatch() async throws {
    let f = try await Fixture.make()
    let adapter = CountingAdapter()
    let broker = Broker(state: f.state, secrets: DelayedSecrets(inner: f.secrets, clock: f.clock),
                        adapter: adapter, now: { f.clock.now() })
    await #expect(throws: VaultError.denied) {
        _ = try await broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)
    }
    #expect(await adapter.calls == 0)
}
