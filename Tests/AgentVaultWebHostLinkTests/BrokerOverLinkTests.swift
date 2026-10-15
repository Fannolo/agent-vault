@testable import AgentVaultCore
@testable import AgentVaultWebHostLink
@testable import AgentVaultWebHostProtocol
import AgentVaultContracts
import Foundation
import Testing

private final class State: StateStore, @unchecked Sendable {
    private let lock = NSLock()
    private var value = VaultState()
    func transaction<T>(_ body: (inout VaultState) throws -> T) throws -> T {
        try lock.withLock {
            var next = value
            let result = try body(&next)
            value = next
            return result
        }
    }
}

private final class Secrets: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [UUID: Data] = [:]
    func save(_ value: Data, for id: UUID) throws { lock.withLock { items[id] = value } }
    func load(for id: UUID) throws -> Data {
        try lock.withLock {
            guard let value = items[id] else { throw VaultError.secretUnavailable }
            return value
        }
    }
    func delete(for id: UUID) throws { _ = lock.withLock { items.removeValue(forKey: id) } }
}

/// The real Broker, the real link and the real host listener over XPC; only the browser is scripted.
private struct Composition {
    let broker: Broker
    let client: ClientRecord
    let accounts: [Account]

    static func make(_ endpoint: @escaping @Sendable () -> NSXPCListenerEndpoint, accounts count: Int = 1) async throws -> Self {
        let link = link(endpoint, budgets: .standard)
        let broker = Broker(state: State(), secrets: Secrets(), webSessions: link)
        let client = try await broker.registerClient()
        var accounts: [Account] = []
        for _ in 0..<count {
            let account = try await broker.enroll(service: .githubWeb, credential: credential.bytes)
            _ = try await broker.grant(clientID: client.id, accountID: account.id, duration: 3600, callLimit: 3)
            accounts.append(account)
        }
        return .init(broker: broker, client: client, accounts: accounts)
    }

    func run(_ index: Int = 0) async throws -> OperationResult {
        try await broker.run(clientID: client.id, accountID: accounts[index].id, action: .githubWebProfile)
    }

    func resume(_ run: BrowserRunID) async throws -> OperationResult { try await broker.resume(run.uuid, clientID: client.id) }
}

@Suite(.serialized) struct BrokerOverLinkTests {
    @Test func pausedRunCompletesThroughTheHumanStepAndTheHostContextEnds() async throws {
        let host = TestHost(handler: pausingHost)
        let c = try await Composition.make { host.endpoint }
        guard case .humanStepRequired(let run) = try await c.run() else { Issue.record("no pause"); return }
        guard let step = try await c.broker.pendingHumanSteps().first else { Issue.record("no step"); return }
        #expect(step.id.run == run)
        let connection = ContinuationConnectionID()
        let lease = try await c.broker.openHumanStep(step.id, connection: connection)
        #expect(try await c.broker.concludeHumanStep(lease, connection: connection, decision: .finished) == .concluded)
        #expect(try await c.resume(run) == .profile(profile))
        await #expect(throws: VaultError.denied) { _ = try await c.resume(run) }
        #expect(host.commands.all == [
            .start(run: run.uuid, workflow: .githubWebProfile, credential: credential, lifetime: 900),
            .classify(run: run.uuid), .end(run: run.uuid)
        ])
    }

    @Test func lateLossOfTheOldHostEndsOnlyItsRunAndTheNewRunSurvives() async throws {
        let first = TestHost(handler: pausingHost)
        let current = Box(first.endpoint)
        let c = try await Composition.make({ current.value }, accounts: 2)
        guard case .humanStepRequired(let old) = try await c.run(0) else { Issue.record("no pause"); return }
        let second = TestHost(handler: pausingHost)
        current.value = second.endpoint
        first.server.invalidate()
        var failure: (any Error)?
        for _ in 0..<200 where failure == nil {
            do { _ = try await c.resume(old); try await Task.sleep(for: .milliseconds(10)) }
            catch { failure = error }
        }
        #expect(failure as? VaultError == .sessionLost)
        guard case .humanStepRequired(let new) = try await c.run(1) else { Issue.record("no pause"); return }
        #expect(try await c.resume(new) == .humanStepRequired(new))
        #expect(try await c.broker.pendingHumanSteps().map(\.id.run) == [new])
        #expect(second.runs == [new.uuid])
    }

    @Test func revocationDuringAHostStartSuppressesTheResultAndEndsTheLateContext() async throws {
        let hold = Latch()
        let host = TestHost { command in
            if case .start = command { await hold.wait() }
            return await pausingHost(command)
        }
        let c = try await Composition.make { host.endpoint }
        let call = Task { try await c.run() }
        #expect(await eventually { host.count(where: isStart) == 1 })
        let grant = try await c.broker.snapshot().grants[0].id
        try await c.broker.revokeGrant(grant)
        #expect(host.count(where: isEnd) == 1, "revocation ends the context while its start is in flight")
        await hold.open()
        await #expect(throws: VaultError.denied) { _ = try await call.value }
        #expect(host.commands.all.filter(isEnd).count >= 1)
    }
}
