import AgentVaultCore
import Foundation

final class MemoryState: StateStore, @unchecked Sendable {
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

final class MemorySecrets: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [UUID: Data] = [:]
    private var readCount = 0
    func save(_ value: Data, for id: UUID) throws { lock.withLock { items[id] = value } }
    func load(for id: UUID) throws -> Data {
        try lock.withLock {
            readCount += 1
            guard let value = items[id] else { throw VaultError.secretUnavailable }
            return value
        }
    }
    func delete(for id: UUID) throws { _ = lock.withLock { items.removeValue(forKey: id) } }
    var reads: Int { lock.withLock { readCount } }
}

final class Clock: @unchecked Sendable {
    private let lock = NSLock()
    private var date = Date(timeIntervalSince1970: 1_700_000_000)
    func now() -> Date { lock.withLock { date } }
    func advance(_ seconds: TimeInterval) { lock.withLock { date.addTimeInterval(seconds) } }
}

struct Fixture {
    let state: MemoryState
    let secrets: MemorySecrets
    let clock: Clock
    let broker: Broker
    let client: ClientRecord
    let account: Account
    let grant: Grant

    static func make(calls: Int = 20, adapter: any ServiceAdapter = FixedServiceAdapter()) async throws -> Fixture {
        let state = MemoryState(), secrets = MemorySecrets(), clock = Clock()
        let broker = Broker(state: state, secrets: secrets, adapter: adapter, now: { clock.now() })
        let account = try await broker.enroll(service: .demo, credential: Data("SYNTHETIC-only-token".utf8))
        let client = try await broker.registerClient()
        let grant = try await broker.grant(clientID: client.id, accountID: account.id,
                                           duration: 60, callLimit: calls)
        return .init(state: state, secrets: secrets, clock: clock, broker: broker,
                     client: client, account: account, grant: grant)
    }
}
