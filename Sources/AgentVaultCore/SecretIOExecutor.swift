import Dispatch
import Foundation

public struct SecretIOPolicy: Sendable {
    public let timeout: TimeInterval
    public static let standard = try! SecretIOPolicy(timeout: 5)
    public init(timeout: TimeInterval) throws {
        guard timeout.isFinite, (0.001...60).contains(timeout) else { throw VaultError.invalidInput }
        self.timeout = timeout
    }
}

enum SecretIOFailure: Error, Sendable {
    case notStarted
    case timedOut
    case operationFailed(VaultError)

    var isUncertain: Bool { if case .timedOut = self { return true }; return false }
    var operationStarted: Bool { if case .notStarted = self { return false }; return true }

    var publicError: VaultError {
        switch self {
        case .notStarted: .busy
        case .timedOut: .secretUnavailable
        case .operationFailed(let error): error
        }
    }
}

/// Four actual synchronous operations, with no waiting queue. A timed-out call
/// retains its slot and write guard until the worker really exits.
final class SecretIOExecutor: @unchecked Sendable {
    private struct Operation { let account: UUID; let writes: Bool }
    private let lock = NSLock()
    private let store: any SecretStore
    private let policy: SecretIOPolicy
    private let workers = DispatchQueue(label: "agent-vault.secret-io", qos: .utility, attributes: .concurrent)
    private let deadlines = DispatchQueue(label: "agent-vault.secret-deadlines", qos: .utility)
    private var operations: [UUID: Operation] = [:]
    static let capacity = 4

    init(store: any SecretStore, policy: SecretIOPolicy) { self.store = store; self.policy = policy }
    var isIdle: Bool { lock.withLock { operations.isEmpty } }
    func hasPendingWrite(account: UUID) -> Bool {
        lock.withLock { operations.values.contains { $0.account == account && $0.writes } }
    }

    func save(_ credential: Data, id: UUID, account: UUID) async throws {
        try await perform(account: account, writes: true) { [store] in try store.save(credential, for: id) }
    }
    func load(id: UUID, account: UUID) async throws -> Data {
        try await perform(account: account, writes: false) { [store] in try store.load(for: id) }
    }
    func delete(id: UUID, account: UUID) async throws {
        try await perform(account: account, writes: true) { [store] in try store.delete(for: id) }
    }

    private func perform<T: Sendable>(account: UUID, writes: Bool,
                                     operation: @escaping @Sendable () throws -> T) async throws -> T {
        let id = UUID()
        let admitted = lock.withLock {
            guard operations.count < Self.capacity else { return false }
            operations[id] = Operation(account: account, writes: writes)
            return true
        }
        guard admitted else { throw SecretIOFailure.notStarted }
        let deadline = DispatchTime.now() + policy.timeout
        return try await withCheckedThrowingContinuation { continuation in
            let request = SecretRequest(deadline: deadline, continuation: continuation)
            request.schedule(on: deadlines)
            workers.async { [self] in
                let result: Result<T, SecretIOFailure>
                if request.canBegin {
                    do { result = .success(try operation()) }
                    catch { result = .failure(.operationFailed((error as? VaultError) ?? .secretUnavailable)) }
                } else { result = .failure(.timedOut) }
                // Release only after the actual operation has finished. Recovery
                // must never delete an item that a late worker could recreate.
                _ = lock.withLock { operations.removeValue(forKey: id) }
                request.finish(result)
            }
        }
    }
}

private final class SecretRequest<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private let deadline: DispatchTime
    private var continuation: CheckedContinuation<T, any Error>?
    private var timer: DispatchSourceTimer?

    init(deadline: DispatchTime, continuation: CheckedContinuation<T, any Error>) {
        self.deadline = deadline; self.continuation = continuation
    }
    var canBegin: Bool { DispatchTime.now().uptimeNanoseconds < deadline.uptimeNanoseconds }

    func schedule(on queue: DispatchQueue) {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: deadline, leeway: .milliseconds(1))
        timer.setEventHandler { [weak self] in self?.expire() }
        lock.withLock { self.timer = timer }
        timer.resume()
    }

    private func expire() {
        let continuation = takeContinuation()
        continuation?.resume(throwing: SecretIOFailure.timedOut)
    }

    func finish(_ result: Result<T, SecretIOFailure>) {
        let continuation = takeContinuation()
        guard let continuation else { return }
        if DispatchTime.now().uptimeNanoseconds >= deadline.uptimeNanoseconds {
            continuation.resume(throwing: SecretIOFailure.timedOut)
        } else {
            switch result {
            case .success(let value): continuation.resume(returning: value)
            case .failure(let error): continuation.resume(throwing: error)
            }
        }
    }

    private func takeContinuation() -> CheckedContinuation<T, any Error>? {
        lock.withLock {
            let value = continuation
            continuation = nil
            timer?.cancel(); timer = nil
            return value
        }
    }
}
