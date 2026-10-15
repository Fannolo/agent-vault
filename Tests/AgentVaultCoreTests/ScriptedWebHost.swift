import AgentVaultContracts
import AgentVaultCore
import Foundation

/// Ordered record shared by the scripted host and secret store, so tests can check sequencing.
final class EventLog: @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [String] = []
    func append(_ entry: String) { lock.withLock { entries.append(entry) } }
    var all: [String] { lock.withLock { entries } }
}

/// Suspends the next armed host call until the test releases it.
actor Hold {
    private var armed = false
    private var reachedWaiter: CheckedContinuation<Void, Never>?
    private var reached = false
    private var release: CheckedContinuation<Void, Never>?

    func arm() { armed = true; reached = false }
    func pass() async {
        guard armed else { return }
        armed = false; reached = true
        reachedWaiter?.resume(); reachedWaiter = nil
        await withCheckedContinuation { release = $0 }
    }
    func waitUntilReached() async {
        if !reached { await withCheckedContinuation { reachedWaiter = $0 } }
    }
    func open() { release?.resume(); release = nil }
}

/// In-process stand-in for the web host: scripted steps, a context table and a loss signal.
/// It holds no authority; it only reports what the broker asked of it.
final class ScriptedWebHost: WebSessionExecutor, @unchecked Sendable {
    private let lock = NSLock()
    private var startSteps: [WebStep]
    private var reclassifySteps: [WebStep]
    private var open: Set<BrowserRunID> = []
    private var ended: [BrowserRunID] = []
    private var usernames: [String] = []
    private var starts = 0
    private var lifetimes: [Int] = []
    let log: EventLog
    let startHold = Hold(), reclassifyHold = Hold()
    let endHold = Hold()
    /// Holds a start where the real link authenticates the host, before it asks for authority.
    let authorityHold = Hold()
    let losses: AsyncStream<Set<BrowserRunID>>
    private let lossSignal: AsyncStream<Set<BrowserRunID>>.Continuation

    init(start: [WebStep], reclassify: [WebStep] = [], log: EventLog = EventLog()) {
        startSteps = start; reclassifySteps = reclassify; self.log = log
        (losses, lossSignal) = AsyncStream.makeStream(of: Set<BrowserRunID>.self)
    }

    func start(_ run: BrowserRunID, workflow: WebWorkflow, credential: WebLoginCredential,
               authority: WebStartAuthority) async -> WebStep {
        await authorityHold.pass()
        // Like the real link: the credential is "sent" only with a live lifetime.
        guard let lifetime = await authority.lifetimeIfStillAuthorized() else {
            log.append("start_withheld")
            return .failed(.unknownRun)
        }
        lock.withLock { starts += 1; usernames.append(credential.username); lifetimes.append(lifetime) }
        log.append("start")
        await startHold.pass()
        return lock.withLock {
            // The host creates the context while starting, even if the broker has since ended the run.
            open.insert(run)
            return startSteps.isEmpty ? .failed(.unexpectedPage) : startSteps.removeFirst()
        }
    }

    func reclassify(_ run: BrowserRunID) async -> WebStep {
        log.append("reclassify")
        await reclassifyHold.pass()
        return lock.withLock {
            guard open.contains(run) else { return .failed(.unknownRun) }
            return reclassifySteps.isEmpty ? .failed(.unexpectedPage) : reclassifySteps.removeFirst()
        }
    }

    func end(_ run: BrowserRunID) async {
        log.append("end")
        await endHold.pass()
        lock.withLock { open.remove(run); ended.append(run) }
    }

    func showHuman(_ step: HumanStepID) async -> Bool { lock.withLock { open.contains(step.run) } }
    func frame(_ step: HumanStepID, after: UInt64) async -> HumanFrame? { nil }
    func input(_ step: HumanStepID, frame: UInt64, _ batch: HumanInputBatch) async -> Bool { false }

    /// The host process died: every context is gone.
    func lose() {
        let lost = lock.withLock { () -> Set<BrowserRunID> in
            defer { open.removeAll() }
            return open
        }
        lossSignal.yield(lost)
    }

    /// Delivers a loss notice for a connection that carried exactly `runs`, possibly long after
    /// that connection ended. Contexts created since then belong to a newer connection.
    func deliverLoss(of runs: Set<BrowserRunID>) {
        lock.withLock { open.subtract(runs) }
        lossSignal.yield(runs)
    }

    var openContexts: Int { lock.withLock { open.count } }
    var startCount: Int { lock.withLock { starts } }
    var startLifetimes: [Int] { lock.withLock { lifetimes } }
    var startedUsernames: [String] { lock.withLock { usernames } }
    func endCount(_ run: BrowserRunID) -> Int { lock.withLock { ended.filter { $0 == run }.count } }
    func contextOpen(_ run: BrowserRunID) -> Bool { lock.withLock { open.contains(run) } }
}

/// Records secret deletions into the shared log, and can block loads until released.
final class LoggedSecrets: SecretStore, @unchecked Sendable {
    private let inner = MemorySecrets()
    private let log: EventLog
    private let gate = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var blockLoads = false
    private var loadStarted: (() -> Void)?
    init(log: EventLog) { self.log = log }
    func save(_ value: Data, for id: UUID) throws { try inner.save(value, for: id) }
    func load(for id: UUID) throws -> Data {
        let wait = lock.withLock { () -> (() -> Void)? in
            guard blockLoads else { return nil }
            blockLoads = false
            return loadStarted ?? {}
        }
        if let wait { wait(); gate.wait() }
        return try inner.load(for: id)
    }
    func delete(for id: UUID) throws { log.append("secret_deleted"); try inner.delete(for: id) }
    func blockNextLoad(started: @escaping @Sendable () -> Void) { lock.withLock { blockLoads = true; loadStarted = started } }
    func releaseLoad() { gate.signal() }
    var reads: Int { inner.reads }
}

let syntheticWebCredential = Data("synthetic-user\nSYNTHETIC-only-password".utf8)
let syntheticProfile = AccountProfile(login: "synthetic-user", userID: 4242)!

struct WebFixture {
    let state: MemoryState
    let secrets: LoggedSecrets
    let clock: Clock
    let host: ScriptedWebHost
    let broker: Broker
    let client: ClientRecord
    let account: Account
    let grant: Grant

    static func make(start: [WebStep], reclassify: [WebStep] = [], calls: Int = 5, duration: TimeInterval = 3600,
                     requiresApproval: Bool = false, windows: LifecycleWindows = .standard,
                     realClock: Bool = false) async throws -> WebFixture {
        let log = EventLog()
        let state = MemoryState(), secrets = LoggedSecrets(log: log), clock = Clock()
        let host = ScriptedWebHost(start: start, reclassify: reclassify, log: log)
        let now: @Sendable () -> Date
        if realClock { now = { Date() } } else { now = { clock.now() } }
        let broker = Broker(state: state, secrets: secrets, webSessions: host, windows: windows, now: now)
        let account = try await broker.enroll(service: .githubWeb, credential: syntheticWebCredential)
        let client = try await broker.registerClient()
        let grant = try await broker.grant(clientID: client.id, accountID: account.id, duration: duration,
                                           callLimit: calls, requiresApproval: requiresApproval)
        return .init(state: state, secrets: secrets, clock: clock, host: host, broker: broker,
                     client: client, account: account, grant: grant)
    }

    func run() async throws -> OperationResult {
        try await broker.run(clientID: client.id, accountID: account.id, action: .githubWebProfile)
    }

    func startPausedRun() async throws -> BrowserRunID {
        guard case .humanStepRequired(let id) = try await run() else { throw VaultError.invalidResponse }
        return id
    }

    func resume(_ id: BrowserRunID) async throws -> OperationResult { try await broker.resume(id.uuid, clientID: client.id) }

    func openHumanStep(_ id: BrowserRunID, connection: ContinuationConnectionID) async throws -> ContinuationLeaseID {
        guard let step = try await broker.pendingHumanSteps().first(where: { $0.id.run == id }) else {
            throw VaultError.denied
        }
        return try await broker.openHumanStep(step.id, connection: connection)
    }

    var callsUsed: Int { (try? state.snapshot().grants.first { $0.id == grant.id }?.callsUsed) ?? -1 }

    /// Invocation audit for this client/account, in order.
    var audit: [String] {
        (try? state.snapshot().audit.filter { $0.clientID == client.id && $0.accountID == account.id }.map(\.outcome)) ?? []
    }
    var humanAudit: [String] {
        (try? state.snapshot().adminAudit.filter { $0.clientID == client.id }.map(\.outcome)) ?? []
    }
}
