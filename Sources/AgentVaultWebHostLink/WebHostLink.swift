import AgentVaultContracts
import AgentVaultCore
import AgentVaultIPC
import AgentVaultWebHostProtocol
import Foundation

/// Absolute per-operation budgets, including connection and authentication time.
///
/// A read waits at most `VaultReadClient.defaultTimeout`. Inside it the broker spends up to
/// the credential-access timeout, one `start`, and the `end` that cleans up a start that ran
/// out of time. `fits` checks that sum, with a margin for XPC and broker work.
public struct WebHostBudgets: Sendable, Equatable {
    public let start: TimeInterval
    public let classify: TimeInterval
    public let end: TimeInterval
    public let showHuman: TimeInterval
    public let frame: TimeInterval
    public let input: TimeInterval

    public static let standard = WebHostBudgets(start: 15, classify: 10, end: 2, showHuman: 5, frame: 2, input: 2)
    public static let margin: TimeInterval = 5

    init(start: TimeInterval, classify: TimeInterval, end: TimeInterval, showHuman: TimeInterval,
         frame: TimeInterval, input: TimeInterval) {
        self.start = start; self.classify = classify; self.end = end
        self.showHuman = showHuman; self.frame = frame; self.input = input
    }

    /// Every caller-visible path, including its cleanup, completes before the caller gives up.
    public func fits(credentialTimeout: TimeInterval, callerTimeout: TimeInterval) -> Bool {
        let paths = [credentialTimeout + start + end, classify + end, showHuman, frame, input + end]
        return paths.allSatisfy { $0 + Self.margin <= callerTimeout }
    }
}

/// The broker's client for the web host. Implements Core's domain port over the host wire.
///
/// Each connection is a generation. It is authenticated by an empty probe whose reply must pass
/// the host's code requirement and UID before any command, and so any credential, is sent.
/// A run is bound to the generation that carried its `start`; every later command for it goes
/// to that generation only. When a generation ends, its pending requests fail at once and
/// `losses` yields exactly the runs bound to it, so a late notice never touches newer runs.
public final class WebHostLink: WebSessionExecutor, @unchecked Sendable {
    public struct Limits: Sendable {
        public var control: Int, frame: Int, teardown: Int
        public static let standard = Limits(control: 8, frame: 4, teardown: 16)
        func limit(_ lane: HostLane) -> Int {
            switch lane {
            case .control: control
            case .frame: frame
            case .teardown: teardown
            }
        }
    }

    enum Target {
        case service(String, privileged: Bool)
        /// Resolved per connection, as launchd resolves a relaunched service's name.
        case endpoint(@Sendable () -> NSXPCListenerEndpoint)
    }

    public let losses: AsyncStream<Set<BrowserRunID>>
    private let lossSignal: AsyncStream<Set<BrowserRunID>>.Continuation
    private let configuration: WebHostConfiguration
    private let target: Target
    private let budgets: WebHostBudgets
    private let limits: Limits
    private let lock = NSLock()
    private var current: Generation?
    private var generations: UInt64 = 0
    private var requests: UInt64 = 0
    private var bound: [BrowserRunID: Generation] = [:]
    private var tombstones = Tombstones()

    /// Production composition: identities from protected configuration, the system bootstrap,
    /// and budgets that must fit inside the bridge's read deadline.
    public convenience init(configuration: WebHostConfiguration, brokerIPC: IPCConfiguration,
                            credentialTimeout: TimeInterval) throws(IPCError) {
        try configuration.validate(for: .broker)
        try configuration.validate(brokerIPC: brokerIPC)
        guard WebHostBudgets.standard.fits(credentialTimeout: credentialTimeout,
                                           callerTimeout: VaultReadClient.defaultTimeout) else {
            throw .invalidConfiguration
        }
        self.init(validated: configuration,
                  target: .service(configuration.serviceName, privileged: !configuration.development),
                  budgets: .standard, limits: .standard)
    }

    init(validated configuration: WebHostConfiguration, target: Target, budgets: WebHostBudgets, limits: Limits) {
        self.configuration = configuration; self.target = target; self.budgets = budgets; self.limits = limits
        (losses, lossSignal) = AsyncStream.makeStream(of: Set<BrowserRunID>.self)
    }

    deinit {
        lossSignal.finish()
        current?.connection.invalidate()
    }

    // MARK: WebSessionExecutor

    public func start(_ run: BrowserRunID, workflow: WebWorkflow, credential: WebLoginCredential,
                      authority: WebStartAuthority) async -> WebStep {
        let deadline = Deadline(budgets.start)
        // Asked only once the host is authenticated, and the start is written right after.
        let outcome = await exchange(route: .bind(run), deadline: deadline) {
            guard let lifetime = await authority.lifetimeIfStillAuthorized() else { return nil }
            return .start(run: run.uuid, workflow: workflow.host, credential: credential,
                          lifetime: min(lifetime, HostCommand.maximumLifetime))
        }
        if case .failure(.timeout) = outcome {
            // The host may still create the context: end it now rather than leave a paid run behind.
            await end(run)
        }
        return step(outcome)
    }

    public func reclassify(_ run: BrowserRunID) async -> WebStep {
        step(await exchange(.classify(run: run.uuid), route: .bound(run), deadline: Deadline(budgets.classify)))
    }

    public func end(_ run: BrowserRunID) async {
        let generation = lock.withLock { () -> Generation? in
            tombstones.insert(run)
            let generation = bound.removeValue(forKey: run)
            generation?.runs.remove(run)
            return generation
        }
        // Never started here, or its generation is gone: the host holds no context for it.
        guard let generation else { return }
        let outcome = await exchange(.end(run: run.uuid), route: .on(generation), deadline: Deadline(budgets.end))
        if case .success(.ended) = outcome { return }
        // A host that cannot confirm teardown loses its only peer, which ends every context it holds.
        generation.connection.invalidate()
    }

    public func showHuman(_ step: HumanStepID) async -> Bool {
        let outcome = await exchange(.showHuman(run: step.run.uuid, step: step.epoch), route: .bound(step.run),
                                     deadline: Deadline(budgets.showHuman))
        if case .success(.accepted) = outcome { return true }
        return false
    }

    public func frame(_ step: HumanStepID, after: UInt64) async -> HumanFrame? {
        let outcome = await exchange(.frame(run: step.run.uuid, step: step.epoch, after: after),
                                     route: .bound(step.run), deadline: Deadline(budgets.frame))
        if case .success(.frame(_, let frame)) = outcome { return frame }
        return nil
    }

    public func input(_ step: HumanStepID, frame: UInt64, _ batch: HumanInputBatch) async -> Bool {
        let outcome = await exchange(.input(run: step.run.uuid, step: step.epoch, frame: frame, batch: batch),
                                     route: .bound(step.run), deadline: Deadline(budgets.input))
        if case .success(.accepted) = outcome { return true }
        return false
    }

    // MARK: Exchange

    enum Failure: Error, Equatable {
        /// The host was not reached or did not authenticate; nothing was sent.
        case unavailable
        /// The run's generation ended, or the run was never bound to a live one.
        case lost
        case timeout
        /// Lane full on this side; nothing was sent.
        case busy
        /// A late or duplicate start for a run this link already ended or started.
        case refused
        /// The broker withdrew authority before the credential was written; nothing was sent.
        case withheld
        /// The host answered outside the protocol; its generation is invalidated.
        case violation
        /// The host's transport refused the request with a fixed code.
        case transport(HostWireError)
    }

    enum Route {
        /// A new run: bind it to the current generation just before its start is sent.
        case bind(BrowserRunID)
        /// An existing run: only the generation that carried its start.
        case bound(BrowserRunID)
        case on(Generation)
    }

    private func exchange(_ command: HostCommand, route: Route, deadline: Deadline) async -> Result<HostReply, Failure> {
        await exchange(route: route, deadline: deadline) { command }
    }

    /// `prepare` runs after the generation is authenticated; the command it returns is admitted
    /// and written without any further suspension.
    private func exchange(route: Route, deadline: Deadline,
                          prepare: () async -> HostCommand?) async -> Result<HostReply, Failure> {
        let generation: Generation
        switch route {
        case .bind(let run):
            guard lock.withLock({ !tombstones.contains(run) && bound[run] == nil }) else { return .failure(.refused) }
            generation = connect()
        case .bound(let run):
            guard let found = lock.withLock({ bound[run] }) else { return .failure(.lost) }
            generation = found
        case .on(let found):
            generation = found
        }
        switch await generation.verified(until: deadline) {
        case .verified: break
        case .rejected: return .failure(.unavailable)
        case .timedOut:
            generation.connection.invalidate()
            return .failure(.timeout)
        case .closed:
            // Nothing was sent on it. Only a run already bound to it has lost its context.
            if case .bind = route { return .failure(.unavailable) }
            return .failure(.lost)
        }
        guard let command = await prepare() else { return .failure(.withheld) }
        let lane = command.lane
        let admission = lock.withLock { () -> Result<HostRequest, Failure> in
            guard !generation.closed else { return .failure(.lost) }
            switch route {
            case .bind(let run):
                guard !tombstones.contains(run), bound[run] == nil else { return .failure(.refused) }
            case .bound(let run):
                guard bound[run] === generation else { return .failure(.lost) }
            case .on: break
            }
            guard generation.inFlight[lane, default: 0] < limits.limit(lane) else { return .failure(.busy) }
            generation.inFlight[lane, default: 0] += 1
            requests += 1
            if case .bind(let run) = route {
                bound[run] = generation
                generation.runs.insert(run)
            }
            return .success(HostRequest(id: requests, command: command))
        }
        guard case .success(let request) = admission else {
            if case .failure(let failure) = admission { return .failure(failure) }
            return .failure(.violation)
        }
        defer { lock.withLock { generation.inFlight[lane, default: 0] -= 1 } }
        guard let data = try? HostWire.encode(request) else { return .failure(.violation) }
        let outcome = await generation.send(data, until: deadline)
        switch outcome {
        case .success(.response(let response)) where response.answers(request):
            return .success(response.reply)
        case .success(.response):
            generation.connection.invalidate()
            return .failure(.violation)
        case .success(.error(let code)):
            return .failure(.transport(code))
        case .failure(let failure):
            if failure == .violation { generation.connection.invalidate() }
            return .failure(failure)
        }
    }

    private func step(_ outcome: Result<HostReply, Failure>) -> WebStep {
        switch outcome {
        case .success(.profile(let profile)): .profile(profile)
        case .success(.humanStep(let kind)): .humanStep(kind)
        case .success(.failed(let failure)): .failed(failure.web)
        case .success(.rejected(let rejection)): .failed(rejection.web)
        case .success: .failed(.rendererUnavailable)
        case .failure(.unavailable): .failed(.hostUnavailable)
        case .failure(.lost): .failed(.hostLost)
        case .failure(.timeout): .failed(.timeout)
        case .failure(.busy), .failure(.transport(.busy)): .failed(.busy)
        case .failure(.refused), .failure(.withheld): .failed(.unknownRun)
        case .failure(.violation), .failure(.transport): .failed(.rendererUnavailable)
        }
    }

    // MARK: Generations

    private func connect() -> Generation {
        lock.withLock {
            if let current, !current.closed { return current }
            let connection: NSXPCConnection
            switch target {
            case .service(let name, let privileged):
                // Production looks the host up only in the system bootstrap, so a same-user
                // launch agent cannot shadow its LaunchDaemon service.
                connection = NSXPCConnection(machServiceName: name, options: privileged ? .privileged : [])
            case .endpoint(let resolve):
                connection = NSXPCConnection(listenerEndpoint: resolve())
            }
            generations += 1
            let generation = Generation(number: generations, connection: connection, hostUID: configuration.hostUID)
            connection.remoteObjectInterface = NSXPCInterface(with: WebHostRPC.self)
            connection.setCodeSigningRequirement(configuration.hostRequirement)
            connection.interruptionHandler = { [weak connection] in connection?.invalidate() }
            connection.invalidationHandler = { [weak self, weak generation] in
                guard let generation else { return }
                self?.closed(generation)
            }
            current = generation
            connection.activate()
            generation.probe(until: Deadline(budgets.start))
            return generation
        }
    }

    /// Test visibility into retained state: runs still bound, and runs held by the current generation.
    var retainedRunCounts: (bound: Int, generation: Int) {
        lock.withLock { (bound.count, current?.runs.count ?? 0) }
    }

    private func closed(_ generation: Generation) {
        let lost = lock.withLock { () -> Set<BrowserRunID> in
            if current === generation { current = nil }
            let runs = generation.runs
            for run in runs where bound[run] === generation { bound.removeValue(forKey: run) }
            return runs.filter { !tombstones.contains($0) }
        }
        generation.close()
        if !lost.isEmpty { lossSignal.yield(lost) }
    }
}

/// One authenticated connection and everything bound to it. Mutable fields other than the
/// generation's own probe and pending state are guarded by the link's lock.
final class Generation: @unchecked Sendable {
    enum Verification { case verified, rejected, timedOut, closed }

    let number: UInt64
    let connection: NSXPCConnection
    private let hostUID: UInt32
    var runs: Set<BrowserRunID> = []
    var inFlight: [HostLane: Int] = [:]

    private let state = NSLock()
    private var verification: Verification?
    private var waiters: [Once<Verification>] = []
    private var pending: [UUID: Once<Result<HostWire.Envelope, WebHostLink.Failure>>] = [:]
    private var isClosed = false

    init(number: UInt64, connection: NSXPCConnection, hostUID: UInt32) {
        self.number = number; self.connection = connection; self.hostUID = hostUID
    }

    var closed: Bool { state.withLock { isClosed } }

    /// Sends the empty probe. A fixed `invalid_request` reply that passed the connection's code
    /// requirement and comes from the host UID is the only proof that unlocks commands.
    func probe(until deadline: Deadline) {
        Task {
            let result = await self.send(Data(), until: deadline)
            let outcome: Verification = switch result {
            case .success(.error(.invalidRequest)): .verified
            case .failure(.timeout): .timedOut
            case .failure(.lost): .closed
            default: .rejected
            }
            if outcome == .rejected { self.connection.invalidate() }
            self.settle(outcome)
        }
    }

    private func settle(_ outcome: Verification) {
        let waiting = state.withLock { () -> [Once<Verification>] in
            guard verification == nil else { return [] }
            verification = outcome
            defer { waiters = [] }
            return waiters
        }
        for waiter in waiting { waiter.resume(outcome) }
    }

    func verified(until deadline: Deadline) async -> Verification {
        await withCheckedContinuation { continuation in
            let once = Once(continuation)
            let settled = state.withLock { () -> Verification? in
                if let verification { return verification }
                if isClosed { return .closed }
                waiters.append(once)
                return nil
            }
            if let settled { return once.resume(settled) }
            deadline.schedule { once.resume(.timedOut) }
        }
    }

    func send(_ data: Data, until deadline: Deadline) async -> Result<HostWire.Envelope, WebHostLink.Failure> {
        await withCheckedContinuation { continuation in
            let key = UUID()
            let once = Once(continuation) { [weak self] in self?.forget(key) }
            let admitted = state.withLock { () -> Bool in
                guard !isClosed else { return false }
                pending[key] = once
                return true
            }
            guard admitted else { return once.resume(.failure(.lost)) }
            deadline.schedule { once.resume(.failure(.timeout)) }
            let hostUID = hostUID, connection = connection
            let proxy = connection.remoteObjectProxyWithErrorHandler { error in
                let error = error as NSError
                let signing = error.domain == NSCocoaErrorDomain && error.code == NSXPCConnectionCodeSigningRequirementFailure
                once.resume(.failure(signing ? .unavailable : .lost))
            }
            guard let host = proxy as? WebHostRPC else { return once.resume(.failure(.unavailable)) }
            host.perform(data) { reply in
                // The reply passed the host code requirement; also pin the sender's kernel UID.
                guard UInt32(connection.effectiveUserIdentifier) == hostUID else {
                    connection.invalidate()
                    return once.resume(.failure(.unavailable))
                }
                do { once.resume(.success(try HostWire.decodeReply(reply))) }
                catch { once.resume(.failure(.violation)) }
            }
        }
    }

    private func forget(_ key: UUID) { _ = state.withLock { pending.removeValue(forKey: key) } }

    /// Fails every pending request and probe waiter at once.
    func close() {
        let (waiting, requests) = state.withLock { () -> ([Once<Verification>], [Once<Result<HostWire.Envelope, WebHostLink.Failure>>]) in
            isClosed = true
            defer { waiters = []; pending = [:] }
            return (verification == nil ? waiters : [], Array(pending.values))
        }
        for waiter in waiting { waiter.resume(.closed) }
        for request in requests { request.resume(.failure(.lost)) }
    }
}

/// A point on the monotonic clock fixed when an operation begins; every later wait uses what remains.
struct Deadline: Sendable {
    let time: DispatchTime
    init(_ budget: TimeInterval) { time = .now() + budget }
    func schedule(_ work: @escaping @Sendable () -> Void) {
        DispatchQueue.global().asyncAfter(deadline: time, execute: work)
    }
}

/// Resumes a continuation exactly once, whichever of reply, error, deadline or close comes first.
final class Once<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Never>?
    private let onResume: (@Sendable () -> Void)?

    init(_ continuation: CheckedContinuation<Value, Never>, onResume: (@Sendable () -> Void)? = nil) {
        self.continuation = continuation; self.onResume = onResume
    }

    func resume(_ value: Value) {
        let continuation = lock.withLock { () -> CheckedContinuation<Value, Never>? in
            defer { self.continuation = nil }
            return self.continuation
        }
        guard let continuation else { return }
        onResume?()
        continuation.resume(returning: value)
    }
}

/// Runs this link already ended. A start racing teardown is refused rather than sent.
struct Tombstones {
    static let capacity = 4096
    private var members: Set<BrowserRunID> = []
    private var order: [BrowserRunID] = []

    func contains(_ run: BrowserRunID) -> Bool { members.contains(run) }

    mutating func insert(_ run: BrowserRunID) {
        guard members.insert(run).inserted else { return }
        order.append(run)
        if order.count > Self.capacity { members.remove(order.removeFirst()) }
    }
}

extension WebWorkflow {
    var host: HostWorkflow {
        switch self {
        case .browserDemo: .browserDemo
        case .githubWebProfile: .githubWebProfile
        }
    }
}

extension HostFailure {
    var web: WebFailure {
        switch self {
        case .invalidCredential: .invalidCredential
        case .originMismatch: .originMismatch
        case .unexpectedPage: .unexpectedPage
        case .loginRejected: .loginRejected
        case .timeout: .timeout
        case .loadFailed: .loadFailed
        case .invalidProfile: .invalidProfile
        case .challengeOriginBlocked: .challengeOriginBlocked
        case .rendererUnavailable: .rendererUnavailable
        }
    }
}

extension HostRejection {
    var web: WebFailure {
        switch self {
        case .unknownRun: .unknownRun
        case .busy: .busy
        case .unsupportedWorkflow: .unsupportedWorkflow
        case .duplicateRun, .notPaused, .staleStep, .captureUnavailable: .unexpectedPage
        }
    }
}
