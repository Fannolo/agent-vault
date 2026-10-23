import AgentVaultCredentials
import AgentVaultContracts
import Foundation

// MARK: - Identifiers. Approval requests, browser runs and continuation leases are separate key spaces.

/// One reserved browser attempt. The agent polls it; it is never an approval request.
public struct BrowserRunID: Hashable, Sendable {
    public let uuid: UUID
    init() { uuid = UUID() }
    init(_ uuid: UUID) { self.uuid = uuid }
}

/// A signed, connection-bound right to act on one human step of one run. A later step needs a new open.
public struct ContinuationLeaseID: Hashable, Sendable {
    public let uuid: UUID
    init() { uuid = UUID() }
    init(_ uuid: UUID) { self.uuid = uuid }
}

/// Identity of one authenticated human-app connection, minted by the transport per accepted
/// connection. A lease is valid only on the connection that opened it, never by process ID.
public struct ContinuationConnectionID: Hashable, Sendable {
    public let uuid: UUID
    private let liveness: @Sendable () -> Bool
    public init() { uuid = UUID(); liveness = { true } }
    /// Wraps the identity the XPC listener minted when it accepted the connection, and that
    /// connection's liveness. Never pass a value that arrived in a request.
    public init(minted uuid: UUID, isOpen: @escaping @Sendable () -> Bool) { self.uuid = uuid; liveness = isOpen }
    /// `false` once the transport has seen the connection end, before its closed callback runs.
    var isOpen: Bool { liveness() }
    public static func == (a: Self, b: Self) -> Bool { a.uuid == b.uuid }
    public func hash(into hasher: inout Hasher) { hasher.combine(uuid) }
}

/// A challenge that already exists before the human app asks to open it.
/// The signed open must name this exact step, rather than just its longer-lived run.
public struct HumanStepID: Hashable, Sendable {
    public let run: BrowserRunID
    public let epoch: UInt64
    init(run: BrowserRunID, epoch: UInt64) { self.run = run; self.epoch = epoch }
}

public struct PendingHumanStep: Equatable, Sendable {
    public let id: HumanStepID
    public let kind: HumanStepKind
    public let account: UUID
    /// The pause deadline, already capped by the grant.
    public let expiresAt: Date
}

public enum HumanStepDecision: Sendable { case finished, cancel }

/// Where a run stands after a person acts on it.
public enum HumanStepProgress: Equatable, Sendable {
    /// The run concluded; its result waits for the agent's next resume.
    case concluded
    /// The page asks for another step. Acting on it needs a new signed open.
    case humanStepRequired(HumanStepKind)
}

// MARK: - Windows. Distinct deadline types: a pause can never be passed where collection is expected.

public struct LifecycleWindows: Sendable {
    /// Approval request: waiting -> approved -> consumed at dispatch.
    public let approval: TimeInterval
    /// Provider MFA or CAPTCHA; starts when the host pauses.
    public let humanPause: TimeInterval
    /// A concluded result is held this long for the agent's resume.
    public let collect: TimeInterval
    /// The broker stops waiting for a host `start` reply after this, whatever the host does.
    /// It sits inside the bridge's 30 s read together with the 5 s credential access.
    public let startReply: TimeInterval
    /// The same bound for a reclassification after a person finishes a step.
    public let classifyReply: TimeInterval
    /// Upper bound the host applies to a browser context even if the broker never ends it.
    public static let hostLifetimeCap: TimeInterval = 900

    public static let standard = try! LifecycleWindows(approval: 120, humanPause: 600, collect: 120)

    public init(approval: TimeInterval, humanPause: TimeInterval, collect: TimeInterval,
                startReply: TimeInterval = 15, classifyReply: TimeInterval = 10) throws {
        for value in [approval, humanPause, collect, startReply, classifyReply] {
            guard value.isFinite, value > 0, value <= Self.hostLifetimeCap else { throw VaultError.invalidInput }
        }
        self.approval = approval; self.humanPause = humanPause; self.collect = collect
        self.startReply = startReply; self.classifyReply = classifyReply
    }

    func approvalEnds(now: Date, grantExpiresAt: Date) -> Date {
        min(grantExpiresAt, now.addingTimeInterval(approval))
    }
    func humanPauseEnds(now: Date, grantExpiresAt: Date) -> HumanPauseDeadline {
        .init(date: min(grantExpiresAt, now.addingTimeInterval(humanPause)))
    }
    func collectEnds(now: Date, grantExpiresAt: Date) -> CollectDeadline {
        .init(date: min(grantExpiresAt, now.addingTimeInterval(collect)))
    }
}

struct HumanPauseDeadline: Equatable, Sendable { let date: Date }
struct CollectDeadline: Equatable, Sendable { let date: Date }
/// When the broker stops waiting for the host request it issued; the run then concludes.
struct HostReplyDeadline: Equatable, Sendable { let date: Date }

// MARK: - The port Core needs from a browser host. Domain values only: no URL, script, CDP or wire type.

public enum WebWorkflow: String, CaseIterable, Sendable { case browserDemo, githubWebProfile }

public enum WebStep: Equatable, Sendable {
    case profile(AccountProfile)
    case humanStep(HumanStepKind)
    case failed(WebFailure)
}

/// Precise host outcomes. Recorded in the broker audit; agents see `failure` only.
public enum WebFailure: String, CaseIterable, Sendable {
    case unsupportedWorkflow = "unsupported_workflow", invalidCredential = "invalid_credential", busy
    case originMismatch = "origin_mismatch", unexpectedPage = "unexpected_page", loginRejected = "login_rejected"
    case timeout, loadFailed = "load_failed", invalidProfile = "invalid_profile"
    case challengeOriginBlocked = "challenge_origin_blocked", rendererUnavailable = "renderer_unavailable"
    case unknownRun = "unknown_run"
    /// The host could not be reached or authenticated before the request was sent.
    case hostUnavailable = "host_unavailable"
    /// The host connection carrying this run ended; its browser context is gone.
    case hostLost = "host_lost"

    var failure: VaultError {
        switch self {
        case .loginRejected: .loginRejected
        case .originMismatch, .unexpectedPage, .invalidProfile: .pageChanged
        case .challengeOriginBlocked: .challengeUnavailable
        case .invalidCredential: .secretUnavailable
        case .unknownRun, .hostLost: .sessionLost
        case .unsupportedWorkflow, .busy, .timeout, .loadFailed, .rendererUnavailable, .hostUnavailable:
            .upstreamUnavailable
        }
    }
}

/// Issued by the broker for one run's `start`. The host link consults it after authenticating the
/// host and immediately before writing the credential, with no suspension in between. `nil` means
/// the run lost its authority, its grant has (nearly) expired or the start deadline passed: send nothing.
public struct WebStartAuthority: Sendable {
    private let check: @Sendable () async -> TimeInterval?
    init(_ check: @escaping @Sendable () async -> TimeInterval?) { self.check = check }
    /// The whole seconds of browser context the host may hold, at least one, if still authorized now.
    public func lifetimeIfStillAuthorized() async -> Int? {
        guard let seconds = await check(), seconds.isFinite, seconds >= 1 else { return nil }
        return Int(min(seconds, LifecycleWindows.hostLifetimeCap).rounded(.down))
    }
}

/// A browser host. Every call is bounded by the implementation; `end` is idempotent and must
/// also dispose a context whose `start` is still in flight. The broker remains the only
/// authority: the host never decides whether a result may be delivered.
public protocol WebSessionExecutor: Sendable {
    /// Must obtain a lifetime from `authority` after any connection setup and immediately before
    /// the credential leaves the process; without one it sends nothing.
    func start(_ run: BrowserRunID, workflow: WebWorkflow, credential: WebLoginCredential,
               authority: WebStartAuthority) async -> WebStep
    /// Re-examine the page after a person says they finished. Never submits anything itself.
    func reclassify(_ run: BrowserRunID) async -> WebStep
    func end(_ run: BrowserRunID) async
    /// Starts raster capture of exactly this step. `false` means it cannot be shown.
    func showHuman(_ step: HumanStepID) async -> Bool
    /// The latest frame of `step` newer than `after`, or `nil` when none is available yet.
    func frame(_ step: HumanStepID, after: UInt64) async -> HumanFrame?
    /// Delivers a person's events only while `frame` is still the latest frame of `step`.
    func input(_ step: HumanStepID, frame: UInt64, _ batch: HumanInputBatch) async -> Bool
    /// Each element names the runs whose browser contexts died with one host connection.
    /// Only those runs conclude as `session_lost`; runs on a later connection are unaffected.
    var losses: AsyncStream<Set<BrowserRunID>> { get }
}

// MARK: - Run state. Owned only by the Broker actor and kept in memory, because the browser
// context it describes dies with either process.

struct RunBinding: Equatable, Sendable {
    let client: UUID
    let account: UUID
    let action: Action
    let grant: UUID
    let credential: UUID
}

/// Lives inside one `awaitingHuman` phase: a new step, reclassification, conclusion or loss of the
/// connection drops it, so a lease always names exactly one human step.
struct ContinuationLease: Equatable, Sendable {
    let id: ContinuationLeaseID
    let connection: ContinuationConnectionID
    let step: HumanStepID
}

enum RunConclusion: Equatable, Sendable {
    case profile(AccountProfile)
    case failed(VaultError)
}

enum RunPhase: Equatable, Sendable {
    case loadingCredential
    case dispatching(HostReplyDeadline)
    case awaitingHuman(HumanStepKind, HumanPauseDeadline, ContinuationLease?)
    case classifying(HumanStepKind, HumanPauseDeadline, HostReplyDeadline)
    case concluded(RunConclusion, CollectDeadline)

    /// Phases in which the host may hold a browser context for the run.
    var hostMayHoldContext: Bool {
        switch self {
        case .dispatching, .awaitingHuman, .classifying: true
        case .loadingCredential, .concluded: false
        }
    }

    var awaitsHostReply: Bool {
        switch self {
        case .dispatching, .classifying: true
        case .loadingCredential, .awaitingHuman, .concluded: false
        }
    }

    /// Phases that occupy a browser slot; a concluded result only waits for collection.
    var isLive: Bool { if case .concluded = self { false } else { true } }

    var deadline: Date? {
        switch self {
        case .awaitingHuman(_, let pause, _): pause.date
        case .classifying(_, let pause, let reply): min(pause.date, reply.date)
        case .dispatching(let reply): reply.date
        case .concluded(_, let collect): collect.date
        case .loadingCredential: nil
        }
    }
}

enum RunEvent: Sendable {
    case credentialLoaded
    /// A host reply to the request issued at `epoch`.
    case host(WebStep, epoch: UInt64)
    /// The broker stopped waiting for the request issued at `epoch`, whether or not the host answers.
    case hostReplyOverdue(epoch: UInt64)
    case opened(ContinuationLease)
    case humanFinished(ContinuationLeaseID)
    case humanCancelled(ContinuationLeaseID)
    case agentCancelled
    case connectionClosed(ContinuationConnectionID)
    case authorityLost
    case hostLost
    case clock(Date)
    case collected
}

enum RunEffect: Equatable, Sendable {
    case endHost
    /// Invocation audit, attributed to the run's client/account/action.
    case audit(String)
    /// Administration audit: actions a person took through the human app.
    case humanAudit(String)
}

struct BrowserRun: Sendable {
    let id: BrowserRunID
    let binding: RunBinding
    let grantExpiresAt: Date
    private(set) var phase: RunPhase = .loadingCredential
    /// Bumped whenever the broker issues a host request; replies tagged with an older epoch are stale.
    private(set) var epoch: UInt64 = 0
    private(set) var challengeEpoch: UInt64 = 0

    init(id: BrowserRunID, binding: RunBinding, grantExpiresAt: Date) {
        self.id = id; self.binding = binding; self.grantExpiresAt = grantExpiresAt
    }

    var lease: ContinuationLease? {
        if case .awaitingHuman(_, _, let lease) = phase { lease } else { nil }
    }

    var humanStep: PendingHumanStep? {
        guard case .awaitingHuman(let kind, let pause, _) = phase else { return nil }
        return .init(id: .init(run: id, epoch: challengeEpoch), kind: kind, account: binding.account, expiresAt: pause.date)
    }

    /// Every lifecycle rule. Returning `nil` removes the run. No event reserves budget:
    /// reservation happened once, before the run existed.
    func applying(_ event: RunEvent, now: Date, windows: LifecycleWindows) -> (BrowserRun?, [RunEffect]) {
        var next = self
        switch (phase, event) {
        case (.loadingCredential, .credentialLoaded):
            next.phase = .dispatching(.init(date: min(grantExpiresAt, now.addingTimeInterval(windows.startReply))))
            next.epoch += 1
            return (next, [])

        // A grant that expires while the host works ends the run as a loss of authority.
        case (.dispatching, .host(_, let replyEpoch)) where replyEpoch == epoch && now >= grantExpiresAt,
             (.dispatching, .hostReplyOverdue(let replyEpoch)) where replyEpoch == epoch && now >= grantExpiresAt:
            return (nil, [.audit("response_suppressed"), .endHost])
        case (.dispatching, .clock(let time)) where time >= grantExpiresAt:
            return (nil, [.audit("response_suppressed"), .endHost])
        // A reply is applied only before its deadline; the original pause deadline wins first.
        case (.classifying(_, let pause, _), .host(_, let replyEpoch)) where replyEpoch == epoch && now >= pause.date,
             (.classifying(_, let pause, _), .hostReplyOverdue(let replyEpoch)) where replyEpoch == epoch && now >= pause.date:
            return next.concluded(.failed(.humanStepExpired), now: now, windows: windows,
                                  effects: [.audit("human_step_expired"), .endHost])
        case (.dispatching(let reply), .host(_, let replyEpoch)) where replyEpoch == epoch && now >= reply.date,
             (.classifying(_, _, let reply), .host(_, let replyEpoch)) where replyEpoch == epoch && now >= reply.date:
            return next.concluding(.failed(.timeout), pause: nil, now: now, windows: windows)
        case (.dispatching, .hostReplyOverdue(let replyEpoch)) where replyEpoch == epoch,
             (.classifying, .hostReplyOverdue(let replyEpoch)) where replyEpoch == epoch:
            return next.concluding(.failed(.timeout), pause: nil, now: now, windows: windows)
        case (.dispatching, .host(let step, let replyEpoch)) where replyEpoch == epoch:
            return next.concluding(step, pause: windows.humanPauseEnds(now: now, grantExpiresAt: grantExpiresAt),
                                   now: now, windows: windows)
        case (.classifying(_, let pause, _), .host(let step, let replyEpoch)) where replyEpoch == epoch:
            // A repeated step keeps the original pause deadline.
            return next.concluding(step, pause: pause, now: now, windows: windows)

        case (.awaitingHuman(let kind, let pause, _), .opened(let lease)) where lease.step == humanStep?.id:
            next.phase = .awaitingHuman(kind, pause, lease)
            return (next, [.humanAudit("continuation_opened")])
        case (.awaitingHuman(let kind, let pause, let lease?), .humanFinished(let id)) where lease.id == id:
            next.phase = .classifying(kind, pause, .init(date: now.addingTimeInterval(windows.classifyReply)))
            next.epoch += 1
            return (next, [.humanAudit("human_finished")])
        case (.awaitingHuman(_, _, let lease?), .humanCancelled(let id)) where lease.id == id:
            return next.concluded(.failed(.humanCancelled), now: now, windows: windows,
                                  effects: [.humanAudit("human_cancelled"), .endHost])

        case (.awaitingHuman(let kind, let pause, let lease?), .connectionClosed(let connection))
            where lease.connection == connection:
            next.phase = .awaitingHuman(kind, pause, nil)
            return (next, [.humanAudit("continuation_closed")])

        case (.concluded, .agentCancelled):
            return (nil, [.audit("run_cancelled")])
        case (_, .agentCancelled):
            return (nil, [.audit("run_cancelled")] + (phase.hostMayHoldContext ? [.endHost] : []))

        case (_, .authorityLost):
            return (nil, [.audit("response_suppressed")] + (phase.hostMayHoldContext ? [.endHost] : []))

        case (.dispatching, .hostLost), (.awaitingHuman, .hostLost), (.classifying, .hostLost):
            return next.concluded(.failed(.sessionLost), now: now, windows: windows, effects: [.audit("session_lost")])

        case (.awaitingHuman(_, let pause, _), .clock(let time)) where time >= pause.date,
             (.classifying(_, let pause, _), .clock(let time)) where time >= pause.date:
            return next.concluded(.failed(.humanStepExpired), now: time, windows: windows,
                                  effects: [.audit("human_step_expired"), .endHost])
        // Nobody needs to be waiting: an unanswered host request ends at its deadline.
        case (.dispatching(let reply), .clock(let time)) where time >= reply.date,
             (.classifying(_, _, let reply), .clock(let time)) where time >= reply.date:
            return next.concluding(.failed(.timeout), pause: nil, now: time, windows: windows)
        case (.concluded(_, let collect), .clock(let time)) where time >= collect.date:
            return (nil, [.audit("result_uncollected")])

        case (.concluded, .collected):
            return (nil, [])

        default:
            // Stale host replies, foreign leases and events that do not apply leave the run unchanged.
            return (self, [])
        }
    }

    private func concluding(_ step: WebStep, pause: HumanPauseDeadline?, now: Date,
                            windows: LifecycleWindows) -> (BrowserRun?, [RunEffect]) {
        var next = self
        switch step {
        case .humanStep(let kind):
            guard let pause else { return concluding(.failed(.unexpectedPage), pause: nil, now: now, windows: windows) }
            next.challengeEpoch += 1
            next.phase = .awaitingHuman(kind, pause, nil)
            return (next, [.audit("human_step_required")])
        case .profile(let profile):
            return concluded(.profile(profile), now: now, windows: windows, effects: [.endHost])
        case .failed(let failure):
            return concluded(.failed(failure.failure), now: now, windows: windows,
                             effects: [.audit("web_" + failure.rawValue), .endHost])
        }
    }

    private func concluded(_ conclusion: RunConclusion, now: Date, windows: LifecycleWindows,
                           effects: [RunEffect]) -> (BrowserRun?, [RunEffect]) {
        var next = self
        let collect = windows.collectEnds(now: now, grantExpiresAt: grantExpiresAt)
        next.phase = .concluded(conclusion, collect)
        return (next, effects)
    }
}

/// Live authority for an already-reserved attempt. It deliberately ignores the remaining call
/// budget: the attempt is paid for, so the run that used a grant's last call stays collectable.
func stillAuthorized(_ binding: RunBinding, in state: VaultState, at now: Date) -> Bool {
    state.clients.contains { $0.id == binding.client && !$0.revoked } &&
        state.accounts.contains {
            $0.id == binding.account && $0.lifecycle == .active && $0.credentialID == binding.credential &&
                $0.service.action == binding.action
        } &&
        state.grants.contains {
            $0.id == binding.grant && !$0.revoked && $0.expiresAt > now && $0.clientID == binding.client &&
                $0.accountID == binding.account && $0.action == binding.action
        }
}
