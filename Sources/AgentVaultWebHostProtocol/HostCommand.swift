import AgentVaultCredentials
import AgentVaultContracts
import Foundation

// The broker <-> web host vocabulary. Credential bytes cross only in `start`, so this module is
// linked by the broker daemon's host link and by the host, never by Core, the app or the bridge.
// No command names an origin, selector, script, CDP method or policy: the host owns those. The
// one URL a command carries (`SiteCommand.navigate`) is a request the host's site policy decides.

/// One Mach service, accepted only from the broker's UID and code requirement.
@objc public protocol WebHostRPC {
    /// An empty payload is the authentication probe: answered with `invalid_request`, never dispatched.
    func perform(_ data: Data, reply: @escaping (Data) -> Void)
}

/// Fixed workflows. The host compiles each one's origins, paths and recipes.
public enum HostWorkflow: String, CaseIterable, Sendable {
    case browserDemo, githubWebProfile
}

public enum HostCommand: Sendable, Equatable {
    /// `lifetime` caps the browser context in seconds even if the broker never sends `end`.
    case start(run: UUID, workflow: HostWorkflow, credential: WebLoginCredential, lifetime: Int)
    /// Re-examine the page after a person says they finished. Never submits anything.
    case classify(run: UUID)
    /// Idempotent. Disposes the context, and refuses any later `start` for this run.
    case end(run: UUID)
    /// Begin raster capture of the paused step numbered `step` by the broker.
    case showHuman(run: UUID, step: UInt64)
    /// The latest frame of `step` newer than `after`.
    case frame(run: UUID, step: UInt64, after: UInt64)
    /// Events aimed at frame `frame` of `step`; refused unless that frame is still the latest.
    case input(run: UUID, step: UInt64, frame: UInt64, batch: HumanInputBatch)

    // Continuing-site sessions. Their IDs share the run namespace: `end` disposes either, and an
    // ended ID is never opened or started again. Run commands never reach a session and vice versa.

    /// A new context on the site's own entry page. No credential crosses.
    case openSite(session: UUID, site: HostSite, lifetime: Int)
    case siteObserve(session: UUID)
    /// Fills and submits the credential only if the page the host observes is eligible for it.
    /// `operation` deduplicates retries of the login with the same `account`; with another
    /// account or version it is refused.
    case siteLogin(session: UUID, operation: UUID, account: CredentialVersion, credential: WebLoginCredential)
    /// `operation` deduplicates retries: the same ID with a different command is refused.
    case siteOperate(session: UUID, operation: UUID, command: SiteCommand)
    /// A person takes control: agent observation and input are refused until release. Takeover and
    /// release answer an observation (at least the page's identity, mode and control epoch) or a
    /// rejection: one made before control changed, or `unknownRun` once the session ended, which it
    /// does when a handover cannot be completed safely (the agent's control is gone either way). Never
    /// a failure that would hide the change.
    case siteTakeover(session: UUID)
    case siteRelease(session: UUID)

    public static let maximumLifetime = 900

    public var run: UUID {
        switch self {
        case .start(let run, _, _, _), .classify(let run), .end(let run), .showHuman(let run, _),
             .frame(let run, _, _), .input(let run, _, _, _): run
        case .openSite(let session, _, _), .siteObserve(let session), .siteLogin(let session, _, _, _),
             .siteOperate(let session, _, _), .siteTakeover(let session), .siteRelease(let session): session
        }
    }

    /// How the transport schedules a command: teardown is never queued behind frames.
    public var lane: HostLane {
        switch self {
        case .end: .teardown
        case .frame: .frame
        case .start, .classify, .showHuman, .input, .openSite, .siteObserve, .siteLogin, .siteOperate,
             .siteTakeover, .siteRelease: .control
        }
    }
}

public enum HostLane: CaseIterable, Sendable { case control, frame, teardown }

/// One numbered command. The reply must echo both the number and the run.
public struct HostRequest: Sendable, Equatable {
    public let id: UInt64
    public let command: HostCommand
    public init(id: UInt64, command: HostCommand) { self.id = id; self.command = command }
}

/// Precise workflow outcomes. The broker records them in audit; agents never see them.
public enum HostFailure: String, CaseIterable, Sendable {
    case invalidCredential = "invalid_credential", originMismatch = "origin_mismatch"
    case unexpectedPage = "unexpected_page", loginRejected = "login_rejected", timeout
    case loadFailed = "load_failed", invalidProfile = "invalid_profile"
    case challengeOriginBlocked = "challenge_origin_blocked", rendererUnavailable = "renderer_unavailable"
}

/// Why the host refused a command without acting on it.
public enum HostRejection: String, CaseIterable, Sendable {
    /// No live context: never started, ended, expired or tombstoned.
    case unknownRun = "unknown_run"
    case busy
    case unsupportedWorkflow = "unsupported_workflow"
    case duplicateRun = "duplicate_run"
    /// The run is not paused on a human step.
    case notPaused = "not_paused"
    /// The step or frame named by the command is no longer the current one.
    case staleStep = "stale_step"
    /// The challenge region could not be established, so nothing is shown.
    case captureUnavailable = "capture_unavailable"
    /// No site policy is compiled for this site in this build.
    case unsupportedSite = "unsupported_site"
    /// The target's document, control epoch or element is no longer current, or is not that kind.
    case staleTarget = "stale_target"
    /// The site policy does not allow this navigation or input.
    case notPermitted = "not_permitted"
    /// A person has control of the session.
    case humanControl = "human_control"
    /// This operation ID already names a different command.
    case operationConflict = "operation_conflict"
    /// This operation ID is still being performed.
    case operationInFlight = "operation_in_flight"
    /// The observed page is not on a credential origin of the site: nothing was filled.
    case credentialOrigin = "credential_origin"
    /// The page has no single login form this host supports; a person must sign in.
    case unsupportedLogin = "unsupported_login"
}

public enum HostReply: Sendable, Equatable {
    case profile(AccountProfile)
    case humanStep(HumanStepKind)
    case failed(HostFailure)
    case frame(step: UInt64, HumanFrame)
    case noFrame(step: UInt64)
    case accepted
    case ended
    case rejected(HostRejection)
    case site(SiteObservation)
    /// The operation was dispatched but its effect is uncertain. Never performed again. After a site
    /// operation may have acted, every later error (a refused request, a failed load, the session
    /// ending) is reported as this, never as `rejected` or `failed`, which mean it did not act.
    case siteUnknown

    /// The replies each command may receive; anything else is a protocol violation.
    public func answers(_ command: HostCommand) -> Bool {
        switch (command, self) {
        case (.start, .profile), (.start, .humanStep), (.start, .failed), (.start, .rejected),
             (.classify, .profile), (.classify, .humanStep), (.classify, .failed), (.classify, .rejected),
             (.end, .ended),
             (.showHuman, .accepted), (.showHuman, .rejected),
             (.input, .accepted), (.input, .rejected),
             (.frame, .rejected),
             (.openSite, .site), (.openSite, .failed), (.openSite, .rejected),
             (.siteObserve, .site), (.siteObserve, .failed), (.siteObserve, .rejected),
             (.siteLogin, .site), (.siteLogin, .failed), (.siteLogin, .rejected), (.siteLogin, .siteUnknown),
             (.siteOperate, .site), (.siteOperate, .failed), (.siteOperate, .rejected), (.siteOperate, .siteUnknown),
             (.siteTakeover, .site), (.siteTakeover, .rejected), (.siteRelease, .site), (.siteRelease, .rejected):
            true
        case (.frame(_, let step, let after), .frame(let replyStep, let frame)):
            replyStep == step && frame.sequence > after
        case (.frame(_, let step, _), .noFrame(let replyStep)):
            replyStep == step
        default:
            false
        }
    }
}

public struct HostResponse: Sendable, Equatable {
    public let request: UInt64
    public let run: UUID
    public let reply: HostReply
    public init(request: UInt64, run: UUID, reply: HostReply) {
        self.request = request; self.run = run; self.reply = reply
    }

    public func answers(_ request: HostRequest) -> Bool {
        self.request == request.id && run == request.command.run && reply.answers(request.command)
    }
}
