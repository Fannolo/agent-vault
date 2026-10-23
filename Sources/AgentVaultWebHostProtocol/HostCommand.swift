import AgentVaultCredentials
import AgentVaultContracts
import Foundation

// The broker <-> web host vocabulary. Credential bytes cross only in `start`, so this module is
// linked by the broker daemon's host link and by the host, never by Core, the app or the bridge.
// No command names a URL, origin, selector, script, CDP method or policy: the host owns those.

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

    public static let maximumLifetime = 900

    public var run: UUID {
        switch self {
        case .start(let run, _, _, _), .classify(let run), .end(let run), .showHuman(let run, _),
             .frame(let run, _, _), .input(let run, _, _, _): run
        }
    }

    /// How the transport schedules a command: teardown is never queued behind frames.
    public var lane: HostLane {
        switch self {
        case .end: .teardown
        case .frame: .frame
        case .start, .classify, .showHuman, .input: .control
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

    /// The replies each command may receive; anything else is a protocol violation.
    public func answers(_ command: HostCommand) -> Bool {
        switch (command, self) {
        case (.start, .profile), (.start, .humanStep), (.start, .failed), (.start, .rejected),
             (.classify, .profile), (.classify, .humanStep), (.classify, .failed), (.classify, .rejected),
             (.end, .ended),
             (.showHuman, .accepted), (.showHuman, .rejected),
             (.input, .accepted), (.input, .rejected),
             (.frame, .rejected):
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
