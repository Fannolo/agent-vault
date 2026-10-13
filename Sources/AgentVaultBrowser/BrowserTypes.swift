import AgentVaultContracts
import Foundation

public enum BrowserWorkflow: String, Sendable, CaseIterable {
    case demo
    case githubWebProfile

    public static func workflow(for action: WireAction) -> BrowserWorkflow? {
        switch action {
        case .browserDemo: .demo
        case .githubWebProfile: .githubWebProfile
        case .demoStatus, .githubProfile: nil
        }
    }
}

public enum HumanStepKind: String, Sendable, Equatable {
    case mfa
    case captcha
}

public struct WebProfile: Sendable, Equatable {
    public let login: String
    public let userID: Int?
    public init(login: String, userID: Int?) { self.login = login; self.userID = userID }
}

/// Closed failure codes. None of them carries a URL, page text or credential-derived data.
public enum BrowserFailure: String, Error, Sendable, Equatable {
    case unsupportedWorkflow = "unsupported_workflow"
    case invalidCredential = "invalid_credential"
    case busy
    case originMismatch = "origin_mismatch"
    case unexpectedPage = "unexpected_page"
    case loginRejected = "login_rejected"
    case timeout
    case sessionUnavailable = "session_unavailable"
    case sessionRevoked = "session_revoked"
    case loadFailed = "load_failed"
    case invalidProfile = "invalid_profile"
}

public enum BrowserOutcome: Sendable, Equatable {
    case profile(WebProfile)
    case humanStepRequired(HumanStepKind)
    case failed(BrowserFailure)

    /// Closed status vocabulary for the wire reply.
    public var wireStatus: String {
        switch self {
        case .profile: "completed"
        case .humanStepRequired: "human_step_required"
        case .failed(let failure): "failed:" + failure.rawValue
        }
    }

    public func readReply(requestID: UUID? = nil) -> ReadReply {
        switch self {
        case .profile(let profile):
            ReadReply(status: wireStatus, requestID: requestID, login: profile.login, userID: profile.userID)
        case .humanStepRequired, .failed:
            ReadReply(status: wireStatus, requestID: requestID)
        }
    }
}

public struct BrowserTimeouts: Sendable {
    public var load: Duration
    public var navigation: Duration
    public var humanPause: Duration
    /// Time allowed for hostile in-page redirects to surface before credentials are injected.
    public var settle: Duration

    public static let production = BrowserTimeouts(load: .seconds(30), navigation: .seconds(30),
                                                   humanPause: .seconds(600), settle: .milliseconds(150))
    public init(load: Duration, navigation: Duration, humanPause: Duration, settle: Duration) {
        self.load = load; self.navigation = navigation; self.humanPause = humanPause; self.settle = settle
    }
}

/// Username + password for a web login. Wire form: UTF-8 `username`, LF, `password`.
public struct WebCredential: Sendable {
    let username: String
    let password: String

    public init?(wireBytes: Data) {
        guard wireBytes.count <= 4096, let text = String(data: wireBytes, encoding: .utf8) else { return nil }
        let parts = text.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty, parts[0].count <= 255,
              !parts[0].unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              !parts[1].unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
        else { return nil }
        username = String(parts[0]); password = String(parts[1])
    }
}

extension WebCredential: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String { "WebCredential(redacted)" }
    public var debugDescription: String { description }
}
