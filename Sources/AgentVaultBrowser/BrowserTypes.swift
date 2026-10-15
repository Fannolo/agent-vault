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
    case profile(AccountProfile)
    case humanStepRequired(HumanStepKind)
    case failed(BrowserFailure)

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
