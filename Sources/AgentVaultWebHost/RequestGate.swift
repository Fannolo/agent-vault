import AgentVaultContracts
import AgentVaultWebHostProtocol
import Foundation

/// An exact scheme + host + port. No suffix, subdomain or wildcard matching.
struct WebOrigin: Hashable, Sendable {
    let scheme: String
    let host: String
    let port: Int

    init?(url: URL?) {
        guard let url, let scheme = url.scheme?.lowercased(), let host = url.host?.lowercased(),
              scheme == "https" || scheme == "http", !host.isEmpty, url.user == nil, url.password == nil else { return nil }
        self.scheme = scheme; self.host = host; self.port = url.port ?? (scheme == "https" ? 443 : 80)
    }

    /// JavaScript `location.origin` spelling; also the CSP source expression.
    var serialized: String {
        let isDefault = (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
        return isDefault ? "\(scheme)://\(host)" : "\(scheme)://\(host):\(port)"
    }

    func url(path: String) -> URL? { URL(string: serialized + path) }
}

/// Selectors and paths of one reviewed workflow. Code constants only.
struct WorkflowDefinition: Sendable {
    let loginPath: String
    let formActionPath: String
    let formSelector: String
    let usernameSelector: String
    let passwordSelector: String
    let submitSelector: String
    /// Main-frame paths that mean a person must act, by kind.
    let humanStepPaths: [(prefix: String, kind: HumanStepKind)]
    /// Where the person's step form may post.
    let humanSubmitPaths: [String]
    /// Pages the site lands on after a successful login or step; the profile is read there.
    let landingPaths: [String]
    let captchaSelector: String
    /// The only region a person is shown, per step kind. Missing or ambiguous: nothing is shown.
    let challengeSelectors: [HumanStepKind: String]
    let profileLoginSelector: String
    let profileIDSelector: String

    // ASSUMPTION (unverified live, gate P4): GitHub's paths, selectors and landing page.
    static let github = WorkflowDefinition(
        loginPath: "/login", formActionPath: "/session", formSelector: "form[action=\"/session\"]",
        usernameSelector: "#login_field", passwordSelector: "#password",
        submitSelector: "input[type=\"submit\"][name=\"commit\"]",
        humanStepPaths: [("/sessions/two-factor", .mfa), ("/sessions/verified-device", .mfa),
                         ("/login/device", .mfa), ("/sessions/recovery", .mfa)],
        humanSubmitPaths: ["/sessions/two-factor", "/sessions/verified-device", "/login/device"],
        landingPaths: ["/"],
        captchaSelector: "#captcha-container, iframe[src*=\"arkoselabs\"]",
        challengeSelectors: [.mfa: "form[action^=\"/sessions/two-factor\"], form[action^=\"/sessions/verified-device\"]",
                             .captcha: "#captcha-container"],
        profileLoginSelector: "head > meta[name=\"user-login\"]",
        profileIDSelector: "head > meta[name=\"octolytics-actor-id\"]")

    static let fixture = WorkflowDefinition(
        loginPath: "/login", formActionPath: "/session", formSelector: "form[action=\"/session\"]",
        usernameSelector: "#login_field", passwordSelector: "#password",
        submitSelector: "input[type=\"submit\"][name=\"commit\"]",
        humanStepPaths: [("/mfa", .mfa), ("/captcha", .captcha)], humanSubmitPaths: ["/step"],
        landingPaths: ["/home"], captchaSelector: "#captcha-container",
        challengeSelectors: [.mfa: "form[action=\"/step\"]", .captcha: "form[action=\"/step\"]"],
        profileLoginSelector: "head > meta[name=\"user-login\"]",
        profileIDSelector: "head > meta[name=\"octolytics-actor-id\"]")

    func stepKind(path: String) -> HumanStepKind? {
        humanStepPaths.first { path == $0.prefix || path.hasPrefix($0.prefix + "/") }?.kind
    }
}

/// Which origins a run may touch and which workflows exist there.
struct HostPolicy: Sendable {
    let primary: WebOrigin
    let assetOrigins: [WebOrigin]
    /// Reviewed third-party challenge origins, allowed only while a CAPTCHA step is shown.
    let challengeOrigins: [WebOrigin]
    let workflows: [HostWorkflow: WorkflowDefinition]

    // ASSUMPTION (unverified live, gate P4). Challenge origins start empty: a CAPTCHA that needs
    // a third-party frame fails closed until a live review adds exactly its origin.
    static let production = HostPolicy(
        primary: WebOrigin(url: URL(string: "https://github.com"))!,
        assetOrigins: [WebOrigin(url: URL(string: "https://github.githubassets.com"))!,
                       WebOrigin(url: URL(string: "https://avatars.githubusercontent.com"))!],
        challengeOrigins: [], workflows: [.githubWebProfile: .github])

    #if DEBUG
    /// Automated verification only: plain HTTP on loopback IP literals with explicit ports.
    static func fixture(primary: URL, challenge: URL? = nil) -> HostPolicy? {
        func loopback(_ url: URL?) -> WebOrigin? {
            guard let url, let origin = WebOrigin(url: url), origin.scheme == "http", origin.host == "127.0.0.1",
                  url.port != nil else { return nil }
            return origin
        }
        guard let origin = loopback(primary) else { return nil }
        let challengeOrigin = challenge.flatMap(loopback)
        if challenge != nil && challengeOrigin == nil { return nil }
        return HostPolicy(primary: origin, assetOrigins: [], challengeOrigins: challengeOrigin.map { [$0] } ?? [],
                          workflows: [.browserDemo: .fixture])
    }
    #endif
}

/// Where a run is, as far as the network is concerned.
enum GatePhase: Equatable, Sendable {
    /// Loading the login page and filling it.
    case login
    /// The login form was submitted: its POST and the redirects it may produce.
    case submitted
    /// A person may act on this step: step paths, the step form, landing and login pages.
    case human(HumanStepKind)
    /// Reading or concluded: no further documents.
    case locked
}

struct GateRequest: Equatable, Sendable {
    let url: URL
    let method: String
    /// CDP `Network.ResourceType`, for example `Document`, `Script`, `Image`, `XHR`.
    let resourceType: String
    let isMainFrame: Bool
}

enum GateDecision: Equatable, Sendable {
    case allow
    /// A subresource refused quietly: the page may work without it.
    case block
    /// A document refused: the run concludes with this failure at its next checkpoint.
    case deny(HostFailure)
}

/// Pure, phase-aware decisions for every request the page makes. No state, no I/O.
struct RequestGate: Sendable {
    let policy: HostPolicy
    let workflow: WorkflowDefinition

    func decide(_ request: GateRequest, phase: GatePhase) -> GateDecision {
        guard let origin = WebOrigin(url: request.url) else {
            return request.resourceType == "Document" ? .deny(.originMismatch) : .block
        }
        let method = request.method.uppercased()
        let challengeShown: Bool = if case .human(.captcha) = phase { true } else { false }
        let documentOrigins = [policy.primary] + (challengeShown ? policy.challengeOrigins : [])
        if request.resourceType == "Document" {
            guard request.isMainFrame else {
                // Subframes: the primary origin, or a reviewed challenge origin while it is shown.
                guard documentOrigins.contains(origin) else { return .deny(.originMismatch) }
                return method == "GET" ? .allow : .deny(.unexpectedPage)
            }
            guard origin == policy.primary else { return .deny(.originMismatch) }
            return allowsMainFrame(path: request.url.path, method: method, phase: phase) ? .allow : .deny(.unexpectedPage)
        }
        if origin == policy.primary { return .allow }
        let readOnly = method == "GET" || method == "HEAD"
        if readOnly && policy.assetOrigins.contains(origin) { return .allow }
        if challengeShown && policy.challengeOrigins.contains(origin) { return .allow }
        return .block
    }

    private func allowsMainFrame(path: String, method: String, phase: GatePhase) -> Bool {
        let landing = workflow.landingPaths.contains(path)
        let step = workflow.stepKind(path: path) != nil
        switch phase {
        case .login:
            return method == "GET" && path == workflow.loginPath
        case .submitted:
            if method == "POST" { return path == workflow.formActionPath }
            return method == "GET" && (step || landing || path == workflow.loginPath)
        case .human:
            if method == "POST" { return step || workflow.humanSubmitPaths.contains(path) }
            return method == "GET" && (step || landing || path == workflow.loginPath)
        case .locked:
            return false
        }
    }

    /// Added to every document response (multiple policies all apply, so a page cannot loosen it).
    /// Measured on Chrome for Testing 149: with this header delivered through `Fetch.fulfillRequest`,
    /// WebSocket handshakes to any origin, service worker registration, off-origin frames, beacons
    /// and fetches are refused before they leave the renderer.
    func contentSecurityPolicy(phase: GatePhase) -> String {
        let primary = policy.primary.serialized
        let challengeShown: Bool = if case .human(.captcha) = phase { true } else { false }
        let frames = ([primary] + (challengeShown ? policy.challengeOrigins.map(\.serialized) : [])).joined(separator: " ")
        return "connect-src \(primary); worker-src 'none'; frame-src \(frames); object-src 'none'; "
            + "base-uri 'none'; form-action \(primary); prefetch-src 'none'"
    }
}
