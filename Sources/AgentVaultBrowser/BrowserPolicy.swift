import AgentVaultContracts
import Foundation

/// Fixed selectors and URL shapes for one reviewed workflow. These are code constants;
/// nothing here is derived from a caller, a page or a tool argument.
struct WorkflowDefinition: Sendable {
    let loginPath: String
    let formSelector: String
    let usernameSelector: String
    let passwordSelector: String
    let submitSelector: String
    let humanStepPaths: [(prefix: String, kind: HumanStepKind)]
    let captchaSelector: String
    let profileLoginSelector: String
    let profileIDSelector: String

    static let github = WorkflowDefinition(
        loginPath: "/login",
        formSelector: "form[action=\"/session\"]",
        usernameSelector: "#login_field",
        passwordSelector: "#password",
        submitSelector: "input[type=\"submit\"][name=\"commit\"]",
        humanStepPaths: [("/sessions/two-factor", .mfa), ("/sessions/verified-device", .mfa),
                         ("/login/device", .mfa), ("/sessions/recovery", .mfa)],
        captchaSelector: "#captcha-container, iframe[src*=\"arkoselabs\"]",
        profileLoginSelector: "head > meta[name=\"user-login\"]",
        profileIDSelector: "head > meta[name=\"octolytics-actor-id\"]")

    static let fixture = WorkflowDefinition(
        loginPath: "/login",
        formSelector: "form[action=\"/session\"]",
        usernameSelector: "#login_field",
        passwordSelector: "#password",
        submitSelector: "input[type=\"submit\"][name=\"commit\"]",
        humanStepPaths: [("/mfa", .mfa), ("/captcha", .captcha)],
        captchaSelector: "#captcha-container",
        profileLoginSelector: "head > meta[name=\"user-login\"]",
        profileIDSelector: "head > meta[name=\"octolytics-actor-id\"]")
}

/// Which origins a browser session may touch and which fixed workflows exist there.
/// Production is fixed to HTTPS GitHub. The loopback fixture policy is a package-internal
/// debug-build facility that only automated verification can construct.
public struct BrowserPolicy: Sendable {
    let primary: WebOrigin
    let assetOrigins: [WebOrigin]
    let workflows: [BrowserWorkflow: WorkflowDefinition]

    /// Production: GitHub web profile only. `browser.demo` has no production origin.
    // ASSUMPTION (unverified live): github.com serves its login form, profile meta tags and
    // static assets from exactly these origins. Verify with a real account before relying on it.
    public static let production = BrowserPolicy(
        primary: WebOrigin(url: URL(string: "https://github.com"))!,
        assetOrigins: [WebOrigin(url: URL(string: "https://github.githubassets.com"))!,
                       WebOrigin(url: URL(string: "https://avatars.githubusercontent.com"))!],
        workflows: [.githubWebProfile: .github])

    #if DEBUG
    /// Trusted test configuration only: plain HTTP on a loopback IP literal with an explicit port.
    package static func fixture(origin: URL) -> BrowserPolicy? {
        guard let parsed = WebOrigin(url: origin), parsed.scheme == "http", parsed.host == "127.0.0.1",
              origin.port != nil else { return nil }
        return BrowserPolicy(primary: parsed, assetOrigins: [], workflows: [.demo: .fixture])
    }
    #endif

    var allowedOrigins: [WebOrigin] { [primary] + assetOrigins }

    /// Block everything, then re-allow only the exact allowed origins. Applies to subresources
    /// and subframes; main-frame navigation is separately restricted by the navigation policy.
    package var contentRuleListJSON: String {
        var rules: [[String: Any]] = [["trigger": ["url-filter": ".*"], "action": ["type": "block"]]]
        for origin in allowedOrigins {
            rules.append(["trigger": ["url-filter": origin.contentRuleFilter],
                          "action": ["type": "ignore-previous-rules"]])
        }
        // JSONSerialization of fixed literals cannot fail.
        let data = try! JSONSerialization.data(withJSONObject: rules)
        return String(decoding: data, as: UTF8.self)
    }
}
