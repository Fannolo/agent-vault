@testable import AgentVaultWebHost
import AgentVaultContracts
import AgentVaultWebHostProtocol
import Foundation
import Testing

private let primary = URL(string: "http://127.0.0.1:4000")!
private let challenge = URL(string: "http://127.0.0.1:4100")!
private let gate = RequestGate(policy: HostPolicy.fixture(primary: primary, challenge: challenge)!, workflow: .fixture)

private func ask(_ url: String, _ method: String = "GET", _ type: String = "Document", main: Bool = true,
                 in phase: GatePhase) -> GateDecision {
    gate.decide(GateRequest(url: URL(string: url)!, method: method, resourceType: type, isMainFrame: main), phase: phase)
}

@Suite struct RequestGateTests {
    static let phases: [GatePhase] = [.login, .submitted, .human(.mfa), .human(.captcha), .locked]

    @Test(arguments: phases) func offOriginDocumentsAreHostileInEveryPhase(_ phase: GatePhase) {
        for url in ["http://127.0.0.1:4001/login", "http://localhost:4000/login", "https://127.0.0.1:4000/login",
                    "http://127.0.0.1/login", "http://user:pw@127.0.0.1:4000/login", "file:///etc/passwd",
                    "data:text/html,hi", "javascript:alert(1)"] {
            #expect(ask(url, in: phase) == .deny(.originMismatch), "\(url)")
            #expect(ask(url, main: false, in: phase) == .deny(.originMismatch) || url.hasPrefix("http://127.0.0.1:4100") , "\(url)")
        }
    }

    @Test func mainFrameNavigationFollowsThePhase() {
        let o = "http://127.0.0.1:4000"
        #expect(ask(o + "/login", in: .login) == .allow)
        #expect(ask(o + "/home", in: .login) == .deny(.unexpectedPage))
        #expect(ask(o + "/session", "POST", in: .login) == .deny(.unexpectedPage))
        #expect(ask(o + "/session", "POST", in: .submitted) == .allow)
        #expect(ask(o + "/elsewhere", "POST", in: .submitted) == .deny(.unexpectedPage))
        for path in ["/mfa", "/captcha", "/home", "/login"] { #expect(ask(o + path, in: .submitted) == .allow, "\(path)") }
        #expect(ask(o + "/settings", in: .submitted) == .deny(.unexpectedPage))
        #expect(ask(o + "/mfa-evil", in: .submitted) == .deny(.unexpectedPage), "prefixes match whole path segments")
        #expect(ask(o + "/step", "POST", in: .human(.mfa)) == .allow)
        #expect(ask(o + "/mfa", "POST", in: .human(.mfa)) == .allow)
        #expect(ask(o + "/session", "POST", in: .human(.mfa)) == .deny(.unexpectedPage))
        #expect(ask(o + "/settings/keys", in: .human(.mfa)) == .deny(.unexpectedPage), "the raster channel is not a browser")
        for path in ["/login", "/home", "/mfa", "/step"] {
            #expect(ask(o + path, in: .locked) == .deny(.unexpectedPage), "\(path)")
        }
    }

    @Test func subframesAndSubresourcesStayOnReviewedOrigins() {
        let o = "http://127.0.0.1:4000", c = "http://127.0.0.1:4100"
        #expect(ask(o + "/inner", main: false, in: .login) == .allow)
        #expect(ask(o + "/inner", "POST", main: false, in: .login) == .deny(.unexpectedPage))
        #expect(ask(c + "/frame", main: false, in: .human(.mfa)) == .deny(.originMismatch))
        #expect(ask(c + "/frame", main: false, in: .human(.captcha)) == .allow, "a reviewed challenge origin, only while shown")
        #expect(ask(c + "/frame", main: false, in: .login) == .deny(.originMismatch))
        #expect(ask(c + "/frame", in: .human(.captcha)) == .deny(.originMismatch), "never as the main frame")
        for type in ["Script", "Image", "Stylesheet", "XHR", "Fetch", "Ping", "EventSource", "Other"] {
            #expect(ask(o + "/x", "POST", type, in: .login) == .allow)
            #expect(ask("http://127.0.0.1:4001/x", "GET", type, main: false, in: .login) == .block, "\(type)")
            #expect(ask(c + "/x", "GET", type, main: false, in: .human(.mfa)) == .block)
            #expect(ask(c + "/x", "GET", type, main: false, in: .human(.captcha)) == .allow)
        }
        #expect(ask("data:image/png;base64,AA==", "GET", "Image", main: false, in: .login) == .block)
    }

    @Test func productionPolicyIsFixedToGitHubWithNoChallengeOrigins() {
        let production = HostPolicy.production
        #expect(production.primary.serialized == "https://github.com")
        #expect(production.challengeOrigins.isEmpty)
        #expect(Set(production.workflows.keys) == [.githubWebProfile])
        let gate = RequestGate(policy: production, workflow: .github)
        #expect(gate.decide(GateRequest(url: URL(string: "https://github.githubassets.com/a.js")!, method: "GET",
                                        resourceType: "Script", isMainFrame: false), phase: .login) == .allow)
        #expect(gate.decide(GateRequest(url: URL(string: "https://github.githubassets.com/a")!, method: "POST",
                                        resourceType: "XHR", isMainFrame: false), phase: .login) == .block)
        #expect(gate.decide(GateRequest(url: URL(string: "https://github.githubassets.com/")!, method: "GET",
                                        resourceType: "Document", isMainFrame: false), phase: .login) == .deny(.originMismatch))
        #expect(HostPolicy.fixture(primary: URL(string: "http://localhost:4000")!) == nil)
        #expect(HostPolicy.fixture(primary: URL(string: "https://127.0.0.1:4000")!) == nil)
        #expect(HostPolicy.fixture(primary: URL(string: "http://127.0.0.1")!) == nil)
    }

    @Test func contentSecurityPolicyConfinesConnectionsWorkersAndFrames() {
        let login = gate.contentSecurityPolicy(phase: .login)
        #expect(login.contains("connect-src http://127.0.0.1:4000;") && login.contains("worker-src 'none'"))
        #expect(login.contains("frame-src http://127.0.0.1:4000;") && login.contains("form-action http://127.0.0.1:4000"))
        #expect(!login.contains("4100"))
        #expect(gate.contentSecurityPolicy(phase: .human(.captcha)).contains("frame-src http://127.0.0.1:4000 http://127.0.0.1:4100;"))
        #expect(!gate.contentSecurityPolicy(phase: .human(.mfa)).contains("4100"))
    }
}

extension GatePhase: CustomTestStringConvertible {
    public var testDescription: String { "\(self)" }
}
