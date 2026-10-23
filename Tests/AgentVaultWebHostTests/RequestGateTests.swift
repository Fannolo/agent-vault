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
    @Test func productionOriginNeverMatchesSuffixesSubdomainsOtherPortsOrSchemes() {
        let production = RequestGate(policy: .production, workflow: .github)
        for address in ["https://github.com.evil.example/login", "https://evilgithub.com/login", "https://api.github.com/login",
                        "http://github.com/login", "https://github.com:8443/login", "https://user@github.com/login",
                        "data:text/html,x", "javascript:alert(1)", "about:blank", "file:///etc/passwd"] {
            let request = GateRequest(url: URL(string: address)!, method: "GET", resourceType: "Document", isMainFrame: true)
            #expect(production.decide(request, phase: .login) == .deny(.originMismatch))
        }
        let request = GateRequest(url: URL(string: "https://GITHUB.com:443/login")!, method: "GET",
                                  resourceType: "Document", isMainFrame: true)
        #expect(production.decide(request, phase: .login) == .allow)
    }

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

private let partner = URL(string: "http://127.0.0.1:4200")!
private let sitePolicy = HostPolicy.fixture(primary: primary, partner: partner)!.sites[.syntheticFixture]!
private let siteGate = SiteGate(policy: sitePolicy)

private func site(_ url: String, _ method: String = "GET", _ type: String = "Document", main: Bool = true,
                  in phase: SitePhase) -> GateDecision {
    siteGate.decide(GateRequest(url: URL(string: url)!, method: method, resourceType: type, isMainFrame: main), phase: phase)
}

@Suite struct SiteGateTests {
    @Test func theFilledFormsOwnPostIsTheOnlyWayOutOfTheLoginPhase() {
        let network = RunNetwork(gate: siteGate, mainFrame: "frame", phase: .login)
        func document(_ url: String, _ method: String) -> GateRequest {
            GateRequest(url: URL(string: url)!, method: method, resourceType: "Document", isMainFrame: true)
        }
        let away = document("http://127.0.0.1:4200/home", "GET")
        #expect(network.decide(away) == .deny(.unexpectedPage) && network.phase == .login)
        #expect(network.decide(document("http://127.0.0.1:4200/session", "POST")) == .deny(.originMismatch) && network.phase == .login)
        #expect(network.decide(document("http://127.0.0.1:4000/session", "POST")) == .allow && network.phase == .submitted)
        #expect(network.decide(away) == .allow, "its redirect")
    }

    @Test func navigationCredentialAndResourceOriginsAreSeparate() {
        // The agent may load and submit to navigation origins, including the partner.
        #expect(site("http://127.0.0.1:4000/notes", "POST", in: .agent) == .allow)
        #expect(site("http://127.0.0.1:4200/signin", in: .agent) == .allow)
        #expect(site("http://127.0.0.1:4200/session", "POST", in: .agent) == .allow)
        // While a login is in flight, the only POST destination is a credential origin.
        #expect(site("http://127.0.0.1:4000/session", "POST", in: .login) == .allow)
        #expect(site("http://127.0.0.1:4200/session", "POST", in: .login) == .deny(.originMismatch))
        // Nothing reaches an origin outside the policy: documents, frames, or GET subresources.
        for phase in [SitePhase.agent, .login, .submitted, .human] {
            #expect(site("http://127.0.0.1:4001/x", in: phase) == .deny(.originMismatch))
            #expect(site("http://127.0.0.1:4001/x", main: false, in: phase) == .deny(.originMismatch))
            #expect(site("http://127.0.0.1:4001/pixel?d=secret", "GET", "Image", in: phase) == .block)
            #expect(site("http://localhost:4000/x", in: phase) == .deny(.originMismatch))
            #expect(site("data:text/html,x", in: phase) == .deny(.originMismatch))
        }
        // A filled form waits to be sent: its own POST to a credential origin is the only document,
        // and no other origin receives anything that could carry the credential.
        #expect(site("http://127.0.0.1:4000/session?password=x", in: .login) == .deny(.unexpectedPage))
        #expect(site("http://127.0.0.1:4200/collect?password=x", in: .login) == .deny(.unexpectedPage))
        #expect(site("http://127.0.0.1:4200/collect?password=x", main: false, in: .login) == .deny(.originMismatch))
        #expect(site("http://127.0.0.1:4200/api", "POST", "XHR", in: .login) == .block)
        #expect(site("http://127.0.0.1:4000/api", "POST", "XHR", in: .login) == .allow)
        // After it is sent, its redirects may land on any page origin, and frames load again.
        #expect(site("http://127.0.0.1:4200/home", in: .submitted) == .allow)
        #expect(site("http://127.0.0.1:4200/frame", main: false, in: .submitted) == .allow)
        #expect(site("http://127.0.0.1:4200/session", "POST", in: .submitted) == .deny(.originMismatch))
        // Frames are read-only, and nothing loads once a session is locked.
        #expect(site("http://127.0.0.1:4000/frame", "POST", main: false, in: .agent) == .deny(.originMismatch))
        #expect(site("http://127.0.0.1:4000/home", in: .locked) == .deny(.unexpectedPage))
        #expect(site("http://127.0.0.1:4000/api", "POST", "XHR", in: .locked) == .block)
    }

    @Test func resourceOriginsArePassiveOnlyAndPoliciesAreValidated() throws {
        let cdn = WebOrigin(url: URL(string: "https://cdn.example.test"))!, app = WebOrigin(url: URL(string: "https://app.example.test"))!
        let policy = try #require(SitePolicy(entry: URL(string: "https://app.example.test/login")!, navigation: [app],
                                             credential: [app], authentication: [], resources: [cdn]))
        let gate = SiteGate(policy: policy)
        func ask(_ url: String, _ method: String, _ type: String) -> GateDecision {
            gate.decide(GateRequest(url: URL(string: url)!, method: method, resourceType: type, isMainFrame: true), phase: .agent)
        }
        #expect(ask("https://cdn.example.test/a.js", "GET", "Script") == .allow)
        #expect(ask("https://cdn.example.test/collect", "POST", "XHR") == .block)
        #expect(ask("https://cdn.example.test/", "GET", "Document") == .deny(.originMismatch))
        #expect(!gate.contentSecurityPolicy(phase: .agent).contains("cdn.example.test"))
        // Production compiles no continuing site; a credential origin must be a page the session can reach.
        #expect(HostPolicy.production.sites.isEmpty)
        #expect(SitePolicy(entry: URL(string: "https://app.example.test/")!, navigation: [app], credential: [cdn],
                           authentication: [], resources: []) == nil)
        #expect(SitePolicy(entry: URL(string: "https://elsewhere.test/")!, navigation: [app], credential: [app],
                           authentication: [], resources: []) == nil)
    }
}
