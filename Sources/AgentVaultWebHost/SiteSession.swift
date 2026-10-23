@_spi(CredentialUse) import AgentVaultCredentials
import AgentVaultContracts
import AgentVaultWebHostProtocol
import Foundation

/// Hands out document epochs for every session of one host, so an epoch names one document only
/// and a target from one session can never match a document of another.
final class DocumentEpochs: @unchecked Sendable {
    private let lock = NSLock()
    private var last: UInt64 = 0
    func next() -> UInt64 { lock.withLock { last += 1; return last } }
}

/// One continuing-site session: one host-created incognito context with one page that logs in
/// privately and then accepts closed, typed operations under its site policy.
///
/// The credential is used only on a page the host itself observes on a credential origin, and
/// exists only inside `login`. Targets are rechecked against the live document, the control epoch
/// and the agent's control, and the element is rechecked and acted on in one recipe call. Operation IDs are remembered for the
/// session's life (in host memory only): a retry gets the first reply, never a second dispatch.
actor SiteSession {
    /// What an operation ID was first used for. A credential is never recorded.
    enum Recorded: Equatable, Sendable { case login, operate(SiteCommand) }

    static let journalCapacity = 1024

    private struct Document {
        let loader: String
        let epoch: UInt64
        /// The isolated world holding this document's element table, once created.
        var world: Int?
    }

    let id: UUID
    private let pipe: ChromiumPipe
    private let router: EventRouter
    private let policy: SitePolicy
    private let timing: WebRun.Timing
    private let epochs: DocumentEpochs
    private var context: String?
    private var target: String?
    private var session: String?
    private var network: RunNetwork<SiteGate>?
    private var mode = SiteMode.agent
    private var auth = SiteAuth.signedOut
    private var control: UInt64 = 1
    private var document: Document?
    private var journal: [UUID: (command: Recorded, reply: HostReply?)] = [:]
    /// One operation at a time: another operation or observation waits for none, it is refused.
    /// Takeover, release and end never wait for it.
    private var operating = false
    private var ended = false

    /// Named suspension points. Debug builds await a test hook there, so a test can interleave a
    /// command at exactly that point; release builds do nothing.
    enum Checkpoint: Sendable { case loginDocument, loginFilled, beforeInput, dispatched, observed }

    #if DEBUG
    typealias Hook = @Sendable (UUID, Checkpoint) async -> Void
    final class Hooks: @unchecked Sendable {
        private let lock = NSLock()
        private var current: Hook?
        var hook: Hook? {
            get { lock.withLock { current } }
            set { lock.withLock { current = newValue } }
        }
    }
    static let hooks = Hooks()
    #endif

    private func pause(_ point: Checkpoint) async {
        #if DEBUG
        if let hook = Self.hooks.hook { await hook(id, point) }
        #endif
    }

    init(id: UUID, pipe: ChromiumPipe, router: EventRouter, policy: SitePolicy, epochs: DocumentEpochs, timing: WebRun.Timing) {
        self.id = id; self.pipe = pipe; self.router = router; self.policy = policy; self.epochs = epochs; self.timing = timing
    }

    // MARK: Lifecycle

    /// Creates the context and page and loads the policy's own entry page.
    func open() async -> HostReply {
        do { try await create() } catch { return .failed(.rendererUnavailable) }
        let before = network?.loads ?? 0
        guard await load(policy.entry) else { return .failed(network?.takeFailure() ?? .loadFailed) }
        await settle(loadedAfter: before)
        if let failure = network?.takeFailure() { return .failed(failure) }
        return await observation()
    }

    private func create() async throws {
        let created = try await pipe.call(.targetCreateBrowserContext, ["disposeOnDetach": true])
        guard let context = created["browserContextId"]?.string else { throw CDPError.protocolError }
        self.context = context
        if ended { _ = await dispose(); throw CDPError.closed }
        _ = try await pipe.call(.browserSetDownloadBehavior, ["behavior": "deny", "browserContextId": context])
        router.beginCreation()
        let page = try? await pipe.call(.targetCreateTarget, ["url": "about:blank", "browserContextId": context])
        let target = page?["targetId"]?.string
        router.endCreation(target)
        guard let target, !ended else { throw CDPError.closed }
        self.target = target
        guard let session = await router.claimSession(for: target), !ended else { throw CDPError.closed }
        self.session = session
        let network = RunNetwork(gate: SiteGate(policy: policy), mainFrame: target, phase: .agent)
        self.network = network
        router.register(session: session, network: network)
        for (method, params) in WebRun.pageSetup {
            _ = try await pipe.call(method, params, session: session)
        }
        _ = try await pipe.call(.runtimeRunIfWaitingForDebugger, [:], session: session)
    }

    /// Disposes the context. Idempotent; returns whether the browser confirmed it.
    func dispose() async -> Bool {
        ended = true
        network?.phase = .locked
        if let target { router.forget(target: target, sessions: session.map { [$0] } ?? []) }
        guard let context else { return true }
        self.context = nil
        return (try? await pipe.call(.targetDisposeBrowserContext, ["browserContextId": context], timeout: 2)) != nil
    }

    // MARK: Agent commands

    func observe() async -> HostReply {
        guard !ended else { return .rejected(.unknownRun) }
        guard mode == .agent else { return .rejected(.humanControl) }
        guard !operating else { return .rejected(.busy) }
        return await observation()
    }

    func operate(_ operation: UUID, _ command: SiteCommand) async -> HostReply {
        await journaled(operation, .operate(command)) {
            guard command.fits else { return .rejected(.notPermitted) }
            guard mode == .agent else { return .rejected(.humanControl) }
            let held = control
            _ = network?.takeFailure()
            switch command {
            case .navigate(let text): return await navigate(text, held)
            case .click(let target): return await click(target)
            case .typePublic(let target, let text): return await type(target, text)
            case .select(let target, let option): return await choose(target, option)
            case .press(let key): return await dispatch(Self.key(key), held)
            case .scroll(let dy): return await scroll(dy, held)
            }
        }
    }

    /// Fills and submits the page's single login form, only if the page the host observes now is on
    /// a credential origin and the form posts to one. Nothing the caller supplied decides that.
    func login(_ operation: UUID, _ credential: WebLoginCredential) async -> HostReply {
        await journaled(operation, .login) {
            let reply = await attemptLogin(credential)
            // Unless signed in by this login, a password the host filled must not stay in a page the
            // agent operates. On a new document there is nothing to clear.
            if case .site = reply, auth == .signedIn { return reply }
            _ = await run(.loginClear, origins: policy.navigation + policy.credential, [:])
            return reply
        }
    }

    private func attemptLogin(_ credential: WebLoginCredential) async -> HostReply {
        guard mode == .agent else { return .rejected(.humanControl) }
        let held = control
        _ = network?.takeFailure()
        guard let (url, page) = await currentDocument(), let origin = WebOrigin(url: url),
              policy.credential.contains(origin) else { return .rejected(.credentialOrigin) }
        await pause(.loginDocument)
        // Taken over (and perhaps released) while reading the page: nothing is filled.
        guard holds(held) else { return fenced }
        network?.phase = .login
        defer { restorePhase() }
        var fields: [String: Any] = [:]
        credential.withLoginBytes { username, password in
            fields["username"] = String(decoding: username, as: UTF8.self)
            fields["password"] = String(decoding: password, as: UTF8.self)
        }
        let filled = await run(.loginFill, origins: policy.credential, fields, while: held)
        fields = [:]
        switch filled {
        case .sent(.string("ok")?): break
        case .sent(.string("origin")?): return .rejected(.credentialOrigin)
        case .notRun where !holds(held): return fenced
        default: return .rejected(.unsupportedLogin)
        }
        try? await Task.sleep(for: timing.settle)
        await pause(.loginFilled)
        // Taken over, ended or replaced while filling: the form stays unsubmitted.
        guard holds(held) else { return fenced }
        guard await currentDocument()?.document.epoch == page.epoch else { return .rejected(.staleTarget) }
        if let failure = network?.takeFailure() { return .failed(failure) }
        let before = network?.loads ?? 0
        switch await run(.loginSubmit, origins: policy.credential, [:], while: held) {
        case .sent(.string("ok")?): break
        case .sent(.string?): return .rejected(.unsupportedLogin)
        case .notRun: return holds(held) ? .rejected(.staleTarget) : fenced
        case .sent: return .siteUnknown
        }
        return await dispatched(loadedAfter: before, judgingLogin: true)
    }

    /// A person takes control: agent observation and input stop, and every earlier target expires.
    func takeover() async -> HostReply {
        guard !ended else { return .rejected(.unknownRun) }
        // Still opening: there is no page to hand over yet, and nothing changes.
        guard document != nil else { return .rejected(.busy) }
        if mode == .agent { fence(.human) }
        return await controlReply()
    }

    /// Control returns to the agent with a new control epoch: targets seen before release expire.
    func release() async -> HostReply {
        guard !ended else { return .rejected(.unknownRun) }
        guard document != nil else { return .rejected(.busy) }
        if mode == .human {
            fence(.agent)
            // The person decided to return control; the page's state is reported, not enforced.
            if auth == .humanRequired || auth == .rejected { await judgeLogin(handOver: false) }
        }
        return await controlReply()
    }

    /// Control may just have changed hands, so the reply always carries the mode and control epoch:
    /// a page that cannot be read yields its last known identity instead of a failure.
    private func controlReply() async -> HostReply {
        let reply = await observation()
        guard case .failed = reply, let page = document else { return reply }
        return .site(summary(page.epoch))
    }

    /// Whether the agent still holds the control generation an operation began under. Takeover and
    /// release both bump `control`, so after any suspension an operation goes on only while this holds.
    private func holds(_ held: UInt64) -> Bool { !ended && mode == .agent && control == held }

    /// The refusal for an operation whose hold ended before it acted.
    private var fenced: HostReply {
        ended ? .rejected(.unknownRun) : mode == .human ? .rejected(.humanControl) : .rejected(.staleTarget)
    }

    private func fence(_ next: SiteMode) {
        mode = next
        control += 1
        restorePhase()
    }

    /// The network phase that matches who is in control; never reopens an ended session.
    private func restorePhase() {
        guard !ended else { return }
        network?.phase = mode == .agent ? .agent : .human
    }

    /// Signed in unless the page still shows a password form or asks for a one-time code, which a
    /// person must enter: after a login the session then passes to them.
    private func judgeLogin(handOver: Bool) async {
        guard await currentDocument() != nil,
              case .object(let state)? = await run(.authState, origins: policy.navigation + policy.credential, [:]).value else {
            auth = .rejected
            return
        }
        if state["code"]?.bool == true {
            auth = .humanRequired
            if handOver && mode == .agent { fence(.human) }
        } else {
            auth = state["password"]?.bool == true ? .rejected : .signedIn
        }
    }

    // MARK: Operations

    private func journaled(_ operation: UUID, _ command: Recorded, _ body: () async -> HostReply) async -> HostReply {
        if let entry = journal[operation] {
            guard entry.command == command else { return .rejected(.operationConflict) }
            return entry.reply ?? .rejected(.operationInFlight)
        }
        guard !ended else { return .rejected(.unknownRun) }
        guard !operating, journal.count < Self.journalCapacity else { return .rejected(.busy) }
        journal[operation] = (command, nil)
        operating = true
        let reply = await body()
        operating = false
        journal[operation]?.reply = reply
        return reply
    }

    private func navigate(_ text: String, _ held: UInt64) async -> HostReply {
        guard let url = URL(string: text), let origin = WebOrigin(url: url), policy.navigation.contains(origin) else {
            return .rejected(.notPermitted)
        }
        await pause(.beforeInput)
        guard holds(held) else { return fenced }
        let before = network?.loads ?? 0
        guard await load(url) else { return .siteUnknown }
        return await dispatched(loadedAfter: before)
    }

    private func click(_ target: SiteTarget) async -> HostReply {
        let roles: [SiteRole] = [.link, .button, .submit, .checkbox, .radio]
        return await act(.activate, target, ["roles": roles.map(\.rawValue)])
    }

    /// Replaces the field's value; an empty text clears it.
    private func type(_ target: SiteTarget, _ text: String) async -> HostReply {
        await act(.enterText, target, ["roles": [SiteRole.textField.rawValue], "text": text])
    }

    private func choose(_ target: SiteTarget, _ option: Int) async -> HostReply {
        await act(.choose, target, ["roles": [SiteRole.select.rawValue], "option": option])
    }

    /// Runs an effect recipe on `target`'s element. A reason it returns means it did not act; a call
    /// that was sent but gave no answer may have acted, so its effect is unknown.
    private func act(_ recipe: SiteRecipe, _ target: SiteTarget, _ values: [String: Any]) async -> HostReply {
        await pause(.beforeInput)
        guard await current(target) else { return .rejected(.staleTarget) }
        switch await run(recipe, origins: policy.navigation, values.merging(["index": target.element]) { $1 }, while: target.control) {
        case .notRun: return .rejected(.staleTarget)
        case .sent(.string("ok")?): break
        case .sent(.string("kind")?): return .rejected(.notPermitted)
        case .sent(.string?): return .rejected(.staleTarget)
        case .sent: return .siteUnknown
        }
        return await dispatched(loadedAfter: nil)
    }

    private func scroll(_ dy: Int, _ held: UInt64) async -> HostReply {
        await dispatch([(.inputDispatchMouseEvent, ["type": "mouseWheel", "x": WebRun.viewport.width / 2,
                                                    "y": WebRun.viewport.height / 2, "deltaX": 0, "deltaY": dy])], held)
    }

    private static func key(_ key: NamedKey) -> [(CDPMethod, CDPParameters)] {
        let (name, code, keyCode, text) = WebRun.keys[key]!
        var down: [String: Any] = ["type": "keyDown", "key": name, "code": code, "windowsVirtualKeyCode": keyCode]
        if let text { down["text"] = text }
        return [(.inputDispatchKeyEvent, CDPParameters(down)),
                (.inputDispatchKeyEvent, ["type": "keyUp", "key": name, "code": code, "windowsVirtualKeyCode": keyCode])]
    }

    /// Sends untargeted input (keys, wheel) only while the agent holds control. Input the browser may
    /// have received without confirming makes the effect unknown; it is never sent again.
    private func dispatch(_ events: [(CDPMethod, CDPParameters)], _ held: UInt64) async -> HostReply {
        await pause(.beforeInput)
        guard let session, holds(held) else { return fenced }
        for (index, (method, params)) in events.enumerated() {
            guard holds(held) else { return index == 0 ? fenced : .siteUnknown }
            guard (try? await pipe.call(method, params, session: session, timeout: 2)) != nil else { return .siteUnknown }
        }
        return await dispatched(loadedAfter: nil)
    }

    /// Whether `target` names the live document, the current control epoch and the agent's control.
    private func current(_ target: SiteTarget) async -> Bool {
        guard mode == .agent, target.control == control, let (_, page) = await currentDocument() else { return false }
        return mode == .agent && target.control == control && target.document == page.epoch
    }

    /// What follows input that may have reached the site. Rejections and failures mean nothing was
    /// done, so from here on only an observation or `siteUnknown` is true: a refused request, a failed
    /// load, the session ending or an observation failing all leave the effect unknown.
    private func dispatched(loadedAfter required: Int?, judgingLogin: Bool = false) async -> HostReply {
        await pause(.dispatched)
        await settle(loadedAfter: required)
        restorePhase()
        guard !ended, network?.takeFailure() == nil else { return .siteUnknown }
        if judgingLogin { await judgeLogin(handOver: true) }
        guard case .site(let page) = await observation() else { return .siteUnknown }
        return .site(page)
    }

    // MARK: Observation

    private func observation() async -> HostReply {
        guard !ended else { return .rejected(.unknownRun) }
        // A document can be replaced, or control can change, between reading the document's identity
        // and its contents: read again under the new state.
        for _ in 0..<3 {
            guard !ended else { return .rejected(.unknownRun) }
            guard let (url, page) = await currentDocument() else { return .failed(.rendererUnavailable) }
            let held = control
            guard mode == .agent, let origin = WebOrigin(url: url), policy.navigation.contains(origin) else {
                return .site(summary(page.epoch))
            }
            let value = await run(.observe, origins: policy.navigation, [:], while: held).value
            await pause(.observed)
            guard await currentDocument()?.document.epoch == page.epoch, holds(held) else { continue }
            guard case .object(let fields)? = value, let title = fields["title"]?.string,
                  let items = fields["elements"]?.array, let lines = fields["text"]?.array else { continue }
            let elements = items.compactMap(Self.element)
            let text = lines.compactMap { $0.string.map { Self.clipped($0, SiteObservation.maximumTextBytes) } }
            guard let observed = SiteObservation(
                document: page.epoch, control: control, mode: mode, auth: auth, origin: origin.serialized,
                path: Self.clipped(url.path, SiteObservation.maximumPathBytes),
                title: Self.clipped(title, SiteElement.maximumLabelBytes),
                elements: Array(elements.prefix(SiteObservation.maximumElements)),
                text: Array(text.prefix(SiteObservation.maximumTextItems))) else { continue }
            return .site(HostWire.fitted(observed))
        }
        return .failed(.rendererUnavailable)
    }

    /// Identity only: what a person in control, or a page outside the policy, lets the agent know.
    private func summary(_ epoch: UInt64) -> SiteObservation {
        SiteObservation(document: epoch, control: control, mode: mode, auth: auth, origin: "", path: "", title: "",
                        elements: [], text: [])!
    }

    private static func element(_ item: JSONValue) -> SiteElement? {
        guard let ref = item["ref"]?.double, let role = item["role"]?.string.flatMap(SiteRole.init(rawValue:)),
              let label = item["label"]?.string, let value = item["value"]?.string,
              let options = item["options"]?.array else { return nil }
        return SiteElement(ref: Int(ref), role: role, label: clipped(label, SiteElement.maximumLabelBytes),
                           value: role == .password ? "" : clipped(value, SiteElement.maximumValueBytes),
                           options: role == .select ? options.compactMap { $0.string.map { clipped($0, SiteElement.maximumLabelBytes) } }
                                                         .prefix(SiteElement.maximumOptions).map { $0 } : [])
    }

    /// At most `bytes` UTF-8 bytes, cut on a character boundary.
    private static func clipped(_ text: String, _ bytes: Int) -> String {
        guard text.utf8.count > bytes else { return text }
        var result = ""
        for character in text {
            guard result.utf8.count + character.utf8.count <= bytes else { break }
            result.append(character)
        }
        return result
    }

    // MARK: CDP helpers

    /// The main frame's URL and document, numbering a new document the first time it is seen.
    private func currentDocument() async -> (url: URL, document: Document)? {
        guard !ended, let session, let tree = try? await pipe.call(.pageGetFrameTree, [:], session: session),
              let frame = tree["frameTree"]?["frame"], let text = frame["url"]?.string, let url = URL(string: text),
              let loader = frame["loaderId"]?.string, !ended else { return nil }
        if document?.loader != loader { document = Document(loader: loader, epoch: epochs.next(), world: nil) }
        return (url, document!)
    }

    /// The current document's isolated world, created once per document.
    private func world() async -> Int? {
        guard let page = document, let session, let target else { return nil }
        if let world = page.world { return world }
        guard let made = try? await pipe.call(.pageCreateIsolatedWorld, ["frameId": target, "worldName": "agentvault-site",
                                                                        "grantUniveralAccess": false], session: session),
              let world = made["executionContextId"]?.double, document?.loader == page.loader else { return nil }
        document?.world = Int(world)
        return Int(world)
    }

    /// Whether a recipe call was never sent, or was sent (with its value, if it answered).
    private enum Ran {
        case notRun
        case sent(JSONValue?)
        var value: JSONValue? { if case .sent(let value) = self { value } else { nil } }
    }

    /// Runs a fixed site recipe in the current document's world, which a page script cannot reach.
    /// The world belongs to one document: if that document is gone, the call fails without running.
    /// With `held`, the call is sent only while the agent still holds that control generation.
    private func run(_ recipe: SiteRecipe, origins: [WebOrigin], _ values: [String: Any], while held: UInt64? = nil) async -> Ran {
        guard !ended, let session, let world = await world() else { return .notRun }
        var arguments = values
        arguments["origins"] = origins.map(\.serialized)
        guard Set(arguments.keys) == Set(recipe.parameters), !ended, held.map(holds) ?? true else { return .notRun }
        let call: CDPParameters = [
            "functionDeclaration": recipe.declaration, "executionContextId": world,
            "arguments": recipe.parameters.map { ["value": arguments[$0]!] }, "returnByValue": true, "awaitPromise": false,
        ]
        let result: JSONValue
        do {
            result = try await pipe.call(.runtimeCallFunctionOn, call, session: session)
        } catch {
            // An error answer (for example, the document's world is gone) means it never ran; a
            // timeout or a lost browser may come after it ran.
            return error == .protocolError ? .notRun : .sent(nil)
        }
        return .sent(result["exceptionDetails"] == nil ? result["result"]?["value"] : nil)
    }

    /// Asks the main frame to load `url`; whether the browser accepted the navigation.
    private func load(_ url: URL) async -> Bool {
        guard let session, let result = try? await pipe.call(.pageNavigate, ["url": url.absoluteString], session: session,
                                                             timeout: timing.load) else { return false }
        return result["errorText"]?.string == nil
    }

    /// Waits for a navigation the last action started, if any, to finish loading. With `loadedAfter`
    /// it also waits for a load event past that count, for actions that always navigate.
    private func settle(loadedAfter required: Int?) async {
        try? await Task.sleep(for: timing.settle)
        let deadline = Date().addingTimeInterval(timing.load)
        while Date() < deadline, !ended {
            let loads = network?.loads ?? 0
            let waiting = network?.isLoading == true || required.map { loads <= $0 } == true
            guard waiting else { return }
            try? await Task.sleep(for: .milliseconds(25))
        }
    }
}
