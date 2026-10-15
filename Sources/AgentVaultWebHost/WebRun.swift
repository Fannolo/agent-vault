import AgentVaultContracts
import AgentVaultWebHostProtocol
import Foundation

/// The region and page a frame was captured from. Input is accepted only against the latest one.
struct CaptureBinding: Equatable, Sendable {
    let sequence: UInt64
    let x: Double, y: Double, width: Int, height: Int
    let path: String
}

/// One run: one disposable incognito browser context with one page.
/// Every method is bounded by CDP call timeouts; teardown never depends on them.
actor WebRun {
    struct Timing: Sendable {
        var load: TimeInterval = 5
        var settle: Duration = .milliseconds(150)
        var frameInterval: TimeInterval = 0.25
        static let standard = Timing()
    }

    enum Stage: Equatable { case starting, human(HumanStepKind, path: String), classifying, done }

    static let viewport = (width: 1280, height: 900)

    let id: UUID
    private let pipe: ChromiumPipe
    private let router: EventRouter
    private let gate: RequestGate
    private let timing: Timing
    private(set) var stage: Stage = .starting
    private var context: String?
    private var target: String?
    private var session: String?
    private var network: RunNetwork?
    private var step: UInt64 = 0
    private var latest: CaptureBinding?
    private var lastCapture = Date.distantPast
    private var ended = false

    init(id: UUID, pipe: ChromiumPipe, router: EventRouter, gate: RequestGate, timing: Timing) {
        self.id = id; self.pipe = pipe; self.router = router; self.gate = gate; self.timing = timing
    }

    // MARK: Lifecycle

    /// Creates the context and page, then logs in. The credential exists only in this call.
    func start(_ credential: WebLoginCredential) async -> HostReply {
        do { try await open() } catch { return .failed(.rendererUnavailable) }
        return await login(credential)
    }

    private func open() async throws {
        let created = try await pipe.call(.targetCreateBrowserContext, ["disposeOnDetach": true])
        guard let context = created["browserContextId"]?.string else { throw CDPError.protocolError }
        self.context = context
        // Ended while the context was being created: dispose the context that now exists.
        if ended { _ = await dispose(); throw CDPError.closed }
        _ = try await pipe.call(.browserSetDownloadBehavior, ["behavior": "deny", "browserContextId": context])
        router.beginCreation()
        let page = try? await pipe.call(.targetCreateTarget, ["url": "about:blank", "browserContextId": context])
        let target = page?["targetId"]?.string
        router.endCreation(target)
        guard let target, !ended else { throw CDPError.closed }
        self.target = target
        // The page starts paused; it runs only after its gate is in place.
        guard let session = await router.claimSession(for: target), !ended else { throw CDPError.closed }
        self.session = session
        let network = RunNetwork(gate: gate, mainFrame: target)
        self.network = network
        router.register(session: session, network: network)
        for (method, params) in [
            (CDPMethod.fetchEnable, ["patterns": EventRouter.fetchPatterns] as CDPParameters),
            (.pageEnable, [:]), (.networkEnable, [:]),
            (.targetSetAutoAttach, ["autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true]),
            (.emulationSetDeviceMetricsOverride, ["width": Self.viewport.width, "height": Self.viewport.height,
                                                  "deviceScaleFactor": 1, "mobile": false]),
        ] {
            _ = try await pipe.call(method, params, session: session)
        }
        _ = try await pipe.call(.runtimeRunIfWaitingForDebugger, [:], session: session)
    }

    /// Disposes the context. Idempotent; returns whether the browser confirmed it.
    func dispose() async -> Bool {
        ended = true
        stage = .done
        network?.phase = .locked
        if let target { router.forget(target: target, sessions: session.map { [$0] } ?? []) }
        guard let context else { return true }
        self.context = nil
        return (try? await pipe.call(.targetDisposeBrowserContext, ["browserContextId": context], timeout: 2)) != nil
    }

    // MARK: Workflow

    private func login(_ credential: WebLoginCredential) async -> HostReply {
        let workflow = gate.workflow
        network?.phase = .login
        guard let url = gate.policy.primary.url(path: workflow.loginPath) else { return .failed(.loadFailed) }
        if let failure = await navigate(url) { return .failed(failure) }
        if let failure = await checkpoint() { return failure }
        var fill = formArguments
        fill["username"] = credential.username; fill["password"] = credential.password
        switch await recipe(.fill, fill) {
        case .string("ok")?: break
        case .string("origin")?: return .failed(.originMismatch)
        default: return .failed(.unexpectedPage)
        }
        if let failure = await checkpoint() { return failure }
        network?.phase = .submitted
        let before = network?.loads ?? 0
        guard case .string("ok")? = await recipe(.submit, formArguments) else { return .failed(.unexpectedPage) }
        await waitForLoad(after: before)
        return await classify()
    }

    /// Decides what the current page means. Never submits anything.
    func classify() async -> HostReply {
        if let failure = await checkpoint() { return failure }
        let workflow = gate.workflow
        guard let url = await mainFrameURL(), WebOrigin(url: url) == gate.policy.primary else {
            return conclude(.failed(.originMismatch))
        }
        let path = url.path
        if let kind = workflow.stepKind(path: path) { return pause(kind, path: path) }
        if case .bool(true)? = await recipe(.contains, ["selector": workflow.captchaSelector]) {
            return pause(.captcha, path: path)
        }
        let formShown: Bool = if case .bool(true)? = await recipe(.contains, ["selector": workflow.formSelector]) { true } else { false }
        if path == workflow.loginPath || formShown { return conclude(.failed(.loginRejected)) }
        network?.phase = .locked
        if let failure = await checkpoint() { return failure }
        guard case .object(let fields)? = await recipe(.profile, ["loginSel": workflow.profileLoginSelector,
                                                                  "idSel": workflow.profileIDSelector]),
              let login = fields["login"]?.string, let text = fields["id"]?.string, (1...12).contains(text.count),
              text.allSatisfy(\.isASCII), let userID = Int(text), let profile = AccountProfile(login: login, userID: userID) else {
            return conclude(.failed(.invalidProfile))
        }
        return conclude(.profile(profile))
    }

    /// The person said they finished: look again, without acting.
    func reclassify() async -> HostReply {
        guard case .human = stage else { return .rejected(.notPaused) }
        stage = .classifying
        latest = nil
        network?.phase = .locked
        return await classify()
    }

    private func pause(_ kind: HumanStepKind, path: String) -> HostReply {
        stage = .human(kind, path: path)
        network?.phase = .human(kind)
        latest = nil
        return .humanStep(kind)
    }

    private func conclude(_ reply: HostReply) -> HostReply {
        stage = .done
        network?.phase = .locked
        return reply
    }

    /// Fails the run if it was ended or any request was refused.
    private func checkpoint() async -> HostReply? {
        try? await Task.sleep(for: timing.settle)
        if ended { return .rejected(.unknownRun) }
        if let failure = network?.failure { return conclude(.failed(failure)) }
        return nil
    }

    // MARK: Human continuation

    /// Begins showing the step numbered `epoch` by the broker. Epochs only move forward.
    func showHuman(step epoch: UInt64) async -> HostReply {
        guard case .human = stage else { return .rejected(.notPaused) }
        guard epoch > step else { return .rejected(.staleStep) }
        guard await challenge() != nil else { return .rejected(.captureUnavailable) }
        step = epoch
        latest = nil
        return .accepted
    }

    func frame(step epoch: UInt64, after: UInt64) async -> HostReply {
        guard case .human = stage else { return .rejected(.notPaused) }
        guard epoch == step, after <= (latest?.sequence ?? 0) else { return .rejected(.staleStep) }
        let wait = timing.frameInterval - Date().timeIntervalSince(lastCapture)
        if wait > 0 { try? await Task.sleep(for: .seconds(wait)) }
        guard let region = await challenge(), let session else { return .rejected(.captureUnavailable) }
        var shot: HumanFrame?
        let sequence = (latest?.sequence ?? 0) + 1
        for quality in [70, 40] where shot == nil {
            guard let result = try? await pipe.call(.pageCaptureScreenshot, [
                "format": "jpeg", "quality": quality, "captureBeyondViewport": false,
                "clip": ["x": region.x, "y": region.y, "width": region.width, "height": region.height, "scale": 1],
            ], session: session, timeout: 3),
                  let data = result["data"]?.string.flatMap({ Data(base64Encoded: $0) }) else { break }
            // The image itself, not just its label, must be exactly the challenge region.
            guard let size = Self.jpegSize(data), size.width == region.width, size.height == region.height else { break }
            shot = HumanFrame(sequence: sequence, width: region.width, height: region.height, jpeg: data)
        }
        lastCapture = Date()
        // Revalidate: the step must still be the same page and region after the capture.
        guard let shot, case .human = stage, epoch == step, await challenge() == region else {
            return .rejected(.captureUnavailable)
        }
        latest = CaptureBinding(sequence: sequence, x: region.x, y: region.y, width: region.width,
                                height: region.height, path: region.path)
        return .frame(step: epoch, shot)
    }

    /// Delivers events only against the latest frame of the current step, inside its region.
    func input(step epoch: UInt64, frame: UInt64, _ batch: HumanInputBatch) async -> HostReply {
        guard case .human = stage else { return .rejected(.notPaused) }
        guard epoch == step, let latest, latest.sequence == frame,
              batch.events.allSatisfy({ $0.fits(width: latest.width, height: latest.height) }),
              let region = await challenge(), region.matches(latest), let session else { return .rejected(.staleStep) }
        for event in batch.events {
            for (method, params) in Self.translate(event, in: latest) {
                guard (try? await pipe.call(method, params, session: session, timeout: 2)) != nil else {
                    return .rejected(.captureUnavailable)
                }
            }
        }
        return .accepted
    }

    private struct Region: Equatable {
        let x: Double, y: Double, width: Int, height: Int, path: String
        func matches(_ binding: CaptureBinding) -> Bool {
            abs(x - binding.x) < 0.5 && abs(y - binding.y) < 0.5 && width == binding.width
                && height == binding.height && path == binding.path
        }
    }

    /// The exact challenge region on the exact reviewed page, or `nil` (fail closed).
    private func challenge() async -> Region? {
        guard case .human(let kind, let pausedPath) = stage, !ended,
              let selector = gate.workflow.challengeSelectors[kind],
              let url = await mainFrameURL(), WebOrigin(url: url) == gate.policy.primary,
              url.path == pausedPath || gate.workflow.stepKind(path: url.path) == kind,
              case .object(let rect)? = await recipe(.challengeRect, ["selector": selector]),
              let x = rect["x"]?.double, let y = rect["y"]?.double, let width = rect["width"]?.double,
              let height = rect["height"]?.double, x >= 0, y >= 0,
              x + width <= Double(Self.viewport.width), y + height <= Double(Self.viewport.height) else { return nil }
        let w = Int(width.rounded(.down)), h = Int(height.rounded(.down))
        guard (1...HumanFrame.maximumWidth).contains(w), (1...HumanFrame.maximumHeight).contains(h) else { return nil }
        return Region(x: x, y: y, width: w, height: h, path: url.path)
    }

    private static func translate(_ event: HumanInput, in frame: CaptureBinding) -> [(CDPMethod, CDPParameters)] {
        switch event {
        case .pointer(let phase, let x, let y):
            let type = switch phase { case .down: "mousePressed"; case .up: "mouseReleased"; case .move: "mouseMoved" }
            var params: [String: Any] = ["type": type, "x": frame.x + Double(x), "y": frame.y + Double(y)]
            if phase != .move { params["button"] = "left"; params["clickCount"] = 1 }
            return [(.inputDispatchMouseEvent, CDPParameters(params))]
        case .wheel(let dx, let dy):
            return [(.inputDispatchMouseEvent, ["type": "mouseWheel", "x": frame.x + Double(frame.width) / 2,
                                                "y": frame.y + Double(frame.height) / 2, "deltaX": dx, "deltaY": dy])]
        case .key(let key):
            let (name, code, keyCode, text) = Self.keys[key]!
            var down: [String: Any] = ["type": "keyDown", "key": name, "code": code, "windowsVirtualKeyCode": keyCode]
            if let text { down["text"] = text }
            return [(.inputDispatchKeyEvent, CDPParameters(down)),
                    (.inputDispatchKeyEvent, ["type": "keyUp", "key": name, "code": code, "windowsVirtualKeyCode": keyCode])]
        case .text(let text):
            return [(.inputInsertText, ["text": text])]
        }
    }

    /// Width and height from the first start-of-frame marker, or `nil` for anything malformed.
    static func jpegSize(_ data: Data) -> (width: Int, height: Int)? {
        let bytes = [UInt8](data)
        guard bytes.count > 4, bytes[0] == 0xFF, bytes[1] == 0xD8 else { return nil }
        var index = 2
        while index + 9 < bytes.count {
            guard bytes[index] == 0xFF else { return nil }
            let marker = bytes[index + 1]
            if marker == 0xFF { index += 1; continue }
            if (0xD0...0xD9).contains(marker) || marker == 0x01 { index += 2; continue }
            let length = Int(bytes[index + 2]) << 8 | Int(bytes[index + 3])
            guard length >= 2 else { return nil }
            if (0xC0...0xCF).contains(marker), ![0xC4, 0xC8, 0xCC].contains(marker) {
                let height = Int(bytes[index + 5]) << 8 | Int(bytes[index + 6])
                let width = Int(bytes[index + 7]) << 8 | Int(bytes[index + 8])
                return (width, height)
            }
            index += 2 + length
        }
        return nil
    }

    private static let keys: [NamedKey: (String, String, Int, String?)] = [
        .enter: ("Enter", "Enter", 13, "\r"), .tab: ("Tab", "Tab", 9, nil), .backspace: ("Backspace", "Backspace", 8, nil),
        .delete: ("Delete", "Delete", 46, nil), .escape: ("Escape", "Escape", 27, nil),
        .arrowLeft: ("ArrowLeft", "ArrowLeft", 37, nil), .arrowRight: ("ArrowRight", "ArrowRight", 39, nil),
        .arrowUp: ("ArrowUp", "ArrowUp", 38, nil), .arrowDown: ("ArrowDown", "ArrowDown", 40, nil),
    ]

    // MARK: CDP helpers

    private var formArguments: [String: Any] {
        let workflow = gate.workflow
        return ["actionPath": workflow.formActionPath, "formSel": workflow.formSelector, "userSel": workflow.usernameSelector,
                "passSel": workflow.passwordSelector, "submitSel": workflow.submitSelector]
    }

    /// Runs a fixed recipe in a fresh isolated world of the main frame.
    private func recipe(_ recipe: Recipe, _ values: [String: Any]) async -> JSONValue? {
        guard !ended, let session, let target else { return nil }
        var arguments = values
        arguments["origin"] = gate.policy.primary.serialized
        guard Set(arguments.keys) == Set(recipe.parameters),
              let world = try? await pipe.call(.pageCreateIsolatedWorld, ["frameId": target, "worldName": "agentvault-recipe",
                                                                         "grantUniveralAccess": false], session: session),
              let context = world["executionContextId"]?.double else { return nil }
        let call: CDPParameters = [
            "functionDeclaration": recipe.declaration, "executionContextId": Int(context),
            "arguments": recipe.parameters.map { ["value": arguments[$0]!] }, "returnByValue": true, "awaitPromise": false,
        ]
        let result = try? await pipe.call(.runtimeCallFunctionOn, call, session: session)
        guard let result, result["exceptionDetails"] == nil else { return nil }
        return result["result"]?["value"]
    }

    private func navigate(_ url: URL) async -> HostFailure? {
        guard let session else { return .rendererUnavailable }
        let before = network?.loads ?? 0
        guard let result = try? await pipe.call(.pageNavigate, ["url": url.absoluteString], session: session,
                                                timeout: timing.load) else { return network?.failure ?? .loadFailed }
        if result["errorText"]?.string != nil { return network?.failure ?? .loadFailed }
        await waitForLoad(after: before)
        return nil
    }

    private func waitForLoad(after count: Int) async {
        let deadline = Date().addingTimeInterval(timing.load)
        while Date() < deadline, !ended, (network?.loads ?? 0) <= count {
            try? await Task.sleep(for: .milliseconds(25))
        }
    }

    private func mainFrameURL() async -> URL? {
        guard let session, let tree = try? await pipe.call(.pageGetFrameTree, [:], session: session),
              let text = tree["frameTree"]?["frame"]?["url"]?.string else { return nil }
        return URL(string: text)
    }
}
