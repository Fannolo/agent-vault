import AgentVaultWebHostProtocol
import Foundation

/// What the router needs from a page's network state, whichever gate it uses.
protocol PageNetwork: AnyObject, Sendable {
    var mainFrame: String { get }
    func decide(_ request: GateRequest) -> GateDecision
    func contentSecurityPolicy() -> String
    func record(_ failure: HostFailure)
    func loaded()
    func mainFrameLoading(_ loading: Bool)
}

/// Network state of one run or session, shared by its page session and any frame sessions under it.
final class RunNetwork<Gate: PhasedGate>: PageNetwork, @unchecked Sendable {
    let gate: Gate
    let mainFrame: String
    private let lock = NSLock()
    private var currentPhase: Gate.Phase
    private var firstFailure: HostFailure?
    private var loadCount = 0
    private var loading = false

    init(gate: Gate, mainFrame: String, phase: Gate.Phase) {
        self.gate = gate; self.mainFrame = mainFrame; currentPhase = phase
    }

    var phase: Gate.Phase {
        get { lock.withLock { currentPhase } }
        set { lock.withLock { currentPhase = newValue } }
    }
    /// The first refused request decides how the run fails at its next checkpoint.
    var failure: HostFailure? { lock.withLock { firstFailure } }
    var loads: Int { lock.withLock { loadCount } }
    /// The main frame started a navigation that has not stopped loading yet.
    var isLoading: Bool { lock.withLock { loading } }

    func record(_ failure: HostFailure) {
        lock.withLock { if firstFailure == nil || failure == .originMismatch { firstFailure = failure } }
    }
    /// Returns and clears the refusal, so a continuing session judges each operation on its own.
    func takeFailure() -> HostFailure? { lock.withLock { defer { firstFailure = nil }; return firstFailure } }
    func loaded() { lock.withLock { loadCount += 1; loading = false } }
    func mainFrameLoading(_ value: Bool) { lock.withLock { loading = value } }
    func decide(_ request: GateRequest) -> GateDecision {
        lock.withLock {
            let decision = gate.decide(request, phase: currentPhase)
            if decision == .allow { currentPhase = gate.phase(after: request, from: currentPhase) }
            return decision
        }
    }
    func contentSecurityPolicy() -> String { gate.contentSecurityPolicy(phase: phase) }
}

/// Routes browser events to runs and polices every target the browser creates.
///
/// Popups, workers and service workers are attached paused (`waitForDebuggerOnStart`) and closed
/// or left paused, so they never load. Every page request passes the run's `RequestGate`, and every
/// document response gets the gate's Content-Security-Policy.
final class EventRouter: @unchecked Sendable {
    static let maximumDocumentBytes = 8 << 20
    static var fetchPatterns: [[String: Any]] {
        [["urlPattern": "*", "requestStage": "Request"],
         ["urlPattern": "*", "resourceType": "Document", "requestStage": "Response"]]
    }

    private let lock = NSLock()
    private var sessions: [String: any PageNetwork] = [:]
    private var ownTargets: Set<String> = []
    /// Paused sessions of our own new pages, waiting for their run to configure and resume them.
    private var ownSessions: [String: String] = [:]
    private var creations = 0
    private var refused = 0
    weak var pipe: ChromiumPipe?

    /// Requests the gate refused since launch; recorded so a refusal is observable even when the
    /// browser would also have refused the request on its own.
    var refusedRequests: Int { lock.withLock { refused } }

    func beginCreation() { lock.withLock { creations += 1 } }
    func endCreation(_ target: String?) {
        lock.withLock { creations -= 1; if let target { ownTargets.insert(target) } }
    }
    func register(session: String, network: any PageNetwork) { lock.withLock { sessions[session] = network } }
    /// The auto-attached, still paused session of a page this host created.
    func claimSession(for target: String, within seconds: TimeInterval = 5) async -> String? {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if let session = lock.withLock({ ownSessions.removeValue(forKey: target) }) { return session }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return nil
    }

    func forget(target: String, sessions forgotten: [String]) {
        lock.withLock {
            ownTargets.remove(target)
            ownSessions.removeValue(forKey: target)
            for session in forgotten { sessions.removeValue(forKey: session) }
        }
    }
    private func network(_ session: String?) -> (any PageNetwork)? {
        guard let session else { return nil }
        return lock.withLock { sessions[session] }
    }

    func handle(_ event: CDPEvent) {
        switch event.method {
        case "Fetch.requestPaused":
            guard let network = network(event.session), let session = event.session else { return }
            Task { await self.gate(event.params, network: network, session: session) }
        case "Page.loadEventFired":
            network(event.session)?.loaded()
        case "Page.frameStartedLoading", "Page.frameStoppedLoading":
            guard let network = network(event.session), event.params["frameId"]?.string == network.mainFrame else { return }
            network.mainFrameLoading(event.method == "Page.frameStartedLoading")
        case "Network.webSocketCreated":
            // Tripwire: the policy should make this impossible.
            network(event.session)?.record(.originMismatch)
        case "Target.attachedToTarget":
            Task { await self.attached(event.params, parent: event.session) }
        default:
            break
        }
    }

    private func gate(_ params: JSONValue, network: any PageNetwork, session: String) async {
        guard let pipe, let id = params["requestId"]?.string, let request = params["request"],
              let text = request["url"]?.string, let url = URL(string: text) else { return }
        if let status = params["responseStatusCode"]?.double {
            await respond(id, status: Int(status), headers: params["responseHeaders"]?.array ?? [],
                          network: network, session: session, pipe: pipe)
            return
        }
        let decision = network.decide(GateRequest(
            url: url, method: request["method"]?.string ?? "GET", resourceType: params["resourceType"]?.string ?? "Other",
            isMainFrame: params["frameId"]?.string == network.mainFrame))
        switch decision {
        case .allow:
            _ = try? await pipe.call(.fetchContinueRequest, ["requestId": id], session: session, timeout: 5)
        case .block:
            lock.withLock { refused += 1 }
            _ = try? await pipe.call(.fetchFailRequest, ["requestId": id, "errorReason": "BlockedByClient"],
                                     session: session, timeout: 5)
        case .deny(let failure):
            lock.withLock { refused += 1 }
            network.record(failure)
            _ = try? await pipe.call(.fetchFailRequest, ["requestId": id, "errorReason": "BlockedByClient"],
                                     session: session, timeout: 5)
        }
    }

    /// Documents are delivered with the gate's Content-Security-Policy added to their own.
    private func respond(_ id: String, status: Int, headers: [JSONValue], network: any PageNetwork,
                         session: String, pipe: ChromiumPipe) async {
        if (300..<400).contains(status) {
            _ = try? await pipe.call(.fetchContinueRequest, ["requestId": id], session: session, timeout: 5)
            return
        }
        guard let body = try? await pipe.call(.fetchGetResponseBody, ["requestId": id], session: session, timeout: 5),
              let content = body["body"]?.string, content.utf8.count <= Self.maximumDocumentBytes * 4 / 3 + 4 else {
            network.record(.loadFailed)
            _ = try? await pipe.call(.fetchFailRequest, ["requestId": id, "errorReason": "Failed"], session: session, timeout: 5)
            return
        }
        let encoded = body["base64Encoded"]?.bool == true ? content : Data(content.utf8).base64EncodedString()
        var fields: [[String: Any]] = headers.compactMap { header in
            guard let name = header["name"]?.string, let value = header["value"]?.string else { return nil }
            return ["name": name, "value": value]
        }
        fields.append(["name": "Content-Security-Policy", "value": network.contentSecurityPolicy()])
        _ = try? await pipe.call(.fetchFulfillRequest, ["requestId": id, "responseCode": status,
                                                         "responseHeaders": fields, "body": encoded],
                                 session: session, timeout: 5)
    }

    /// Every target the browser creates on its own is closed or left paused; only our pages and
    /// their same-origin frames run.
    private func attached(_ params: JSONValue, parent: String?) async {
        guard let pipe, let info = params["targetInfo"], let type = info["type"]?.string,
              let target = info["targetId"]?.string, let session = params["sessionId"]?.string else { return }
        if let parent {
            // Page-level: frames inherit the run's gate. Popups and workers are closed; one that
            // cannot be closed stays paused and never runs.
            guard type == "iframe", let network = network(parent) else {
                _ = try? await pipe.call(.targetCloseTarget, ["targetId": target], timeout: 5)
                return
            }
            register(session: session, network: network)
            _ = try? await pipe.call(.fetchEnable, ["patterns": Self.fetchPatterns], session: session, timeout: 5)
            _ = try? await pipe.call(.runtimeRunIfWaitingForDebugger, [:], session: session, timeout: 5)
            return
        }
        // Browser-level: our own pages go to their run, still paused; anything else (popups,
        // workers, service workers) is closed before it runs.
        if type == "page" {
            for _ in 0..<100 where lock.withLock({ creations > 0 && !ownTargets.contains(target) }) {
                try? await Task.sleep(for: .milliseconds(50))
            }
            let own = lock.withLock { () -> Bool in
                guard ownTargets.contains(target) else { return false }
                ownSessions[target] = session
                return true
            }
            if own { return }
        }
        _ = try? await pipe.call(.targetCloseTarget, ["targetId": target], timeout: 5)
    }
}
