import AgentVaultCredentials
@testable import AgentVaultCore
@testable import AgentVaultWebHostLink
@testable import AgentVaultWebHostProtocol
import AgentVaultContracts
import AgentVaultIPC
import Foundation
import Security

/// Signing identity of the test process, so one process can play broker and host.
let testCode: (cdhash: String, identifier: String) = {
    var code: SecCode?, staticCode: SecStaticCode?, info: CFDictionary?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
          SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
          SecCodeCopySigningInformation(staticCode, [], &info) == errSecSuccess,
          let info = info as? [String: Any], let unique = info[kSecCodeInfoUnique as String] as? Data,
          let identifier = info[kSecCodeInfoIdentifier as String] as? String else { fatalError("test host is not signed") }
    return (unique.map { String(format: "%02x", $0) }.joined(), identifier)
}()
let me = UInt32(getuid())
let wrongCDHash = String(repeating: "0", count: 40)
let hostPin = "identifier \"\(testCode.identifier)\" and cdhash H\"\(testCode.cdhash)\""
let brokerPin = "cdhash H\"\(testCode.cdhash)\""

func developmentConfiguration(host: String = hostPin, broker: String = brokerPin, hostUID: UInt32 = me,
                              brokerUID: UInt32 = me) -> WebHostConfiguration {
    WebHostConfiguration(serviceName: "dev.agentvault.test.webhost", hostRequirement: host, brokerRequirement: broker,
                         hostUID: hostUID, brokerUID: brokerUID, agentUID: me, development: true)
}

let fastBudgets = WebHostBudgets(start: 0.6, classify: 0.6, end: 0.3, showHuman: 0.6, frame: 0.6, input: 0.6)

func link(_ endpoint: @escaping @Sendable () -> NSXPCListenerEndpoint,
          configuration: WebHostConfiguration = developmentConfiguration(),
          budgets: WebHostBudgets = fastBudgets, limits: WebHostLink.Limits = .standard) -> WebHostLink {
    WebHostLink(validated: configuration, target: .endpoint(endpoint), budgets: budgets, limits: limits)
}

let credentialData = Data("synthetic-user\nSYNTHETIC-only-password".utf8)
let credential = WebLoginCredential(credentialData)!
let profile = AccountProfile(login: "synthetic-user", userID: 4242)!
let tinyJPEG = Data([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0xFF, 0xD9])

/// A broker authority that always grants `seconds`; the broker's real callback is tested in Core.
func authority(_ seconds: Int) -> WebStartAuthority { WebStartAuthority { TimeInterval(seconds) } }

func step(_ run: BrowserRunID, _ epoch: UInt64 = 1) -> HumanStepID { HumanStepID(run: run, epoch: epoch) }

/// Thread-safe ordered log.
final class Log<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [Value] = []
    func append(_ value: Value) { lock.withLock { values.append(value) } }
    var all: [Value] { lock.withLock { values } }
}

/// A gate a scripted handler can wait on; the test opens it, or never does.
actor Latch {
    private var opened = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func wait() async {
        if opened { return }
        await withCheckedContinuation { waiters.append($0) }
    }
    func open() {
        opened = true
        for waiter in waiters { waiter.resume() }
        waiters = []
    }
}

/// The real host listener on an anonymous endpoint, with a scripted command handler.
final class TestHost: @unchecked Sendable {
    let server: WebHostServer
    let endpoint: NSXPCListenerEndpoint
    let commands = Log<HostCommand>()
    let peerLosses = Log<Date>()

    init(configuration: WebHostConfiguration = developmentConfiguration(),
         limits: WebHostServer.Limits = .standard,
         handler: @escaping @Sendable (HostCommand) async -> HostReply) {
        let listener = NSXPCListener.anonymous()
        let commands = commands, peerLosses = peerLosses
        server = WebHostServer(validated: configuration, listener: listener, limits: limits, handler: { command in
            commands.append(command)
            return await handler(command)
        }, peerLost: { peerLosses.append(Date()) })
        server.activate()
        endpoint = listener.endpoint
    }

    var runs: [UUID] { commands.all.map(\.run) }
    func count(where predicate: (HostCommand) -> Bool) -> Int { commands.all.filter(predicate).count }

    deinit { server.invalidate() }
}

func isStart(_ command: HostCommand) -> Bool { if case .start = command { true } else { false } }
func isEnd(_ command: HostCommand) -> Bool { if case .end = command { true } else { false } }

/// Answers like a scripted host: starts pause on MFA, classification yields the profile.
let pausingHost: @Sendable (HostCommand) async -> HostReply = { command in
    switch command {
    case .start: .humanStep(.mfa)
    case .classify: .profile(profile)
    case .end: .ended
    case .showHuman, .input: .accepted
    case .frame(_, let step, _): .frame(step: step, HumanFrame(sequence: 1, width: 4, height: 2, jpeg: tinyJPEG)!)
    case .openSite, .siteObserve, .siteLogin, .siteOperate, .siteTakeover, .siteRelease: .rejected(.unsupportedSite)
    }
}

/// Any listener that exports `WebHostRPC`, records raw payloads and answers with a fixed script.
/// It applies no identity checks of its own: it stands in for an impostor or a broken host.
final class RawHost: NSObject, NSXPCListenerDelegate, WebHostRPC, @unchecked Sendable {
    let listener = NSXPCListener.anonymous()
    let received = Log<Data>()
    let invalidations = Log<Date>()
    private let answer: @Sendable (Data) -> Data?

    init(answer: @escaping @Sendable (Data) -> Data?) {
        self.answer = answer
        super.init()
        listener.delegate = self
        listener.activate()
    }

    var endpoint: NSXPCListenerEndpoint { listener.endpoint }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: WebHostRPC.self)
        connection.exportedObject = self
        let invalidations = invalidations
        connection.invalidationHandler = { invalidations.append(Date()) }
        connection.activate()
        return true
    }

    func perform(_ data: Data, reply: @escaping (Data) -> Void) {
        received.append(data)
        if let response = answer(data) { reply(response) }
    }

    deinit { listener.invalidate() }
}

/// Sends raw payloads to a host listener, bypassing the link, to probe the server directly.
final class RawClient: @unchecked Sendable {
    let connection: NSXPCConnection

    init(_ endpoint: NSXPCListenerEndpoint, requirement: String = hostPin) {
        connection = NSXPCConnection(listenerEndpoint: endpoint)
        connection.remoteObjectInterface = NSXPCInterface(with: WebHostRPC.self)
        connection.setCodeSigningRequirement(requirement)
        connection.activate()
    }

    /// `nil` when the connection failed or nothing came back in time.
    func send(_ data: Data, timeout: TimeInterval = 2) async -> Data? {
        await withCheckedContinuation { continuation in
            let once = Once<Data?>(continuation)
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { once.resume(nil) }
            let proxy = connection.remoteObjectProxyWithErrorHandler { _ in once.resume(nil) }
            (proxy as? WebHostRPC)?.perform(data) { once.resume($0) }
        }
    }

    deinit { connection.invalidate() }
}

func errorEnvelope(_ code: HostWireError) -> Data { HostWire.errorReply(code) }

/// Polls until `condition` holds or about two seconds pass.
func eventually(_ condition: @Sendable () async -> Bool) async -> Bool {
    for _ in 0..<200 {
        if await condition() { return true }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return await condition()
}

/// The single consumer of a link's loss stream.
final class Losses: @unchecked Sendable {
    let log = Log<Set<BrowserRunID>>()
    private var task: Task<Void, Never>?
    init(_ link: WebHostLink) {
        let stream = link.losses, log = log
        task = Task { for await lost in stream { log.append(lost) } }
    }
    var all: [Set<BrowserRunID>] { log.all }
    deinit { task?.cancel() }
}
