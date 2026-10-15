import AgentVaultBrowserFixture
import AgentVaultContracts
@testable import AgentVaultAppSupport
@testable import AgentVaultCore
@testable import AgentVaultIPC
@testable import AgentVaultWebHost
@testable import AgentVaultWebHostLink
@testable import AgentVaultWebHostProtocol
import Darwin
import Foundation
import Security
import Testing

let fixtureChromium = ProcessInfo.processInfo.environment["AGENT_VAULT_TEST_CHROMIUM"].map(URL.init(fileURLWithPath:))

private let identity: (uid: UInt32, hash: String, identifier: String) = {
    var code: SecCode?, staticCode: SecStaticCode?, info: CFDictionary?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
          SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
          SecCodeCopySigningInformation(staticCode, [], &info) == errSecSuccess,
          let dictionary = info as? [String: Any], let hash = dictionary[kSecCodeInfoUnique as String] as? Data,
          let identifier = dictionary[kSecCodeInfoIdentifier as String] as? String else { fatalError("unsigned test runner") }
    return (UInt32(getuid()), hash.map { String(format: "%02x", $0) }.joined(), identifier)
}()

final class TestState: StateStore, @unchecked Sendable {
    private let lock = NSLock()
    private var state = VaultState()
    func transaction<T>(_ body: (inout VaultState) throws -> T) throws -> T {
        try lock.withLock { var next = state; let result = try body(&next); state = next; return result }
    }
}

private final class TestSecrets: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [UUID: Data] = [:]
    func save(_ value: Data, for id: UUID) throws { lock.withLock { values[id] = value } }
    func load(for id: UUID) throws -> Data {
        try lock.withLock { guard let value = values[id] else { throw VaultError.secretUnavailable }; return value }
    }
    func delete(for id: UUID) throws { _ = lock.withLock { values.removeValue(forKey: id) } }
}

final class CommandCounts: @unchecked Sendable {
    private let lock = NSLock()
    private var counts: [String: Int] = [:]
    func record(_ command: HostCommand) {
        let name: String
        switch command {
        case .start: name = "start"
        case .classify: name = "classify"
        case .end: name = "end"
        case .showHuman: name = "show"
        case .frame: name = "frame"
        case .input: name = "input"
        }
        lock.withLock { counts[name, default: 0] += 1 }
    }
    func count(_ name: String) -> Int { lock.withLock { counts[name, default: 0] } }
}

private final class FatalSignal: @unchecked Sendable {
    private let lock = NSLock()
    private var handler: (@Sendable () -> Void)?
    func install(_ action: @escaping @Sendable () -> Void) { lock.withLock { handler = action } }
    func fire() { lock.withLock { handler }?() }
}

@MainActor
func eventually(seconds: Double = 5, _ condition: @MainActor () async -> Bool) async -> Bool {
    let deadline = ContinuousClock.now + .seconds(seconds)
    while ContinuousClock.now < deadline {
        if await condition() { return true }
        try? await Task.sleep(for: .milliseconds(20))
    }
    return await condition()
}

/// All production ports, both authenticated XPC seams, one synthetic origin. Product targets
/// never import this composition. Software signing and same-UID pins prove neither user presence
/// nor OS isolation. Chromium cleanup uses its pinned OwnedGroup, never a searched PID or name.
@MainActor
final class HeadlessStack {
    let site: FixtureSite
    let directory: URL
    let host: HostService
    let hostServer: WebHostServer
    let commands: CommandCounts
    let state: TestState
    let broker: Broker
    let signer: SoftwareFixtureSigner
    let server: VaultXPCServer
    let read: VaultReadClient
    let adminEndpoint: NSXPCListenerEndpoint
    let configuration: IPCConfiguration
    let account: Account
    let grant: Grant
    private var adminClients: [VaultAdminClient] = []
    private var models: [AppModel] = []
    private var watchdog: Task<Void, Never>?

    private init(site: FixtureSite, directory: URL, host: HostService, hostServer: WebHostServer,
                 commands: CommandCounts, state: TestState, broker: Broker, signer: SoftwareFixtureSigner,
                 server: VaultXPCServer, read: VaultReadClient, adminEndpoint: NSXPCListenerEndpoint,
                 configuration: IPCConfiguration, account: Account, grant: Grant) {
        self.site = site; self.directory = directory; self.host = host; self.hostServer = hostServer
        self.commands = commands; self.state = state; self.broker = broker; self.signer = signer
        self.server = server; self.read = read; self.adminEndpoint = adminEndpoint
        self.configuration = configuration; self.account = account; self.grant = grant
        // Retain the actual pipe as soon as it exists. The watchdog's final cleanup does not
        // ask the service to end a run or trust the teardown being tested.
        watchdog = Task.detached {
            let deadline = ContinuousClock.now + .seconds(45)
            while !Task.isCancelled, ContinuousClock.now < deadline {
                if let pipe = await host.launched {
                    do { try await Task.sleep(until: deadline, clock: .continuous) } catch { return }
                    Issue.record("U5 test exceeded its owned-browser watchdog deadline")
                    pipe.killGroup()
                    let reapDeadline = ContinuousClock.now + .seconds(5)
                    while !pipe.isReaped, ContinuousClock.now < reapDeadline {
                        try? await Task.sleep(for: .milliseconds(20))
                    }
                    #expect(pipe.isReaped, "U5 owned browser watchdog could not confirm reap")
                    return
                }
                do { try await Task.sleep(for: .milliseconds(20)) } catch { return }
            }
        }
    }

    static func make(user: String = "mfa-user", windows: LifecycleWindows = .standard) async throws -> HeadlessStack {
        let binary = try #require(fixtureChromium)
        let site = FixtureSite()
        try await site.start()
        var template = Array(FileManager.default.temporaryDirectory.appendingPathComponent("av-u5-XXXXXX").path.utf8CString)
        guard let created = mkdtemp(&template) else { site.stop(); throw VaultError.stateUnavailable }
        let directory = URL(fileURLWithPath: String(cString: created))
        var ready = false
        defer { if !ready { site.stop(); try? FileManager.default.removeItem(at: directory) } }
        let brokerPin = "cdhash H\"\(identity.hash)\""
        let config = IPCConfiguration(readServiceName: "dev.agentvault.u5.read", adminServiceName: "dev.agentvault.u5.admin",
            brokerRequirement: brokerPin, readRequirement: "\(brokerPin) and \(brokerPin)", adminRequirement: "(\(brokerPin))",
            brokerUID: identity.uid, allowedUID: identity.uid, development: true)
        let hostConfig = WebHostConfiguration(serviceName: "dev.agentvault.u5.host",
            hostRequirement: "identifier \"\(identity.identifier)\" and \(brokerPin)", brokerRequirement: brokerPin,
            hostUID: identity.uid, brokerUID: identity.uid, agentUID: identity.uid, development: true)
        try config.validate(for: .broker)
        try hostConfig.validate(for: .host)
        try hostConfig.validate(brokerIPC: config)
        let fatal = FatalSignal(), commands = CommandCounts()
        let host = HostService(policy: try #require(HostPolicy.fixture(primary: site.origin)), binary: binary,
                               runDirectory: directory, onFatal: { fatal.fire() })
        let hostListener = NSXPCListener.anonymous()
        let hostServer = WebHostServer(validated: hostConfig, listener: hostListener, limits: .standard,
            handler: { command in commands.record(command); return await host.perform(command) },
            peerLost: { await host.teardown() })
        fatal.install { [weak hostServer] in hostServer?.invalidate() }
        hostServer.activate()
        let endpoint = hostListener.endpoint
        let link = WebHostLink(validated: hostConfig, target: .endpoint({ endpoint }), budgets: .standard, limits: .standard)
        let state = TestState(), signer = SoftwareFixtureSigner()
        let broker = Broker(state: state, secrets: TestSecrets(), webSessions: link, windows: windows)
        let account = try await broker.enroll(service: .browserDemo, credential: FixtureSite.credential(user: user))
        let client = try await broker.registerClient(uid: identity.uid)
        let grant = try await broker.grant(clientID: client.id, accountID: account.id, duration: 300, callLimit: 1)
        let admin = try Administration(broker: broker, publicKey: signer.publicKey.x963Representation)
        let reader = ReadOperations(broker: broker), continuation = ContinuationOperations(broker: broker)
        let handlers = VaultXPCServer.Handlers(
            read: { uid, request in
                do { return try await reader.perform(uid: uid, request: request) }
                catch { return ReadReply(.failure((error as? VaultError)?.readFailure ?? .operationFailed)) }
            }, snapshot: { _ in try await admin.snapshot() },
            begin: { peer, request in
                do { return try await admin.begin(request, connection: .init(minted: peer.id, isOpen: { peer.isOpen })) }
                catch { throw AdminRejection(status: (error as? VaultError)?.rawValue ?? "operation_failed") }
            }, authorize: { peer, id, signature in
                do { return try await admin.authorize(id, signature: signature, connection: .init(minted: peer.id, isOpen: { peer.isOpen })) }
                catch { return AdminReply(status: (error as? VaultError)?.rawValue ?? "operation_failed") }
            }, continuation: { peer, request in
                await continuation.perform(request, connection: .init(minted: peer.id, isOpen: { peer.isOpen }))
            }, closed: { peer in await broker.continuationConnectionClosed(.init(minted: peer.id, isOpen: { peer.isOpen })) })
        let readListener = NSXPCListener.anonymous(), adminListener = NSXPCListener.anonymous()
        let server = VaultXPCServer(validated: config, limits: .standard, readListener: readListener,
                                    adminListener: adminListener, handlers: handlers)
        server.activate()
        let read = VaultReadClient(validated: config, endpoint: readListener.endpoint, timeout: 25)
        let stack = HeadlessStack(site: site, directory: directory, host: host, hostServer: hostServer,
            commands: commands, state: state, broker: broker, signer: signer, server: server, read: read,
            adminEndpoint: adminListener.endpoint, configuration: config, account: account, grant: grant)
        ready = true
        return stack
    }

    static func using(user: String = "mfa-user", windows: LifecycleWindows = .standard,
                      _ body: @MainActor (HeadlessStack) async throws -> Void) async throws {
        let stack = try await make(user: user, windows: windows)
        do { try await body(stack) } catch { await stack.finish(); throw error }
        await stack.finish()
    }

    func transport() -> (XPCAdminTransport, VaultAdminClient) {
        let client = VaultAdminClient(validated: configuration, endpoint: adminEndpoint, timeout: 12)
        adminClients.append(client)
        return (XPCAdminTransport(client: client), client)
    }
    func app() -> AppModel {
        let model = AppModel(transport: transport().0, signer: signer)
        models.append(model)
        return model
    }
    func pause() async throws -> UUID {
        let reply = try await read.perform(.init(operation: .run, accountID: account.id, action: .browserDemo))
        #expect(reply.parsedStatus == .outcome(.humanStepRequired))
        return try #require(reply.requestID)
    }
    func collect(_ run: UUID) async throws -> ReadReply { try await read.perform(.init(operation: .resume, requestID: run)) }
    func open(_ transport: XPCAdminTransport, step: HumanStepSummary) async throws -> UUID {
        var request = AdminRequest(operation: .openHumanStep)
        request.requestID = step.runID; request.accountID = step.accountID
        request.stepEpoch = step.epoch; request.humanStepKind = step.kind
        return try #require(try await AdminAuthorizationService(transport: transport, signer: signer)
            .perform(request, summary: "Synthetic U5 step").id)
    }
    func frame(_ transport: XPCAdminTransport, lease: UUID, after: UInt64 = 0) async throws -> HumanFrame {
        for _ in 0..<60 {
            switch try await transport.continueHuman(.init(lease: lease, operation: .frame(after: after))) {
            case .frame(let frame): return frame
            case .noFrame, .failure(.busy): try await Task.sleep(for: .milliseconds(60))
            default: throw VaultError.denied
            }
        }
        throw VaultError.upstreamUnavailable
    }
    var posts: [FixtureRequest] { site.trusted.requests.filter { $0.method == "POST" } }

    private func finish() async {
        // Independent of host.end/teardown: retain the owned pipe, kill through its pinned
        // handle and await confirmed reap before any service cleanup or directory removal.
        if let pipe = await host.launched {
            pipe.killGroup()
            #expect(await eventually { pipe.isReaped }, "U5 cleanup requires a confirmed owned-group reap")
        }
        watchdog?.cancel(); await watchdog?.value; watchdog = nil
        for model in models { await model.dismissHumanStep() }
        for client in adminClients { client.invalidate() }
        read.invalidate(); server.invalidate(); hostServer.invalidate()
        await host.teardown()
        site.stop()
        try? FileManager.default.removeItem(at: directory)
    }
}
