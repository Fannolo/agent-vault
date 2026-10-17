import AgentVaultContracts
@testable import AgentVaultAppSupport
@testable import AgentVaultCore
@testable import AgentVaultIPC
import Foundation
import Security
import Testing

// The real human app model, over the real admin XPC listener and client, into the real
// Administration, ContinuationOperations and Broker. Only the browser host is scripted.

private let me = UInt32(getuid())
private let credential = Data("synthetic-user\nSYNTHETIC-only-password".utf8)
private let profile = AccountProfile(login: "synthetic-user", userID: 4242)!

private let cdhash: String = {
    var code: SecCode?, staticCode: SecStaticCode?, info: CFDictionary?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
          SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
          SecCodeCopySigningInformation(staticCode, [], &info) == errSecSuccess,
          let unique = (info as? [String: Any])?[kSecCodeInfoUnique as String] as? Data else { fatalError("test host is not signed") }
    return unique.map { String(format: "%02x", $0) }.joined()
}()

private let configuration = IPCConfiguration(
    readServiceName: "dev.agentvault.test.read", adminServiceName: "dev.agentvault.test.admin",
    brokerRequirement: "cdhash H\"\(cdhash)\"", readRequirement: "cdhash H\"\(cdhash)\" and cdhash H\"\(cdhash)\"",
    adminRequirement: "(cdhash H\"\(cdhash)\")", brokerUID: me, allowedUID: me, development: true)

private final class State: StateStore, @unchecked Sendable {
    private let lock = NSLock()
    private var value = VaultState()
    func transaction<T>(_ body: (inout VaultState) throws -> T) throws -> T {
        try lock.withLock { var next = value; let result = try body(&next); value = next; return result }
    }
}

private final class Secrets: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [UUID: Data] = [:]
    func save(_ value: Data, for id: UUID) throws { lock.withLock { items[id] = value } }
    func load(for id: UUID) throws -> Data {
        try lock.withLock { guard let value = items[id] else { throw VaultError.secretUnavailable }; return value }
    }
    func delete(for id: UUID) throws { _ = lock.withLock { items.removeValue(forKey: id) } }
}

/// Pauses for a person, serves a new synthetic frame after each delivered batch and records input.
private final class FrameHost: WebSessionExecutor, @unchecked Sendable {
    private let lock = NSLock()
    private var open: Set<BrowserRunID> = []
    private var sequence: UInt64 = 1
    private var events: [HumanInput] = []
    private var shows = 0
    let reclassifyGate = Gate()
    let losses: AsyncStream<Set<BrowserRunID>> = AsyncStream { _ in }

    func start(_ run: BrowserRunID, workflow: WebWorkflow, credential: WebLoginCredential,
               authority: WebStartAuthority) async -> WebStep {
        guard await authority.lifetimeIfStillAuthorized() != nil else { return .failed(.timeout) }
        lock.withLock { _ = open.insert(run) }
        return .humanStep(.mfa)
    }
    func reclassify(_ run: BrowserRunID) async -> WebStep {
        await reclassifyGate.pass()
        return lock.withLock { open.contains(run) } ? .profile(profile) : .failed(.unknownRun)
    }
    func end(_ run: BrowserRunID) async { _ = lock.withLock { open.remove(run) } }
    func showHuman(_ step: HumanStepID) async -> Bool { lock.withLock { shows += 1; return open.contains(step.run) } }
    func frame(_ step: HumanStepID, after: UInt64) async -> HumanFrame? {
        let current = lock.withLock { open.contains(step.run) ? sequence : 0 }
        return current > after ? SyntheticFrames.frame(current) : nil
    }
    func input(_ step: HumanStepID, frame: UInt64, _ batch: HumanInputBatch) async -> Bool {
        lock.withLock {
            guard open.contains(step.run), frame == sequence else { return false }
            events += batch.events
            sequence += 1
            return true
        }
    }
    var received: [HumanInput] { lock.withLock { events } }
    var contexts: Int { lock.withLock { open.count } }
    var showCount: Int { lock.withLock { shows } }
}

/// Parks the next armed call until released.
private actor Gate {
    private var armed = false, reached = false
    private var parked: [CheckedContinuation<Void, Never>] = []
    func arm() { armed = true; reached = false }
    func pass() async {
        guard armed else { return }
        armed = false; reached = true
        await withCheckedContinuation { parked.append($0) }
    }
    var wasReached: Bool { reached }
    func release() { parked.forEach { $0.resume() }; parked = [] }
}

private final class Closed: @unchecked Sendable {
    private let lock = NSLock()
    private var ids: [UUID] = []
    func add(_ id: UUID) { lock.withLock { ids.append(id) } }
    var all: [UUID] { lock.withLock { ids } }
}

private final class Stack: @unchecked Sendable {
    let state = State()
    let host = FrameHost()
    let signer = SoftwareFixtureSigner()
    let broker: Broker
    let server: VaultXPCServer
    let endpoint: NSXPCListenerEndpoint
    let account: Account
    let client: ClientRecord
    let grant: Grant
    let authorizeGate = Gate()
    let closed = Closed()

    init() async throws {
        broker = Broker(state: state, secrets: Secrets(), webSessions: host)
        let admin = try Administration(broker: broker, publicKey: signer.publicKey.x963Representation)
        let operations = ContinuationOperations(broker: broker), broker = broker
        let authorizeGate = authorizeGate, closedLog = closed
        account = try await broker.enroll(service: .githubWeb, credential: credential)
        // A paired agent always has a UID; the snapshot wire refuses UID 0.
        client = try await broker.registerClient(uid: 4242)
        grant = try await broker.grant(clientID: client.id, accountID: account.id, duration: 3600, callLimit: 3)
        // The same closures BrokerMain composes.
        let handlers = VaultXPCServer.Handlers(
            read: { _, _ in ReadReply(.failure(.accessDenied)) },
            snapshot: { _ in try await admin.snapshot() },
            begin: { peer, request in
                do { return try await admin.begin(request, connection: ContinuationConnectionID(peer)) }
                catch { throw AdminRejection(status: (error as? VaultError)?.rawValue ?? "operation_failed") }
            },
            authorize: { peer, id, signature in
                await authorizeGate.pass()
                do { return try await admin.authorize(id, signature: signature, connection: ContinuationConnectionID(peer)) }
                catch { return AdminReply(status: (error as? VaultError)?.rawValue ?? "operation_failed") }
            },
            continuation: { peer, request in await operations.perform(request, connection: ContinuationConnectionID(peer)) },
            closed: { peer in
                await broker.continuationConnectionClosed(ContinuationConnectionID(peer))
                closedLog.add(peer.id)
            })
        let read = NSXPCListener.anonymous(), adminListener = NSXPCListener.anonymous()
        server = VaultXPCServer(validated: configuration, limits: .standard, readListener: read,
                                adminListener: adminListener, handlers: handlers)
        server.activate()
        endpoint = adminListener.endpoint
    }

    deinit { server.invalidate() }

    func transport() -> (XPCAdminTransport, VaultAdminClient) {
        let client = VaultAdminClient(validated: configuration, endpoint: endpoint, timeout: 5)
        return (XPCAdminTransport(client: client), client)
    }

    @MainActor func app() -> AppModel { AppModel(transport: transport().0, signer: signer) }

    func pausedRun() async throws -> BrowserRunID {
        guard case .humanStepRequired(let run) = try await broker.run(clientID: client.id, accountID: account.id,
                                                                     action: .githubWebProfile) else { throw VaultError.invalidResponse }
        return run
    }

    func openRequest(_ step: HumanStepSummary) -> AdminRequest {
        var request = AdminRequest(operation: .openHumanStep)
        request.requestID = step.runID; request.accountID = step.accountID
        request.stepEpoch = step.epoch; request.humanStepKind = step.kind
        return request
    }
}

private extension ContinuationConnectionID {
    init(_ peer: AdminConnection) { self.init(minted: peer.id, isOpen: { peer.isOpen }) }
}

@MainActor
private func eventually(_ condition: @MainActor () async -> Bool) async -> Bool {
    for _ in 0..<400 {
        if await condition() { return true }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return false
}

@MainActor @Suite(.serialized)
struct HumanContinuationE2ETests {
    @Test func aPersonCompletesTheStepInTheAppAndTheAgentCollectsTheResultOnce() async throws {
        let stack = try await Stack()
        let run = try await stack.pausedRun()
        let model = stack.app()
        await model.refresh()
        let step = try #require(model.humanSteps.first)
        #expect(step.runID == run.uuid && step.kind == .mfa && step.epoch == 1 && step.accountID == stack.account.id)
        #expect(await model.openHumanStep(step))
        let window = try #require(model.humanStep)
        #expect(await eventually { window.phase == .live && window.frame?.sequence == 1 })

        let secret = "SYNTHETIC-MFA-918273"
        window.type(secret)
        window.key(.enter)
        #expect(await eventually { stack.host.received.count == 2 })
        #expect(stack.host.received == [.text(secret), .key(.enter)])
        #expect(await eventually { window.frame?.sequence ?? 0 >= 2 }, "the next frame follows the delivered input")
        await window.finish()
        #expect(window.phase == .ended(.concluded))
        await model.dismissHumanStep()

        #expect(try await stack.broker.resume(run.uuid, clientID: stack.client.id) == .profile(profile))
        await #expect(throws: VaultError.denied) { _ = try await stack.broker.resume(run.uuid, clientID: stack.client.id) }
        let state = try stack.state.snapshot()
        #expect(state.grants.first?.callsUsed == 1)
        #expect(!String(decoding: try JSONEncoder().encode(state), as: UTF8.self).contains(secret))
        #expect(state.adminAudit.map(\.outcome).suffix(2) == ["continuation_opened", "human_finished"])
        #expect(stack.signer.signCount == 1)
    }

    @Test func aLeaseIsRefusedOnAnyOtherConnectionAndDiesWithItsOwn() async throws {
        let stack = try await Stack()
        let run = try await stack.pausedRun()
        let (first, firstClient) = stack.transport()
        let (second, _) = stack.transport()
        let step = try #require(try await first.snapshot().humanSteps.first)
        let service = AdminAuthorizationService(transport: first, signer: stack.signer)
        let lease = try #require(try await service.perform(stack.openRequest(step), summary: "synthetic open").id)

        let poll = ContinuationRequest(lease: lease, operation: .frame(after: 0))
        #expect(try await second.continueHuman(poll) == .failure(.accessDenied))
        #expect(try await second.continueHuman(.init(lease: lease, operation: .cancel)) == .failure(.accessDenied))
        guard case .frame(let frame) = try await first.continueHuman(poll) else { Issue.record("owner got no frame"); return }
        #expect(frame.sequence == 1)

        // The next call on this client opens a new connection with a new identity.
        firstClient.invalidate()
        #expect(await eventually { (try? await first.continueHuman(poll)) == .failure(.accessDenied) })
        #expect(try await stack.broker.resume(run.uuid, clientID: stack.client.id) == .humanStepRequired(run))
        #expect(stack.host.contexts == 1, "losing the window keeps the pause")
        let reopened = try #require(try await AdminAuthorizationService(transport: second, signer: stack.signer)
            .perform(stack.openRequest(step), summary: "synthetic reopen").id)
        try await Task.sleep(for: .milliseconds(60))
        guard case .frame = try await second.continueHuman(.init(lease: reopened, operation: .frame(after: 0))) else {
            Issue.record("reopened lease got no frame"); return
        }
    }

    @Test func revocationWhileTheWindowIsOpenEndsItAndTheBrowserContext() async throws {
        let stack = try await Stack()
        _ = try await stack.pausedRun()
        let model = stack.app()
        await model.refresh()
        #expect(await model.openHumanStep(try #require(model.humanSteps.first)))
        let window = try #require(model.humanStep)
        #expect(await eventually { window.phase == .live })
        try await stack.broker.revokeGrant(stack.grant.id)
        #expect(await eventually { window.phase == .ended(.unavailable) })
        #expect(stack.host.contexts == 0)
        await model.refresh()
        #expect(model.humanSteps.isEmpty)
    }

    @Test func aStaleSnapshotCannotOpenTheNextChallenge() async throws {
        let stack = try await Stack()
        _ = try await stack.pausedRun()
        let model = stack.app()
        await model.refresh()
        let step = try #require(model.humanSteps.first)
        let wrong = HumanStepSummary(runID: step.runID, epoch: step.epoch + 1, kind: step.kind, accountID: step.accountID,
                                     service: step.service, expiresAt: step.expiresAt)
        #expect(await model.openHumanStep(wrong) == false)
        #expect(model.notice?.text.contains("access_denied") == true)
        #expect(stack.signer.signCount == 0, "nobody is asked to sign a step that does not exist")
        #expect(model.humanStep == nil)
    }

    @Test func aSignedOpenThatCompletesAfterItsConnectionClosedGrantsNoLease() async throws {
        let stack = try await Stack()
        let run = try await stack.pausedRun()
        let (transport, client) = stack.transport()
        let step = try #require(try await transport.snapshot().humanSteps.first)
        guard case .challenge(let challenge) = try await client.begin(stack.openRequest(step)) else {
            Issue.record("no challenge"); return
        }
        let signature = try await stack.signer.sign(payload: challenge.payload, reason: "synthetic open")
        await stack.authorizeGate.arm()
        let call = Task { try? await client.authorize(id: challenge.id, signature: signature) }
        #expect(await eventually { await stack.authorizeGate.wasReached })
        client.invalidate()
        _ = await call.value
        #expect(await eventually { !stack.closed.all.isEmpty })
        await stack.authorizeGate.release()
        // The held authorize now runs on the broker for a connection that no longer exists.
        #expect(await eventually { await stack.broker.relayCount == 0 && stack.host.showCount == 0 })
        try await Task.sleep(for: .milliseconds(100))
        #expect(await stack.broker.relayCount == 0, "no lease or relay for a closed connection")
        #expect(stack.host.showCount == 0)
        #expect(!(try stack.state.snapshot().adminAudit.map(\.outcome).contains("continuation_opened")))
        #expect(try await stack.broker.resume(run.uuid, clientID: stack.client.id) == .humanStepRequired(run))
    }

    @Test func pollingDuringAFinishCannotTurnItsSuccessIntoUnavailable() async throws {
        let stack = try await Stack()
        let run = try await stack.pausedRun()
        let model = stack.app()
        await model.refresh()
        #expect(await model.openHumanStep(try #require(model.humanSteps.first)))
        let window = try #require(model.humanStep)
        #expect(await eventually { window.phase == .live })
        await stack.host.reclassifyGate.arm()
        let finishing = Task { await window.finish() }
        #expect(await eventually { await stack.host.reclassifyGate.wasReached })
        // Several poll intervals pass while the broker waits for the host.
        try await Task.sleep(for: .milliseconds(350))
        #expect(window.phase == .finishing)
        await stack.host.reclassifyGate.release()
        await finishing.value
        #expect(window.phase == .ended(.concluded))
        #expect(try await stack.broker.resume(run.uuid, clientID: stack.client.id) == .profile(profile))
    }

    @Test func theAgentReadWireHasNoContinuationOperation() {
        for operation in ["frame", "input", "continueHuman", "openHumanStep", "finish", "close"] {
            let data = Data(#"{"operation":"\#(operation)","requestID":"\#(UUID().uuidString)"}"#.utf8)
            #expect(throws: IPCError.invalidRequest) { _ = try WireCodec.decodeRead(data, limits: .standard) }
        }
    }
}

