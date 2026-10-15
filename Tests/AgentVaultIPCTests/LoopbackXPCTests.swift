@testable import AgentVaultIPC
import AgentVaultContracts
import Foundation
import Testing

@Suite(.serialized) struct LoopbackXPCTests {
    @Test func readCallReachesHandlerWithKernelUID() async throws {
        let loop = Loopback()
        let reply = try await loop.readClient().perform(ReadRequest(operation: .run, accountID: UUID(),
                                                                    action: .demoStatus))
        #expect(reply.login == "uid-\(me)")
        #expect(loop.recorder.uids == [me])
    }

    @Test func adminFlowReturnsChallengeAndReply() async throws {
        let loop = Loopback(begin: { _, request in
            guard request.operation == .prune else { throw AdminRejection(status: "unsupported") }
            return AdminChallenge(id: UUID(), payload: Data(repeating: 7, count: 32), expiresAt: Date() + 60)
        })
        let admin = loop.adminClient()
        #expect(try await admin.snapshot().clients.first?.uid == me)
        guard case .challenge(let challenge) = try await admin.begin(AdminRequest(operation: .prune)) else {
            Issue.record("expected challenge"); return
        }
        guard case .rejected(let refusal) = try await admin.begin(AdminRequest(operation: .recover)) else {
            Issue.record("expected rejection"); return
        }
        #expect(refusal.status == "unsupported")
        let reply = try await admin.authorize(id: challenge.id, signature: Data(repeating: 1, count: 64))
        #expect(reply.status == "applied" && reply.id == challenge.id)
    }

    @Test func readHandlersAreCancelledWhenTheirConnectionGoesButAdminWorkCompletes() async throws {
        let events = Recorder()
        let loop = Loopback(read: { _, _ in
            await withTaskCancellationHandler { try? await Task.sleep(for: .seconds(5)) } onCancel: { events.record(1) }
            return ReadReply(.outcome(.ready))
        }, begin: { _, _ in
            try? await Task.sleep(for: .milliseconds(400))
            events.record(Task.isCancelled ? 3 : 2)
            return AdminChallenge(id: UUID(), payload: Data(repeating: 7, count: 32), expiresAt: Date() + 60)
        })
        let read = loop.readClient(timeout: 3), admin = loop.adminClient(timeout: 3)
        let pendingRead = Task { try? await read.perform(ReadRequest(operation: .accounts)) }
        let pendingAdmin = Task { try? await admin.begin(AdminRequest(operation: .prune)) }
        try await Task.sleep(for: .milliseconds(150))
        read.invalidate(); admin.invalidate()
        _ = await pendingRead.value; _ = await pendingAdmin.value
        for _ in 0..<100 where events.uids.count < 2 { try await Task.sleep(for: .milliseconds(10)) }
        #expect(events.uids.sorted() == [1, 2], "the read is cancelled; the admin mutation is not")
    }

    @Test func handlerFinishingBeforeRegistrationIsNotRetained() {
        let work = CancellableWork()
        let key = work.reserve()
        let task = Task<Void, Never> {}
        work.complete(key)
        #expect(work.register(key, task), "a finished task needs no cancellation")
        #expect(work.retained == (0, 0))
        #expect(work.invalidate().isEmpty)
    }

    @Test func registrationAfterInvalidationCancelsTheHandler() {
        let work = CancellableWork()
        let key = work.reserve()
        #expect(work.invalidate().isEmpty)
        #expect(!work.register(key, Task<Void, Never> {}), "the dispatcher must cancel it")
        #expect(work.retained == (0, 0))
        // A handler dispatched after invalidation is also cancelled at registration.
        let late = work.reserve()
        #expect(!work.register(late, Task<Void, Never> {}))
        work.complete(key); work.complete(late)
        #expect(work.retained == (0, 0))
    }

    @Test func registeredRunningHandlerIsCancelledOnceAndThenForgotten() async {
        let work = CancellableWork()
        let key = work.reserve()
        let task = Task<Void, Never> { try? await Task.sleep(for: .seconds(5)) }
        #expect(work.register(key, task))
        #expect(work.retained == (1, 1))
        let cancelled = work.invalidate()
        #expect(cancelled.count == 1)
        cancelled.forEach { $0.cancel() }
        await task.value
        #expect(task.isCancelled && work.retained == (0, 0))
        work.complete(key)
        #expect(work.retained == (0, 0))
    }

    @Test func maximalSnapshotCrossesXPC() async throws {
        let loop = Loopback(snapshot: { _ in maximalSnapshot() })
        let snapshot = try await loop.adminClient().snapshot()
        #expect(snapshot.audit.count == 1000 && snapshot.grants.count == 512 && snapshot.pending.count == 128)
    }

    @Test func serverRefusesClientFailingReadRequirement() async {
        let loop = Loopback(server: developmentConfiguration(read: "cdhash H\"\(wrongCDHash)\""))
        await #expect(throws: IPCError.connectionFailed) {
            try await loop.readClient().perform(ReadRequest(operation: .accounts))
        }
        #expect(loop.recorder.uids.isEmpty)
    }

    @Test func serverRefusesUnexpectedKernelUID() async {
        let loop = Loopback(server: developmentConfiguration(allowedUID: me + 1))
        await #expect(throws: IPCError.connectionFailed) {
            try await loop.readClient().perform(ReadRequest(operation: .accounts))
        }
        await #expect(throws: IPCError.connectionFailed) { try await loop.adminClient().snapshot() }
        #expect(loop.recorder.uids.isEmpty)
    }

    @Test func clientRefusesBrokerFailingBrokerRequirement() async {
        let loop = Loopback(client: developmentConfiguration(broker: "cdhash H\"\(wrongCDHash)\""))
        await #expect(throws: IPCError.brokerRejected) {
            try await loop.readClient().perform(ReadRequest(operation: .accounts))
        }
        #expect(loop.recorder.uids.isEmpty)
    }

    @Test func clientRefusesBrokerWithUnexpectedUID() async {
        let loop = Loopback(client: developmentConfiguration(brokerUID: me + 1))
        await #expect(throws: IPCError.brokerRejected) {
            try await loop.readClient().perform(ReadRequest(operation: .accounts))
        }
    }

    @Test func excessConcurrencyOnOneConnectionReturnsBusy() async throws {
        var limits = IPCLimits.standard
        limits.maxInFlightPerConnection = 2
        let loop = Loopback(limits: limits, read: { _, _ in
            try await Task.sleep(nanoseconds: 400_000_000)
            return ReadReply(.outcome(.ready))
        })
        let client = loop.readClient()
        let outcomes = await withTaskGroup(of: String.self) { group in
            for _ in 0..<6 {
                group.addTask {
                    do throws(IPCError) {
                        return try await client.perform(ReadRequest(operation: .accounts)).status
                    } catch { return error.rawValue }
                }
            }
            return await group.reduce(into: [String: Int]()) { $0[$1, default: 0] += 1 }
        }
        #expect(outcomes == ["ready": 2, "busy": 4])
        #expect(try await client.perform(ReadRequest(operation: .accounts)).status == "ready")
    }

    @Test func saturatedReadTrafficPreservesFreshAndEstablishedAdminAccess() async throws {
        let held = HeldCalls<ReadReply>()
        let snapshots = Recorder(), begins = Recorder()
        let loop = Loopback(read: { _, _ in
            await held.perform(ReadReply(.outcome(.ready)))
        }, snapshot: { uid in
            snapshots.record(uid)
            return AdminSnapshot(accounts: [], clients: [], grants: [], pending: [])
        }, begin: { uid, _ in
            begins.record(uid)
            return AdminChallenge(id: UUID(), payload: Data(repeating: 7, count: 32), expiresAt: Date() + 60)
        })
        let established = loop.adminClient()
        _ = try await established.snapshot()
        let clients = (0..<8).map { _ in loop.readClient(timeout: 10) }
        let tasks = clients.flatMap { client in
            (0..<4).map { _ in
                Task { try await client.perform(ReadRequest(operation: .accounts)) }
            }
        }
        let fresh = loop.adminClient()
        let excess = loop.readClient()
        defer {
            held.release()
            clients.forEach { $0.invalidate() }
            established.invalidate(); fresh.invalidate(); excess.invalidate()
        }
        let saturated = await held.waitUntilStarted(32)
        #expect(saturated)
        guard saturated else { return }

        // Even a new channel can authenticate with its empty probe while all 32 read calls wait.
        #expect(await raw(loop.readEndpoint, Data()) == #"{"error":"invalid_request"}"#)
        #expect(await raw(loop.adminEndpoint, protocol: VaultAdminRPC.self) { proxy, reply in
            (proxy as? VaultAdminRPC)?.begin(Data(), reply: reply)
        } == #"{"error":"invalid_request"}"#)
        await #expect(throws: IPCError.busy) {
            try await excess.perform(ReadRequest(operation: .accounts))
        }
        #expect(held.started == 32)
        _ = try await fresh.snapshot()
        _ = try await established.snapshot()
        guard case .challenge = try await fresh.begin(AdminRequest(operation: .prune)) else {
            Issue.record("admin begin did not issue a challenge while reads were saturated"); return
        }
        #expect(snapshots.uids == [me, me, me])
        #expect(begins.uids == [me]) // Empty probes never reach the mutation handler.
        held.release()
        for task in tasks { #expect(try await task.value.status == "ready") }
    }

    @Test func standardConnectionStillAllowsOnlyFourInFlightReadCalls() async throws {
        let held = HeldCalls<ReadReply>()
        let loop = Loopback(read: { _, _ in await held.perform(ReadReply(.outcome(.ready))) })
        let client = loop.readClient(timeout: 10)
        let tasks = (0..<4).map { _ in
            Task { try await client.perform(ReadRequest(operation: .accounts)) }
        }
        defer { held.release(); client.invalidate() }
        let saturated = await held.waitUntilStarted(4)
        #expect(saturated)
        guard saturated else { return }
        await #expect(throws: IPCError.busy) {
            try await client.perform(ReadRequest(operation: .accounts))
        }
        #expect(held.started == 4)
        held.release()
        for task in tasks { #expect(try await task.value.status == "ready") }
        #expect(try await client.perform(ReadRequest(operation: .accounts)).status == "ready")
    }

    @Test func saturatedAdminWorkDoesNotDelayInvalidProbesOrInvokeTheirHandlers() async throws {
        let held = HeldCalls<AdminSnapshot>()
        let begins = Recorder()
        let loop = Loopback(snapshot: { _ in
            await held.perform(AdminSnapshot(accounts: [], clients: [], grants: [], pending: []))
        }, begin: { uid, _ in
            begins.record(uid)
            return AdminChallenge(id: UUID(), payload: Data(repeating: 7, count: 32), expiresAt: Date() + 60)
        })
        let client = loop.adminClient(timeout: 10)
        let tasks = (0..<4).map { _ in Task { try await client.snapshot() } }
        let fresh = loop.adminClient()
        defer { held.release(); client.invalidate(); fresh.invalidate() }
        let saturated = await held.waitUntilStarted(4)
        #expect(saturated)
        guard saturated else { return }
        #expect(await raw(loop.adminEndpoint, protocol: VaultAdminRPC.self) { proxy, reply in
            (proxy as? VaultAdminRPC)?.begin(Data(), reply: reply)
        } == #"{"error":"invalid_request"}"#)
        // The fresh client's probe succeeds, then its valid request meets the admin work bound.
        await #expect(throws: IPCError.busy) { try await fresh.begin(AdminRequest(operation: .prune)) }
        #expect(held.started == 4)
        #expect(begins.uids.isEmpty)
        held.release()
        for task in tasks { #expect(try await task.value.accounts.isEmpty) }
    }

    @Test func handlerFailureAndInvalidHandlerOutputBecomeUnavailable() async {
        struct Boom: Error {}
        let failing = Loopback(read: { _, _ in throw Boom() })
        await #expect(throws: IPCError.unavailable) {
            try await failing.readClient().perform(ReadRequest(operation: .accounts))
        }
        // A closed status carrying a field it does not define is still invalid handler output.
        let invalid = Loopback(read: { _, _ in ReadReply(.failure(.busy), requestID: UUID()) })
        await #expect(throws: IPCError.unavailable) {
            try await invalid.readClient().perform(ReadRequest(operation: .accounts))
        }
    }

    @Test func rawMalformedRequestsGetFixedCodes() async {
        let loop = Loopback()
        #expect(await raw(loop.readEndpoint, json(#"{"operation":"accounts","uid":0}"#)) == #"{"error":"invalid_request"}"#)
        #expect(await raw(loop.readEndpoint, Data(count: 20_000)) == #"{"error":"request_too_large"}"#)
        #expect(loop.recorder.uids.isEmpty)
    }

    @Test func adminSelectorOnReadServiceIsNotDispatched() async {
        let loop = Loopback()
        let outcome = await raw(loop.readEndpoint, protocol: VaultAdminRPC.self) { proxy, reply in
            (proxy as? VaultAdminRPC)?.snapshot(reply: reply)
        }
        #expect(!outcome.hasPrefix("{"))
        #expect(loop.recorder.uids.isEmpty)
    }

    @Test func impostorBrokerNeverReceivesRequestBytes() async {
        let impostor = FakeBroker(reply: json(#"{"readReply":{"status":"completed","login":"impostor","userID":7}}"#))
        let configuration = developmentConfiguration(broker: "cdhash H\"\(wrongCDHash)\"")
        let client = VaultReadClient(validated: configuration, endpoint: impostor.endpoint, timeout: 3)
        await #expect(throws: IPCError.brokerRejected) {
            try await client.perform(ReadRequest(operation: .run, accountID: UUID(), action: .githubProfile))
        }
        #expect(impostor.received == [Data()])
    }

    @Test func clientRejectsMalformedBrokerReplies() async {
        for body in [#"{"error":"broker_rejected"}"#, #"{"readReply":{"status":"ready","password":"x"}}"#, "junk"] {
            let fake = FakeBroker(reply: json(body))
            let client = VaultReadClient(validated: developmentConfiguration(), endpoint: fake.endpoint, timeout: 3)
            await #expect(throws: IPCError.malformedReply) { try await client.perform(ReadRequest(operation: .accounts)) }
        }
    }
}

/// Holds actual dispatched XPC work until the test explicitly releases it.
private final class HeldCalls<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    private var released = false
    private var waiting: [(CheckedContinuation<Value, Never>, Value)] = []

    var started: Int { lock.withLock { count } }

    func perform(_ value: Value) async -> Value {
        await withCheckedContinuation { continuation in
            let immediate = lock.withLock {
                count += 1
                guard !released else { return true }
                waiting.append((continuation, value))
                return false
            }
            if immediate { continuation.resume(returning: value) }
        }
    }

    func waitUntilStarted(_ expected: Int) async -> Bool {
        let deadline = Date() + 4
        while started < expected && Date() < deadline {
            try? await Task.sleep(for: .milliseconds(10))
        }
        return started == expected
    }

    func release() {
        let pending = lock.withLock {
            released = true
            defer { waiting.removeAll() }
            return waiting
        }
        for (continuation, value) in pending { continuation.resume(returning: value) }
    }
}

private func raw(_ endpoint: NSXPCListenerEndpoint, _ data: Data) async -> String {
    await raw(endpoint, protocol: VaultReadRPC.self) { proxy, reply in (proxy as? VaultReadRPC)?.perform(data, reply: reply) }
}

/// Sends through a bare connection that still enforces the broker requirement.
private func raw(_ endpoint: NSXPCListenerEndpoint, protocol interface: Protocol,
                 _ send: @escaping @Sendable (AnyObject, @escaping (Data) -> Void) -> Void?) async -> String {
    let connection = NSXPCConnection(listenerEndpoint: endpoint)
    connection.remoteObjectInterface = NSXPCInterface(with: interface)
    connection.setCodeSigningRequirement(pinned().broker)
    connection.activate()
    defer { connection.invalidate() }
    let box = UncheckedBox(connection)
    return await withCheckedContinuation { (continuation: CheckedContinuation<String, Never>) in
        let once = StringOnce(continuation)
        let proxy = box.value.remoteObjectProxyWithErrorHandler { once.resume("xpc_error_\(($0 as NSError).code)") }
        DispatchQueue.global().asyncAfter(deadline: .now() + 3) { once.resume("timeout") }
        _ = send(proxy as AnyObject) { once.resume(String(decoding: $0, as: UTF8.self)) }
    }
}

private final class UncheckedBox<T>: @unchecked Sendable {
    let value: T
    init(_ value: T) { self.value = value }
}

private final class StringOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<String, Never>?
    init(_ continuation: CheckedContinuation<String, Never>) { self.continuation = continuation }
    func resume(_ value: String) {
        let continuation = lock.withLock { () -> CheckedContinuation<String, Never>? in
            defer { self.continuation = nil }
            return self.continuation
        }
        continuation?.resume(returning: value)
    }
}

/// A listener that answers every read with fixed bytes, standing in for a hostile broker.
private final class FakeBroker: NSObject, NSXPCListenerDelegate, VaultReadRPC, @unchecked Sendable {
    private let listener = NSXPCListener.anonymous()
    private let reply: Data
    private let lock = NSLock()
    private var payloads: [Data] = []
    var endpoint: NSXPCListenerEndpoint { listener.endpoint }
    var received: [Data] { lock.withLock { payloads } }

    init(reply: Data) {
        self.reply = reply
        super.init()
        listener.delegate = self
        listener.activate()
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: VaultReadRPC.self)
        connection.exportedObject = self
        connection.activate()
        return true
    }

    func perform(_ data: Data, reply: @escaping (Data) -> Void) {
        lock.withLock { payloads.append(data) }
        reply(data.isEmpty ? json(#"{"error":"invalid_request"}"#) : self.reply)
    }
}
