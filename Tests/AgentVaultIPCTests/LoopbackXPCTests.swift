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
            return ReadReply(status: "ok")
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
        #expect(outcomes == ["ok": 2, "busy": 4])
        #expect(try await client.perform(ReadRequest(operation: .accounts)).status == "ok")
    }

    @Test func handlerFailureAndInvalidHandlerOutputBecomeUnavailable() async {
        struct Boom: Error {}
        let failing = Loopback(read: { _, _ in throw Boom() })
        await #expect(throws: IPCError.unavailable) {
            try await failing.readClient().perform(ReadRequest(operation: .accounts))
        }
        let invalid = Loopback(read: { _, _ in ReadReply(status: "Leaked Secret Value") })
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
        let impostor = FakeBroker(reply: json(#"{"readReply":{"status":"ok","login":"impostor"}}"#))
        let configuration = developmentConfiguration(broker: "cdhash H\"\(wrongCDHash)\"")
        let client = VaultReadClient(validated: configuration, endpoint: impostor.endpoint, timeout: 3)
        await #expect(throws: IPCError.brokerRejected) {
            try await client.perform(ReadRequest(operation: .run, accountID: UUID(), action: .githubProfile))
        }
        #expect(impostor.received == [Data()])
    }

    @Test func clientRejectsMalformedBrokerReplies() async {
        for body in [#"{"error":"broker_rejected"}"#, #"{"readReply":{"status":"ok","password":"x"}}"#, "junk"] {
            let fake = FakeBroker(reply: json(body))
            let client = VaultReadClient(validated: developmentConfiguration(), endpoint: fake.endpoint, timeout: 3)
            await #expect(throws: IPCError.malformedReply) { try await client.perform(ReadRequest(operation: .accounts)) }
        }
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
