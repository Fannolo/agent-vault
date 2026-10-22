@testable import AgentVaultIPC
import AgentVaultContracts
import Foundation
import Testing

private let lease = UUID()
private let jpeg = Data([0xFF, 0xD8, 0x00, 0x00, 0xFF, 0xD9])

/// Collects values from XPC handler threads.
private final class Seen<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [Value] = []
    func add(_ value: Value) { lock.withLock { values.append(value) } }
    var all: [Value] { lock.withLock { values } }
    func wait(count: Int) async -> Bool {
        let deadline = Date() + 4
        while all.count < count && Date() < deadline { try? await Task.sleep(for: .milliseconds(10)) }
        return all.count >= count
    }
}

/// Parks handler calls until released.
private final class Parked: @unchecked Sendable {
    private let lock = NSLock()
    private var released = false
    private var waiting: [CheckedContinuation<Void, Never>] = []
    let started = Seen<Int>()

    func park() async {
        await withCheckedContinuation { continuation in
            let now = lock.withLock {
                started.add(1)
                if released { return true }
                waiting.append(continuation)
                return false
            }
            if now { continuation.resume() }
        }
    }

    func release() {
        let pending = lock.withLock { released = true; defer { waiting = [] }; return waiting }
        pending.forEach { $0.resume() }
    }
}

@Suite(.serialized) struct ContinuationXPCTests {
    @Test func theListenerMintsOneIdentityPerConnectionAndReportsItWhenTheConnectionCloses() async throws {
        let seen = Seen<AdminConnection>(), closed = Seen<AdminConnection>()
        let loop = Loopback(begin: { peer, _ in
            seen.add(peer)
            return AdminChallenge(id: UUID(), payload: Data(repeating: 7, count: 32), expiresAt: Date() + 60)
        }, authorize: { peer, id, _ in
            seen.add(peer)
            return AdminReply(status: "completed", id: id)
        }, continuation: { peer, _ in
            seen.add(peer)
            return .noFrame
        }, closed: { closed.add($0) })
        let first = loop.adminClient(), second = loop.adminClient()
        guard case .challenge(let challenge) = try await first.begin(AdminRequest(operation: .prune)) else {
            Issue.record("expected challenge"); return
        }
        _ = try await first.authorize(id: challenge.id, signature: Data(repeating: 1, count: 64))
        #expect(try await first.continueHuman(ContinuationRequest(lease: lease, operation: .frame(after: 0))) == .noFrame)
        #expect(try await second.continueHuman(ContinuationRequest(lease: lease, operation: .close)) == .noFrame)

        let identities = seen.all
        #expect(identities.count == 4 && identities.allSatisfy { $0.uid == me })
        #expect(Set(identities.prefix(3).map(\.id)).count == 1, "begin, authorize and continuation share one connection")
        #expect(identities[3].id != identities[0].id)

        first.invalidate()
        #expect(await closed.wait(count: 1))
        #expect(closed.all.map(\.id) == [identities[0].id])
        second.invalidate()
        #expect(await closed.wait(count: 2))
    }

    @Test func continuationSaturationLeavesAdminCapacityAndIsBoundedPerConnection() async throws {
        let parked = Parked()
        let loop = Loopback(continuation: { _, _ in
            await parked.park()
            return .noFrame
        })
        let clients = (0..<3).map { _ in loop.adminClient(timeout: 10) }
        defer { parked.release(); clients.forEach { $0.invalidate() } }
        let poll = ContinuationRequest(lease: lease, operation: .frame(after: 0))
        _ = try await clients[0].snapshot()
        let held = (0..<4).map { index in Task { try await clients[index / 2].continueHuman(poll) } }
        #expect(await parked.started.wait(count: 4))

        await #expect(throws: IPCError.busy) { try await clients[0].continueHuman(poll) }
        await #expect(throws: IPCError.busy) { try await clients[2].continueHuman(poll) }
        // Revocation and other controls keep their own lanes on the same connections.
        #expect(try await clients[0].snapshot().clients.first?.uid == me)
        guard case .challenge = try await clients[2].begin(AdminRequest(operation: .prune)) else {
            Issue.record("admin begin starved by continuation"); return
        }
        parked.release()
        for task in held { #expect(try await task.value == .noFrame) }
        #expect(parked.started.all.count == 4, "refused calls never reached the handler")
    }

    @Test func typedRequestsAndRepliesCrossXPCExactly() async throws {
        let requests = Seen<ContinuationRequest>()
        let frame = HumanFrame(sequence: 3, width: 640, height: 480, jpeg: jpeg)!
        let loop = Loopback(continuation: { _, request in
            requests.add(request)
            switch request.operation {
            case .frame(let after): return after < 3 ? .frame(frame) : .frame(HumanFrame(sequence: 2, width: 1, height: 1, jpeg: jpeg)!)
            case .input: return .delivered
            case .finish: return .nextStep(.captcha)
            case .cancel: return .concluded
            case .close: return .failure(.accessDenied)
            }
        })
        let client = loop.adminClient()
        let events = HumanInputBatch([.pointer(.down, x: 0, y: 899), .wheel(dx: -2000, dy: 5), .key(.arrowLeft),
                                      .text("é 1/2 \"q\"")])!
        let sent: [ContinuationRequest] = [
            .init(lease: lease, operation: .frame(after: 0)),
            .init(lease: lease, operation: .input(batch: 9, frame: 3, events)),
            .init(lease: lease, operation: .finish), .init(lease: lease, operation: .cancel), .init(lease: lease, operation: .close)
        ]
        var replies: [ContinuationReply] = []
        for request in sent { replies.append(try await client.continueHuman(request)) }
        #expect(replies == [.frame(frame), .delivered, .nextStep(.captcha), .concluded, .failure(.accessDenied)])
        #expect(requests.all == sent)
        await #expect(throws: IPCError.malformedReply, "a frame not newer than requested is refused by the client") {
            try await client.continueHuman(.init(lease: lease, operation: .frame(after: 3)))
        }
    }

    @Test func malformedContinuationBytesNeverReachTheHandler() async {
        let requests = Seen<ContinuationRequest>()
        let loop = Loopback(continuation: { _, request in requests.add(request); return .noFrame })
        for text in [#"{"operation":"frame","lease":"\#(lease)","after":0,"url":"https://example.invalid"}"#,
                     #"{"operation":"frame","lease":"\#(lease)","after":0,"after":1}"#, "", "[]"] {
            let data = Data(text.utf8)
            #expect(await rawAdmin(loop.adminEndpoint, data) == #"{"error":"invalid_request"}"#)
        }
        let oversized = Data((#"{"operation":"close","lease":"\#(lease)"}"# + String(repeating: " ", count: 8_192)).utf8)
        #expect(await rawAdmin(loop.adminEndpoint, oversized) == #"{"error":"request_too_large"}"#)
        #expect(requests.all.isEmpty)
    }
}

private func rawAdmin(_ endpoint: NSXPCListenerEndpoint, _ data: Data) async -> String {
    let connection = NSXPCConnection(listenerEndpoint: endpoint)
    connection.remoteObjectInterface = NSXPCInterface(with: VaultAdminRPC.self)
    connection.setCodeSigningRequirement(pinned().broker)
    connection.activate()
    defer { connection.invalidate() }
    let reply = Seen<String>()
    let proxy = connection.remoteObjectProxyWithErrorHandler { reply.add("xpc_error_\(($0 as NSError).code)") }
    (proxy as? VaultAdminRPC)?.continueHuman(data) { reply.add(String(decoding: $0, as: UTF8.self)) }
    _ = await reply.wait(count: 1)
    return reply.all.first ?? "timeout"
}

@Suite struct ContinuationWireTests {
    static let id = lease.uuidString

    static let accepted: [String] = [
        #"{"operation":"frame","lease":"\#(id)","after":0}"#,
        #"{"operation":"frame","lease":"\#(id)","after":9007199254740992}"#,
        #"{"operation":"input","lease":"\#(id)","batch":1,"frame":1,"events":[{"type":"pointer","phase":"move","x":1279,"y":0}]}"#,
        #"{"operation":"input","lease":"\#(id)","batch":1,"frame":1,"events":[{"type":"wheel","dx":0,"dy":-2000}]}"#,
        #"{"operation":"input","lease":"\#(id)","batch":1,"frame":1,"events":[{"type":"key","key":"backspace"}]}"#,
        #"{"operation":"input","lease":"\#(id)","batch":1,"frame":1,"events":[{"type":"text","text":"\#(String(repeating: "a", count: 64))"}]}"#,
        #"{"operation":"finish","lease":"\#(id)"}"#, #"{"operation":"cancel","lease":"\#(id)"}"#, #"{"operation":"close","lease":"\#(id)"}"#
    ]

    static func input(_ event: String, batch: String = "1", frame: String = "1") -> String {
        #"{"operation":"input","lease":"\#(id)","batch":\#(batch),"frame":\#(frame),"events":[\#(event)]}"#
    }

    static let refused: [String] = [
        #"{"operation":"navigate","lease":"\#(id)"}"#,
        #"{"operation":"frame","after":0}"#,
        #"{"operation":"frame","lease":"not-a-uuid","after":0}"#,
        #"{"operation":"frame","lease":"\#(id)"}"#,
        #"{"operation":"frame","lease":"\#(id)","after":null}"#,
        #"{"operation":"frame","lease":"\#(id)","after":1.5}"#,
        #"{"operation":"frame","lease":"\#(id)","after":-1}"#,
        #"{"operation":"frame","lease":"\#(id)","after":9007199254740993}"#,
        #"{"operation":"frame","lease":"\#(id)","after":"0"}"#,
        #"{"operation":"finish","lease":"\#(id)","after":0}"#,
        #"{"operation":"close","lease":"\#(id)","script":"x"}"#,
        #"{"operation":"input","lease":"\#(id)","batch":1,"frame":1}"#,
        #"{"operation":"input","lease":"\#(id)","batch":1,"frame":1,"events":[]}"#,
        #"{"operation":"input","lease":"\#(id)","batch":1,"frame":1,"events":{"type":"key","key":"tab"}}"#,
        #"{"operation":"input","lease":"\#(id)","batch":1,"frame":1,"events":[\#(Array(repeating: #"{"type":"key","key":"tab"}"#, count: 33).joined(separator: ","))]}"#,
        input(#"{"type":"key","key":"tab"}"#, batch: "0"),
        input(#"{"type":"key","key":"tab"}"#, frame: "0"),
        input(#"{"type":"click","x":1,"y":1}"#),
        input(#"{"type":"key","key":"f12"}"#),
        input(#"{"type":"key","key":"tab","text":"x"}"#),
        input(#"{"type":"key","key":"tab","key":"enter"}"#),
        input(#"{"type":"pointer","phase":"drag","x":1,"y":1}"#),
        input(#"{"type":"pointer","phase":"down","x":-1,"y":1}"#),
        input(#"{"type":"pointer","phase":"down","x":1280,"y":1}"#),
        input(#"{"type":"pointer","phase":"down","x":1,"y":900}"#),
        input(#"{"type":"pointer","phase":"down","x":1}"#),
        input(#"{"type":"wheel","dx":-9223372036854775808,"dy":1}"#),
        input(#"{"type":"wheel","dx":2001,"dy":0}"#),
        input(#"{"type":"wheel","dx":0,"dy":0}"#),
        input(#"{"type":"text","text":""}"#),
        input(#"{"type":"text","text":"\#(String(repeating: "a", count: 65))"}"#),
        input(#"{"type":"text","text":"\#(String(repeating: "é", count: 33))"}"#),
        input(#"{"type":"text","text":"a\nb"}"#),
        input(#"{"type":"text","text":"a\u0007"}"#),
        input(#"{"type":"text","text":{"value":"a"}}"#),
        input(#"{"type":"text","text":null}"#)
    ]

    @Test(arguments: accepted)
    func acceptedRequestsRoundTrip(_ text: String) throws {
        let request = try WireCodec.decodeContinuation(Data(text.utf8), limits: .standard)
        #expect(try WireCodec.decodeContinuation(try WireCodec.encode(request), limits: .standard) == request)
    }

    @Test(arguments: refused)
    func refusedRequestsNeverProduceATypedValue(_ text: String) {
        #expect(throws: IPCError.invalidRequest) { _ = try WireCodec.decodeContinuation(Data(text.utf8), limits: .standard) }
    }

    @Test func requestsAreBoundedBelowTheAdminLimit() throws {
        let worst = HumanInputBatch(Array(repeating: HumanInput.text(String(repeating: "\"", count: 64)), count: 32))!
        let data = try WireCodec.encode(ContinuationRequest(lease: lease, operation: .input(batch: 1, frame: 1, worst)))
        #expect(data.count <= ContinuationLimits.maxRequestBytes)
        let padded = Data((#"{"operation":"close","lease":"\#(Self.id)"}"# + String(repeating: " ", count: ContinuationLimits.maxRequestBytes)).utf8)
        #expect(throws: IPCError.requestTooLarge) { _ = try WireCodec.decodeContinuation(padded, limits: .standard) }
    }

    static let refusedReplies: [String] = [
        #"{"humanFrame":{"sequence":1,"width":1,"height":1,"jpeg":"AAAA"}}"#,
        #"{"humanFrame":{"sequence":0,"width":1,"height":1,"jpeg":"/9gAAP/Z"}}"#,
        #"{"humanFrame":{"sequence":1,"width":1281,"height":1,"jpeg":"/9gAAP/Z"}}"#,
        #"{"humanFrame":{"sequence":1,"width":1,"height":901,"jpeg":"/9gAAP/Z"}}"#,
        #"{"humanFrame":{"sequence":1,"width":1,"height":1,"jpeg":"/9gAAP/Z","url":"x"}}"#,
        #"{"humanFrame":{"sequence":1,"width":1,"height":1,"jpeg":"/9gAAP/Z"},"humanReply":{"status":"closed"}}"#,
        #"{"humanReply":{"status":"next_step"}}"#,
        #"{"humanReply":{"status":"concluded","kind":"mfa"}}"#,
        #"{"humanReply":{"status":"next_step","kind":"password"}}"#,
        #"{"humanReply":{"status":"completed"}}"#,
        #"{"humanReply":{"status":"closed","status":"concluded"}}"#,
        #"{"readReply":{"status":"ready"}}"#
    ]

    @Test(arguments: refusedReplies)
    func refusedRepliesAreMalformed(_ text: String) {
        guard case .failure(.malformedReply) = WireCodec.decodeReply(Data(text.utf8), allowed: [.humanFrame, .humanReply],
                                                                     limits: .standard) else {
            Issue.record("accepted \(text)"); return
        }
    }

    @Test func everyReplyRoundTripsAndTheLargestFrameFitsTheReplyLimit() throws {
        var biggest = Data([0xFF, 0xD8]); biggest.append(Data(repeating: 0x5A, count: HumanFrame.maximumJPEGBytes - 4)); biggest.append(contentsOf: [0xFF, 0xD9])
        let replies: [ContinuationReply] = [
            .frame(HumanFrame(sequence: HumanFrame.maximumSequence, width: 1280, height: 900, jpeg: biggest)!),
            .noFrame, .delivered, .notDelivered, .concluded, .nextStep(.mfa), .closed
        ] + ContinuationFailure.allCases.map(ContinuationReply.failure)
        for reply in replies {
            let data = try #require(WireCodec.continuationReply(reply, limits: .standard))
            guard case .success(.continuation(let decoded)) = WireCodec.decodeReply(data, allowed: [.humanFrame, .humanReply],
                                                                                     limits: .standard) else {
                Issue.record("reply did not round trip"); continue
            }
            #expect(decoded == reply)
        }
    }
}
