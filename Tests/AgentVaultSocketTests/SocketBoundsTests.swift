@testable import AgentVaultIPC
import AgentVaultContracts
import CAgentVaultSocket
import Foundation
import Testing
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Reply backlog, stop and deadline checks, startup ownership, cleanup capacity and the test
/// peer's descriptor ownership.
@Suite(.serialized) struct SocketBoundsTests {
    private let accounts = SocketFrame.request(id: 1, opcode: .read, body: try! WireCodec.encode(ReadRequest(operation: .accounts)))

    // MARK: Test peer

    @Test func rawPeerCloseIsOneShot() throws {
        // The freed number is taken again by this test's own descriptor; a second close must
        // leave it open. Retried in case a concurrent suite takes the number first.
        for _ in 0..<20 {
            var pair: [Int32] = [-1, -1]
            try #require(av_socket_pipe(&pair) == 0)
            let peer = RawPeer(accepted: pair[0])
            peer.close()
            var mine: [Int32] = [-1, -1]
            try #require(av_socket_pipe(&mine) == 0)
            defer { closeDescriptor(mine[0]); closeDescriptor(mine[1]); closeDescriptor(pair[1]) }
            guard mine.contains(pair[0]) else { continue }
            peer.close()
            #expect(fcntl(pair[0], F_GETFD) != -1, "a second close must not touch a reused descriptor")
            return
        }
        Issue.record("the freed descriptor number was never reused")
    }

    // MARK: Stop and deadlines

    @Test func readerObservesStopWhileBytesAreReady() throws {
        let (server, peer) = try streamPair()
        let wake = try WakePipe()
        defer { closeDescriptor(server); closeDescriptor(peer); wake.close() }
        #expect(SocketIO.writeAll(peer, wake: -1, accounts + accounts, deadline: .after(2)))
        guard case .success(.complete) = SocketIO.readFrame(server, wake: wake.read, headerSize: SocketFrame.requestHeader,
                                                            maxBody: 1 << 16, timeout: 2) else {
            throw Unexpected(what: "first frame")
        }
        // The second frame's bytes are ready, but stop fired between frames.
        wake.fire()
        guard case .failure(.stopped) = SocketIO.readFrame(server, wake: wake.read, headerSize: SocketFrame.requestHeader,
                                                           maxBody: 1 << 16, timeout: 2) else {
            throw Unexpected(what: "stop between ready frames")
        }
    }

    @Test func writerSendsNothingAfterStopOrPastItsDeadline() throws {
        let (server, peer) = try streamPair()
        let wake = try WakePipe()
        defer { closeDescriptor(server); closeDescriptor(peer); wake.close() }
        // Both writes could complete at once; neither may start.
        #expect(!SocketIO.writeAll(server, wake: -1, accounts, deadline: .after(0)), "an expired write")
        wake.fire()
        #expect(!SocketIO.writeAll(server, wake: wake.read, accounts, deadline: .after(2)), "a write after stop")
        var byte: UInt8 = 0
        let count = av_socket_recv(peer, &byte, 1)
        let failure = errno
        #expect(count == -1 && (failure == EAGAIN || failure == EWOULDBLOCK), "no byte reached the peer")
    }

    @Test func anExpiredQueuedCallIsNeverSentAndTheConnectionStaysUsable() async throws {
        let (client, broker) = try streamPair()
        defer { closeDescriptor(broker) }
        let connection = ClientConnection(fd: client, limits: .standard, timeouts: testTimeouts) { _ in }
        connection.start()
        let body = try WireCodec.encode(ReadRequest(operation: .accounts))
        guard case .failure(.timeout) = await connection.call(.read, body, allowed: [.readReply], deadline: .after(0)) else {
            throw Unexpected(what: "expired call")
        }
        let live = Task { await connection.call(.read, body, allowed: [.readReply], deadline: .after(3)) }
        let id = try await blocking { () throws -> UInt32 in
            guard case .ready = SocketIO.wait(broker, wake: -1, events: Int32(AV_WAIT_READ), deadline: .after(3)),
                  case .success(.complete(let header, _)) = SocketIO.readFrame(broker, wake: -1, headerSize: SocketFrame.requestHeader,
                                                                              maxBody: 1 << 16, timeout: 2) else {
                throw Unexpected(what: "live frame")
            }
            return SocketFrame.number(header, at: 4)
        }
        #expect(id == 2, "the first frame on the wire belongs to the live call")
        let reply = try #require(WireCodec.reply(ReadReply(.outcome(.completed), accounts: []), kind: .readReply, limits: .standard))
        #expect(SocketIO.writeAll(broker, wake: -1, SocketFrame.reply(id: id, body: reply), deadline: .after(2)))
        guard case .success(.readReply) = await live.value else { throw Unexpected(what: "live reply") }
        await connection.close()
    }

    @Test func acceptLoopStopsBetweenConnectionsWhileMoreAreQueued() async throws {
        let directory = try OwnedDirectory()
        defer { directory.remove(["listen.sock"]) }
        let path = directory.file("listen.sock")
        let listener = av_socket_bind(path)
        try #require(listener >= 0)
        defer { closeDescriptor(listener) }
        try #require(av_socket_listen(listener, 8) == 0)
        var peers: [RawPeer] = []
        defer { for peer in peers { peer.close() } }
        for _ in 0..<3 { peers.append(try await RawPeer(path)) }
        let wake = try WakePipe()
        defer { wake.close() }
        let admitted = try await blocking { () -> Int in
            var admitted = 0
            VaultSocketServer.acceptLoop(listener, wake: wake.read) { fd in
                admitted += 1
                closeDescriptor(fd)
                wake.fire()   // stop arrives while two more connections wait in the backlog
            }
            return admitted
        }
        #expect(admitted == 1)
    }

    // MARK: Reply backlog

    @Test func repliesHoldWorkCapacityUntilTheyAreWritten() async throws {
        let events = Events()
        // The largest valid read reply: few fit in a socket buffer, so the writer soon stalls.
        let many = (0..<128).map { _ in AccountSummary(id: UUID(), service: .demo) }
        let handlers = stubHandlers(events, read: { _, _ in
            events.record("read")
            return ReadReply(.outcome(.completed), accounts: many)
        })
        var limits = IPCLimits.standard
        limits.maxInFlightPerConnection = 2
        try await withStack(handlers: handlers, limits: limits) { stack in
            let raw = try await RawPeer(stack.configuration.read.path)
            defer { raw.close() }
            // The peer paces its reads so each could finish before the next, and never reads a reply.
            let read = try WireCodec.encode(ReadRequest(operation: .accounts))
            try await blocking {
                for id in UInt32(1)...500 {
                    guard SocketIO.writeAll(raw.fd, wake: -1, SocketFrame.request(id: id, opcode: .read, body: read),
                                            deadline: .after(0.2)) else { break }
                    Thread.sleep(forTimeInterval: 0.002)
                }
            }
            // Through the stalled write's deadline and the close that follows it, only replies
            // the kernel buffered plus the per-connection limit reached the broker.
            let served = await events.await("read", times: 64, within: testTimeouts.write + 1)
            #expect(!served, "\(events.count("read")) reads served to a peer that read no reply")
        }
    }

    @Test func errorRepliesCountAgainstTheReplyBacklog() async throws {
        try await withStack(handlers: stubHandlers()) { stack in
            let raw = try await RawPeer(stack.configuration.read.path)
            defer { raw.close() }
            // Malformed requests of the largest admitted size, whose error replies are never read.
            let junk = SocketFrame.request(id: 9, opcode: .read,
                                           body: Data(repeating: UInt8(ascii: "x"), count: IPCLimits.standard.maxRequestBytes))
            let written = try await blocking { () -> Int in
                let window = Deadline.after(1)
                var written = 0
                while written < 64 << 20, window.pollTimeout != nil,
                      SocketIO.writeAll(raw.fd, wake: -1, junk, deadline: .after(0.2)) {
                    written += junk.count
                }
                return written
            }
            #expect(written < 32 << 20, "the server read \(written) bytes from a peer that read no reply")
        }
    }

    /// A read that runs until cancelled, then large replies that stall the writer and fill the
    /// backlog, so the reader is held waiting for the writer.
    private func stallBehindABlockedRead(_ stack: Stack, _ events: Events) async throws -> RawPeer {
        let raw = try await RawPeer(stack.configuration.read.path)
        let run = try WireCodec.encode(ReadRequest(operation: .run, accountID: UUID(), action: .demoStatus))
        let read = try WireCodec.encode(ReadRequest(operation: .accounts))
        #expect(await raw.request(id: 1, .read, run))
        #expect(await events.await("run started"))
        try await blocking {
            for id in UInt32(2)...200 {
                guard SocketIO.writeAll(raw.fd, wake: -1, SocketFrame.request(id: id, opcode: .read, body: read),
                                        deadline: .after(0.2)) else { break }
            }
        }
        return raw
    }

    private func stallHandlers(_ events: Events) -> BrokerHandlers {
        let many = (0..<128).map { _ in AccountSummary(id: UUID(), service: .demo) }
        return stubHandlers(events, read: { _, request in
            guard request.operation == .run else { return ReadReply(.outcome(.completed), accounts: many) }
            events.record("run started")
            await withTaskCancellationHandler { try? await Task.sleep(for: .seconds(30)) } onCancel: { events.record("run cancelled") }
            return ReadReply(.outcome(.completed), accounts: [])
        })
    }

    @Test func aDisconnectStillCancelsReadsWhileTheReaderWaitsForTheWriter() async throws {
        let events = Events()
        var limits = IPCLimits.standard
        limits.maxInFlightPerConnection = 2
        try await withStack(handlers: stallHandlers(events), limits: limits) { stack in
            let raw = try await stallBehindABlockedRead(stack, events)
            let closed = Date()
            raw.close()
            // Well before the stalled write's own deadline.
            #expect(await events.await("run cancelled", within: testTimeouts.write * 0.5))
            #expect(Date().timeIntervalSince(closed) < testTimeouts.write * 0.5)
        }
    }

    @Test func stopIsPromptWhileTheReaderWaitsForTheWriter() async throws {
        let events = Events()
        var limits = IPCLimits.standard
        limits.maxInFlightPerConnection = 2
        let stack = try Stack(handlers: stallHandlers(events), limits: limits)
        let raw = try await stallBehindABlockedRead(stack, events)
        defer { raw.close() }
        let server = stack.server
        let stopped = await finishes(within: testTimeouts.write * 0.5) { await server.stop() }
        #expect(stopped, "stop must not wait for a stalled reply write's deadline")
        #expect(events.count("run cancelled") == 1)
        await stack.shutdown()
    }

    // MARK: Cleanup capacity

    @Test func anAdminSlotStaysTakenUntilTheClosedCallbackFinishes() async throws {
        let events = Events(), cleanup = Completion()
        let handlers = stubHandlers(events, closed: { _ in
            events.record("cleanup started")
            await cleanup.wait()
            events.record("cleanup finished")
        })
        var limits = IPCLimits.standard
        limits.maxConnectionsPerService = 1
        try await withStack(handlers: handlers, limits: limits) { stack in
            let path = stack.configuration.admin.path
            let first = try await RawPeer(path)
            #expect(await first.request(id: 1, .snapshot, Data()))
            guard case .reply(1, _) = await first.read(within: 3) else { throw Unexpected(what: "snapshot") }
            first.close()
            #expect(await events.await("cleanup started"))
            // The broker is still cleaning up the first connection: its slot is still taken.
            let second = try await RawPeer(path)
            #expect(await second.read(within: 3) == .eof, "a connection beyond the limit is closed during cleanup")
            second.close()
            cleanup.signal()
            #expect(await events.await("cleanup finished"))
            var admitted = false
            for _ in 0..<50 where !admitted {
                let retry = try await RawPeer(path)
                if await retry.request(id: 2, .snapshot, Data()), case .reply = await retry.read(within: 0.5) { admitted = true }
                retry.close()
            }
            #expect(admitted, "the slot is free once cleanup finished")
        }
    }
}
