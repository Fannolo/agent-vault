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

    @Test func unwrittenRepliesKeepTheirServiceCapacity() async throws {
        let events = Events()
        let many = (0..<128).map { _ in AccountSummary(id: UUID(), service: .demo) }
        let handlers = stubHandlers(events, read: { _, _ in
            events.record("read")
            return ReadReply(.outcome(.completed), accounts: many)
        })
        var limits = IPCLimits.standard
        limits.maxInFlightTotal = 2
        let lanes = SocketLanes(limits: limits), tracker = WorkTracker(), wake = try WakePipe()
        defer { wake.close() }
        let (stalledEnd, stalledFD) = try streamPair(), (otherEnd, otherFD) = try streamPair()
        // A send buffer smaller than one reply, so the stalled peer's first reply cannot be written.
        var small: Int32 = 4096
        _ = setsockopt(stalledEnd, SOL_SOCKET, SO_SNDBUF, &small, socklen_t(MemoryLayout<Int32>.size))
        func serve(_ fd: Int32) -> ServerConnection {
            let connection = ServerConnection(fd: fd, role: .read, uid: me, limits: limits, timeouts: testTimeouts, lanes: lanes,
                                              handlers: handlers, tracker: tracker, wake: wake.read)
            connection.run {}
            return connection
        }
        let stalled = serve(stalledEnd), other = serve(otherEnd)
        let stalledPeer = RawPeer(accepted: stalledFD), otherPeer = RawPeer(accepted: otherFD)
        defer { stalledPeer.close(); otherPeer.close() }
        let read = try WireCodec.encode(ReadRequest(operation: .accounts))
        let sentFirst = await stalledPeer.request(id: 1, .read, read), sentSecond = await stalledPeer.request(id: 2, .read, read)
        #expect(sentFirst && sentSecond)
        #expect(await events.await("read", times: 2))
        // Both replies are done but unwritten; they still hold the whole service capacity.
        #expect(await otherPeer.request(id: 1, .read, read))
        #expect(await otherPeer.read(within: 3) == .reply(id: 1, body: errorBody(.busy)))
        // Once the stalled peer leaves, its replies are dropped and the capacity returns.
        stalledPeer.close()
        var served = false
        for id in UInt32(2)..<50 where !served {
            #expect(await otherPeer.request(id: id, .read, read))
            if case .reply(id, let body) = await otherPeer.read(within: 3), body != errorBody(.busy) { served = true }
        }
        #expect(served)
        otherPeer.close()
        await stalled.finished.wait()
        await other.finished.wait()
        await tracker.drained()
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

    /// One served read connection over a socket pair whose server send buffer is smaller than one
    /// reply. A read runs until cancelled; the next read's reply stalls the writer, a busy reply
    /// queued behind it fills the backlog, and the reader holds a further frame waiting for room.
    private struct Stall {
        let connection: ServerConnection
        let peer: RawPeer
        let wake: WakePipe
    }

    private func stallBehindABlockedRead(_ events: Events) async throws -> Stall {
        let many = (0..<128).map { _ in AccountSummary(id: UUID(), service: .demo) }
        let handlers = stubHandlers(events, read: { _, request in
            guard request.operation == .run else { return ReadReply(.outcome(.completed), accounts: many) }
            events.record("run started")
            await withTaskCancellationHandler { try? await Task.sleep(for: .seconds(30)) } onCancel: { events.record("run cancelled") }
            return ReadReply(.outcome(.completed), accounts: [])
        })
        var limits = IPCLimits.standard
        limits.maxInFlightPerConnection = 2
        let (serverEnd, peerEnd) = try streamPair(), wake = try WakePipe()
        var small: Int32 = 4096
        _ = setsockopt(serverEnd, SOL_SOCKET, SO_SNDBUF, &small, socklen_t(MemoryLayout<Int32>.size))
        let connection = ServerConnection(fd: serverEnd, role: .read, uid: me, limits: limits, timeouts: testTimeouts,
                                          lanes: SocketLanes(limits: limits), handlers: handlers, tracker: WorkTracker(),
                                          wake: wake.read)
        connection.run {}
        let peer = RawPeer(accepted: peerEnd)
        let run = try WireCodec.encode(ReadRequest(operation: .run, accountID: UUID(), action: .demoStatus))
        let read = try WireCodec.encode(ReadRequest(operation: .accounts))
        #expect(await peer.request(id: 1, .read, run))
        #expect(await events.await("run started"))
        #expect(await peer.request(id: 2, .read, read))
        // The first bytes of that reply have arrived: the writer is now stalled on it.
        let started = try await blocking {
            SocketIO.wait(peerEnd, wake: -1, events: Int32(AV_WAIT_READ), deadline: .after(3)) == .ready
        }
        #expect(started)
        for id in UInt32(3)...5 { #expect(await peer.request(id: id, .read, read)) }
        return Stall(connection: connection, peer: peer, wake: wake)
    }

    @Test func aDisconnectStillCancelsReadsWhileTheReaderWaitsForTheWriter() async throws {
        let events = Events()
        let stall = try await stallBehindABlockedRead(events)
        defer { stall.wake.close() }
        // Let the reader reach the full backlog; the stalled write's own deadline is far later.
        try await Task.sleep(for: .milliseconds(100))
        stall.peer.close()
        #expect(await events.await("run cancelled", within: testTimeouts.write * 0.5))
        #expect(await finishes(within: testTimeouts.write * 0.5) { await stall.connection.finished.wait() })
    }

    @Test func stopIsPromptWhileTheReaderWaitsForTheWriter() async throws {
        let events = Events()
        let stall = try await stallBehindABlockedRead(events)
        defer { stall.peer.close(); stall.wake.close() }
        try await Task.sleep(for: .milliseconds(100))
        stall.wake.fire()
        let ended = await finishes(within: testTimeouts.write * 0.5) { await stall.connection.finished.wait() }
        #expect(ended, "stop must not wait for a stalled reply write's deadline")
        #expect(events.count("run cancelled") == 1)
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

    // MARK: Startup ownership

    @Test func aConcurrentStartCannotTakeOverOrRemoveAStartingServersSockets() async throws {
        let directory = try OwnedDirectory()
        defer { directory.remove() }
        let config = configuration(directory)
        let firstEvents = Events(), rivalEvents = Events(), outcome = Events()
        let rival = VaultSocketServer(validated: config, limits: .standard, timeouts: testTimeouts,
                                      handlers: stubHandlers(rivalEvents))
        // The rival starts while the first server has bound its read socket but not yet listened.
        let first = VaultSocketServer(validated: config, limits: .standard, timeouts: testTimeouts,
                                      handlers: stubHandlers(firstEvents), didBind: { role in
            guard role == .read else { return }
            do throws(IPCError) { try rival.start(); outcome.record("rival started") } catch {
                outcome.record("rival \(error.rawValue)")
            }
        })
        var firstError: IPCError?
        do throws(IPCError) { try first.start() } catch { firstError = error }
        #expect(outcome.all == ["rival unavailable"])
        #expect(firstError == nil)
        if outcome.all == ["rival started"] {
            // The rival must keep both of its sockets whatever the first server did.
            var info = stat()
            #expect(lstat(config.read.path, &info) == 0, "the rival's live read socket was unlinked")
        }
        if firstError == nil {
            let read = VaultSocketReadClient(channel: SocketChannel(path: config.read.path, brokerUID: me, limits: .standard,
                                                                    timeout: 3, timeouts: testTimeouts))
            _ = try await read.perform(ReadRequest(operation: .accounts))
            await read.close()
            #expect(firstEvents.all == ["read accounts uid=\(me)"] && rivalEvents.all.isEmpty)
        }
        await first.stop()
        await rival.stop()
        // Once the first server stopped, its paths are free for the next start.
        let next = VaultSocketServer(validated: config, limits: .standard, timeouts: testTimeouts, handlers: stubHandlers())
        try next.start()
        await next.stop()
    }
}
