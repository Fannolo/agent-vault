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
}
