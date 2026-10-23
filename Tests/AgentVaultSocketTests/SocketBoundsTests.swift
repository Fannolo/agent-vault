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
}
