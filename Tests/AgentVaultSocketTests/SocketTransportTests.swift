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

/// Peer authentication, framing, deadlines, capacity and lifecycle of the socket transport.
@Suite(.serialized) struct SocketTransportTests {
    private let accounts = SocketFrame.request(id: 1, opcode: .read, body: try! WireCodec.encode(ReadRequest(operation: .accounts)))

    @Test func deniedPeerUIDIsClosedBeforeAnyRequestIsRead() async throws {
        let events = Events()
        try await withStack(handlers: stubHandlers(events), server: { configuration($0, readUID: stranger) }) { stack in
            await #expect(throws: IPCError.connectionFailed) {
                _ = try await stack.readClient().perform(ReadRequest(operation: .accounts))
            }
            let raw = try RawPeer(stack.configuration.read.path)
            defer { raw.close() }
            raw.send(accounts)
            #expect(raw.read(within: 3) == .eof)
            #expect(events.all.isEmpty)
        }
    }

    @Test func unauthorizedAdminUIDCannotReachTheAdminEndpoint() async throws {
        let events = Events()
        try await withStack(handlers: stubHandlers(events), server: { configuration($0, adminUID: stranger) }) { stack in
            _ = try await stack.readClient().perform(ReadRequest(operation: .accounts))
            await #expect(throws: IPCError.connectionFailed) { _ = try await stack.adminClient().snapshot() }
            await #expect(throws: IPCError.connectionFailed) {
                _ = try await stack.adminClient().begin(AdminRequest(operation: .prune))
            }
            #expect(events.all == ["read accounts uid=\(me)"])
        }
    }

    @Test func clientRefusesAMismatchedBrokerBeforeSendingAByte() async throws {
        let events = Events()
        try await withStack(handlers: stubHandlers(events)) { stack in
            // This process runs the server, so its socket peer is not the configured broker UID.
            let client = VaultSocketReadClient(channel: stack.channel(.read, brokerUID: stranger))
            await #expect(throws: IPCError.brokerRejected) { _ = try await client.perform(ReadRequest(operation: .accounts)) }
            let admin = VaultSocketAdminClient(channel: stack.channel(.admin, brokerUID: stranger))
            await #expect(throws: IPCError.brokerRejected) { _ = try await admin.snapshot() }
            try await Task.sleep(for: .milliseconds(100))
            // The refused admin connection may report its close; no request reached a handler.
            #expect(events.all.allSatisfy { $0.hasPrefix("closed ") }, "no request reached the server")
            _ = try await stack.readClient().perform(ReadRequest(operation: .accounts))
            #expect(events.all.filter { !$0.hasPrefix("closed ") } == ["read accounts uid=\(me)"])
        }
    }

    @Test func readSocketRefusesAdminOpcodes() async throws {
        let events = Events()
        try await withStack(handlers: stubHandlers(events)) { stack in
            let read = try RawPeer(stack.configuration.read.path)
            defer { read.close() }
            #expect(read.request(id: 1, .snapshot, Data()))
            #expect(read.read(within: 3) == .eof)
            let admin = try RawPeer(stack.configuration.admin.path)
            defer { admin.close() }
            admin.send(accounts)
            #expect(admin.read(within: 3) == .eof)
            // Only the admin connection's closed callback may run; no request reached a handler.
            #expect(events.all.allSatisfy { $0.hasPrefix("closed ") })
        }
    }

    @Test func malformedRequestsGetFixedErrorsAndTheConnectionStaysUsable() async throws {
        let events = Events()
        try await withStack(handlers: stubHandlers(events)) { stack in
            let raw = try RawPeer(stack.configuration.read.path)
            defer { raw.close() }
            for (id, body) in [(UInt32(5), #"{"operation":"accounts","accountID":null}"#), (6, #"{"operation":"accounts","x":1}"#),
                               (7, "[]"), (8, #"{"operation":"teleport"}"#)] {
                #expect(raw.request(id: id, .read, Data(body.utf8)))
                #expect(raw.read(within: 3) == .reply(id: id, body: errorBody(.invalidRequest)))
            }
            raw.send(accounts)
            guard case .reply(1, let body) = raw.read(within: 3) else { throw Unexpected(what: "reply") }
            guard case .success(.readReply(let reply)) = WireCodec.decodeReply(body, allowed: [.readReply], limits: .standard)
            else { throw Unexpected(what: "read reply") }
            #expect(reply.status == "completed")
            #expect(events.all == ["read accounts uid=\(me)"])

            // Admin snapshot takes no body; authorize needs a canonical ID and a bounded signature.
            let admin = try RawPeer(stack.configuration.admin.path)
            defer { admin.close() }
            #expect(admin.request(id: 2, .snapshot, Data("{}".utf8)))
            #expect(admin.read(within: 3) == .reply(id: 2, body: errorBody(.invalidRequest)))
            let notAnID = Data(String(repeating: "x", count: 36).utf8) + Data(repeating: 1, count: 64)
            #expect(admin.request(id: 3, .authorize, notAnID))
            #expect(admin.read(within: 3) == .reply(id: 3, body: errorBody(.invalidRequest)))
            #expect(admin.request(id: 4, .authorize, Data(UUID().uuidString.utf8) + Data(repeating: 1, count: 73)))
            #expect(admin.read(within: 3) == .reply(id: 4, body: errorBody(.invalidRequest)))
        }
    }

    @Test func oversizedFrameIsRefusedFromItsHeader() async throws {
        let events = Events()
        try await withStack(handlers: stubHandlers(events)) { stack in
            let raw = try RawPeer(stack.configuration.read.path)
            defer { raw.close() }
            // Only the header is sent: the server must not wait for the declared body.
            let header = SocketFrame.request(id: 77, opcode: .read, body: Data(count: IPCLimits.standard.maxRequestBytes + 1))
            #expect(raw.send(header.prefix(SocketFrame.requestHeader)))
            #expect(raw.read(within: 0.3) == .reply(id: 77, body: errorBody(.requestTooLarge)))
            #expect(raw.read(within: 3) == .eof)
            #expect(events.all.isEmpty)
        }
    }

    @Test func stalledPartialFrameIsClosedAtItsDeadline() async throws {
        let events = Events()
        try await withStack(handlers: stubHandlers(events)) { stack in
            // An idle connection is kept: a controller holds its admin connection open.
            let idle = try RawPeer(stack.configuration.read.path)
            defer { idle.close() }
            #expect(idle.read(within: testTimeouts.frame * 2) == .timeout)
            idle.send(accounts)
            guard case .reply(1, _) = idle.read(within: 3) else { throw Unexpected(what: "idle reply") }

            let partial = try RawPeer(stack.configuration.read.path)
            defer { partial.close() }
            let started = Date()
            #expect(partial.send(accounts.prefix(SocketFrame.requestHeader + 3)))
            #expect(partial.read(within: 5) == .eof)
            let elapsed = Date().timeIntervalSince(started)
            #expect(elapsed >= testTimeouts.frame * 0.9 && elapsed < 3)
            #expect(events.all == ["read accounts uid=\(me)"])
        }
    }

    @Test func clientCallTimesOutAtItsAbsoluteDeadlineAndDiscardsTheLateReply() async throws {
        let events = Events()
        let handlers = stubHandlers(events, read: { _, request in
            if request.operation == .run { try await Task.sleep(for: .seconds(1)) }
            events.record("read \(request.operation.rawValue)")
            return ReadReply(.outcome(.completed), accounts: [])
        })
        try await withStack(handlers: handlers) { stack in
            let client = stack.readClient(timeout: 0.3)
            let started = Date()
            await #expect(throws: IPCError.timeout) {
                _ = try await client.perform(ReadRequest(operation: .run, accountID: UUID(), action: .demoStatus))
            }
            let elapsed = Date().timeIntervalSince(started)
            #expect(elapsed >= 0.25 && elapsed < 1)
            // The same connection still serves; the late reply for the timed-out call is dropped.
            #expect(await events.await("read run", within: 3))
            let after = try await client.perform(ReadRequest(operation: .accounts))
            #expect(after.status == "completed")
        }
    }

    @Test func duplicateInFlightRequestIDClosesTheConnection() async throws {
        let events = Events()
        let handlers = stubHandlers(events, read: { _, _ in
            await withTaskCancellationHandler { try? await Task.sleep(for: .seconds(5)) } onCancel: { events.record("cancelled") }
            return ReadReply(.outcome(.completed), accounts: [])
        })
        try await withStack(handlers: handlers) { stack in
            let raw = try RawPeer(stack.configuration.read.path)
            defer { raw.close() }
            raw.send(accounts + accounts)
            #expect(raw.read(within: 3) == .eof)
            #expect(await events.await("cancelled"))
        }
    }

    @Test func connectionAndWorkLimitsAreEnforced() async throws {
        let events = Events()
        let handlers = stubHandlers(events, read: { _, request in
            if request.operation == .run { try await Task.sleep(for: .milliseconds(500)) }
            return ReadReply(.outcome(.completed), accounts: [])
        })
        var limits = IPCLimits.standard
        limits.maxConnectionsPerService = 2; limits.maxInFlightPerConnection = 1
        try await withStack(handlers: handlers, limits: limits) { stack in
            let first = try RawPeer(stack.configuration.read.path), second = try RawPeer(stack.configuration.read.path)
            defer { first.close(); second.close() }
            for peer in [first, second] {
                peer.send(accounts)
                guard case .reply = peer.read(within: 3) else { throw Unexpected(what: "admitted reply") }
            }
            let third = try RawPeer(stack.configuration.read.path)
            defer { third.close() }
            #expect(third.read(within: 3) == .eof, "a connection beyond the per-service limit is closed")

            let run = try WireCodec.encode(ReadRequest(operation: .run, accountID: UUID(), action: .demoStatus))
            #expect(first.request(id: 10, .read, run) && first.request(id: 11, .read, run))
            #expect(first.read(within: 3) == .reply(id: 11, body: errorBody(.busy)))
            guard case .reply(10, _) = first.read(within: 3) else { throw Unexpected(what: "first run") }

            // A closed connection frees its slot.
            second.close()
            var admitted = false
            for _ in 0..<50 where !admitted {
                let retry = try RawPeer(stack.configuration.read.path)
                retry.send(accounts)
                if case .reply = retry.read(within: 0.5) { admitted = true }
                retry.close()
            }
            #expect(admitted)
        }
    }

    @Test func adminIdentityIsPerConnectionAndEndsWithIt() async throws {
        let events = Events()
        try await withStack(handlers: stubHandlers(events)) { stack in
            let admin = stack.adminClient()
            for _ in 0..<2 { _ = try await admin.begin(AdminRequest(operation: .prune)) }
            let lease = UUID()
            #expect(try await admin.continueHuman(ContinuationRequest(lease: lease, operation: .frame(after: 0))) == .noFrame)
            let ids = Set(events.all.map { $0.split(separator: " ")[1] })
            #expect(ids.count == 1, "begin and continuation see one connection identity")
            let id = try #require(ids.first)
            await admin.close()
            #expect(await events.await("closed \(id) open=false"), "liveness ends before the closed callback")

            // The next call opens a new connection with a new identity.
            _ = try await admin.begin(AdminRequest(operation: .prune))
            let next = try #require(events.all.last?.split(separator: " ")[1])
            #expect(next != id)
        }
    }

    @Test func stopClosesPeersAwaitsWorkAndRemovesOnlyItsSockets() async throws {
        let events = Events()
        let handlers = stubHandlers(events, read: { _, _ in
            events.record("read started")
            await withTaskCancellationHandler { try? await Task.sleep(for: .seconds(10)) } onCancel: { events.record("read cancelled") }
            return ReadReply(.outcome(.completed), accounts: [])
        }, begin: { _, _ in
            events.record("begin started")
            try await Task.sleep(for: .milliseconds(300))
            events.record("begin finished")
            return AdminChallenge(id: UUID(), payload: Data(repeating: 7, count: 32), expiresAt: Date() + 60)
        })
        let directory = try OwnedDirectory()
        defer { directory.remove(["unrelated"]) }
        #expect(FileManager.default.createFile(atPath: directory.file("unrelated"), contents: Data("keep".utf8)))
        let server = VaultSocketServer(validated: configuration(directory), limits: .standard, timeouts: testTimeouts,
                                       handlers: handlers)
        try server.start()
        let config = configuration(directory)
        let read = VaultSocketReadClient(channel: SocketChannel(path: config.read.path, brokerUID: me, limits: .standard,
                                                                timeout: 10, timeouts: testTimeouts))
        let admin = VaultSocketAdminClient(channel: SocketChannel(path: config.admin.path, brokerUID: me, limits: .standard,
                                                                  timeout: 10, timeouts: testTimeouts))
        let pendingRead = Task { () -> IPCError? in
            do { _ = try await read.perform(ReadRequest(operation: .accounts)); return nil } catch { return error as? IPCError }
        }
        let pendingBegin = Task { () -> IPCError? in
            do { _ = try await admin.begin(AdminRequest(operation: .prune)); return nil } catch { return error as? IPCError }
        }
        #expect(await events.await("read started"))
        #expect(await events.await("begin started"))

        let stopped = await finishes(within: 5) { await server.stop() }
        #expect(stopped, "stop must not wait on a connected peer")
        guard stopped else { return }
        // When stop returns, the read was cancelled and the admin mutation ran to completion.
        #expect(events.count("read cancelled") == 1 && events.count("begin finished") == 1)
        #expect(events.all.contains { $0.hasPrefix("closed ") && $0.hasSuffix("open=false") })
        let readOutcome = await pendingRead.value, beginOutcome = await pendingBegin.value
        #expect(readOutcome == .connectionFailed && beginOutcome == .connectionFailed)
        var info = stat()
        #expect(lstat(config.read.path, &info) != 0 && lstat(config.admin.path, &info) != 0)
        #expect(FileManager.default.contents(atPath: directory.file("unrelated")) == Data("keep".utf8))
        #expect(throws: (any Error).self) { _ = try RawPeer(config.read.path) }
        await server.stop()   // idempotent
        await read.close(); await admin.close()
    }

    @Test func startRefusesUnsafePathsAndNeverUnlinksForeignFiles() async throws {
        let directory = try OwnedDirectory()
        defer { directory.remove(["read.sock", "admin.sock", "elsewhere"]) }
        let config = configuration(directory)
        func server() -> VaultSocketServer {
            VaultSocketServer(validated: config, limits: .standard, timeouts: testTimeouts, handlers: stubHandlers())
        }

        // A regular file at the socket path is neither replaced nor removed.
        #expect(FileManager.default.createFile(atPath: config.read.path, contents: Data("data".utf8)))
        #expect(throws: IPCError.invalidConfiguration) { try server().start() }
        #expect(FileManager.default.contents(atPath: config.read.path) == Data("data".utf8))
        _ = unlink(config.read.path)

        // A directory others can write is refused; so is a symlinked directory component.
        _ = chmod(directory.path, 0o777)
        #expect(throws: IPCError.invalidConfiguration) { try server().start() }
        _ = chmod(directory.path, 0o700)
        #expect(symlink(directory.path, directory.file("elsewhere")) == 0)
        var linked = config
        linked.read.path = directory.file("elsewhere/read.sock")
        #expect(throws: IPCError.invalidConfiguration) {
            try VaultSocketServer(validated: linked, limits: .standard, timeouts: testTimeouts, handlers: stubHandlers()).start()
        }

        // A stale socket from an earlier run is replaced; a live one is not.
        let stale = av_socket_bind(config.read.path)
        try #require(stale >= 0)
        closeDescriptor(stale)
        let live = server()
        try live.start()
        #expect(throws: IPCError.unavailable) { try server().start() }
        _ = try await VaultSocketReadClient(channel: SocketChannel(path: config.read.path, brokerUID: me, limits: .standard,
                                                                   timeout: 3, timeouts: testTimeouts))
            .perform(ReadRequest(operation: .accounts))
        await live.stop()
        var info = stat()
        #expect(lstat(config.read.path, &info) != 0)
    }

    @Test func socketFilesHaveFinalPermissionsAndTheConfiguredGroup() async throws {
        try await withStack(handlers: stubHandlers()) { stack in
            for path in [stack.configuration.read.path, stack.configuration.admin.path] {
                var info = stat()
                #expect(lstat(path, &info) == 0)
                #expect(info.st_mode & S_IFMT == S_IFSOCK && info.st_mode & 0o777 == 0o660)
                #expect(info.st_uid == me && info.st_gid == myGroup)
            }
        }
    }
}
