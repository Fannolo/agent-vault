@testable import AgentVaultBrokerDaemon
@testable import AgentVaultIPC
import AgentVaultContracts
import AgentVaultCore
import CAgentVaultSocket
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// Synthetic canaries; scripts/verify-socket-transport.py fails if either reaches a log.
let canary = Data("SYNTHETIC-socket-canary-credential-6c41".utf8)
let rotatedCanary = Data("SYNTHETIC-socket-canary-rotated-93be".utf8)

let me = UInt32(geteuid())
let myGroup = UInt32(getegid())
/// A UID this process does not run as.
let stranger: UInt32 = me == 4242 ? 4243 : 4242

/// Fast bounds so deadline tests finish quickly; production uses `SocketTimeouts.standard`.
let testTimeouts = SocketTimeouts(frame: 0.4, write: 2)

final class Events: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String] = []
    func record(_ value: String) { lock.withLock { values.append(value) } }
    var all: [String] { lock.withLock { values } }
    func count(_ value: String) -> Int { lock.withLock { values.filter { $0 == value }.count } }

    /// Polls for up to `seconds`; returns whether `value` was recorded at least `times` times.
    func await(_ value: String, times: Int = 1, within seconds: Double = 5) async -> Bool {
        let deadline = Date() + seconds
        while Date() < deadline {
            if count(value) >= times { return true }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return count(value) >= times
    }
}

/// A fresh directory of this test's own, with no symlink in its path. Removal deletes only the
/// entries this test names and then the directory itself.
final class OwnedDirectory: @unchecked Sendable {
    let path: String

    init() throws {
        guard let resolved = realpath(NSTemporaryDirectory(), nil) else { throw POSIXError(.ENOENT) }
        defer { free(resolved) }
        var template = Array((String(cString: resolved) + "/avs-XXXXXX").utf8CString)
        guard mkdtemp(&template) != nil else { throw POSIXError(.EEXIST) }
        path = String(cString: template)
    }

    func file(_ name: String) -> String { path + "/" + name }

    func remove(_ names: [String] = ["read.sock", "admin.sock"]) {
        for name in names { _ = unlink(file(name)) }
        _ = rmdir(path)
    }
}

func configuration(_ directory: OwnedDirectory, readUID: UInt32 = me, adminUID: UInt32 = me,
                   brokerUID: UInt32 = me) -> SocketConfiguration {
    SocketConfiguration(read: .init(path: directory.file("read.sock"), clientUID: readUID, group: myGroup),
                        admin: .init(path: directory.file("admin.sock"), clientUID: adminUID, group: myGroup),
                        brokerUID: brokerUID, development: true)
}

func stubHandlers(_ events: Events = Events(), read: BrokerHandlers.Read? = nil, begin: BrokerHandlers.Begin? = nil,
                  continuation: BrokerHandlers.Continuation? = nil, closed: BrokerHandlers.Closed? = nil) -> BrokerHandlers {
    BrokerHandlers(
        read: read ?? { uid, request in
            events.record("read \(request.operation.rawValue) uid=\(uid)")
            return ReadReply(.outcome(.completed), accounts: [])
        },
        snapshot: { uid in
            events.record("snapshot uid=\(uid)")
            return AdminSnapshot(accounts: [], clients: [], grants: [], pending: [])
        },
        begin: begin ?? { peer, _ in
            events.record("begin \(peer.id)")
            return AdminChallenge(id: UUID(), payload: Data(repeating: 7, count: 32), expiresAt: Date() + 60)
        },
        authorize: { _, id, _ in AdminReply(status: "completed", id: id) },
        continuation: continuation ?? { peer, _ in
            events.record("continuation \(peer.id)")
            return .noFrame
        },
        closed: closed ?? { peer in events.record("closed \(peer.id) open=\(peer.isOpen)") })
}

/// A running socket server in an owned directory plus the clients a test opened. `shutdown`
/// closes every client, stops the server and removes the directory, awaiting each step.
final class Stack: @unchecked Sendable {
    let directory: OwnedDirectory
    let configuration: SocketConfiguration
    let server: VaultSocketServer
    private let lock = NSLock()
    private var channels: [SocketChannel] = []

    init(handlers: BrokerHandlers, limits: IPCLimits = .standard,
         server serverConfiguration: ((OwnedDirectory) -> SocketConfiguration)? = nil) throws {
        directory = try OwnedDirectory()
        configuration = AgentVaultSocketTests.configuration(directory)
        server = VaultSocketServer(validated: serverConfiguration?(directory) ?? configuration, limits: limits,
                                   timeouts: testTimeouts, handlers: handlers)
        do { try server.start() } catch { directory.remove(); throw error }
    }

    func channel(_ role: SocketRole, brokerUID: UInt32? = nil, timeout: TimeInterval = 5) -> SocketChannel {
        let endpoint = role == .read ? configuration.read : configuration.admin
        let channel = SocketChannel(path: endpoint.path, brokerUID: brokerUID ?? configuration.brokerUID,
                                    limits: .standard, timeout: timeout, timeouts: testTimeouts)
        lock.withLock { channels.append(channel) }
        return channel
    }

    func readClient(timeout: TimeInterval = 5) -> VaultSocketReadClient {
        VaultSocketReadClient(channel: channel(.read, timeout: timeout))
    }

    func adminClient(timeout: TimeInterval = 5) -> VaultSocketAdminClient {
        VaultSocketAdminClient(channel: channel(.admin, timeout: timeout))
    }

    func shutdown() async {
        for channel in lock.withLock({ channels }) { await channel.close() }
        await server.stop()
        directory.remove()
    }
}

func withStack(handlers: BrokerHandlers, limits: IPCLimits = .standard,
               server: ((OwnedDirectory) -> SocketConfiguration)? = nil,
               _ body: (Stack) async throws -> Void) async throws {
    let stack = try Stack(handlers: handlers, limits: limits, server: server)
    do { try await body(stack) } catch { await stack.shutdown(); throw error }
    await stack.shutdown()
}

/// Runs blocking descriptor work on a thread of its own, so a waiting test never occupies a
/// cooperative-pool thread that other suites' deadlines depend on.
func blocking<T: Sendable>(_ body: @escaping @Sendable () throws -> T) async throws -> T {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<T, any Error>) in
        startThread("agent-vault.test.blocking") { continuation.resume(with: Result { try body() }) }
    }
}

/// Returns `true` if `operation` finished within `seconds`.
func finishes(within seconds: Double, _ operation: @escaping @Sendable () async -> Void) async -> Bool {
    let done = Events()
    let task = Task { await operation(); done.record("done") }
    let finished = await done.await("done", within: seconds)
    if finished { await task.value }
    return finished
}

/// A hand-driven peer for malformed, partial and raw frames.
final class RawPeer: @unchecked Sendable {
    enum Read: Equatable { case reply(id: UInt32, body: Data), eof, timeout, broken }

    let fd: Int32
    private let lock = NSLock()
    private var open = true

    init(_ path: String) throws {
        var inProgress: Int32 = 0
        let fd = av_socket_connect(path, &inProgress)
        guard fd >= 0 else { throw POSIXError(.ECONNREFUSED) }
        if inProgress != 0 {
            guard case .ready = SocketIO.wait(fd, wake: -1, events: Int32(AV_WAIT_WRITE), deadline: .after(2)),
                  av_socket_connect_result(fd) == 0 else { closeDescriptor(fd); throw POSIXError(.ECONNREFUSED) }
        }
        self.fd = fd
    }

    init(accepted fd: Int32) { self.fd = fd }

    @discardableResult
    func send(_ data: Data) -> Bool { SocketIO.writeAll(fd, wake: -1, data, deadline: .after(2)) }

    func request(id: UInt32, _ opcode: SocketFrame.Opcode, _ body: Data) -> Bool {
        send(SocketFrame.request(id: id, opcode: opcode, body: body))
    }

    func read(within seconds: Double) -> Read {
        switch SocketIO.wait(fd, wake: -1, events: Int32(AV_WAIT_READ), deadline: .after(seconds)) {
        case .expired: return .timeout
        case .woken, .failed: return .broken
        case .ready: break
        }
        switch SocketIO.readFrame(fd, wake: -1, headerSize: SocketFrame.replyHeader, maxBody: 1 << 20, timeout: 2) {
        case .success(.complete(let header, let body)): return .reply(id: SocketFrame.number(header, at: 4), body: Data(body))
        case .success(.oversized): return .broken
        case .failure(.closed): return .eof
        case .failure: return .broken
        }
    }

    /// Closes the descriptor exactly once. Later calls do nothing, so a number the process has
    /// since reused for another descriptor is never closed.
    func close() {
        guard lock.withLock({ () -> Bool in defer { open = false }; return open }) else { return }
        _ = av_socket_shutdown(fd)
        closeDescriptor(fd)
    }
}

func errorBody(_ code: IPCError) -> Data { WireCodec.errorReply(code) }

/// A connected nonblocking stream pair for driving `SocketIO` directly.
func streamPair() throws -> (Int32, Int32) {
    var fds: [Int32] = [-1, -1]
#if canImport(Darwin)
    let stream = SOCK_STREAM
#else
    let stream = Int32(SOCK_STREAM.rawValue)
#endif
    guard socketpair(AF_UNIX, stream, 0, &fds) == 0 else { throw POSIXError(.EMFILE) }
    for fd in fds {
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
#if canImport(Darwin)
        var one: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
#endif
    }
    return (fds[0], fds[1])
}

/// A stop signal like the server's: once fired it stays readable.
final class WakePipe: @unchecked Sendable {
    let read: Int32
    private let writeEnd: Int32

    init() throws {
        var fds: [Int32] = [-1, -1]
        guard av_socket_pipe(&fds) == 0 else { throw POSIXError(.EMFILE) }
        read = fds[0]; writeEnd = fds[1]
    }

    func fire() { writeByte(writeEnd) }
    func close() { closeDescriptor(read); closeDescriptor(writeEnd) }
}

private func writeByte(_ fd: Int32) {
    var byte: UInt8 = 1
    _ = write(fd, &byte, 1)
}

// MARK: Real broker

final class MemoryState: StateStore, @unchecked Sendable {
    private let lock = NSLock()
    private var value = VaultState()
    func transaction<T>(_ body: (inout VaultState) throws -> T) throws -> T {
        try lock.withLock {
            var next = value
            let result = try body(&next)
            value = next
            return result
        }
    }
}

final class MemorySecrets: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [UUID: Data] = [:]
    let saveDelay: TimeInterval
    let events: Events
    init(saveDelay: TimeInterval = 0, events: Events = Events()) { self.saveDelay = saveDelay; self.events = events }
    func save(_ value: Data, for id: UUID) throws {
        if saveDelay > 0 { Thread.sleep(forTimeInterval: saveDelay) }
        lock.withLock { items[id] = value }
        events.record("saved")
    }
    func load(for id: UUID) throws -> Data {
        try lock.withLock {
            guard let value = items[id] else { throw VaultError.secretUnavailable }
            return value
        }
    }
    func delete(for id: UUID) throws { _ = lock.withLock { items.removeValue(forKey: id) } }
}

/// Holds a demo call open until cancelled, recording both events.
struct BlockingAdapter: ServiceAdapter {
    let events: Events
    func execute(service: APIService, credential: Data) async throws -> ServiceOutput {
        events.record("adapter started")
        await withTaskCancellationHandler {
            try? await Task.sleep(for: .seconds(10))
        } onCancel: { events.record("adapter cancelled") }
        throw CancellationError()
    }
}

/// The broker, administration and handler composition the daemon serves, with a test signer.
struct BrokerRig {
    let state = MemoryState()
    let secrets: MemorySecrets
    let key = P256.Signing.PrivateKey()
    let broker: Broker
    let administration: Administration

    init(adapter: any ServiceAdapter = FixedServiceAdapter(), secrets: MemorySecrets = MemorySecrets()) throws {
        self.secrets = secrets
        broker = Broker(state: state, secrets: secrets, adapter: adapter)
        administration = try Administration(broker: broker, publicKey: key.publicKey.x963Representation,
                                             allowedServices: [.demo, .github], allowedClientUID: me)
    }

    var handlers: BrokerHandlers { BrokerComposition.handlers(broker: broker, administration: administration) }

    func sign(_ challenge: AdminChallenge) throws -> Data { try key.signature(for: challenge.payload).derRepresentation }
}

struct Unexpected: Error { let what: String }
