#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import AgentVaultContracts
import CAgentVaultSocket
import Dispatch
import Foundation

/// Read-role socket client for the agent bridge. It holds no credential store and can send only
/// closed `ReadRequest` values, and only to a socket whose kernel peer UID is `brokerUID`.
public final class VaultSocketReadClient: Sendable {
    private let channel: SocketChannel

    public init(configuration: SocketConfiguration, limits: IPCLimits = .standard,
                timeout: TimeInterval = VaultSocketReadClient.defaultTimeout) throws(IPCError) {
        try configuration.validate(for: .readClient)
        channel = SocketChannel(path: configuration.read.path, brokerUID: configuration.brokerUID, limits: limits,
                                timeout: timeout, timeouts: .standard)
    }

    /// Every broker-side step of a read must finish inside it, as on the XPC transport.
    public static let defaultTimeout: TimeInterval = 30

    init(channel: SocketChannel) { self.channel = channel }

    public func perform(_ request: ReadRequest) async throws(IPCError) -> ReadReply {
        let body = try WireCodec.encode(request)
        guard case .readReply(let reply) = try await channel.exchange(.read, body, allowed: [.readReply]).get() else {
            throw .malformedReply
        }
        return reply
    }

    /// Closes the connection; the broker cancels this client's in-flight reads.
    public func close() async { await channel.close() }
}

/// Admin-role socket client for a controller. One persistent connection carries every call, so
/// a continuation lease opened through it stays bound to it; after any disconnect the next call
/// uses a new connection, and the lease needs a new signed open.
public final class VaultSocketAdminClient: Sendable {
    private let channel: SocketChannel

    public init(configuration: SocketConfiguration, limits: IPCLimits = .standard,
                timeout: TimeInterval = 30) throws(IPCError) {
        try configuration.validate(for: .adminClient)
        channel = SocketChannel(path: configuration.admin.path, brokerUID: configuration.brokerUID, limits: limits,
                                timeout: timeout, timeouts: .standard)
    }

    init(channel: SocketChannel) { self.channel = channel }

    public func snapshot() async throws(IPCError) -> AdminSnapshot {
        guard case .snapshot(let snapshot) = try await channel.exchange(.snapshot, Data(), allowed: [.snapshot]).get() else {
            throw .malformedReply
        }
        return snapshot
    }

    public func begin(_ request: AdminRequest) async throws(IPCError) -> AdminBeginResult {
        let body = try WireCodec.encode(request)
        switch try await channel.exchange(.begin, body, allowed: [.challenge, .adminReply]).get() {
        case .challenge(let challenge): return .challenge(challenge)
        case .adminReply(let reply): return .rejected(reply)
        default: throw .malformedReply
        }
    }

    /// A `timeout` or `connection_failed` result means the mutation's outcome is unknown. The
    /// client never retries it; read a fresh snapshot instead.
    public func authorize(id: UUID, signature: Data) async throws(IPCError) -> AdminReply {
        let text = id.uuidString
        _ = try WireCodec.decodeAuthorize(id: text, signature: signature)
        let body = Data(text.utf8) + signature
        guard case .adminReply(let reply) = try await channel.exchange(.authorize, body, allowed: [.adminReply]).get() else {
            throw .malformedReply
        }
        return reply
    }

    public func continueHuman(_ request: ContinuationRequest) async throws(IPCError) -> ContinuationReply {
        let body = try WireCodec.encode(request)
        guard case .continuation(let reply) = try await channel.exchange(.continuation, body,
                                                                         allowed: [.humanFrame, .humanReply]).get() else {
            throw .malformedReply
        }
        try WireCodec.checkContinuation(reply, for: request)
        return reply
    }

    /// Closes the connection, which ends every continuation lease bound to it.
    public func close() async { await channel.close() }
}

/// One lazily opened connection, authenticated by kernel peer UID before its first byte is sent.
/// Calls are multiplexed by frame ID; each has one absolute deadline covering connect, write
/// and reply. A call that misses it returns `timeout` and its late reply is discarded.
final class SocketChannel: @unchecked Sendable {
    private let path: String
    private let brokerUID: UInt32
    private let limits: IPCLimits
    private let timeout: TimeInterval
    private let timeouts: SocketTimeouts
    private let connecting = DispatchQueue(label: "agent-vault.socket.connect")
    private let lock = NSLock()
    private var current: ClientConnection?

    init(path: String, brokerUID: UInt32, limits: IPCLimits, timeout: TimeInterval, timeouts: SocketTimeouts) {
        self.path = path; self.brokerUID = brokerUID; self.limits = limits
        self.timeout = timeout; self.timeouts = timeouts
    }

    func exchange(_ opcode: SocketFrame.Opcode, _ body: Data,
                  allowed: Set<WireCodec.ReplyKind>) async -> Result<WireCodec.Envelope, IPCError> {
        let deadline = Deadline.after(timeout)
        let connection: ClientConnection
        switch await link(by: deadline) {
        case .success(let value): connection = value
        case .failure(let error): return .failure(error)
        }
        let result = await connection.call(opcode, body, allowed: allowed, deadline: deadline)
        if case .success(.error(let code)) = result { return .failure(code) }
        return result
    }

    func close() async {
        guard let connection = lock.withLock({ current }) else { return }
        await connection.close()
    }

    private func link(by deadline: Deadline) async -> Result<ClientConnection, IPCError> {
        if let live = lock.withLock({ current }), live.isOpen { return .success(live) }
        return await withCheckedContinuation { (continuation: CheckedContinuation<Result<ClientConnection, IPCError>, Never>) in
            // Serialized, so concurrent first calls share one connection.
            connecting.async { [self] in
                if let live = lock.withLock({ current }), live.isOpen { return continuation.resume(returning: .success(live)) }
                switch SocketIO.connect(path: path, brokerUID: brokerUID, deadline: deadline) {
                case .success(let fd):
                    let connection = ClientConnection(fd: fd, limits: limits, timeouts: timeouts) { [weak self] ended in
                        self?.lock.withLock { if self?.current === ended { self?.current = nil } }
                    }
                    lock.withLock { current = connection }
                    connection.start()
                    continuation.resume(returning: .success(connection))
                case .failure(let error):
                    continuation.resume(returning: .failure(error))
                }
            }
        }
    }
}

/// The client side of one connection. The descriptor is closed only on `writer`, after the
/// reader thread has exited.
final class ClientConnection: @unchecked Sendable {
    typealias Outcome = Result<WireCodec.Envelope, IPCError>

    private struct Waiter {
        let allowed: Set<WireCodec.ReplyKind>
        let continuation: CheckedContinuation<Outcome, Never>
    }

    private let fd: Int32
    private let limits: IPCLimits
    private let timeouts: SocketTimeouts
    private let ended: @Sendable (ClientConnection) -> Void
    private let writer = DispatchQueue(label: "agent-vault.socket.client-writer")
    private let lock = NSLock()
    private var waiters: [UInt32: Waiter] = [:]
    private var nextID: UInt32 = 0
    private var open = true
    private var descriptorClosed = false   // writer-confined
    private let finished = Completion()

    init(fd: Int32, limits: IPCLimits, timeouts: SocketTimeouts, ended: @escaping @Sendable (ClientConnection) -> Void) {
        self.fd = fd; self.limits = limits; self.timeouts = timeouts; self.ended = ended
    }

    var isOpen: Bool { lock.withLock { open } }

    func start() {
        startThread("agent-vault.socket.client") { [self] in
            readLoop()
            teardown()
        }
    }

    func call(_ opcode: SocketFrame.Opcode, _ body: Data, allowed: Set<WireCodec.ReplyKind>,
              deadline: Deadline) async -> Outcome {
        await withCheckedContinuation { (continuation: CheckedContinuation<Outcome, Never>) in
            let id = lock.withLock { () -> UInt32? in
                guard open else { return nil }
                repeat { nextID &+= 1 } while waiters[nextID] != nil
                waiters[nextID] = Waiter(allowed: allowed, continuation: continuation)
                return nextID
            }
            guard let id else { return continuation.resume(returning: .failure(.connectionFailed)) }
            if let time = deadline.dispatchTime {
                DispatchQueue.global().asyncAfter(deadline: time) { [self] in resolve(id, .failure(.timeout)) }
            }
            let frame = SocketFrame.request(id: id, opcode: opcode, body: body)
            writer.async { [self] in
                guard !descriptorClosed else { return resolve(id, .failure(.connectionFailed)) }
                // A call that expired while queued is never sent, and the stream stays usable.
                guard deadline.pollTimeout != nil else { return resolve(id, .failure(.timeout)) }
                guard SocketIO.writeAll(fd, wake: -1, frame, deadline: deadline) else {
                    // A partial frame leaves the stream unusable; end the connection.
                    resolve(id, .failure(deadline.pollTimeout == nil ? .timeout : .connectionFailed))
                    _ = av_socket_shutdown(fd)
                    return
                }
            }
        }
    }

    func close() async {
        writer.async { [self] in if !descriptorClosed { _ = av_socket_shutdown(fd) } }
        await finished.wait()
    }

    private func readLoop() {
        while true {
            switch SocketIO.readFrame(fd, wake: -1, headerSize: SocketFrame.replyHeader, maxBody: limits.maxReplyBytes,
                                      timeout: timeouts.frame) {
            case .success(.complete(let header, let body)):
                let id = SocketFrame.number(header, at: 4)
                // A reply nobody awaits belongs to a call that already timed out.
                guard let waiter = lock.withLock({ waiters.removeValue(forKey: id) }) else { continue }
                waiter.continuation.resume(returning: WireCodec.decodeReply(Data(body), allowed: waiter.allowed,
                                                                            limits: limits))
            case .success(.oversized):
                return failAll(.malformedReply)
            case .failure:
                return failAll(.connectionFailed)
            }
        }
    }

    private func resolve(_ id: UInt32, _ outcome: Outcome) {
        lock.withLock { waiters.removeValue(forKey: id) }?.continuation.resume(returning: outcome)
    }

    private func failAll(_ error: IPCError) {
        let pending = lock.withLock { () -> [Waiter] in
            open = false
            defer { waiters = [:] }
            return Array(waiters.values)
        }
        for waiter in pending { waiter.continuation.resume(returning: .failure(error)) }
    }

    private func teardown() {
        failAll(.connectionFailed)
        ended(self)
        writer.async { [self] in
            descriptorClosed = true
            _ = av_socket_shutdown(fd)
            closeDescriptor(fd)
            finished.signal()
        }
    }
}
