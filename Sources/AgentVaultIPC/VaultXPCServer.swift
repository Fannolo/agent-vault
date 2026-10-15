import AgentVaultContracts
import Foundation

/// Broker-side listeners for the read (bridge) and admin (human app) services.
///
/// Each service has its own exact code requirement, set on the listener and on every accepted
/// connection before activation. A connection is accepted only from the configured kernel
/// effective UID, and that UID is bound to the connection and passed to every handler.
public final class VaultXPCServer: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    public typealias ReadHandler = @Sendable (UInt32, ReadRequest) async throws -> ReadReply
    public typealias SnapshotHandler = @Sendable (UInt32) async throws -> AdminSnapshot
    public typealias BeginHandler = @Sendable (UInt32, AdminRequest) async throws -> AdminChallenge
    public typealias AuthorizeHandler = @Sendable (UInt32, UUID, Data) async throws -> AdminReply

    struct Handlers: Sendable {
        let read: ReadHandler
        let snapshot: SnapshotHandler
        let begin: BeginHandler
        let authorize: AuthorizeHandler
    }

    private let configuration: IPCConfiguration
    private let limits: IPCLimits
    private let handlers: Handlers
    private let readListener: NSXPCListener
    private let adminListener: NSXPCListener
    private let readInFlight: Gate
    private let adminInFlight: Gate
    private let readConnections: Gate
    private let adminConnections: Gate

    public convenience init(configuration: IPCConfiguration, limits: IPCLimits = .standard,
                            read: @escaping ReadHandler, snapshot: @escaping SnapshotHandler,
                            begin: @escaping BeginHandler, authorize: @escaping AuthorizeHandler) throws(IPCError) {
        try configuration.validate(for: .broker)
        self.init(validated: configuration, limits: limits,
                  readListener: NSXPCListener(machServiceName: configuration.readServiceName),
                  adminListener: NSXPCListener(machServiceName: configuration.adminServiceName),
                  handlers: Handlers(read: read, snapshot: snapshot, begin: begin, authorize: authorize))
    }

    init(validated configuration: IPCConfiguration, limits: IPCLimits, readListener: NSXPCListener,
         adminListener: NSXPCListener, handlers: Handlers) {
        self.configuration = configuration; self.limits = limits; self.handlers = handlers
        self.readListener = readListener; self.adminListener = adminListener
        readInFlight = Gate(limit: limits.maxInFlightTotal)
        // Revocation and other human controls retain capacity even when every read slot is occupied.
        adminInFlight = Gate(limit: 4)
        readConnections = Gate(limit: limits.maxConnectionsPerService)
        adminConnections = Gate(limit: limits.maxConnectionsPerService)
        super.init()
    }

    public func activate() {
        readListener.delegate = self
        adminListener.delegate = self
        readListener.setConnectionCodeSigningRequirement(configuration.readRequirement)
        adminListener.setConnectionCodeSigningRequirement(configuration.adminRequirement)
        readListener.activate()
        adminListener.activate()
    }

    public func invalidate() {
        readListener.invalidate()
        adminListener.invalidate()
    }

    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        let admin: Bool
        if listener === adminListener { admin = true }
        else if listener === readListener { admin = false }
        else { return false }

        let uid = UInt32(connection.effectiveUserIdentifier)
        guard uid == configuration.allowedUID, uid != 0 else { return false }
        let slots = admin ? adminConnections : readConnections
        guard slots.acquire() else { return false }

        connection.setCodeSigningRequirement(admin ? configuration.adminRequirement : configuration.readRequirement)
        // A read whose bridge connection is gone is cancelled, so a browser run it started cannot be
        // left paused with no caller that knows its ID. Admin work always runs to completion: signed
        // lifecycle mutations keep their journal and uncertainty semantics.
        let peer = Peer(uid: uid, limits: limits, connectionInFlight: Gate(limit: limits.maxInFlightPerConnection),
                        serviceInFlight: admin ? adminInFlight : readInFlight, cancelsOnInvalidation: !admin)
        if admin {
            connection.exportedInterface = NSXPCInterface(with: VaultAdminRPC.self)
            connection.exportedObject = AdminEndpoint(peer: peer, handlers: handlers)
        } else {
            connection.exportedInterface = NSXPCInterface(with: VaultReadRPC.self)
            connection.exportedObject = ReadEndpoint(peer: peer, handlers: handlers)
        }
        connection.invalidationHandler = {
            slots.release()
            peer.connectionInvalidated()
        }
        connection.activate()
        return true
    }
}

final class Gate: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    let limit: Int

    init(limit: Int) { self.limit = limit }

    func acquire() -> Bool {
        lock.withLock {
            guard count < limit else { return false }
            count += 1
            return true
        }
    }

    func release() { lock.withLock { count -= 1 } }
}

/// Calls an XPC reply block at most once.
final class ReplyOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var block: ((Data) -> Void)?

    init(_ block: @escaping (Data) -> Void) { self.block = block }

    func send(_ data: Data) {
        let block = lock.withLock { () -> ((Data) -> Void)? in
            defer { self.block = nil }
            return self.block
        }
        block?(data)
    }
}

/// State bound to one accepted connection.
final class Peer: Sendable {
    let uid: UInt32
    let limits: IPCLimits
    private let connectionInFlight: Gate
    private let serviceInFlight: Gate
    private let cancelsOnInvalidation: Bool
    let work = CancellableWork()

    init(uid: UInt32, limits: IPCLimits, connectionInFlight: Gate, serviceInFlight: Gate,
         cancelsOnInvalidation: Bool = false) {
        self.uid = uid; self.limits = limits
        self.connectionInFlight = connectionInFlight; self.serviceInFlight = serviceInFlight
        self.cancelsOnInvalidation = cancelsOnInvalidation
    }

    /// The connection is gone. For a read peer, its in-flight handlers are cancelled.
    func connectionInvalidated() {
        guard cancelsOnInvalidation else { return }
        for task in work.invalidate() { task.cancel() }
    }

    /// Validates size and shape before allocating capacity, then runs `work` off the XPC queue.
    func dispatch<Input: Sendable>(size: Int, reply block: @escaping (Data) -> Void,
                                   parse: () throws(IPCError) -> Input,
                                   work: @escaping @Sendable (UInt32, Input) async -> Data) {
        let reply = ReplyOnce(block)
        guard let current = NSXPCConnection.current(), UInt32(current.effectiveUserIdentifier) == uid else {
            NSXPCConnection.current()?.invalidate()
            return
        }
        guard size <= limits.maxRequestBytes else { return reply.send(WireCodec.errorReply(.requestTooLarge)) }
        let input: Input
        do {
            input = try parse()
        } catch {
            return reply.send(WireCodec.errorReply(error))
        }
        guard connectionInFlight.acquire() else { return reply.send(WireCodec.errorReply(.busy)) }
        guard serviceInFlight.acquire() else {
            connectionInFlight.release()
            return reply.send(WireCodec.errorReply(.busy))
        }
        let uid = uid, registry = self.work
        // Reserved before the task exists, so completion and invalidation can each happen first.
        let key = cancelsOnInvalidation ? registry.reserve() : nil
        let task = Task {
            let data = await work(uid, input)
            self.release()
            if let key { registry.complete(key) }
            reply.send(data)
        }
        if let key, !registry.register(key, task) { task.cancel() }
    }

    private func release() {
        connectionInFlight.release()
        serviceInFlight.release()
    }
}

/// Handler tasks of one connection that must be cancelled when it goes away.
///
/// Each task's key is reserved before the task starts. The task completes its key; the dispatcher
/// registers the task only while its key is still reserved. Any order of finish, register and
/// invalidate leaves nothing retained, and a task registered after invalidation is cancelled.
final class CancellableWork: @unchecked Sendable {
    private let lock = NSLock()
    private var reserved: Set<UUID> = []
    private var tasks: [UUID: Task<Void, Never>] = [:]
    private var invalidated = false

    /// A key for one task. After invalidation the work still runs, but is cancelled at registration.
    func reserve() -> UUID {
        let key = UUID()
        lock.withLock { if !invalidated { reserved.insert(key) } }
        return key
    }

    /// Returns `false` if the task must be cancelled because its connection is already gone.
    func register(_ key: UUID, _ task: Task<Void, Never>) -> Bool {
        lock.withLock {
            if invalidated { return false }
            guard reserved.contains(key) else { return true }   // already finished: nothing to keep
            tasks[key] = task
            return true
        }
    }

    func complete(_ key: UUID) {
        lock.withLock {
            reserved.remove(key)
            tasks.removeValue(forKey: key)
        }
    }

    func invalidate() -> [Task<Void, Never>] {
        lock.withLock {
            invalidated = true
            defer { tasks = [:]; reserved = [] }
            return Array(tasks.values)
        }
    }

    var retained: (reserved: Int, tasks: Int) { lock.withLock { (reserved.count, tasks.count) } }
}

final class ReadEndpoint: NSObject, VaultReadRPC {
    private let peer: Peer
    private let handlers: VaultXPCServer.Handlers

    init(peer: Peer, handlers: VaultXPCServer.Handlers) { self.peer = peer; self.handlers = handlers }

    func perform(_ data: Data, reply: @escaping (Data) -> Void) {
        let limits = peer.limits, handler = handlers.read
        peer.dispatch(size: data.count, reply: reply, parse: { () throws(IPCError) in
            try WireCodec.decodeRead(data, limits: limits)
        }, work: { uid, request in
            guard let result = try? await handler(uid, request) else { return WireCodec.errorReply(.unavailable) }
            return WireCodec.reply(result, kind: .readReply, limits: limits) ?? WireCodec.errorReply(.unavailable)
        })
    }
}

final class AdminEndpoint: NSObject, VaultAdminRPC {
    private let peer: Peer
    private let handlers: VaultXPCServer.Handlers

    init(peer: Peer, handlers: VaultXPCServer.Handlers) { self.peer = peer; self.handlers = handlers }

    func snapshot(reply: @escaping (Data) -> Void) {
        let limits = peer.limits, handler = handlers.snapshot
        peer.dispatch(size: 0, reply: reply, parse: {}, work: { uid, _ in
            guard let result = try? await handler(uid) else { return WireCodec.errorReply(.unavailable) }
            return WireCodec.reply(result, kind: .snapshot, limits: limits) ?? WireCodec.errorReply(.unavailable)
        })
    }

    func begin(_ data: Data, reply: @escaping (Data) -> Void) {
        let limits = peer.limits, handler = handlers.begin
        peer.dispatch(size: data.count, reply: reply, parse: { () throws(IPCError) in
            try WireCodec.decodeAdmin(data, limits: limits)
        }, work: { uid, request in
            do {
                let challenge = try await handler(uid, request)
                return WireCodec.reply(challenge, kind: .challenge, limits: limits) ?? WireCodec.errorReply(.unavailable)
            } catch let rejection as AdminRejection {
                return WireCodec.reply(AdminReply(status: rejection.status), kind: .adminReply, limits: limits)
                    ?? WireCodec.errorReply(.unavailable)
            } catch {
                return WireCodec.errorReply(.unavailable)
            }
        })
    }

    func authorize(_ id: String, signature: Data, reply: @escaping (Data) -> Void) {
        let limits = peer.limits, handler = handlers.authorize
        peer.dispatch(size: id.utf8.count + signature.count, reply: reply, parse: { () throws(IPCError) in
            Authorization(id: try WireCodec.decodeAuthorize(id: id, signature: signature), signature: signature)
        }, work: { uid, input in
            guard let result = try? await handler(uid, input.id, input.signature) else {
                return WireCodec.errorReply(.unavailable)
            }
            return WireCodec.reply(result, kind: .adminReply, limits: limits) ?? WireCodec.errorReply(.unavailable)
        })
    }

    private struct Authorization: Sendable {
        let id: UUID
        let signature: Data
    }
}
