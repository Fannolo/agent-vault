#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import AgentVaultContracts
import CAgentVaultSocket
import Dispatch
import Foundation

/// Broker-side Unix-socket listeners for the read (agent bridge) and admin (controller) roles.
///
/// Each accepted connection's kernel peer UID is checked against its endpoint before a byte is
/// read, then bound to the connection and passed to every handler. Admin connections get an
/// `AdminConnection` minted at accept, so a continuation lease follows the socket rather than
/// any value a request carries. `stop()` closes listeners and peers and returns only after every
/// descriptor is closed, every handler task has finished and both socket files are removed.
public final class VaultSocketServer: @unchecked Sendable {
    private enum Phase { case idle, running, stopping, stopped }

    private struct Listener: Sendable {
        let role: SocketRole
        let fd: Int32
        let path: String
        let identity: FileIdentity
        let lock: Int32
        let finished: Completion
    }

    private let configuration: SocketConfiguration
    private let limits: IPCLimits
    private let timeouts: SocketTimeouts
    private let handlers: BrokerHandlers
    private let lanes: SocketLanes
    private let didBind: @Sendable (SocketRole) -> Void
    private let tracker = WorkTracker()
    private let stopped = Completion()
    private let lock = NSLock()
    private var phase = Phase.idle
    private var wake: (read: Int32, write: Int32) = (-1, -1)
    private var listeners: [Listener] = []
    private var connections: [ObjectIdentifier: ServerConnection] = [:]

    public convenience init(configuration: SocketConfiguration, limits: IPCLimits = .standard,
                            handlers: BrokerHandlers) throws(IPCError) {
        try configuration.validate(for: .broker)
        self.init(validated: configuration, limits: limits, timeouts: .standard, handlers: handlers)
    }

    /// `didBind` is a test seam: it runs after each socket is bound and before it listens.
    init(validated configuration: SocketConfiguration, limits: IPCLimits, timeouts: SocketTimeouts,
         handlers: BrokerHandlers, didBind: @escaping @Sendable (SocketRole) -> Void = { _ in }) {
        self.configuration = configuration; self.limits = limits; self.timeouts = timeouts
        self.handlers = handlers; self.didBind = didBind; lanes = SocketLanes(limits: limits)
    }

    /// Binds both sockets in their protected directories and starts accepting. Each path is held
    /// under its lock file from before the stale check until stop, so a second broker fails
    /// `unavailable` instead of racing this one. A stale socket left by an earlier broker is
    /// replaced only if nothing answers on it; any other file is refused.
    public func start() throws(IPCError) {
        lock.lock()
        defer { lock.unlock() }
        guard phase == .idle else { throw .invalidConfiguration }
        var fds: [Int32] = [-1, -1]
        guard av_socket_pipe(&fds) == 0 else { throw .unavailable }
        wake = (fds[0], fds[1])
        do {
            for role in [SocketRole.read, .admin] {
                listeners.append(try Self.bind(endpoint(role), role: role, backlog: limits.maxConnectionsPerService,
                                               didBind: { didBind(role) }))
            }
        } catch {
            for listener in listeners { Self.remove(listener) }
            listeners = []
            close(wake.read); close(wake.write); wake = (-1, -1)
            throw error
        }
        phase = .running
        for listener in listeners {
            startThread("agent-vault.accept.\(listener.role)") { [self] in accept(listener) }
        }
    }

    public func stop() async {
        let first = lock.withLock { () -> Bool in
            switch phase {
            case .idle: phase = .stopped; stopped.signal(); return false
            case .running: phase = .stopping; return true
            case .stopping, .stopped: return false
            }
        }
        guard first else { return await stopped.wait() }
        var byte: UInt8 = 1
        _ = write(wake.write, &byte, 1)
        for listener in listeners { await listener.finished.wait() }
        // Accept threads are done: no connection can be added from here on.
        for listener in listeners { Self.remove(listener) }
        for connection in lock.withLock({ Array(connections.values) }) { await connection.finished.wait() }
        await tracker.drained()
        close(wake.read); close(wake.write)
        lock.withLock { phase = .stopped; listeners = [] }
        stopped.signal()
    }

    private func endpoint(_ role: SocketRole) -> SocketConfiguration.Endpoint {
        role == .read ? configuration.read : configuration.admin
    }

    // MARK: Accepting

    private func accept(_ listener: Listener) {
        defer { listener.finished.signal() }
        let endpoint = endpoint(listener.role)
        Self.acceptLoop(listener.fd, wake: wake.read) { fd in admit(fd, role: listener.role, endpoint: endpoint) }
    }

    /// Hands each accepted descriptor to `admit` until `wake` fires or the listener fails. Every
    /// accept waits first, so peers that keep connecting cannot hold off `stop()`.
    static func acceptLoop(_ listenFD: Int32, wake: Int32, _ admit: (Int32) -> Void) {
        while case .ready = SocketIO.wait(listenFD, wake: wake, events: Int32(AV_WAIT_READ), deadline: .never) {
            let fd = av_socket_accept(listenFD)
            if fd >= 0 { admit(fd); continue }
            let failure = errno
            if failure == EINTR || failure == ECONNABORTED || failure == EAGAIN || failure == EWOULDBLOCK { continue }
            // Descriptor or memory exhaustion: back off instead of spinning on a ready listener.
            if case .woken = SocketIO.wait(wake, wake: -1, events: Int32(AV_WAIT_READ), deadline: .after(0.05)) { return }
        }
    }

    /// Checks the kernel peer UID and capacity before any request byte is read.
    private func admit(_ fd: Int32, role: SocketRole, endpoint: SocketConfiguration.Endpoint) {
        var uid: UInt32 = 0
        guard av_socket_peer_uid(fd, &uid) == 0, uid == endpoint.clientUID, uid != 0 else { return refuse(fd) }
        let slots = lanes.connections(role)
        guard slots.acquire() else { return refuse(fd) }
        let connection = ServerConnection(fd: fd, role: role, uid: uid, limits: limits, timeouts: timeouts,
                                          lanes: lanes, handlers: handlers, tracker: tracker, wake: wake.read)
        let key = ObjectIdentifier(connection)
        let admitted = lock.withLock { () -> Bool in
            guard phase == .running else { return false }
            connections[key] = connection
            return true
        }
        guard admitted else { slots.release(); return refuse(fd) }
        connection.run { [self] in
            slots.release()
            lock.withLock { _ = connections.removeValue(forKey: key) }
        }
    }

    private func refuse(_ fd: Int32) {
        _ = av_socket_shutdown(fd)
        close(fd)
    }

    // MARK: Socket files

    private static func bind(_ endpoint: SocketConfiguration.Endpoint, role: SocketRole, backlog: Int,
                             didBind: () -> Void) throws(IPCError) -> Listener {
        let path = endpoint.path
        try SocketPath.requireProtectedDirectory(of: path)
        let lock = try SocketPath.lock(path)
        do throws(IPCError) {
            try SocketPath.clearStale(path)
            let fd = av_socket_bind(path)
            guard fd >= 0 else { throw .unavailable }
            // Under the lock no other broker can replace the file: this identity is our own, and
            // it alone decides what a rollback or stop may unlink.
            guard let identity = SocketPath.ownedSocket(path) else { close(fd); throw .unavailable }
            didBind()
            // Permissions are final before listen(), so no client can connect under a looser mode.
            guard chmod(path, 0o660) == 0, chown(path, UInt32.max, endpoint.group) == 0,
                  av_socket_listen(fd, Int32(backlog)) == 0 else {
                close(fd)
                SocketPath.remove(path, ifStill: identity)
                throw .unavailable
            }
            return Listener(role: role, fd: fd, path: path, identity: identity, lock: lock, finished: Completion())
        } catch {
            close(lock)
            throw error
        }
    }

    /// Unlinks the socket before releasing its lock, so a successor never sees this one's file.
    private static func remove(_ listener: Listener) {
        close(listener.fd)
        SocketPath.remove(listener.path, ifStill: listener.identity)
        close(listener.lock)
    }
}

enum SocketRole: String, Sendable { case read, admin }

/// Shared capacity: per-service connections and in-flight work, with separate continuation lanes.
final class SocketLanes: Sendable {
    let readWork: Gate
    let adminWork = Gate(limit: ServiceLanes.adminTotal)
    let continuationWork = Gate(limit: ServiceLanes.continuationTotal)
    private let readConnections: Gate
    private let adminConnections: Gate

    init(limits: IPCLimits) {
        readWork = Gate(limit: limits.maxInFlightTotal)
        readConnections = Gate(limit: limits.maxConnectionsPerService)
        adminConnections = Gate(limit: limits.maxConnectionsPerService)
    }

    func connections(_ role: SocketRole) -> Gate { role == .read ? readConnections : adminConnections }
}

/// One accepted connection. Its descriptor is used by the reader thread until that thread exits,
/// and otherwise only on `writer`; `writer` alone closes it, so a late reply can never reach a
/// reused descriptor.
///
/// Every reply, error replies included, counts against a backlog from the moment it is queued
/// until it is written or dropped, and a handler's work capacity is held just as long. While the
/// backlog is full the reader takes no further frame, so a peer that does not read its replies
/// stops being served; the first write that misses its deadline ends the connection.
final class ServerConnection: @unchecked Sendable {
    private let fd: Int32
    private let role: SocketRole
    private let uid: UInt32
    private let limits: IPCLimits
    private let timeouts: SocketTimeouts
    private let lanes: SocketLanes
    private let handlers: BrokerHandlers
    private let tracker: WorkTracker
    private let wake: Int32
    private let identity: AdminConnection?
    private let work = CancellableWork()
    private let connectionWork: Gate
    private let continuationWork = Gate(limit: ServiceLanes.continuationPerConnection)
    private let writer = DispatchQueue(label: "agent-vault.socket.writer")
    private let lock = NSLock()
    private var inFlight: Set<UInt32> = []
    private var closed = false   // writer-confined
    private let backlog = NSCondition()
    private let replyLimit: Int
    private var queued = 0         // guarded by `backlog`
    private var writable = true    // guarded by `backlog`; false once a reply write failed
    let finished = Completion()

    init(fd: Int32, role: SocketRole, uid: UInt32, limits: IPCLimits, timeouts: SocketTimeouts, lanes: SocketLanes,
         handlers: BrokerHandlers, tracker: WorkTracker, wake: Int32) {
        self.fd = fd; self.role = role; self.uid = uid; self.limits = limits; self.timeouts = timeouts
        self.lanes = lanes; self.handlers = handlers; self.tracker = tracker; self.wake = wake
        identity = role == .admin ? AdminConnection(uid: uid) : nil
        connectionWork = Gate(limit: limits.maxInFlightPerConnection)
        replyLimit = max(1, limits.maxInFlightPerConnection)
    }

    func run(released: @escaping @Sendable () -> Void) {
        startThread("agent-vault.socket.\(role)") { [self] in
            readLoop()
            teardown(released: released)
        }
    }

    private func readLoop() {
        while true {
            // A body above the request limit is refused from its header alone.
            switch SocketIO.readFrame(fd, wake: wake, headerSize: SocketFrame.requestHeader, maxBody: limits.maxRequestBytes,
                                      timeout: timeouts.frame) {
            case .success(.complete(let header, let body)):
                guard awaitReplyRoom(),
                      dispatch(id: SocketFrame.number(header, at: 4), opcode: header[8], body: Data(body)) else { return }
            case .success(.oversized(let header)):
                // The stream cannot be resynchronized without reading the body; answer and close.
                send(id: SocketFrame.number(header, at: 4), WireCodec.errorReply(.requestTooLarge))
                return
            case .failure:
                return
            }
        }
    }

    /// Returns `false` for a protocol violation, which closes the connection without a reply.
    /// An ID is in flight from here until its reply, error replies included, is written or
    /// dropped; a duplicate before then is a violation.
    private func dispatch(id: UInt32, opcode: UInt8, body: Data) -> Bool {
        guard let opcode = SocketFrame.Opcode(rawValue: opcode),
              lock.withLock({ inFlight.insert(id).inserted }) else { return false }
        let limits = limits, handlers = handlers, uid = uid
        switch (role, opcode, identity) {
        case (.read, .read, nil):
            return start(id: id, connection: connectionWork, service: lanes.readWork, cancellable: true,
                         parse: { () throws(IPCError) in try WireCodec.decodeRead(body, limits: limits) },
                         work: { request in await handlers.readReply(uid: uid, request, limits: limits) })
        case (.admin, .snapshot, .some):
            return start(id: id, connection: connectionWork, service: lanes.adminWork,
                         parse: { () throws(IPCError) in guard body.isEmpty else { throw .invalidRequest } },
                         work: { _ in await handlers.snapshotReply(uid: uid, limits: limits) })
        case (.admin, .begin, .some(let identity)):
            return start(id: id, connection: connectionWork, service: lanes.adminWork,
                         parse: { () throws(IPCError) in try WireCodec.decodeAdmin(body, limits: limits) },
                         work: { request in await handlers.beginReply(identity, request, limits: limits) })
        case (.admin, .authorize, .some(let identity)):
            return start(id: id, connection: connectionWork, service: lanes.adminWork,
                         parse: { () throws(IPCError) in try Self.authorization(body) },
                         work: { input in
                             await handlers.authorizeReply(identity, id: input.0, signature: input.1, limits: limits)
                         })
        case (.admin, .continuation, .some(let identity)):
            return start(id: id, connection: continuationWork, service: lanes.continuationWork,
                         parse: { () throws(IPCError) in try WireCodec.decodeContinuation(body, limits: limits) },
                         work: { request in await handlers.continuationReply(identity, request, limits: limits) })
        default:
            return false
        }
    }

    /// `id:36 ASCII | DER signature`.
    private static func authorization(_ body: Data) throws(IPCError) -> (UUID, Data) {
        guard body.count > 36, let text = String(data: body.prefix(36), encoding: .utf8) else { throw .invalidRequest }
        let signature = Data(body.dropFirst(36))
        return (try WireCodec.decodeAuthorize(id: text, signature: signature), signature)
    }

    /// Mirrors the XPC dispatcher: shape, then capacity, then work off the reader thread.
    private func start<Input: Sendable>(id: UInt32, connection: Gate, service: Gate, cancellable: Bool = false,
                                        parse: () throws(IPCError) -> Input,
                                        work: @escaping @Sendable (Input) async -> Data) -> Bool {
        let input: Input
        do { input = try parse() } catch {
            send(id: id, WireCodec.errorReply(error))
            return true
        }
        guard connection.acquire() else { send(id: id, WireCodec.errorReply(.busy)); return true }
        guard service.acquire() else {
            connection.release()
            send(id: id, WireCodec.errorReply(.busy))
            return true
        }
        tracker.enter()
        // Reserved before the task exists, so completion and disconnect can each happen first.
        // Admin work always runs to completion: signed mutations keep their journal semantics, and
        // a reply that can no longer be delivered leaves the caller with an explicit unknown outcome.
        let registry = self.work, key = cancellable ? registry.reserve() : nil
        let task = Task { [self] in
            let data = await work(input)
            if let key { registry.complete(key) }
            send(id: id, data) { connection.release(); service.release() }
            tracker.leave()
        }
        if let key, !registry.register(key, task) { task.cancel() }
        return true
    }

    /// Queues one reply on the backlog. Once it is written or dropped its ID leaves `inFlight`,
    /// then `then` runs.
    private func send(id: UInt32, _ body: Data, then: @escaping @Sendable () -> Void = {}) {
        let frame = SocketFrame.reply(id: id, body: body), deadline = Deadline.after(timeouts.write)
        backlog.withLock { queued += 1 }
        writer.async { [self] in
            let written = !closed && SocketIO.writeAll(fd, wake: wake, frame, deadline: deadline)
            if !written && !closed { _ = av_socket_shutdown(fd) }
            backlog.withLock {
                queued -= 1
                if !written { writable = false }
                backlog.broadcast()
            }
            lock.withLock { _ = inFlight.remove(id) }
            then()
        }
    }

    /// Holds the reader while the backlog is full. Each queued write ends by its deadline or at
    /// stop, and fails at once on a closed peer, so this wait cannot outlast any of them.
    /// Returns `false` once a write has failed: the connection takes no further request.
    private func awaitReplyRoom() -> Bool {
        backlog.lock()
        defer { backlog.unlock() }
        while writable && queued >= replyLimit { backlog.wait() }
        return writable
    }

    /// Runs on the reader thread after it stops using the descriptor.
    private func teardown(released: @escaping @Sendable () -> Void) {
        identity?.close()
        for task in work.invalidate() { task.cancel() }
        let closedHandler = handlers.closed, identity = identity, tracker = tracker, finished = finished
        // Queued replies (such as `request_too_large`) flush first, each within its write deadline.
        writer.async { [self] in
            closed = true
            _ = av_socket_shutdown(fd)
            close(fd)
            guard let identity else { released(); return finished.signal() }
            // The connection slot is held until the broker's cleanup finishes, so reconnecting
            // cannot pile up closed callbacks. Counted before release, so a stop that no longer
            // sees this connection still awaits it.
            tracker.enter()
            Task {
                await closedHandler(identity)
                released()
                finished.signal()
                tracker.leave()
            }
        }
    }
}

struct FileIdentity: Equatable, Sendable {
    let device: UInt64
    let inode: UInt64
}

/// Socket file placement. The directory chain must be real directories that only root or the
/// broker can modify, so path-based bind, chmod and unlink cannot be redirected by another user.
enum SocketPath {
    static func requireProtectedDirectory(of path: String) throws(IPCError) {
        let directory = ProtectedFile.parent(of: path)
        guard directory.hasPrefix("/") else { throw .invalidConfiguration }
        let owner = UInt32(geteuid())
        var prefixes = ["/"], current = ""
        for component in directory.split(separator: "/") {
            current += "/" + component
            prefixes.append(current)
        }
        for (index, prefix) in prefixes.enumerated() {
            var info = stat()
            guard lstat(prefix, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
                  info.st_uid == 0 || info.st_uid == owner else { throw .invalidConfiguration }
            let writable = info.st_mode & 0o022 != 0
            // A sticky ancestor such as /tmp is acceptable: nobody else can rename our entry in it.
            if index == prefixes.count - 1 {
                guard !writable else { throw .invalidConfiguration }
            } else if writable && info.st_mode & 0o1000 == 0 {
                throw .invalidConfiguration
            }
        }
    }

    /// Takes the exclusive `flock` on `<path>.lock` that serializes every broker's startup, stale
    /// replacement and removal of `path`. It is held until stop; the lock file itself stays.
    static func lock(_ path: String) throws(IPCError) -> Int32 {
        let fd = open(path + ".lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw .invalidConfiguration }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid() else {
            close(fd)
            throw .invalidConfiguration
        }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            close(fd)
            throw .unavailable
        }
        return fd
    }

    /// Removes a socket file left by an earlier broker run. Anything that is not a socket owned by
    /// this UID, or a socket that still accepts connections, is left in place and refused.
    static func clearStale(_ path: String) throws(IPCError) {
        var info = stat()
        guard lstat(path, &info) == 0 else {
            guard errno == ENOENT else { throw .invalidConfiguration }
            return
        }
        guard let identity = ownedSocket(path) else { throw .invalidConfiguration }
        var inProgress: Int32 = 0
        let probe = av_socket_connect(path, &inProgress)
        let failure = errno
        if probe >= 0 { close(probe); throw .unavailable }
        guard failure == ECONNREFUSED else { throw .unavailable }
        remove(path, ifStill: identity)
    }

    static func ownedSocket(_ path: String) -> FileIdentity? {
        var info = stat()
        guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFSOCK, info.st_uid == geteuid() else { return nil }
        return FileIdentity(device: UInt64(truncatingIfNeeded: info.st_dev), inode: UInt64(truncatingIfNeeded: info.st_ino))
    }

    /// Unlinks `path` only while it is still the socket this broker created or vetted.
    static func remove(_ path: String, ifStill identity: FileIdentity?) {
        guard let identity, ownedSocket(path) == identity else { return }
        _ = unlink(path)
    }
}
