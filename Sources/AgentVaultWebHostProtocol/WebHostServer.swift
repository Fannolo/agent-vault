import AgentVaultIPC
import Foundation

/// The web host's listener. It serves exactly one peer in its lifetime: the broker, identified by
/// kernel UID and code requirement on the connection and again on every message. Losing that peer
/// is terminal: its in-flight handlers are cancelled, their results are dropped, no other peer is
/// ever accepted, and `peerLost` tears every browser context down; the host process then exits.
public final class WebHostServer: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    public typealias Handler = @Sendable (HostCommand) async -> HostReply

    /// Work the host admits at once, per lane. Teardown has its own reserve, so frame or
    /// control saturation can never delay an `end`.
    public struct Limits: Sendable {
        public var control: Int, frame: Int, teardown: Int
        public static let standard = Limits(control: 8, frame: 4, teardown: 16)
        func limit(_ lane: HostLane) -> Int {
            switch lane {
            case .control: control
            case .frame: frame
            case .teardown: teardown
            }
        }
    }

    private let configuration: WebHostConfiguration
    private let listener: NSXPCListener
    private let handler: Handler
    private let peerLost: @Sendable () async -> Void
    private let limits: Limits
    private let lock = NSLock()
    private var peer: NSXPCConnection?
    private var terminated = false
    private var inFlight: [HostLane: Int] = [:]
    /// Admitted requests of the current peer; a handler may answer only while its key is here.
    private var active: Set<UUID> = []
    private var handlers: [UUID: Task<Void, Never>] = [:]

    public convenience init(configuration: WebHostConfiguration, handler: @escaping Handler,
                            peerLost: @escaping @Sendable () async -> Void) throws(IPCError) {
        try configuration.validate(for: .host)
        self.init(validated: configuration, listener: NSXPCListener(machServiceName: configuration.serviceName),
                  limits: .standard, handler: handler, peerLost: peerLost)
    }

    init(validated configuration: WebHostConfiguration, listener: NSXPCListener, limits: Limits,
         handler: @escaping Handler, peerLost: @escaping @Sendable () async -> Void) {
        self.configuration = configuration; self.listener = listener; self.limits = limits
        self.handler = handler; self.peerLost = peerLost
        super.init()
    }

    public func activate() {
        listener.delegate = self
        listener.setConnectionCodeSigningRequirement(configuration.brokerRequirement)
        listener.activate()
    }

    public func invalidate() {
        listener.invalidate()
        lock.withLock { peer }?.invalidate()
    }

    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard listener === self.listener else { return false }
        let uid = UInt32(connection.effectiveUserIdentifier)
        guard uid == configuration.brokerUID, uid != 0 else { return false }
        let accepted = lock.withLock { () -> Bool in
            guard peer == nil, !terminated else { return false }
            peer = connection
            return true
        }
        guard accepted else { return false }
        connection.setCodeSigningRequirement(configuration.brokerRequirement)
        connection.exportedInterface = NSXPCInterface(with: WebHostRPC.self)
        connection.exportedObject = Endpoint(server: self, uid: uid)
        connection.interruptionHandler = { [weak connection] in connection?.invalidate() }
        connection.invalidationHandler = { [weak self, weak connection] in self?.ended(connection) }
        connection.activate()
        return true
    }

    /// True once the peer was lost. Nothing the host does afterwards may outlive teardown.
    public var isTerminated: Bool { lock.withLock { terminated } }

    private func ended(_ connection: NSXPCConnection?) {
        let running = lock.withLock { () -> [Task<Void, Never>]? in
            guard let connection, peer === connection, !terminated else { return nil }
            peer = nil; terminated = true
            defer { handlers = [:]; active = [] }
            return Array(handlers.values)
        }
        guard let running else { return }
        for handler in running { handler.cancel() }
        let peerLost = peerLost
        Task(priority: .high) { await peerLost() }
    }

    fileprivate func perform(_ data: Data, uid: UInt32, reply block: @escaping (Data) -> Void) {
        let reply = ReplyOnce(block)
        guard let current = NSXPCConnection.current(), UInt32(current.effectiveUserIdentifier) == uid,
              lock.withLock({ peer === current }) else {
            NSXPCConnection.current()?.invalidate()
            return
        }
        // Authentication probe: a fixed answer, no admission, no handler.
        guard !data.isEmpty else { return reply.send(HostWire.errorReply(.invalidRequest)) }
        let request: HostRequest
        do { request = try HostWire.decodeRequest(data) }
        catch { return reply.send(HostWire.errorReply(error)) }
        let lane = request.command.lane
        let key = UUID()
        let admitted = lock.withLock { () -> Bool in
            guard !terminated, inFlight[lane, default: 0] < limits.limit(lane) else { return false }
            inFlight[lane, default: 0] += 1
            active.insert(key)
            return true
        }
        guard admitted else { return reply.send(HostWire.errorReply(.busy)) }
        let handler = handler
        let task = Task(priority: lane == .frame ? .low : .high) {
            let result = await handler(request.command)
            let live = self.lock.withLock { () -> Bool in
                self.inFlight[lane, default: 0] -= 1
                self.handlers.removeValue(forKey: key)
                return self.active.remove(key) != nil && !self.terminated
            }
            guard live else { return }
            let response = HostResponse(request: request.id, run: request.command.run, reply: result)
            guard response.answers(request), let data = try? HostWire.encode(response) else {
                return reply.send(HostWire.errorReply(.unavailable))
            }
            reply.send(data)
        }
        let orphaned = lock.withLock { () -> Bool in
            guard active.contains(key) else { return terminated }
            handlers[key] = task
            return false
        }
        if orphaned { task.cancel() }
    }

    private final class Endpoint: NSObject, WebHostRPC {
        private weak var server: WebHostServer?
        private let uid: UInt32
        init(server: WebHostServer, uid: UInt32) { self.server = server; self.uid = uid }
        func perform(_ data: Data, reply: @escaping (Data) -> Void) {
            server?.perform(data, uid: uid, reply: reply)
        }
    }
}

private final class ReplyOnce: @unchecked Sendable {
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
