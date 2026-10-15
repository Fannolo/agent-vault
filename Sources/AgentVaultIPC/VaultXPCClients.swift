import AgentVaultContracts
import Foundation

/// Read-service client used by the MCP bridge. It carries no credential store; it can only
/// send closed `ReadRequest` values to a broker that satisfies `brokerRequirement`.
public final class VaultReadClient: Sendable {
    /// How long the bridge waits for one read. Every broker-side step of a read, including
    /// credential access and a browser host start, must finish inside it.
    public static let defaultTimeout: TimeInterval = 30
    private let channel: Channel

    public init(configuration: IPCConfiguration, limits: IPCLimits = .standard,
                timeout: TimeInterval = VaultReadClient.defaultTimeout) throws(IPCError) {
        try configuration.validate(for: .readClient)
        channel = Channel(configuration: configuration, limits: limits, timeout: timeout,
                          target: .service(configuration.readServiceName), protocol: VaultReadRPC.self,
                          probe: Self.probe)
    }

    init(validated configuration: IPCConfiguration, endpoint: NSXPCListenerEndpoint,
         limits: IPCLimits = .standard, timeout: TimeInterval = 5) {
        channel = Channel(configuration: configuration, limits: limits, timeout: timeout,
                          target: .endpoint(endpoint), protocol: VaultReadRPC.self, probe: Self.probe)
    }

    private static let probe: Channel.Send = { proxy, reply in (proxy as? VaultReadRPC)?.perform(Data(), reply: reply) }

    public func perform(_ request: ReadRequest) async throws(IPCError) -> ReadReply {
        let data = try WireCodec.encode(request)
        let envelope = await channel.exchange(allowed: [.readReply]) { proxy, reply in
            (proxy as? VaultReadRPC)?.perform(data, reply: reply)
        }
        guard case .readReply(let reply) = try envelope.get() else { throw .malformedReply }
        return reply
    }

    public func invalidate() { channel.invalidate() }
}

/// Admin-service client used by the human app.
public final class VaultAdminClient: Sendable {
    private let channel: Channel

    public init(configuration: IPCConfiguration, limits: IPCLimits = .standard,
                timeout: TimeInterval = 30) throws(IPCError) {
        try configuration.validate(for: .adminClient)
        channel = Channel(configuration: configuration, limits: limits, timeout: timeout,
                          target: .service(configuration.adminServiceName), protocol: VaultAdminRPC.self,
                          probe: Self.probe)
    }

    init(validated configuration: IPCConfiguration, endpoint: NSXPCListenerEndpoint,
         limits: IPCLimits = .standard, timeout: TimeInterval = 5) {
        channel = Channel(configuration: configuration, limits: limits, timeout: timeout,
                          target: .endpoint(endpoint), protocol: VaultAdminRPC.self, probe: Self.probe)
    }

    private static let probe: Channel.Send = { proxy, reply in (proxy as? VaultAdminRPC)?.begin(Data(), reply: reply) }

    public func snapshot() async throws(IPCError) -> AdminSnapshot {
        let envelope = await channel.exchange(allowed: [.snapshot]) { proxy, reply in
            (proxy as? VaultAdminRPC)?.snapshot(reply: reply)
        }
        guard case .snapshot(let snapshot) = try envelope.get() else { throw .malformedReply }
        return snapshot
    }

    public enum BeginResult: Sendable {
        case challenge(AdminChallenge)
        case rejected(AdminReply)
    }

    public func begin(_ request: AdminRequest) async throws(IPCError) -> BeginResult {
        let data = try WireCodec.encode(request)
        let envelope = await channel.exchange(allowed: [.challenge, .adminReply]) { proxy, reply in
            (proxy as? VaultAdminRPC)?.begin(data, reply: reply)
        }
        switch try envelope.get() {
        case .challenge(let challenge): return .challenge(challenge)
        case .adminReply(let reply): return .rejected(reply)
        default: throw .malformedReply
        }
    }

    public func authorize(id: UUID, signature: Data) async throws(IPCError) -> AdminReply {
        let text = id.uuidString
        _ = try WireCodec.decodeAuthorize(id: text, signature: signature)
        let envelope = await channel.exchange(allowed: [.adminReply]) { proxy, reply in
            (proxy as? VaultAdminRPC)?.authorize(text, signature: signature, reply: reply)
        }
        guard case .adminReply(let reply) = try envelope.get() else { throw .malformedReply }
        return reply
    }

    /// One call on a lease opened through this same client: its connection is the lease's binding,
    /// so a reconnect needs a new signed open.
    public func continueHuman(_ request: ContinuationRequest) async throws(IPCError) -> ContinuationReply {
        let data = try WireCodec.encode(request)
        let envelope = await channel.exchange(allowed: [.humanFrame, .humanReply]) { proxy, reply in
            (proxy as? VaultAdminRPC)?.continueHuman(data, reply: reply)
        }
        guard case .continuation(let reply) = try envelope.get() else { throw .malformedReply }
        if case .frame(let frame) = reply, case .frame(let after) = request.operation, frame.sequence <= after {
            throw .malformedReply
        }
        return reply
    }

    public func invalidate() { channel.invalidate() }
}

/// One lazily created connection that enforces the broker's code requirement and UID.
///
/// XPC checks a client-side code requirement on messages the client receives, so a request
/// sent to an impostor would still be delivered. Each new connection therefore completes a
/// payload-free probe, answered by the broker with a fixed `invalid_request` before concurrency
/// admission, before any request is sent. An interrupted connection is discarded so its
/// replacement is probed again.
final class Channel: @unchecked Sendable {
    enum Target {
        case service(String)
        case endpoint(NSXPCListenerEndpoint)
    }

    typealias Send = @Sendable (AnyObject, @escaping (Data) -> Void) -> Void?

    private struct Link {
        let connection: NSXPCConnection
        let verified: Task<IPCError?, Never>
    }

    private let configuration: IPCConfiguration
    private let limits: IPCLimits
    private let timeout: TimeInterval
    private let target: Target
    private let interface: Protocol
    private let probe: Send
    private let lock = NSLock()
    private var current: Link?

    init(configuration: IPCConfiguration, limits: IPCLimits, timeout: TimeInterval, target: Target,
         protocol interface: Protocol, probe: @escaping Send) {
        self.configuration = configuration; self.limits = limits; self.timeout = timeout
        self.target = target; self.interface = interface; self.probe = probe
    }

    func invalidate() {
        lock.withLock { current }?.connection.invalidate()
    }

    func exchange(allowed: Set<WireCodec.ReplyKind>, _ send: Send) async -> Result<WireCodec.Envelope, IPCError> {
        let link = link()
        if let failure = await link.verified.value {
            link.connection.invalidate()
            return .failure(failure)
        }
        return await roundTrip(link.connection, allowed: allowed, send)
    }

    private func link() -> Link {
        lock.withLock {
            if let current { return current }
            let connection: NSXPCConnection
            switch target {
            case .service(let name):
                // Production looks the name up only in the system bootstrap, so a same-user
                // launch agent cannot shadow the broker's LaunchDaemon service.
                connection = NSXPCConnection(machServiceName: name,
                                             options: configuration.development ? [] : .privileged)
            case .endpoint(let endpoint):
                connection = NSXPCConnection(listenerEndpoint: endpoint)
            }
            connection.remoteObjectInterface = NSXPCInterface(with: interface)
            connection.setCodeSigningRequirement(configuration.brokerRequirement)
            connection.interruptionHandler = { [weak connection] in connection?.invalidate() }
            connection.invalidationHandler = { [weak self, weak connection] in
                guard let self else { return }
                self.lock.withLock { if self.current?.connection === connection { self.current = nil } }
            }
            connection.activate()
            let probe = probe, box = ConnectionBox(connection)
            let verified = Task { () -> IPCError? in
                switch await self.roundTrip(box.connection, allowed: [], probe) {
                case .failure(.invalidRequest): return nil
                case .failure(.brokerRejected): return .brokerRejected
                case .failure(.timeout): return .timeout
                default: return .connectionFailed
                }
            }
            let link = Link(connection: connection, verified: verified)
            current = link
            return link
        }
    }

    private func roundTrip(_ connection: NSXPCConnection, allowed: Set<WireCodec.ReplyKind>,
                           _ send: Send) async -> Result<WireCodec.Envelope, IPCError> {
        let brokerUID = configuration.brokerUID, limits = limits, timeout = timeout
        let result = await withCheckedContinuation { (continuation: CheckedContinuation<Result<WireCodec.Envelope, IPCError>, Never>) in
            let once = ResumeOnce(continuation)
            let proxy = connection.remoteObjectProxyWithErrorHandler { error in
                once.resume(.failure(Self.map(error)))
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { once.resume(.failure(.timeout)) }
            let sent: Void? = send(proxy as AnyObject) { data in
                // The reply has passed the broker code requirement; also pin the sender's UID.
                guard UInt32(connection.effectiveUserIdentifier) == brokerUID else {
                    return once.resume(.failure(.brokerRejected))
                }
                once.resume(WireCodec.decodeReply(data, allowed: allowed, limits: limits))
            }
            if sent == nil { once.resume(.failure(.connectionFailed)) }
        }
        if case .success(.error(let code)) = result { return .failure(code) }
        return result
    }

    private static func map(_ error: any Error) -> IPCError {
        let error = error as NSError
        if error.domain == NSCocoaErrorDomain && error.code == NSXPCConnectionCodeSigningRequirementFailure {
            return .brokerRejected
        }
        return .connectionFailed
    }
}

private final class ConnectionBox: @unchecked Sendable {
    let connection: NSXPCConnection
    init(_ connection: NSXPCConnection) { self.connection = connection }
}

final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Result<WireCodec.Envelope, IPCError>, Never>?

    init(_ continuation: CheckedContinuation<Result<WireCodec.Envelope, IPCError>, Never>) {
        self.continuation = continuation
    }

    func resume(_ result: Result<WireCodec.Envelope, IPCError>) {
        let continuation = lock.withLock { () -> CheckedContinuation<Result<WireCodec.Envelope, IPCError>, Never>? in
            defer { self.continuation = nil }
            return self.continuation
        }
        continuation?.resume(returning: result)
    }
}
