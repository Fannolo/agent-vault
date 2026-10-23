import AgentVaultContracts
import Foundation

/// The broker operations behind a transport, shared by XPC and Unix sockets.
///
/// A transport passes the kernel-checked peer UID, or the `AdminConnection` it minted when it
/// accepted the connection. No request field can supply or replace either identity.
public struct BrokerHandlers: Sendable {
    public typealias Read = @Sendable (UInt32, ReadRequest) async throws -> ReadReply
    public typealias Snapshot = @Sendable (UInt32) async throws -> AdminSnapshot
    public typealias Begin = @Sendable (AdminConnection, AdminRequest) async throws -> AdminChallenge
    public typealias Authorize = @Sendable (AdminConnection, UUID, Data) async throws -> AdminReply
    public typealias Continuation = @Sendable (AdminConnection, ContinuationRequest) async -> ContinuationReply
    public typealias Closed = @Sendable (AdminConnection) async -> Void

    let read: Read
    let snapshot: Snapshot
    let begin: Begin
    let authorize: Authorize
    let continuation: Continuation
    let closed: Closed

    public init(read: @escaping Read, snapshot: @escaping Snapshot, begin: @escaping Begin,
                authorize: @escaping Authorize,
                continuation: @escaping Continuation = { _, _ in .failure(.upstreamUnavailable) },
                closed: @escaping Closed = { _ in }) {
        self.read = read; self.snapshot = snapshot; self.begin = begin; self.authorize = authorize
        self.continuation = continuation; self.closed = closed
    }

    // Each call returns the validated reply envelope; handler errors become fixed codes.

    func readReply(uid: UInt32, _ request: ReadRequest, limits: IPCLimits) async -> Data {
        guard let result = try? await read(uid, request) else { return WireCodec.errorReply(.unavailable) }
        return WireCodec.reply(result, kind: .readReply, limits: limits) ?? WireCodec.errorReply(.unavailable)
    }

    func snapshotReply(uid: UInt32, limits: IPCLimits) async -> Data {
        guard let result = try? await snapshot(uid) else { return WireCodec.errorReply(.unavailable) }
        return WireCodec.reply(result, kind: .snapshot, limits: limits) ?? WireCodec.errorReply(.unavailable)
    }

    func beginReply(_ identity: AdminConnection, _ request: AdminRequest, limits: IPCLimits) async -> Data {
        do {
            let challenge = try await begin(identity, request)
            return WireCodec.reply(challenge, kind: .challenge, limits: limits) ?? WireCodec.errorReply(.unavailable)
        } catch let rejection as AdminRejection {
            return WireCodec.reply(AdminReply(status: rejection.status), kind: .adminReply, limits: limits)
                ?? WireCodec.errorReply(.unavailable)
        } catch {
            return WireCodec.errorReply(.unavailable)
        }
    }

    func authorizeReply(_ identity: AdminConnection, id: UUID, signature: Data, limits: IPCLimits) async -> Data {
        guard let result = try? await authorize(identity, id, signature) else { return WireCodec.errorReply(.unavailable) }
        return WireCodec.reply(result, kind: .adminReply, limits: limits) ?? WireCodec.errorReply(.unavailable)
    }

    func continuationReply(_ identity: AdminConnection, _ request: ContinuationRequest, limits: IPCLimits) async -> Data {
        WireCodec.continuationReply(await continuation(identity, request), limits: limits) ?? WireCodec.errorReply(.unavailable)
    }
}

/// Continuation work runs on its own lanes, so frame polling cannot occupy admin capacity.
enum ServiceLanes {
    /// Revocation and other human controls retain capacity even when every read slot is occupied.
    static let adminTotal = 4
    static let continuationPerConnection = 2
    static let continuationTotal = 4
}

public enum AdminBeginResult: Sendable {
    case challenge(AdminChallenge)
    case rejected(AdminReply)
}

extension WireCodec {
    /// A frame reply must advance past the sequence the caller already holds.
    static func checkContinuation(_ reply: ContinuationReply, for request: ContinuationRequest) throws(IPCError) {
        if case .frame(let frame) = reply, case .frame(let after) = request.operation, frame.sequence <= after {
            throw .malformedReply
        }
    }
}
