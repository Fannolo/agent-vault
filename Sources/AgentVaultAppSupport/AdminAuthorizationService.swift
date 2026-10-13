import AgentVaultContracts
import Foundation

public enum AdminFailure: Error, Equatable, Sendable {
    case transport(AdminTransportError)
    case challengeExpired
    case signing(ApprovalSigningError)
    case rejected(String)
}

public struct AdminOutcome: Equatable, Sendable {
    /// Account or client created by the operation, when the broker reports one.
    public let id: UUID?
}

/// Runs the only admin sequence the app has: begin, human-approved signature, authorize.
/// Every mutation goes through `perform`; there is no way to call `authorize` without a challenge
/// that this broker just issued for this exact request.
public struct AdminAuthorizationService: Sendable {
    /// Replies the broker uses to say the frozen request was applied.
    static let successStatuses: Set<String> = ["ok", "completed", "applied", "authorized"]
    static let expiryMargin: TimeInterval = 1

    private let transport: VaultAdminTransport
    private let signer: ApprovalSigning
    private let now: @Sendable () -> Date

    public init(transport: VaultAdminTransport, signer: ApprovalSigning, now: @escaping @Sendable () -> Date = Date.init) {
        self.transport = transport; self.signer = signer; self.now = now
    }

    /// `summary` is shown by the system authentication prompt. It is built by the app from the
    /// request it sent, never taken from the challenge.
    public func perform(_ request: AdminRequest, summary: String) async throws -> AdminOutcome {
        let challenge: AdminChallenge
        do { challenge = try await transport.begin(request) }
        catch let error as AdminTransportError { throw AdminFailure.transport(error) }
        guard challenge.expiresAt.timeIntervalSince(now()) > Self.expiryMargin else { throw AdminFailure.challengeExpired }

        let signature: Data
        do { signature = try await signer.sign(payload: challenge.payload, reason: summary) }
        catch let error as ApprovalSigningError { throw AdminFailure.signing(error) }
        guard challenge.expiresAt > now() else { throw AdminFailure.challengeExpired }

        let reply: AdminReply
        do { reply = try await transport.authorize(challengeID: challenge.id, signature: signature) }
        catch let error as AdminTransportError { throw AdminFailure.transport(error) }
        guard Self.successStatuses.contains(reply.status) else { throw AdminFailure.rejected(reply.status) }
        return AdminOutcome(id: reply.id)
    }
}
