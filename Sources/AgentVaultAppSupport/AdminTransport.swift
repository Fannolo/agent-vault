import AgentVaultContracts
import Foundation

/// Safe audit metadata only: no credential, token, payload, signature or provider output.
public struct AuditEntry: Codable, Sendable, Equatable, Identifiable {
    public let timestamp: Date
    public let clientID: UUID
    public let accountID: UUID?
    public let action: String?
    public let outcome: String
    public var id: String { "\(timestamp.timeIntervalSince1970)-\(clientID)-\(accountID?.uuidString ?? "-")-\(outcome)" }

    public init(timestamp: Date, clientID: UUID, accountID: UUID?, action: String?, outcome: String) {
        self.timestamp = timestamp; self.clientID = clientID; self.accountID = accountID
        self.action = action; self.outcome = outcome
    }

    public init(_ summary: AuditSummary) {
        self.init(timestamp: summary.timestamp, clientID: summary.clientID, accountID: summary.accountID,
                  action: summary.action?.rawValue, outcome: summary.outcome)
    }
}

public enum AdminTransportError: Error, Equatable, Sendable {
    /// The broker cannot be reached or the channel failed authentication.
    case unavailable
    /// The broker does not offer this operation yet.
    case unsupported
    /// The broker answered with a closed rejection code.
    case rejected(String)
}

/// The human app's only path to the broker. The production implementation is the
/// authenticated admin XPC channel; unit tests and previews use in-memory implementations.
/// Credential bytes cross only inside `AdminRequest.credential` on `begin`.
public protocol VaultAdminTransport: Sendable {
    /// Accounts, clients, grants, pending requests and the bounded audit tail, all metadata only.
    func snapshot() async throws -> AdminSnapshot
    /// Validates and freezes the request; the broker answers with a single-use challenge.
    func begin(_ request: AdminRequest) async throws -> AdminChallenge
    /// Verifies the signature over `challenge.payload`, consumes the challenge, then applies the request.
    func authorize(challengeID: UUID, signature: Data) async throws -> AdminReply
    /// One call on a human-step lease. It must travel on the connection that authorized the open.
    func continueHuman(_ request: ContinuationRequest) async throws -> ContinuationReply
}

/// Used until a real channel is wired in: every call fails closed.
public struct UnavailableTransport: VaultAdminTransport {
    public init() {}
    public func snapshot() async throws -> AdminSnapshot { throw AdminTransportError.unavailable }
    public func begin(_ request: AdminRequest) async throws -> AdminChallenge { throw AdminTransportError.unavailable }
    public func authorize(challengeID: UUID, signature: Data) async throws -> AdminReply { throw AdminTransportError.unavailable }
    public func continueHuman(_ request: ContinuationRequest) async throws -> ContinuationReply { throw AdminTransportError.unavailable }
}
