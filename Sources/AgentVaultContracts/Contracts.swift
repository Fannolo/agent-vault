import Foundation

public enum WireAction: String, Codable, CaseIterable, Sendable {
    case demoStatus = "demo.status"
    case githubProfile = "github.profile"
    case browserDemo = "browser.demo"
    case githubWebProfile = "github.web_profile"
}

public enum WireService: String, Codable, CaseIterable, Sendable {
    case demo, github, browserDemo, githubWeb
}

public struct AccountSummary: Codable, Sendable, Identifiable {
    public let id: UUID
    public let service: WireService
    public let status: String
    public init(id: UUID, service: WireService, status: String = "active") {
        self.id = id; self.service = service; self.status = status
    }
}

public struct ClientSummary: Codable, Sendable, Identifiable {
    public let id: UUID
    public let uid: UInt32
    public let revoked: Bool
    public init(id: UUID, uid: UInt32, revoked: Bool) { self.id = id; self.uid = uid; self.revoked = revoked }
}

public struct GrantSummary: Codable, Sendable, Identifiable {
    public let id: UUID
    public let clientID: UUID
    public let accountID: UUID
    public let expiresAt: Date
    public let callsRemaining: Int
    public let requiresApproval: Bool
    public let revoked: Bool
    public init(id: UUID, clientID: UUID, accountID: UUID, expiresAt: Date, callsRemaining: Int,
                requiresApproval: Bool, revoked: Bool) {
        self.id = id; self.clientID = clientID; self.accountID = accountID; self.expiresAt = expiresAt
        self.callsRemaining = callsRemaining; self.requiresApproval = requiresApproval; self.revoked = revoked
    }
}

public struct PendingSummary: Codable, Sendable, Identifiable {
    public let id: UUID
    public let clientID: UUID
    public let accountID: UUID
    public let action: WireAction
    public let expiresAt: Date
    public let status: String
    public init(id: UUID, clientID: UUID, accountID: UUID, action: WireAction, expiresAt: Date, status: String = "waiting") {
        self.id = id; self.clientID = clientID; self.accountID = accountID; self.action = action; self.expiresAt = expiresAt; self.status = status
    }
}

public struct AuditSummary: Codable, Sendable {
    public let timestamp: Date
    public let clientID: UUID
    public let accountID: UUID?
    public let action: WireAction?
    public let outcome: String
    public init(timestamp: Date, clientID: UUID, accountID: UUID?, action: WireAction?, outcome: String) {
        self.timestamp = timestamp; self.clientID = clientID; self.accountID = accountID; self.action = action; self.outcome = outcome
    }
}

public struct AdminSnapshot: Codable, Sendable {
    public let accounts: [AccountSummary]
    public let clients: [ClientSummary]
    public let grants: [GrantSummary]
    public let pending: [PendingSummary]
    public let audit: [AuditSummary]
    /// Challenges paused for a person. Metadata only: no page address, text or image.
    public let humanSteps: [HumanStepSummary]
    public init(accounts: [AccountSummary], clients: [ClientSummary], grants: [GrantSummary], pending: [PendingSummary],
                audit: [AuditSummary] = [], humanSteps: [HumanStepSummary] = []) {
        self.accounts = accounts; self.clients = clients; self.grants = grants; self.pending = pending
        self.audit = audit; self.humanSteps = humanSteps
    }
}

// Flat closed envelopes allow strict-key validation before Codable decoding.
public struct ReadRequest: Codable, Sendable {
    public enum Operation: String, Codable, Sendable { case accounts, run, resume, cancel }
    public let operation: Operation
    public let accountID: UUID?
    public let action: WireAction?
    public let requestID: UUID?
    public init(operation: Operation, accountID: UUID? = nil, action: WireAction? = nil, requestID: UUID? = nil) {
        self.operation = operation; self.accountID = accountID; self.action = action; self.requestID = requestID
    }
}

public struct ReadReply: Codable, Sendable {
    public let status: String
    public let accounts: [AccountSummary]?
    public let requestID: UUID?
    public let login: String?
    public let userID: Int?
    // Construct replies with `init(_: ReadStatus, ...)`; the string form is the decoded wire shape.
    init(status: String, accounts: [AccountSummary]?, requestID: UUID?, login: String?, userID: Int?) {
        self.status = status; self.accounts = accounts; self.requestID = requestID
        self.login = login; self.userID = userID
    }
}

public struct AdminRequest: Codable, Sendable {
    public enum Operation: String, Codable, Sendable {
        case enroll, rotate, deleteAccount, pairClient, grant, revokeGrant, revokeClient,
             approveInvocation, rejectInvocation, recover, prune, openHumanStep
    }
    public let operation: Operation
    public var service: WireService?
    public var credential: Data?
    public var accountID: UUID?
    public var clientID: UUID?
    public var grantID: UUID?
    public var requestID: UUID?
    public var uid: UInt32?
    public var duration: Double?
    public var callLimit: Int?
    public var requiresApproval: Bool?
    /// `openHumanStep` names one exact paused challenge: run (`requestID`), account, step epoch and kind.
    public var stepEpoch: UInt64?
    public var humanStepKind: HumanStepKind?
    public init(operation: Operation) { self.operation = operation }
}

public struct AdminChallenge: Codable, Sendable {
    public let id: UUID
    public let payload: Data
    public let expiresAt: Date
    public let nonce: Data
    public init(id: UUID, payload: Data, expiresAt: Date, nonce: Data = Data(repeating: 0, count: 32)) {
        self.id = id; self.payload = payload; self.expiresAt = expiresAt; self.nonce = nonce
    }
}

public struct AdminReply: Codable, Sendable {
    public let status: String
    public let id: UUID?
    public init(status: String, id: UUID? = nil) { self.status = status; self.id = id }
}

@objc public protocol VaultReadRPC {
    func perform(_ data: Data, reply: @escaping (Data) -> Void)
}

@objc public protocol VaultAdminRPC {
    func snapshot(reply: @escaping (Data) -> Void)
    func begin(_ data: Data, reply: @escaping (Data) -> Void)
    func authorize(_ id: String, signature: Data, reply: @escaping (Data) -> Void)
    /// Frame, input and conclusion for a lease opened on this same connection.
    func continueHuman(_ data: Data, reply: @escaping (Data) -> Void)
}
