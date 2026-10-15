import Foundation

public enum VaultError: String, Error, Sendable {
    case invalidInput = "invalid_input"
    case stateUnavailable = "state_unavailable"
    case secretUnavailable = "secret_unavailable"
    case denied = "access_denied"
    case upstreamUnavailable = "upstream_unavailable"
    case invalidResponse = "invalid_response"
    case approvalRequired = "approval_required"
    case replay = "replay_denied"
    case busy = "busy"
}

public enum Action: String, Codable, CaseIterable, Sendable {
    case demoStatus = "demo.status"
    case githubProfile = "github.profile"
    case browserDemo = "browser.demo"
    case githubWebProfile = "github.web_profile"
}

public enum Service: String, Codable, Sendable {
    case demo
    case github, browserDemo, githubWeb

    public var action: Action {
        switch self {
        case .demo: .demoStatus
        case .github: .githubProfile
        case .browserDemo: .browserDemo
        case .githubWeb: .githubWebProfile
        }
    }
}

public enum AccountLifecycle: String, Codable, Sendable { case enrolling, active, rotating, deleting }

public struct Account: Codable, Equatable, Sendable {
    public let id: UUID
    public let service: Service
    public var credentialID: UUID
    public var stagedCredentialID: UUID?
    public var retiredCredentialID: UUID?
    public var lifecycle: AccountLifecycle
    public init(id: UUID = UUID(), service: Service, lifecycle: AccountLifecycle = .active) {
        self.id = id; self.service = service; self.credentialID = id; self.lifecycle = lifecycle
    }
    private enum CodingKeys: String, CodingKey { case id, service, credentialID, stagedCredentialID, retiredCredentialID, lifecycle }
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id); service = try c.decode(Service.self, forKey: .service)
        credentialID = try c.decode(UUID.self, forKey: .credentialID)
        stagedCredentialID = try c.decodeIfPresent(UUID.self, forKey: .stagedCredentialID)
        retiredCredentialID = try c.decodeIfPresent(UUID.self, forKey: .retiredCredentialID)
        lifecycle = try c.decode(AccountLifecycle.self, forKey: .lifecycle)
    }
}

public struct ClientRecord: Codable, Sendable {
    public let id: UUID
    public var revoked: Bool
    public let uid: UInt32?
    public init(id: UUID = UUID(), revoked: Bool = false, uid: UInt32? = nil) {
        self.id = id; self.revoked = revoked; self.uid = uid
    }
}

public struct Grant: Codable, Sendable {
    public let id: UUID
    public let clientID: UUID
    public let accountID: UUID
    public let action: Action
    public let expiresAt: Date
    public let callLimit: Int
    public var callsUsed: Int
    public var revoked: Bool
    public let requiresApproval: Bool

    public init(id: UUID = UUID(), clientID: UUID, accountID: UUID, action: Action,
                expiresAt: Date, callLimit: Int, callsUsed: Int = 0, revoked: Bool = false,
                requiresApproval: Bool = false) {
        self.id = id; self.clientID = clientID; self.accountID = accountID
        self.action = action; self.expiresAt = expiresAt; self.callLimit = callLimit
        self.callsUsed = callsUsed; self.revoked = revoked
        self.requiresApproval = requiresApproval
    }

    private enum CodingKeys: String, CodingKey {
        case id, clientID, accountID, action, expiresAt, callLimit, callsUsed, revoked, requiresApproval
    }
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id); clientID = try c.decode(UUID.self, forKey: .clientID)
        accountID = try c.decode(UUID.self, forKey: .accountID); action = try c.decode(Action.self, forKey: .action)
        expiresAt = try c.decode(Date.self, forKey: .expiresAt); callLimit = try c.decode(Int.self, forKey: .callLimit)
        callsUsed = try c.decode(Int.self, forKey: .callsUsed); revoked = try c.decode(Bool.self, forKey: .revoked)
        requiresApproval = try c.decode(Bool.self, forKey: .requiresApproval)
    }
}

public struct PendingInvocation: Codable, Sendable, Identifiable {
    public enum Status: String, Codable, Sendable { case waiting, approved, consumed, cancelled }
    public let id: UUID
    public let clientID: UUID
    public let accountID: UUID
    public let action: Action
    public let grantID: UUID
    public let expiresAt: Date
    public var status: Status
}

public struct AuditEvent: Codable, Sendable {
    public let timestamp: Date
    public let clientID: UUID
    public let accountID: UUID?
    public let action: Action?
    public let outcome: String
}

public struct VaultState: Codable, Sendable {
    public static let maxAccounts = 128
    public static let maxClients = 128
    public static let maxGrants = 512
    public static let maxInvocationAudit = 744
    public static let maxAdministrationAudit = 256
    public static let administrationPrincipal = UUID(uuidString: "00000000-0000-0000-0000-000000000000")!
    public var version: Int = 3
    public var accounts: [Account] = []
    public var clients: [ClientRecord] = []
    public var grants: [Grant] = []
    public var audit: [AuditEvent] = []
    public var adminAudit: [AuditEvent] = []
    public var pending: [PendingInvocation] = []
    public init() {}

    public mutating func record(client: UUID, account: UUID?, action: Action?, outcome: String,
                                at timestamp: Date) {
        // Only paired clients own retention partitions. Arbitrary denied identities
        // must not manufacture partitions or displace an authenticated client's history.
        guard clients.contains(where: { $0.id == client }) else { return }
        // Unapproved requests, cancellations and denials are representatives,
        // not attempt counts. A real reservation/terminal event resets the tuple.
        let representatives: Set<String> = ["denied", "approval_requested", "approval_cancelled"]
        if representatives.contains(outcome) {
            for event in audit.reversed() where event.clientID == client && event.accountID == account && event.action == action {
                guard representatives.contains(event.outcome) else { break }
                if event.outcome == outcome { return }
            }
        }
        audit.append(.init(timestamp: timestamp, clientID: client, accountID: account,
                           action: action, outcome: outcome))
        while audit.count > Self.maxInvocationAudit {
            let registered = Set(clients.map(\.id))
            if let retired = audit.firstIndex(where: { !registered.contains($0.clientID) }) {
                audit.remove(at: retired)
            } else {
                let counts = Dictionary(grouping: audit, by: \.clientID).mapValues(\.count)
                let largest = counts.values.max()!
                // Ties evict the oldest event across the equally largest histories.
                let oldest = audit.firstIndex { counts[$0.clientID] == largest }!
                audit.remove(at: oldest)
            }
        }
    }

    public mutating func recordAdministration(client: UUID = VaultState.administrationPrincipal,
                                             account: UUID? = nil, action: Action? = nil,
                                             outcome: String, at timestamp: Date) {
        adminAudit.append(.init(timestamp: timestamp, clientID: client, accountID: account,
                               action: action, outcome: outcome))
        if adminAudit.count > Self.maxAdministrationAudit {
            adminAudit.removeFirst(adminAudit.count - Self.maxAdministrationAudit)
        }
    }
}

public struct GitHubProfile: Codable, Equatable, Sendable {
    public let login: String
    public let id: Int
    public init(login: String, id: Int) { self.login = login; self.id = id }
}

public enum OperationResult: Equatable, Sendable {
    case demoReady
    case githubProfile(GitHubProfile)
    case approvalRequired(UUID)
    case humanStepRequired(UUID)
}

public protocol StateStore: Sendable {
    func transaction<T>(_ body: (inout VaultState) throws -> T) throws -> T
    func snapshot() throws -> VaultState
}

public extension StateStore {
    func snapshot() throws -> VaultState { try transaction { $0 } }
}

public protocol SecretStore: Sendable {
    func save(_ value: Data, for accountID: UUID) throws
    func load(for accountID: UUID) throws -> Data
    func delete(for accountID: UUID) throws
}

public protocol ServiceAdapter: Sendable {
    func execute(service: Service, credential: Data) async throws -> OperationResult
}

public protocol SessionServiceAdapter: ServiceAdapter {
    func execute(sessionID: UUID, expiresAt: Date, service: Service, credential: Data) async throws -> OperationResult
    func invalidate(sessionID: UUID) async
}
