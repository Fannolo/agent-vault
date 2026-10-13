import Foundation

public enum VaultError: String, Error, Sendable {
    case invalidInput = "invalid_input"
    case stateUnavailable = "state_unavailable"
    case secretUnavailable = "secret_unavailable"
    case denied = "access_denied"
    case upstreamUnavailable = "upstream_unavailable"
    case invalidResponse = "invalid_response"
}

public enum Action: String, Codable, CaseIterable, Sendable {
    case demoStatus = "demo.status"
    case githubProfile = "github.profile"
}

public enum Service: String, Codable, Sendable {
    case demo
    case github

    public var action: Action { self == .demo ? .demoStatus : .githubProfile }
}

public struct Account: Codable, Equatable, Sendable {
    public let id: UUID
    public let service: Service
    public init(id: UUID = UUID(), service: Service) { self.id = id; self.service = service }
}

public struct ClientRecord: Codable, Sendable {
    public let id: UUID
    public var revoked: Bool
    public init(id: UUID = UUID(), revoked: Bool = false) { self.id = id; self.revoked = revoked }
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

    public init(id: UUID = UUID(), clientID: UUID, accountID: UUID, action: Action,
                expiresAt: Date, callLimit: Int, callsUsed: Int = 0, revoked: Bool = false) {
        self.id = id; self.clientID = clientID; self.accountID = accountID
        self.action = action; self.expiresAt = expiresAt; self.callLimit = callLimit
        self.callsUsed = callsUsed; self.revoked = revoked
    }
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
    public var version: Int = 1
    public var accounts: [Account] = []
    public var clients: [ClientRecord] = []
    public var grants: [Grant] = []
    public var audit: [AuditEvent] = []
    public init() {}

    public mutating func record(client: UUID, account: UUID?, action: Action?, outcome: String,
                                at timestamp: Date) {
        audit.append(.init(timestamp: timestamp, clientID: client, accountID: account,
                           action: action, outcome: outcome))
        if audit.count > 1000 { audit.removeFirst(audit.count - 1000) }
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
