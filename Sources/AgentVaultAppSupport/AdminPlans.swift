import AgentVaultContracts
import Foundation

extension WireService {
    public var displayName: String {
        switch self {
        case .demo: "Demo"
        case .github: "GitHub API (token)"
        case .browserDemo: "Browser demo"
        case .githubWeb: "GitHub web profile"
        }
    }

    /// Browser workflows sign in with a username and password; the others take one token.
    public var usesPassword: Bool { self == .browserDemo || self == .githubWeb }
}

/// Builds the credential bytes for enrollment or rotation and rejects malformed input before it
/// leaves the app. The broker remains the authority; this only avoids sending obvious mistakes.
public enum CredentialInput {
    public static func data(service: WireService, secret: String, username: String = "") -> Data? {
        guard !secret.isEmpty, secret.utf8.count <= 8192, !hasControl(secret) else { return nil }
        if service.usesPassword {
            let name = username.trimmingCharacters(in: .whitespaces)
            guard !name.isEmpty, name.count <= 255, !hasControl(name) else { return nil }
            return Data((name + "\n" + secret).utf8)
        }
        if service == .github {
            let bytes = Data(secret.utf8)
            guard bytes.count >= 10, bytes.allSatisfy({ (0x21...0x7E).contains($0) }) else { return nil }
        }
        return Data(secret.utf8)
    }

    private static func hasControl(_ text: String) -> Bool {
        text.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }
}

public enum GrantDuration: Double, CaseIterable, Identifiable, Sendable {
    case fifteenMinutes = 900, oneHour = 3600, eightHours = 28_800, oneDay = 86_400, sevenDays = 604_800
    public var id: Double { rawValue }
    public var label: String {
        switch self {
        case .fifteenMinutes: "15 minutes"
        case .oneHour: "1 hour"
        case .eightHours: "8 hours"
        case .oneDay: "24 hours"
        case .sevenDays: "7 days"
        }
    }
}

/// One exact grant: this client, this account, this lifetime, this many calls.
public struct GrantPlan: Equatable, Sendable {
    public static let maxCalls = 1000
    public var clientID: UUID
    public var accountID: UUID
    public var duration: GrantDuration
    public var callLimit: Int
    public var alwaysRequireApproval: Bool

    public init(clientID: UUID, accountID: UUID, duration: GrantDuration = .oneHour, callLimit: Int = 10,
                alwaysRequireApproval: Bool = true) {
        self.clientID = clientID; self.accountID = accountID; self.duration = duration
        self.callLimit = callLimit; self.alwaysRequireApproval = alwaysRequireApproval
    }

    public var isValid: Bool { (1...Self.maxCalls).contains(callLimit) }

    public var request: AdminRequest {
        var request = AdminRequest(operation: .grant)
        request.clientID = clientID
        request.accountID = accountID
        request.duration = duration.rawValue
        request.callLimit = callLimit
        request.requiresApproval = alwaysRequireApproval
        return request
    }
}

/// Plain-language summaries shown by the system prompt and the confirmation UI.
public enum AdminSummary {
    public static func short(_ id: UUID) -> String { String(id.uuidString.prefix(8)).lowercased() }

    public static func text(for request: AdminRequest) -> String {
        switch request.operation {
        case .enroll: "Add a \(request.service?.displayName ?? "service") account"
        case .rotate: "Replace the credential for account \(request.accountID.map(short) ?? "?")"
        case .deleteAccount: "Delete account \(request.accountID.map(short) ?? "?") and its credential"
        case .pairClient: "Pair the client running as user ID \(request.uid.map(String.init) ?? "?")"
        case .grant:
            "Let client \(request.clientID.map(short) ?? "?") use account \(request.accountID.map(short) ?? "?") "
                + "for \(request.callLimit ?? 0) calls" + (request.requiresApproval == true ? ", each needing approval" : "")
        case .revokeGrant: "Revoke grant \(request.grantID.map(short) ?? "?")"
        case .revokeClient: "Revoke client \(request.clientID.map(short) ?? "?")"
        case .approveInvocation: "Approve request \(request.requestID.map(short) ?? "?")"
        case .rejectInvocation: "Reject request \(request.requestID.map(short) ?? "?")"
        case .recover: "Recover broker state"
        case .prune: "Prune expired broker records"
        }
    }
}

/// Capabilities this build exposes. Browser-backed services need a GUI host process that the
/// production broker does not have (see docs/BROWSER-DEPLOYMENT.md), so they stay off until a
/// reviewed isolated host exists.
public struct AppFeatures: Sendable, Equatable {
    public var browserServicesEnabled: Bool
    public init(browserServicesEnabled: Bool = false) { self.browserServicesEnabled = browserServicesEnabled }

    public static let production = AppFeatures()

    public func allows(_ service: WireService) -> Bool { !service.usesPassword || browserServicesEnabled }
    public var enrollableServices: [WireService] { WireService.allCases.filter(allows) }
}

/// What the Requests screen shows. Only a waiting request can be approved or rejected; anything
/// else, including a status this build does not know, is displayed without actions.
public struct PendingItem: Identifiable, Equatable, Sendable {
    public enum State: Sendable, Equatable { case waiting, approved, unknown }
    public let summary: PendingSummary
    public let state: State
    public var id: UUID { summary.id }

    public init(_ summary: PendingSummary) {
        self.summary = summary
        switch summary.status {
        case "waiting": state = .waiting
        case "approved": state = .approved
        default: state = .unknown
        }
    }
}

extension PendingSummary: Equatable {
    public static func == (a: PendingSummary, b: PendingSummary) -> Bool {
        a.id == b.id && a.clientID == b.clientID && a.accountID == b.accountID && a.action == b.action
            && a.expiresAt == b.expiresAt && a.status == b.status
    }
}
