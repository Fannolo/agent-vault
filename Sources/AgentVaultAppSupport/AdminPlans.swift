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

extension HumanStepKind {
    public var displayName: String {
        switch self {
        case .mfa: "two-factor"
        case .captcha: "CAPTCHA"
        }
    }
}

/// Builds the credential bytes for enrollment or rotation and rejects malformed input before it
/// leaves the app. The broker remains the authority; this only avoids sending obvious mistakes.
public enum CredentialInput {
    public static func data(service: WireService, secret: String, username: String = "") -> Data? {
        guard !secret.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return nil }
        let data = service.usesPassword
            ? Data((username.trimmingCharacters(in: .whitespaces) + "\n" + secret).utf8)
            : Data(secret.utf8)
        return CredentialFormat.isValid(data, for: service) ? data : nil
    }
}

public enum GrantDuration: Double, CaseIterable, Identifiable, Sendable {
    case fifteenMinutes = 900, oneHour = 3600, eightHours = 28_800, oneDay = 86_400
    public var id: Double { rawValue }
    public var label: String {
        switch self {
        case .fifteenMinutes: "15 minutes"
        case .oneHour: "1 hour"
        case .eightHours: "8 hours"
        case .oneDay: "24 hours"
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

    public static func text(for request: AdminRequest, snapshot: AdminSnapshot? = nil) -> String {
        func full(_ id: UUID?) -> String { id?.uuidString.lowercased() ?? "?" }
        let account = snapshot?.accounts.first { $0.id == request.accountID }
        let client = snapshot?.clients.first { $0.id == request.clientID }
        let pending = snapshot?.pending.first { $0.id == request.requestID }
        let operationContext = pending.map {
            "Account \($0.accountID.uuidString.lowercased()), action \($0.action.rawValue), client \($0.clientID.uuidString.lowercased()), expires \($0.expiresAt.ISO8601Format()). "
        } ?? ""
        return switch request.operation {
        case .enroll: "Add a \(request.service?.displayName ?? "service") account"
        case .rotate: "Replace the credential for account \(full(request.accountID))"
        case .deleteAccount: "Delete account \(full(request.accountID)) and its credential"
        case .pairClient: "Pair the client running as user ID \(request.uid.map(String.init) ?? "?")"
        case .grant:
            "Let client \(full(request.clientID)) (UID \(client?.uid.description ?? "?")) use account \(full(request.accountID)) "
                + "(\(account?.service.displayName ?? "fixed service")) for \(Int(request.duration ?? 0)) seconds after approval, "
                + "\(request.callLimit ?? 0) calls" + (request.requiresApproval == true ? ", each needing approval" : ", without per-call approval")
        case .revokeGrant: "Revoke grant \(full(request.grantID))"
        case .revokeClient: "Revoke client \(full(request.clientID))"
        case .approveInvocation: operationContext + "Approve request \(full(request.requestID))"
        case .rejectInvocation: operationContext + "Reject request \(full(request.requestID))"
        case .recover: "Recover broker state"
        case .prune: "Prune expired broker records"
        case .openHumanStep:
            "Open the \(request.humanStepKind?.displayName ?? "?") step \(request.stepEpoch.map(String.init) ?? "?") of sign-in "
                + "\(full(request.requestID)) for account \(full(request.accountID)) (\(account?.service.displayName ?? "web account"))"
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
