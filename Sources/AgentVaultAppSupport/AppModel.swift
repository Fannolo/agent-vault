import AgentVaultContracts
import Foundation
import Observation

public struct Notice: Equatable, Sendable, Identifiable {
    public enum Kind: Sendable { case success, failure }
    public let id = UUID()
    public let kind: Kind
    public let text: String
}

public enum AuditStatus: Equatable, Sendable { case notLoaded, loaded, unavailable }

public enum AppSheet: String, Identifiable, Sendable { case enroll, pair, grant; public var id: String { rawValue } }

public enum AppSection: String, CaseIterable, Identifiable, Sendable {
    case accounts, clients, grants, requests, audit, approvalKey
    public var id: String { rawValue }
}

/// State and actions behind every screen. All mutations go through `AdminAuthorizationService`,
/// so each one needs a broker challenge and a user-presence-protected signature.
@MainActor @Observable
public final class AppModel {
    public private(set) var snapshot: AdminSnapshot?
    public private(set) var audit: [AuditEntry] = []
    public private(set) var auditStatus = AuditStatus.notLoaded
    public private(set) var registration: ApprovalKeyRegistration?
    public private(set) var keyProblem: String?
    public private(set) var brokerReachable: Bool?
    public private(set) var isBusy = false
    public var notice: Notice?
    public var selection = AppSection.accounts
    public var sheet: AppSheet?
    /// Identifier of the client created by the last pairing, for the pairing sheet.
    public private(set) var lastPairedClientID: UUID?

    public let features: AppFeatures
    private let transport: VaultAdminTransport
    private let signer: ApprovalSigning
    private let service: AdminAuthorizationService

    public init(transport: VaultAdminTransport, signer: ApprovalSigning, features: AppFeatures = .production,
                now: @escaping @Sendable () -> Date = Date.init) {
        self.transport = transport
        self.signer = signer
        self.features = features
        service = AdminAuthorizationService(transport: transport, signer: signer, now: now)
    }

    public var pendingItems: [PendingItem] { (snapshot?.pending ?? []).map(PendingItem.init) }

    // MARK: Reads

    /// Reads the broker snapshot. The audit tail arrives in the same reply.
    public func refresh() async {
        do {
            let next = try await transport.snapshot()
            snapshot = next
            audit = next.audit.map(AuditEntry.init).sorted { $0.timestamp > $1.timestamp }
            auditStatus = .loaded
            brokerReachable = true
        } catch {
            brokerReachable = false
            snapshot = nil
            audit = []
            auditStatus = .unavailable
        }
    }

    public func refreshAudit() async { await refresh() }

    public func loadApprovalKey() async {
        do {
            registration = try await signer.registration()
            keyProblem = nil
        } catch let error as ApprovalSigningError {
            registration = nil
            keyProblem = Self.describe(error)
        } catch {
            registration = nil
            keyProblem = "The approval key is unavailable."
        }
    }

    // MARK: Admin operations (each needs challenge + signature)

    @discardableResult
    public func enroll(service: WireService, secret: String, username: String = "") async -> Bool {
        guard features.allows(service) else {
            notice = Notice(kind: .failure, text: "\(service.displayName) accounts are disabled in this build.")
            return false
        }
        guard let data = CredentialInput.data(service: service, secret: secret, username: username) else {
            notice = Notice(kind: .failure, text: "The credential is empty or malformed.")
            return false
        }
        var request = AdminRequest(operation: .enroll)
        request.service = service
        request.credential = data
        return await run(request, success: "Account added.")
    }

    @discardableResult
    public func rotate(account: AccountSummary, secret: String, username: String = "") async -> Bool {
        guard let data = CredentialInput.data(service: account.service, secret: secret, username: username) else {
            notice = Notice(kind: .failure, text: "The credential is empty or malformed.")
            return false
        }
        var request = AdminRequest(operation: .rotate)
        request.accountID = account.id
        request.credential = data
        return await run(request, success: "Credential replaced.")
    }

    @discardableResult
    public func delete(account: AccountSummary) async -> Bool {
        var request = AdminRequest(operation: .deleteAccount)
        request.accountID = account.id
        return await run(request, success: "Account deleted.")
    }

    @discardableResult
    public func pair(uid: UInt32) async -> Bool {
        var request = AdminRequest(operation: .pairClient)
        request.uid = uid
        return await run(request, success: "Client paired.") { [self] outcome in lastPairedClientID = outcome.id }
    }

    @discardableResult
    public func grant(_ plan: GrantPlan) async -> Bool {
        guard plan.isValid else {
            notice = Notice(kind: .failure, text: "Choose between 1 and \(GrantPlan.maxCalls) calls.")
            return false
        }
        return await run(plan.request, success: "Grant created.")
    }

    @discardableResult
    public func revoke(grant: GrantSummary) async -> Bool {
        var request = AdminRequest(operation: .revokeGrant)
        request.grantID = grant.id
        return await run(request, success: "Grant revoked.")
    }

    @discardableResult
    public func revoke(client: ClientSummary) async -> Bool {
        var request = AdminRequest(operation: .revokeClient)
        request.clientID = client.id
        return await run(request, success: "Client revoked.")
    }

    @discardableResult
    public func approve(_ pending: PendingSummary) async -> Bool {
        guard PendingItem(pending).state == .waiting else {
            notice = Notice(kind: .failure, text: "Only a waiting request can be approved.")
            return false
        }
        var request = AdminRequest(operation: .approveInvocation)
        request.requestID = pending.id
        return await run(request, success: "Request approved.")
    }

    @discardableResult
    public func reject(_ pending: PendingSummary) async -> Bool {
        guard PendingItem(pending).state == .waiting else {
            notice = Notice(kind: .failure, text: "Only a waiting request can be rejected.")
            return false
        }
        var request = AdminRequest(operation: .rejectInvocation)
        request.requestID = pending.id
        return await run(request, success: "Request rejected.")
    }

    public func exportAudit(to url: URL) {
        do {
            try AuditExport.write(audit, to: url)
            notice = Notice(kind: .success, text: "Exported \(audit.count) audit entries.")
        } catch {
            notice = Notice(kind: .failure, text: "The audit export could not be written.")
        }
    }

    // MARK: Plumbing

    private func run(_ request: AdminRequest, success: String,
                     onSuccess: ((AdminOutcome) -> Void)? = nil) async -> Bool {
        guard !isBusy else { return false }
        isBusy = true
        defer { isBusy = false }
        do {
            let outcome = try await service.perform(request, summary: AdminSummary.text(for: request, snapshot: snapshot))
            onSuccess?(outcome)
            notice = Notice(kind: .success, text: success)
            await refresh()
            return true
        } catch let failure as AdminFailure {
            notice = Notice(kind: .failure, text: Self.describe(failure))
            return false
        } catch {
            notice = Notice(kind: .failure, text: "The operation could not be confirmed. Refresh the broker state before retrying.")
            return false
        }
    }

    static func describe(_ failure: AdminFailure) -> String {
        switch failure {
        case .transport(.unavailable): "The broker could not confirm the operation. Refresh its state before retrying."
        case .transport(.unsupported): "This broker does not support that operation."
        case .transport(.rejected(let code)): "The broker refused the request (\(code))."
        case .challengeExpired: "The approval request expired. Try again."
        case .intentMismatch: "The approval challenge did not match this operation. Nothing was approved."
        case .signing(let error): describe(error)
        case .rejected(let code): "The broker reported a failure (\(code)). Refresh its state before retrying."
        }
    }

    static func describe(_ error: ApprovalSigningError) -> String {
        switch error {
        case .unsupported: "Touch ID or a device password is required to approve changes, and none is available."
        case .userCancelled: "Approval cancelled. Nothing was changed."
        case .authenticationFailed: "Authentication failed. Nothing was changed."
        case .keyCreationFailed(let status):
            "This build cannot create a protected approval key (Keychain status \(status)). Use a build signed with Keychain access."
        case .keyUnavailable: "The approval key is missing. Create it in Approval Key first."
        case .keyLookupFailed(let status):
            "The approval key could not be read (Keychain status \(status)). Unlock your Mac and try again; no new key was created."
        case .keyNotProtected: "The stored approval key does not have the required protection and was not used."
        case .invalidPayload, .signingFailed: "The approval could not be signed. Nothing was changed."
        }
    }
}
