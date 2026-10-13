#if DEBUG
import AgentVaultContracts
import AgentVaultApproval
import CryptoKit
import Foundation

/// Stand-in broker for tests and the DEBUG preview. It follows the contract: `begin` freezes a
/// request and issues a single-use challenge, `authorize` verifies an ECDSA DER signature with
/// the configured public key, consumes the challenge, then applies the frozen request.
package actor InMemoryBroker: VaultAdminTransport {
    private struct Frozen { let request: AdminRequest; let payload: Data; let expiresAt: Date }

    private let publicKey: P256.Signing.PublicKey
    private let now: @Sendable () -> Date
    private var challenges: [UUID: Frozen] = [:]
    private var accounts: [AccountSummary] = []
    private var clients: [ClientSummary] = []
    private var grants: [GrantSummary] = []
    private var pending: [PendingSummary] = []
    private var events: [AuditSummary] = []
    package private(set) var credentialsReceived: [UUID: Data] = [:]
    package private(set) var appliedOperations: [AdminRequest.Operation] = []
    package private(set) var rejectedAuthorizations = 0
    package var challengeLifetime: TimeInterval = 60

    package init(publicKey: P256.Signing.PublicKey, now: @escaping @Sendable () -> Date = Date.init) {
        self.publicKey = publicKey; self.now = now
    }

    package func seed(accounts: [AccountSummary] = [], clients: [ClientSummary] = [], pending: [PendingSummary] = [],
                      grants: [GrantSummary] = [], audit: [AuditSummary] = []) {
        self.accounts += accounts; self.clients += clients; self.pending += pending
        self.grants += grants; events += audit
    }

    package func snapshot() async throws -> AdminSnapshot {
        AdminSnapshot(accounts: accounts, clients: clients, grants: grants, pending: pending, audit: events)
    }

    package func begin(_ request: AdminRequest) async throws -> AdminChallenge {
        try validate(request)
        var nonce = Data()
        for _ in 0..<4 { nonce.append(contentsOf: withUnsafeBytes(of: UInt64.random(in: .min ... .max)) { Array($0) }) }
        let id = UUID()
        let expiry = now().addingTimeInterval(challengeLifetime)
        let payload = try ApprovalIntent.payload(request: request, id: id, nonce: nonce, expiresAt: expiry)
        challenges[id] = Frozen(request: request, payload: payload, expiresAt: expiry)
        return AdminChallenge(id: id, payload: payload, expiresAt: expiry, nonce: nonce)
    }

    package func authorize(challengeID: UUID, signature: Data) async throws -> AdminReply {
        // Single use: consumed whether or not verification succeeds.
        guard let frozen = challenges.removeValue(forKey: challengeID), frozen.expiresAt > now() else {
            rejectedAuthorizations += 1
            return AdminReply(status: "challenge_invalid")
        }
        guard let der = try? P256.Signing.ECDSASignature(derRepresentation: signature),
              publicKey.isValidSignature(der, for: frozen.payload) else {
            rejectedAuthorizations += 1
            return AdminReply(status: "signature_invalid")
        }
        let id = apply(frozen.request)
        appliedOperations.append(frozen.request.operation)
        return AdminReply(status: "ok", id: id)
    }

    private func validate(_ r: AdminRequest) throws {
        func need(_ ok: Bool) throws { if !ok { throw AdminTransportError.rejected("invalid_input") } }
        switch r.operation {
        case .enroll: try need(r.service != nil && !(r.credential ?? Data()).isEmpty)
        case .rotate: try need(accounts.contains { $0.id == r.accountID } && !(r.credential ?? Data()).isEmpty)
        case .deleteAccount: try need(accounts.contains { $0.id == r.accountID })
        case .pairClient: try need(r.uid != nil)
        case .grant:
            try need(clients.contains { $0.id == r.clientID && !$0.revoked } && accounts.contains { $0.id == r.accountID }
                     && (r.duration ?? 0) > 0 && (r.callLimit ?? 0) > 0 && r.requiresApproval != nil)
        case .revokeGrant: try need(grants.contains { $0.id == r.grantID })
        case .revokeClient: try need(clients.contains { $0.id == r.clientID })
        case .approveInvocation, .rejectInvocation: try need(pending.contains { $0.id == r.requestID && $0.status == "waiting" })
        case .recover, .prune: break
        }
    }

    private func apply(_ r: AdminRequest) -> UUID? {
        switch r.operation {
        case .enroll:
            let account = AccountSummary(id: UUID(), service: r.service!)
            accounts.append(account); credentialsReceived[account.id] = r.credential
            return account.id
        case .rotate: credentialsReceived[r.accountID!] = r.credential
        case .deleteAccount:
            accounts.removeAll { $0.id == r.accountID }
            grants.removeAll { $0.accountID == r.accountID }
            credentialsReceived[r.accountID!] = nil
        case .pairClient:
            let client = ClientSummary(id: UUID(), uid: r.uid!, revoked: false)
            clients.append(client)
            return client.id
        case .grant:
            let grant = GrantSummary(id: UUID(), clientID: r.clientID!, accountID: r.accountID!,
                                     expiresAt: now().addingTimeInterval(r.duration!), callsRemaining: r.callLimit!,
                                     requiresApproval: r.requiresApproval!, revoked: false)
            grants.append(grant)
            return grant.id
        case .revokeGrant:
            grants = grants.map { $0.id == r.grantID ? mark($0) : $0 }
        case .revokeClient:
            clients = clients.map { $0.id == r.clientID ? ClientSummary(id: $0.id, uid: $0.uid, revoked: true) : $0 }
            grants = grants.map { $0.clientID == r.clientID ? mark($0) : $0 }
        case .approveInvocation:
            pending = pending.map { $0.id == r.requestID ? PendingSummary(id: $0.id, clientID: $0.clientID, accountID: $0.accountID,
                                                                         action: $0.action, expiresAt: $0.expiresAt, status: "approved") : $0 }
        case .rejectInvocation:
            pending.removeAll { $0.id == r.requestID }
        case .recover, .prune: break
        }
        return nil
    }

    private func mark(_ g: GrantSummary) -> GrantSummary {
        GrantSummary(id: g.id, clientID: g.clientID, accountID: g.accountID, expiresAt: g.expiresAt,
                     callsRemaining: g.callsRemaining, requiresApproval: g.requiresApproval, revoked: true)
    }
}
#endif
