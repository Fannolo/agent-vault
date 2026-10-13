import Foundation
import CryptoKit
import AgentVaultContracts

/// The transport must authorize the human-app peer before exposing this object.
public actor Administration {
    private struct Frozen {
        let request: AdminRequest
        let payload: Data
        let expiresAt: Date
    }
    private let broker: Broker
    private let publicKey: P256.Signing.PublicKey
    private let now: @Sendable () -> Date
    private let allowedServices: [Service]
    private let allowedClientUID: UInt32?
    private var frozen: [UUID: Frozen] = [:]

    public init(broker: Broker, publicKey: Data,
                allowedServices: [Service] = [.demo, .github, .browserDemo, .githubWeb],
                allowedClientUID: UInt32? = nil,
                now: @escaping @Sendable () -> Date = { Date() }) throws {
        self.broker = broker; self.now = now
        self.allowedServices = allowedServices; self.allowedClientUID = allowedClientUID
        do { self.publicKey = try P256.Signing.PublicKey(x963Representation: publicKey) }
        catch { throw VaultError.invalidInput }
    }

    public func snapshot() async throws -> AdminSnapshot {
        let state = try await broker.snapshot()
        return .init(accounts: state.accounts.map {
            .init(id: $0.id, service: WireService(rawValue: $0.service.rawValue)!, status: $0.lifecycle.rawValue)
        }, clients: state.clients.map { .init(id: $0.id, uid: $0.uid ?? 0, revoked: $0.revoked) },
        grants: state.grants.map {
            .init(id: $0.id, clientID: $0.clientID, accountID: $0.accountID, expiresAt: $0.expiresAt,
                  callsRemaining: max(0, $0.callLimit - $0.callsUsed), requiresApproval: $0.requiresApproval, revoked: $0.revoked)
        }, pending: state.pending.filter { [.waiting, .approved].contains($0.status) && $0.expiresAt > now() }.map {
            .init(id: $0.id, clientID: $0.clientID, accountID: $0.accountID,
                  action: WireAction(rawValue: $0.action.rawValue)!, expiresAt: $0.expiresAt, status: $0.status.rawValue)
        }, audit: state.audit.map {
            .init(timestamp: $0.timestamp, clientID: $0.clientID, accountID: $0.accountID,
                  action: $0.action.flatMap { WireAction(rawValue: $0.rawValue) }, outcome: $0.outcome)
        })
    }

    public func begin(_ request: AdminRequest) throws -> AdminChallenge {
        try validate(request)
        let timestamp = now()
        frozen = frozen.filter { $0.value.expiresAt > timestamp }
        guard frozen.count < 32 else { throw VaultError.busy }
        let id = UUID(), payload = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })
        let expiresAt = timestamp.addingTimeInterval(60)
        frozen[id] = Frozen(request: request, payload: payload, expiresAt: expiresAt)
        return .init(id: id, payload: payload, expiresAt: expiresAt)
    }

    public func authorize(_ id: UUID, signature: Data) async throws -> AdminReply {
        guard let invocation = frozen[id], invocation.expiresAt > now(), signature.count <= 80 else { throw VaultError.denied }
        guard let signature = try? P256.Signing.ECDSASignature(derRepresentation: signature),
              publicKey.isValidSignature(signature, for: invocation.payload) else { throw VaultError.denied }
        // Consume before awaiting mutation; replay never re-enters a mutation.
        frozen.removeValue(forKey: id)
        let request = invocation.request
        let resultID: UUID?
        switch request.operation {
        case .enroll:
            resultID = try await broker.enroll(service: Service(rawValue: request.service!.rawValue)!, credential: request.credential!).id
        case .rotate:
            try await broker.rotate(accountID: request.accountID!, credential: request.credential!); resultID = request.accountID
        case .deleteAccount:
            try await broker.deleteAccount(request.accountID!); resultID = request.accountID
        case .pairClient:
            resultID = try await broker.registerClient(uid: request.uid!).id
        case .grant:
            resultID = try await broker.grant(clientID: request.clientID!, accountID: request.accountID!,
                duration: request.duration!, callLimit: request.callLimit!, requiresApproval: request.requiresApproval!).id
        case .revokeGrant:
            try await broker.revokeGrant(request.grantID!); resultID = request.grantID
        case .revokeClient:
            try await broker.revokeClient(request.clientID!); resultID = request.clientID
        case .approveInvocation:
            try await broker.approveInvocation(request.requestID!); resultID = request.requestID
        case .rejectInvocation:
            try await broker.rejectInvocation(request.requestID!); resultID = request.requestID
        case .recover:
            try await broker.recoverInterruptedLifecycle(); resultID = nil
        case .prune:
            try await broker.prune(); resultID = nil
        }
        return .init(status: "completed", id: resultID)
    }

    private func validate(_ request: AdminRequest) throws {
        let data = try JSONEncoder().encode(request)
        guard data.count <= 16_384 else { throw VaultError.invalidInput }
        var keys = Set((try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]).keys)
        keys.remove("operation")
        let required: Set<String>
        switch request.operation {
        case .enroll: required = ["service", "credential"]
        case .rotate: required = ["accountID", "credential"]
        case .deleteAccount: required = ["accountID"]
        case .pairClient: required = ["uid"]
        case .grant: required = ["clientID", "accountID", "duration", "callLimit", "requiresApproval"]
        case .revokeGrant: required = ["grantID"]
        case .revokeClient: required = ["clientID"]
        case .approveInvocation, .rejectInvocation: required = ["requestID"]
        case .recover, .prune: required = []
        }
        guard keys == required else { throw VaultError.invalidInput }
        if let service = request.service {
            guard let service = Service(rawValue: service.rawValue), allowedServices.contains(service) else { throw VaultError.invalidInput }
        }
        if let credential = request.credential { guard !credential.isEmpty, credential.count <= 8192 else { throw VaultError.invalidInput } }
        if let uid = request.uid { guard uid != 0, allowedClientUID == nil || uid == allowedClientUID else { throw VaultError.invalidInput } }
        if let duration = request.duration { guard duration > 0, duration <= 86_400, duration.isFinite else { throw VaultError.invalidInput } }
        if let calls = request.callLimit { guard (1...10_000).contains(calls) else { throw VaultError.invalidInput } }
    }
}

public struct ReadOperations: Sendable {
    private let broker: Broker
    public init(broker: Broker) { self.broker = broker }
    public func perform(uid: UInt32, request: ReadRequest) async throws -> ReadReply {
        let client = try await broker.clientID(for: uid)
        switch request.operation {
        case .accounts:
            guard request.accountID == nil, request.action == nil, request.requestID == nil else { throw VaultError.invalidInput }
            let accounts = try await broker.availableAccounts(clientID: client)
            return .init(status: "completed", accounts: accounts.map {
                .init(id: $0.id, service: WireService(rawValue: $0.service.rawValue)!)
            })
        case .run:
            guard let account = request.accountID, let action = request.action, request.requestID == nil,
                  let coreAction = Action(rawValue: action.rawValue) else { throw VaultError.invalidInput }
            return reply(try await broker.run(clientID: client, accountID: account, action: coreAction))
        case .resume:
            guard let id = request.requestID, request.accountID == nil, request.action == nil else { throw VaultError.invalidInput }
            return reply(try await broker.resume(id, clientID: client))
        case .cancel:
            guard let id = request.requestID, request.accountID == nil, request.action == nil else { throw VaultError.invalidInput }
            try await broker.cancelInvocation(id, clientID: client)
            return .init(status: "cancelled", requestID: id)
        }
    }
    private func reply(_ result: OperationResult) -> ReadReply {
        switch result {
        case .demoReady: .init(status: "ready")
        case .githubProfile(let profile): .init(status: "completed", login: profile.login, userID: profile.id)
        case .approvalRequired(let id): .init(status: "approval_required", requestID: id)
        case .humanStepRequired(let id): .init(status: "human_step_required", requestID: id)
        }
    }
}
