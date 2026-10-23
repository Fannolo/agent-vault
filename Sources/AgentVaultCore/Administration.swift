import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import AgentVaultContracts
import AgentVaultApproval

/// The transport must authorize the human-app peer before exposing this object.
public actor Administration {
    private struct Frozen {
        let request: AdminRequest
        let payload: Data
        let expiresAt: Date
        /// The connection that asked; a human-step open is authorized only on that same connection.
        let connection: ContinuationConnectionID?
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
        let state = try await broker.snapshot(), timestamp = now()
        let accounts: [AccountSummary] = state.accounts.map {
            .init(id: $0.id, service: $0.service.wire, status: $0.lifecycle.rawValue)
        }
        let clients: [ClientSummary] = state.clients.map { .init(id: $0.id, uid: $0.uid ?? 0, revoked: $0.revoked) }
        let grants: [GrantSummary] = state.grants.map {
            .init(id: $0.id, clientID: $0.clientID, accountID: $0.accountID, expiresAt: $0.expiresAt,
                  callsRemaining: max(0, $0.callLimit - $0.callsUsed), requiresApproval: $0.requiresApproval, revoked: $0.revoked)
        }
        let pending: [PendingSummary] = state.pending.filter { [.waiting, .approved].contains($0.status) && $0.expiresAt > timestamp }.map {
            .init(id: $0.id.uuid, clientID: $0.clientID, accountID: $0.accountID,
                  action: WireAction(rawValue: $0.action.rawValue)!, expiresAt: $0.expiresAt, status: $0.status.rawValue)
        }
        let audit: [AuditSummary] = (state.audit + state.adminAudit).sorted { $0.timestamp < $1.timestamp }.map {
            .init(timestamp: $0.timestamp, clientID: $0.clientID, accountID: $0.accountID,
                  action: $0.action.flatMap { WireAction(rawValue: $0.rawValue) }, outcome: $0.outcome)
        }
        let services = Dictionary(state.accounts.map { ($0.id, $0.service.wire) }, uniquingKeysWith: { first, _ in first })
        let steps: [HumanStepSummary] = try await broker.pendingHumanSteps().compactMap { step in
            guard let service = services[step.account] else { return nil }
            return .init(runID: step.id.run.uuid, epoch: step.id.epoch, kind: step.kind, accountID: step.account,
                         service: service, expiresAt: step.expiresAt)
        }
        return .init(accounts: accounts, clients: clients, grants: grants, pending: pending, audit: audit, humanSteps: steps)
    }

    /// `connection` is the transport-minted identity of the asking connection. An open must name a
    /// step that exists now, exactly as the snapshot showed it.
    public func begin(_ request: AdminRequest, connection: ContinuationConnectionID? = nil) async throws -> AdminChallenge {
        try validate(request)
        if request.operation == .openHumanStep {
            guard connection != nil, try await broker.pendingHumanSteps().contains(where: { request.names($0) })
            else { throw VaultError.denied }
        }
        let timestamp = now()
        frozen = frozen.filter { $0.value.expiresAt > timestamp }
        guard frozen.count < 32 else { throw VaultError.busy }
        let id = UUID(), nonce = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })
        let expiresAt = timestamp.addingTimeInterval(60)
        let payload = try ApprovalIntent.payload(request: request, id: id, nonce: nonce, expiresAt: expiresAt)
        frozen[id] = Frozen(request: request, payload: payload, expiresAt: expiresAt, connection: connection)
        Task { [weak self] in
            try? await Task.sleep(for: .seconds(60))
            await self?.expire(id)
        }
        return .init(id: id, payload: payload, expiresAt: expiresAt, nonce: nonce)
    }

    private func expire(_ id: UUID) {
        if let value = frozen[id], value.expiresAt <= now() { frozen.removeValue(forKey: id) }
    }

    public func authorize(_ id: UUID, signature: Data, connection: ContinuationConnectionID? = nil) async throws -> AdminReply {
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
            try await broker.approveInvocation(ApprovalID(request.requestID!)); resultID = request.requestID
        case .rejectInvocation:
            try await broker.rejectInvocation(ApprovalID(request.requestID!)); resultID = request.requestID
        case .recover:
            try await broker.recoverInterruptedLifecycle(); resultID = nil
        case .prune:
            try await broker.prune(); resultID = nil
        case .openHumanStep:
            // The broker accepts only the exact step that was signed, on the connection that began it.
            guard let connection, connection == invocation.connection else { throw VaultError.denied }
            let step = HumanStepID(run: BrowserRunID(request.requestID!), epoch: request.stepEpoch!)
            guard try await broker.pendingHumanSteps().contains(where: { request.names($0) }) else { throw VaultError.denied }
            resultID = try await broker.openHumanStep(step, connection: connection).uuid
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
        case .openHumanStep: required = ["requestID", "accountID", "stepEpoch", "humanStepKind"]
        }
        guard keys == required else { throw VaultError.invalidInput }
        if let service = request.service {
            guard let service = Service(rawValue: service.rawValue), allowedServices.contains(service) else { throw VaultError.invalidInput }
        }
        if let credential = request.credential {
            guard !credential.isEmpty, credential.count <= CredentialFormat.transportMaximum else { throw VaultError.invalidInput }
            // Early rejection before a person is asked to sign; the broker enforces it again.
            if let service = request.service, !CredentialFormat.isValid(credential, for: service) { throw VaultError.invalidInput }
        }
        if let uid = request.uid { guard uid != 0, allowedClientUID == nil || uid == allowedClientUID else { throw VaultError.invalidInput } }
        if let duration = request.duration { guard duration > 0, duration <= 86_400, duration.isFinite else { throw VaultError.invalidInput } }
        if let calls = request.callLimit { guard (1...10_000).contains(calls) else { throw VaultError.invalidInput } }
        if let epoch = request.stepEpoch { guard (1...HumanFrame.maximumSequence).contains(epoch) else { throw VaultError.invalidInput } }
    }
}

private extension AdminRequest {
    func names(_ step: PendingHumanStep) -> Bool {
        requestID == step.id.run.uuid && stepEpoch == step.id.epoch && humanStepKind == step.kind && accountID == step.account
    }
}

/// Frame, input and conclusion calls from the authenticated human app. `connection` must be the
/// identity the transport minted for the connection carrying the call.
public struct ContinuationOperations: Sendable {
    private let broker: Broker
    public init(broker: Broker) { self.broker = broker }

    public func perform(_ request: ContinuationRequest, connection: ContinuationConnectionID) async -> ContinuationReply {
        let lease = ContinuationLeaseID(request.lease)
        do {
            switch request.operation {
            case .frame(let after):
                return try await broker.humanFrame(lease, connection: connection, after: after).map(ContinuationReply.frame) ?? .noFrame
            case .input(let batch, let frame, let events):
                return try await broker.humanInput(lease, connection: connection, batch: batch, frame: frame, events)
                    ? .delivered : .notDelivered
            case .finish, .cancel:
                let decision: HumanStepDecision = request.operation == .finish ? .finished : .cancel
                switch try await broker.concludeHumanStep(lease, connection: connection, decision: decision) {
                case .concluded: return .concluded
                case .humanStepRequired(let kind): return .nextStep(kind)
                }
            case .close:
                try await broker.closeHumanLease(lease, connection: connection)
                return .closed
            }
        } catch let error as VaultError {
            switch error {
            case .busy: return .failure(.busy)
            case .invalidInput: return .failure(.invalidInput)
            case .upstreamUnavailable: return .failure(.upstreamUnavailable)
            default: return .failure(.accessDenied)
            }
        } catch {
            return .failure(.accessDenied)
        }
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
            return .init(.outcome(.completed), accounts: accounts.map { .init(id: $0.id, service: $0.service.wire) })
        case .run:
            guard let account = request.accountID, let action = request.action, request.requestID == nil,
                  let coreAction = Action(rawValue: action.rawValue) else { throw VaultError.invalidInput }
            return reply(try await broker.run(clientID: client, accountID: account, action: coreAction))
        case .resume:
            guard let id = request.requestID, request.accountID == nil, request.action == nil else { throw VaultError.invalidInput }
            return reply(try await broker.resume(id, clientID: client))
        case .cancel:
            guard let id = request.requestID, request.accountID == nil, request.action == nil else { throw VaultError.invalidInput }
            try await broker.cancel(id, clientID: client)
            return .init(.outcome(.cancelled), requestID: id)
        }
    }
    private func reply(_ result: OperationResult) -> ReadReply {
        switch result {
        case .demoReady: .init(.outcome(.ready))
        case .profile(let profile): .init(.outcome(.completed), profile: profile)
        case .approvalRequired(let id): .init(.outcome(.approvalRequired), requestID: id.uuid)
        case .humanStepRequired(let id): .init(.outcome(.humanStepRequired), requestID: id.uuid)
        }
    }
}
