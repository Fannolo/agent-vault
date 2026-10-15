import Foundation

public actor Broker {
    private let state: any StateStore
    private let secretIO: SecretIOExecutor
    private let adapter: any ServiceAdapter
    private let now: @Sendable () -> Date
    private var lifecycleMutations: Set<UUID> = []
    private var recoveryInProgress = false

    public init(state: any StateStore, secrets: any SecretStore,
                adapter: any ServiceAdapter = FixedServiceAdapter(),
                now: @escaping @Sendable () -> Date = { Date() },
                secretIOPolicy: SecretIOPolicy = .standard) {
        self.state = state; self.secretIO = SecretIOExecutor(store: secrets, policy: secretIOPolicy)
        self.adapter = adapter; self.now = now
    }

    public func enroll(service: Service, credential: Data) async throws -> Account {
        guard !credential.isEmpty, credential.count <= 8192 else { throw VaultError.invalidInput }
        if service == .github { try GitHubAdapter.validateCredential(credential) }
        var account = Account(service: service, lifecycle: .enrolling)
        try beginLifecycle(account.id)
        defer { lifecycleMutations.remove(account.id) }
        try state.transaction {
            guard $0.accounts.count < VaultState.maxAccounts else { throw VaultError.stateUnavailable }
            $0.accounts.append(account)
            $0.recordAdministration(account: account.id, action: service.action, outcome: "enrollment_started", at: now())
        }
        // Persist intent before Keychain mutation so a crash never loses the item ID.
        do { try await secretIO.save(credential, id: account.credentialID, account: account.id) }
        catch {
            let failure = secretFailure(error)
            recordLifecycleFailure(account: account.id, action: service.action, operation: "enrollment", failure: failure)
            if !failure.isUncertain {
                do {
                    if failure.operationStarted {
                        try await secretIO.delete(id: account.credentialID, account: account.id)
                    }
                    try removeAccountRecord(account.id, outcome: "enrollment_aborted")
                } catch {
                    recordLifecycleFailure(account: account.id, action: service.action,
                                           operation: "enrollment_compensation", failure: secretFailure(error))
                }
            }
            throw failure.publicError
        }
        account.lifecycle = .active
        try state.transaction {
            guard let index = $0.accounts.firstIndex(where: { $0.id == account.id && $0.lifecycle == .enrolling })
            else { throw VaultError.stateUnavailable }
            $0.accounts[index] = account
            $0.recordAdministration(account: account.id, action: service.action, outcome: "enrollment_completed", at: now())
        }
        return account
    }

    public func registerClient(uid: UInt32? = nil) throws -> ClientRecord {
        try state.transaction { state in
            if let uid, let existing = state.clients.first(where: { $0.uid == uid && !$0.revoked }) {
                state.recordAdministration(client: existing.id, outcome: "client_pair_reused", at: now())
                return existing
            }
            guard state.clients.count < VaultState.maxClients else { throw VaultError.stateUnavailable }
            let client = ClientRecord(uid: uid)
            state.clients.append(client)
            state.recordAdministration(client: client.id, outcome: "client_paired", at: now())
            return client
        }
    }

    public func grant(clientID: UUID, accountID: UUID, duration: TimeInterval,
                      callLimit: Int, requiresApproval: Bool = false) throws -> Grant {
        guard duration > 0, duration <= 86_400, duration.isFinite,
              callLimit > 0, callLimit <= 10_000 else { throw VaultError.invalidInput }
        return try state.transaction { state in
            let timestamp = now()
            guard state.grants.count < VaultState.maxGrants else { throw VaultError.stateUnavailable }
            guard state.clients.contains(where: { $0.id == clientID && !$0.revoked }),
                  let account = state.accounts.first(where: { $0.id == accountID && $0.lifecycle == .active }) else {
                throw VaultError.denied
            }
            let grant = Grant(clientID: clientID, accountID: accountID, action: account.service.action,
                              expiresAt: timestamp.addingTimeInterval(duration), callLimit: callLimit,
                              requiresApproval: requiresApproval)
            state.grants.append(grant)
            state.recordAdministration(client: clientID, account: accountID, action: grant.action,
                         outcome: "grant_created", at: timestamp)
            return grant
        }
    }

    public func revokeGrant(_ id: UUID) async throws {
        try state.transaction { state in
            let timestamp = now()
            guard let index = state.grants.firstIndex(where: { $0.id == id }) else {
                throw VaultError.invalidInput
            }
            state.grants[index].revoked = true
            for i in state.pending.indices where state.pending[i].grantID == id { state.pending[i].status = .cancelled }
            let grant = state.grants[index]
            state.recordAdministration(client: grant.clientID, account: grant.accountID, action: grant.action,
                         outcome: "grant_revoked", at: timestamp)
        }
        await (adapter as? any SessionServiceAdapter)?.invalidate(sessionID: id)
    }

    public func revokeClient(_ id: UUID) async throws {
        let sessions = try state.transaction { state in
            let timestamp = now()
            guard let index = state.clients.firstIndex(where: { $0.id == id }) else {
                throw VaultError.invalidInput
            }
            state.clients[index].revoked = true
            for i in state.grants.indices where state.grants[i].clientID == id {
                state.grants[i].revoked = true
            }
            for i in state.pending.indices where state.pending[i].clientID == id { state.pending[i].status = .cancelled }
            state.recordAdministration(client: id, outcome: "client_revoked", at: timestamp)
            return state.grants.filter { $0.clientID == id }.map(\.id)
        }
        for session in sessions { await (adapter as? any SessionServiceAdapter)?.invalidate(sessionID: session) }
    }

    public func availableAccounts(clientID: UUID) throws -> [Account] {
        let snapshot = try state.snapshot()
        let timestamp = now()
        guard snapshot.clients.contains(where: { $0.id == clientID && !$0.revoked }) else { return [] }
        return snapshot.accounts.filter { account in
            guard account.lifecycle == .active else { return false }
            return snapshot.grants.contains { grant in
                Self.permits(grant, client: clientID, account: account.id,
                             action: account.service.action, at: timestamp)
            }
        }
    }

    public func run(clientID: UUID, accountID: UUID, action: Action) async throws -> OperationResult {
        let pending: UUID? = try state.transaction { state in
            let timestamp = now()
            guard state.clients.contains(where: { $0.id == clientID && !$0.revoked }),
                  state.accounts.contains(where: { $0.id == accountID && $0.lifecycle == .active && $0.service.action == action }),
                  let grant = state.grants.first(where: { Self.permits($0, client: clientID, account: accountID, action: action, at: timestamp) }),
                  grant.requiresApproval else { return nil }
            if let existing = state.pending.first(where: {
                $0.clientID == clientID && $0.accountID == accountID && $0.action == action &&
                $0.grantID == grant.id && $0.expiresAt > timestamp && [.waiting, .approved].contains($0.status)
            }) { return existing.id }
            state.pending.removeAll { $0.expiresAt <= timestamp || [.cancelled, .consumed].contains($0.status) }
            guard state.pending.count < 128 else { throw VaultError.busy }
            let invocation = PendingInvocation(id: UUID(), clientID: clientID, accountID: accountID,
                action: action, grantID: grant.id, expiresAt: min(grant.expiresAt, timestamp.addingTimeInterval(120)), status: .waiting)
            state.pending.append(invocation)
            state.record(client: clientID, account: accountID, action: action, outcome: "approval_requested", at: timestamp)
            return invocation.id
        }
        if let pending { return .approvalRequired(pending) }
        return try await execute(clientID: clientID, accountID: accountID, action: action, approvedRequest: nil)
    }

    public func approveInvocation(_ id: UUID) throws {
        try state.transaction { state in
            let timestamp = now()
            guard let index = state.pending.firstIndex(where: { $0.id == id && $0.status == .waiting && $0.expiresAt > timestamp }),
                  let grant = state.grants.first(where: { $0.id == state.pending[index].grantID }),
                  Self.permits(grant, client: state.pending[index].clientID, account: state.pending[index].accountID,
                               action: state.pending[index].action, at: timestamp) else { throw VaultError.denied }
            state.pending[index].status = .approved
            let invocation = state.pending[index]
            state.recordAdministration(client: invocation.clientID, account: invocation.accountID,
                                       action: invocation.action, outcome: "invocation_approved", at: timestamp)
        }
    }

    public func rejectInvocation(_ id: UUID) throws {
        try state.transaction { state in
            guard let index = state.pending.firstIndex(where: {
                $0.id == id && [.waiting, .approved].contains($0.status)
            }) else { throw VaultError.denied }
            state.pending[index].status = .cancelled
            let invocation = state.pending[index]
            state.recordAdministration(client: invocation.clientID, account: invocation.accountID,
                                       action: invocation.action, outcome: "invocation_rejected", at: now())
        }
    }

    public func cancelInvocation(_ id: UUID, clientID: UUID) throws {
        try state.transaction { state in
            guard state.clients.contains(where: { $0.id == clientID && !$0.revoked }),
                  let index = state.pending.firstIndex(where: {
                      $0.id == id && $0.clientID == clientID && [.waiting, .approved].contains($0.status)
                  }) else { throw VaultError.denied }
            state.pending[index].status = .cancelled
            let invocation = state.pending[index]
            state.record(client: clientID, account: invocation.accountID, action: invocation.action,
                         outcome: "approval_cancelled", at: now())
        }
    }

    public func resume(_ id: UUID, clientID: UUID) async throws -> OperationResult {
        let snapshot = try state.snapshot(), timestamp = now()
        guard let invocation = snapshot.pending.first(where: { $0.id == id && $0.clientID == clientID && $0.expiresAt > timestamp }),
              snapshot.clients.contains(where: { $0.id == clientID && !$0.revoked }),
              snapshot.accounts.contains(where: { $0.id == invocation.accountID && $0.lifecycle == .active && $0.service.action == invocation.action }),
              let grant = snapshot.grants.first(where: { $0.id == invocation.grantID && $0.requiresApproval }),
              Self.permits(grant, client: clientID, account: invocation.accountID, action: invocation.action, at: timestamp)
        else { throw VaultError.denied }
        if invocation.status == .waiting { return .approvalRequired(id) }
        guard invocation.status == .approved else { throw VaultError.denied }
        return try await execute(clientID: clientID, accountID: invocation.accountID, action: invocation.action, approvedRequest: id)
    }

    private func execute(clientID: UUID, accountID: UUID, action: Action, approvedRequest: UUID?) async throws -> OperationResult {
        guard !recoveryInProgress else { throw VaultError.busy }
        let permit: (Account, UUID)? = try state.transaction { state in
            let timestamp = now()
            guard state.clients.contains(where: { $0.id == clientID && !$0.revoked }),
                  let account = state.accounts.first(where: { $0.id == accountID && $0.lifecycle == .active }),
                  account.service.action == action,
                  let index = state.grants.firstIndex(where: { grant in
                      Self.permits(grant, client: clientID, account: accountID, action: action, at: timestamp) &&
                      (approvedRequest == nil || state.pending.contains(where: { pending in
                          pending.id == approvedRequest && pending.grantID == grant.id
                      }))
                  }) else {
                if state.accounts.contains(where: { $0.id == accountID }) {
                    state.record(client: clientID, account: accountID, action: action, outcome: "denied", at: timestamp)
                }
                return nil
            }
            if state.grants[index].requiresApproval {
                guard let approvedRequest,
                      let pendingIndex = state.pending.firstIndex(where: {
                          $0.id == approvedRequest && $0.clientID == clientID && $0.accountID == accountID &&
                          $0.action == action && $0.grantID == state.grants[index].id &&
                          $0.status == .approved && $0.expiresAt > timestamp
                      }) else { return nil }
                state.pending[pendingIndex].status = .consumed
            } else if approvedRequest != nil { return nil }
            // Reserve before dispatch; attempted calls consume budget even if the provider fails.
            state.grants[index].callsUsed += 1
            state.record(client: clientID, account: accountID, action: action, outcome: "reserved", at: timestamp)
            return (account, state.grants[index].id)
        }
        guard let (account, grantID) = permit else { throw VaultError.denied }
        var finishAttempted = false
        do {
            let credential = try await secretIO.load(id: account.credentialID, account: account.id)
            // Keychain access may block on a human prompt. Recheck before dispatch.
            let current = try state.snapshot()
            guard current.clients.contains(where: { $0.id == clientID && !$0.revoked }),
                  current.accounts.contains(where: {
                      $0.id == accountID && $0.lifecycle == .active && $0.credentialID == account.credentialID
                  }),
                  current.grants.contains(where: { $0.id == grantID && !$0.revoked && $0.expiresAt > now() }) else {
                throw VaultError.denied
            }
            let output: OperationResult
            if let sessionAdapter = adapter as? any SessionServiceAdapter,
               let grant = current.grants.first(where: { $0.id == grantID }) {
                output = try await sessionAdapter.execute(sessionID: grantID, expiresAt: grant.expiresAt,
                                                          service: account.service, credential: credential)
            } else {
                output = try await adapter.execute(service: account.service, credential: credential)
            }
            // Revocation during an in-flight request also suppresses its response.
            finishAttempted = true
            let allowed = try finish(client: clientID, account: accountID, action: action,
                                     grant: grantID, succeeded: true)
            guard allowed else { throw VaultError.denied }
            return output
        } catch {
            if !finishAttempted {
                _ = try? finish(client: clientID, account: accountID, action: action,
                                grant: grantID, succeeded: false)
            }
            // An unreadable final policy state is also a loss of authority.
            await (adapter as? any SessionServiceAdapter)?.invalidate(sessionID: grantID)
            throw (error as? SecretIOFailure)?.publicError ?? (error as? VaultError) ?? VaultError.upstreamUnavailable
        }
    }

    public func snapshot() throws -> VaultState { try state.snapshot() }

    public func clientID(for uid: UInt32) throws -> UUID {
        let clients = try state.snapshot().clients.filter { $0.uid == uid && !$0.revoked }
        guard clients.count == 1 else { throw VaultError.denied }
        return clients[0].id
    }

    public func rotate(accountID: UUID, credential: Data) async throws {
        guard !credential.isEmpty, credential.count <= 8192 else { throw VaultError.invalidInput }
        try beginLifecycle(accountID)
        defer { lifecycleMutations.remove(accountID) }
        let staged = UUID()
        let original: Account = try state.transaction { state in
            guard let i = state.accounts.firstIndex(where: {
                $0.id == accountID && $0.lifecycle == .active && $0.retiredCredentialID == nil
            }) else { throw VaultError.denied }
            if state.accounts[i].service == .github { try GitHubAdapter.validateCredential(credential) }
            state.accounts[i].lifecycle = .rotating; state.accounts[i].stagedCredentialID = staged
            state.recordAdministration(account: accountID, action: state.accounts[i].service.action,
                                       outcome: "rotation_started", at: now())
            return state.accounts[i]
        }
        do { try await secretIO.save(credential, id: staged, account: accountID) }
        catch {
            let failure = secretFailure(error)
            recordLifecycleFailure(account: accountID, action: original.service.action, operation: "rotation", failure: failure)
            if !failure.isUncertain {
                do {
                    try await abortFailedRotation(accountID: accountID, staged: staged, original: original,
                                                  deleteStage: failure.operationStarted)
                } catch {
                    recordLifecycleFailure(account: accountID, action: original.service.action,
                                           operation: "rotation_compensation", failure: secretFailure(error))
                }
            }
            throw failure.publicError
        }
        let sessions = try state.transaction { state in
            guard let i = state.accounts.firstIndex(where: { $0.id == accountID && $0.stagedCredentialID == staged }) else { throw VaultError.stateUnavailable }
            state.accounts[i].credentialID = staged; state.accounts[i].stagedCredentialID = nil
            state.accounts[i].retiredCredentialID = original.credentialID; state.accounts[i].lifecycle = .active
            for index in state.grants.indices where state.grants[index].accountID == accountID { state.grants[index].revoked = true }
            for index in state.pending.indices where state.pending[index].accountID == accountID { state.pending[index].status = .cancelled }
            state.recordAdministration(account: accountID, action: original.service.action,
                                       outcome: "rotation_committed", at: now())
            return state.grants.filter { $0.accountID == accountID }.map(\.id)
        }
        for session in sessions { await (adapter as? any SessionServiceAdapter)?.invalidate(sessionID: session) }
        do { try await secretIO.delete(id: original.credentialID, account: accountID) }
        catch {
            let failure = secretFailure(error)
            recordLifecycleFailure(account: accountID, action: original.service.action, operation: "retirement", failure: failure)
            throw failure.publicError
        }
        try state.transaction { state in
            guard let i = state.accounts.firstIndex(where: { $0.id == accountID && $0.retiredCredentialID == original.credentialID })
            else { throw VaultError.stateUnavailable }
            state.accounts[i].retiredCredentialID = nil
            state.recordAdministration(account: accountID, action: original.service.action,
                                       outcome: "rotation_completed", at: now())
        }
    }

    public func deleteAccount(_ id: UUID) async throws {
        try beginLifecycle(id)
        defer { lifecycleMutations.remove(id) }
        let account = try state.transaction { state in
            guard let i = state.accounts.firstIndex(where: { $0.id == id }) else { throw VaultError.invalidInput }
            state.accounts[i].lifecycle = .deleting
            for j in state.grants.indices where state.grants[j].accountID == id { state.grants[j].revoked = true }
            for j in state.pending.indices where state.pending[j].accountID == id { state.pending[j].status = .cancelled }
            state.recordAdministration(account: id, action: state.accounts[i].service.action,
                                       outcome: "deletion_started", at: now())
            return state.accounts[i]
        }
        for grant in try state.snapshot().grants where grant.accountID == id {
            await (adapter as? any SessionServiceAdapter)?.invalidate(sessionID: grant.id)
        }
        do { try await removeCredentialItems(account) }
        catch {
            let failure = secretFailure(error)
            recordLifecycleFailure(account: id, action: account.service.action, operation: "deletion", failure: failure)
            throw failure.publicError
        }
        try removeAccountRecord(id, outcome: "deletion_completed")
    }

    // Called by the single broker owner before accepting connections.
    public func recoverInterruptedLifecycle() async throws {
        guard lifecycleMutations.isEmpty, !recoveryInProgress, secretIO.isIdle else { throw VaultError.busy }
        recoveryInProgress = true
        defer { recoveryInProgress = false }
        try state.transaction { $0.recordAdministration(outcome: "recovery_started", at: now()) }
        for account in try state.snapshot().accounts {
            switch account.lifecycle {
            case .enrolling, .deleting:
                try await recoverSecretItems(account)
                try removeAccountRecord(account.id, outcome: account.lifecycle == .enrolling ? "enrollment_recovered" : "deletion_recovered")
            case .rotating:
                if let staged = account.stagedCredentialID { try await recoverSecretItem(staged, account: account) }
                try state.transaction { state in
                    if let i = state.accounts.firstIndex(where: { $0.id == account.id }) {
                        state.accounts[i].stagedCredentialID = nil; state.accounts[i].lifecycle = .active
                        state.recordAdministration(account: account.id, action: account.service.action,
                                                   outcome: "rotation_recovered", at: now())
                    }
                }
            case .active:
                if let retired = account.retiredCredentialID {
                    try await recoverSecretItem(retired, account: account)
                    try state.transaction { state in
                        if let i = state.accounts.firstIndex(where: { $0.id == account.id }) {
                            state.accounts[i].retiredCredentialID = nil
                            state.recordAdministration(account: account.id, action: account.service.action,
                                                       outcome: "retirement_recovered", at: now())
                        }
                    }
                }
            }
        }
        try state.transaction { $0.recordAdministration(outcome: "recovery_completed", at: now()) }
    }

    public func prune() throws {
        try state.transaction { state in
            let timestamp = now()
            state.pending.removeAll { [.consumed, .cancelled].contains($0.status) || $0.expiresAt <= timestamp }
            let needed = Set(state.pending.map(\.grantID))
            state.grants.removeAll { ($0.revoked || $0.expiresAt <= timestamp) && !needed.contains($0.id) }
            let used = Set(state.grants.map(\.clientID))
            state.clients.removeAll { $0.revoked && !used.contains($0.id) }
            state.recordAdministration(outcome: "pruned", at: timestamp)
        }
    }

    private func removeCredentialItems(_ account: Account) async throws {
        for id in Set([account.credentialID, account.stagedCredentialID, account.retiredCredentialID].compactMap { $0 }) {
            try await secretIO.delete(id: id, account: account.id)
        }
    }

    private func abortFailedRotation(accountID: UUID, staged: UUID, original: Account, deleteStage: Bool) async throws {
        if deleteStage { try await secretIO.delete(id: staged, account: accountID) }
        try state.transaction { state in
            guard let i = state.accounts.firstIndex(where: {
                $0.id == accountID && $0.lifecycle == .rotating && $0.stagedCredentialID == staged &&
                    $0.credentialID == original.credentialID
            }) else { throw VaultError.stateUnavailable }
            state.accounts[i].stagedCredentialID = nil
            state.accounts[i].lifecycle = .active
            state.recordAdministration(account: accountID, action: original.service.action,
                                       outcome: "rotation_aborted", at: now())
        }
    }

    private func beginLifecycle(_ account: UUID) throws {
        guard !recoveryInProgress, !secretIO.hasPendingWrite(account: account),
              lifecycleMutations.insert(account).inserted else { throw VaultError.busy }
    }

    private func secretFailure(_ error: any Error) -> SecretIOFailure {
        (error as? SecretIOFailure) ?? .operationFailed((error as? VaultError) ?? .secretUnavailable)
    }

    private func recordLifecycleFailure(account: UUID, action: Action, operation: String, failure: SecretIOFailure) {
        let outcome = operation + (failure.isUncertain ? "_uncertain" : "_failed")
        try? state.transaction { $0.recordAdministration(account: account, action: action, outcome: outcome, at: now()) }
    }

    private func recoverSecretItems(_ account: Account) async throws {
        do { try await removeCredentialItems(account) }
        catch {
            let failure = secretFailure(error)
            recordLifecycleFailure(account: account.id, action: account.service.action, operation: "recovery", failure: failure)
            throw failure.publicError
        }
    }

    private func recoverSecretItem(_ id: UUID, account: Account) async throws {
        do { try await secretIO.delete(id: id, account: account.id) }
        catch {
            let failure = secretFailure(error)
            recordLifecycleFailure(account: account.id, action: account.service.action, operation: "recovery", failure: failure)
            throw failure.publicError
        }
    }

    private func removeAccountRecord(_ id: UUID, outcome: String) throws {
        try state.transaction { state in
            guard let account = state.accounts.first(where: { $0.id == id }) else { throw VaultError.stateUnavailable }
            state.accounts.removeAll { $0.id == id }; state.grants.removeAll { $0.accountID == id }; state.pending.removeAll { $0.accountID == id }
            state.recordAdministration(account: id, action: account.service.action, outcome: outcome, at: now())
        }
    }

    private func finish(client: UUID, account: UUID, action: Action, grant: UUID,
                        succeeded: Bool) throws -> Bool {
        return try state.transaction { state in
            let timestamp = now()
            let allowed = state.clients.contains(where: { $0.id == client && !$0.revoked }) &&
                state.accounts.contains(where: { $0.id == account && $0.lifecycle == .active }) &&
                state.grants.contains(where: { $0.id == grant && !$0.revoked && $0.expiresAt > timestamp })
            state.record(client: client, account: account, action: action,
                         outcome: allowed ? (succeeded ? "completed" : "failed") : "response_suppressed",
                         at: timestamp)
            return allowed
        }
    }

    private static func permits(_ grant: Grant, client: UUID, account: UUID,
                                action: Action, at timestamp: Date) -> Bool {
        !grant.revoked && grant.clientID == client && grant.accountID == account &&
        grant.action == action && grant.expiresAt > timestamp && grant.callsUsed < grant.callLimit
    }
}
