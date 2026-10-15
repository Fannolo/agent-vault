import AgentVaultContracts
import Foundation

public actor Broker {
    static let maxLiveRuns = 4
    static let maxRuns = 16
    private let state: any StateStore
    private let secretIO: SecretIOExecutor
    private let adapter: any ServiceAdapter
    private let web: (any WebSessionExecutor)?
    private let windows: LifecycleWindows
    private let now: @Sendable () -> Date
    private let recoveryDrainTimeout: Duration
    private var lifecycleMutations: Set<UUID> = []
    private var recoveryInProgress = false
    private var runs: [BrowserRunID: BrowserRun] = [:]
    private var sweepTasks: [BrowserRunID: (deadline: Date, task: Task<Void, Never>)] = [:]

    var scheduledDeadlineCount: Int { sweepTasks.count }

    deinit {
        for entry in sweepTasks.values { entry.task.cancel() }
    }

    /// Without `webSessions`, browser services are refused before any budget is reserved.
    public init(state: any StateStore, secrets: any SecretStore,
                adapter: any ServiceAdapter = FixedServiceAdapter(),
                webSessions: (any WebSessionExecutor)? = nil,
                windows: LifecycleWindows = .standard,
                now: @escaping @Sendable () -> Date = { Date() },
                secretIOPolicy: SecretIOPolicy = .standard) {
        self.state = state; self.secretIO = SecretIOExecutor(store: secrets, policy: secretIOPolicy)
        self.adapter = adapter; self.web = webSessions; self.windows = windows; self.now = now
        self.recoveryDrainTimeout = .seconds(secretIOPolicy.timeout)
        if let losses = webSessions?.losses {
            Task { [weak self] in
                for await lost in losses {
                    guard let self else { return }
                    await self.hostLost(lost)
                }
            }
        }
    }

    public func enroll(service: Service, credential: Data) async throws -> Account {
        guard CredentialFormat.isValid(credential, for: service.wire) else { throw VaultError.invalidInput }
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
        await reconcileRuns()
    }

    public func revokeClient(_ id: UUID) async throws {
        try state.transaction { state in
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
        }
        await reconcileRuns()
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
        let pending: ApprovalID? = try state.transaction { state in
            let timestamp = now()
            guard state.clients.contains(where: { $0.id == clientID && !$0.revoked }),
                  let account = state.accounts.first(where: { $0.id == accountID && $0.lifecycle == .active && $0.service.action == action }),
                  let grant = state.grants.first(where: { Self.permits($0, client: clientID, account: accountID, action: action, at: timestamp) })
            else { return nil }
            guard canExecute(account.service) else { throw VaultError.upstreamUnavailable }
            guard grant.requiresApproval else { return nil }
            if let existing = state.pending.first(where: {
                $0.clientID == clientID && $0.accountID == accountID && $0.action == action &&
                $0.grantID == grant.id && $0.expiresAt > timestamp && [.waiting, .approved].contains($0.status)
            }) { return existing.id }
            state.pending.removeAll { $0.expiresAt <= timestamp || [.cancelled, .consumed].contains($0.status) }
            guard state.pending.count < 128 else { throw VaultError.busy }
            let invocation = PendingInvocation(id: ApprovalID(UUID()), clientID: clientID, accountID: accountID,
                action: action, grantID: grant.id,
                expiresAt: windows.approvalEnds(now: timestamp, grantExpiresAt: grant.expiresAt), status: .waiting)
            state.pending.append(invocation)
            state.record(client: clientID, account: accountID, action: action, outcome: "approval_requested", at: timestamp)
            return invocation.id
        }
        if let pending { return .approvalRequired(pending) }
        return try await execute(clientID: clientID, accountID: accountID, action: action, approvedRequest: nil)
    }

    public func approveInvocation(_ id: ApprovalID) throws {
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

    public func rejectInvocation(_ id: ApprovalID) throws {
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

    /// Agent cancellation of the request ID from its latest reply: a browser run or an approval request.
    public func cancel(_ requestID: UUID, clientID: UUID) async throws {
        if let run = runs[BrowserRunID(requestID)] {
            guard run.binding.client == clientID else { throw VaultError.denied }
            await apply(run.id, .agentCancelled)
            return
        }
        let id = ApprovalID(requestID)
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

    /// The current state of the request ID from the agent's latest reply. Polling a browser run is
    /// free: budget was reserved once when the run was created.
    public func resume(_ requestID: UUID, clientID: UUID) async throws -> OperationResult {
        if let run = runs[BrowserRunID(requestID)] {
            guard run.binding.client == clientID else { throw VaultError.denied }
            return try await collect(run.id)
        }
        let id = ApprovalID(requestID)
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

    private func execute(clientID: UUID, accountID: UUID, action: Action, approvedRequest: ApprovalID?) async throws -> OperationResult {
        guard !recoveryInProgress else { throw VaultError.busy }
        let permit: (Account, Grant, SecretIOExecutor.ReadReservation)? = try state.transaction { state in
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
            let pendingIndex: Int?
            if state.grants[index].requiresApproval {
                guard let approvedRequest,
                      let approvedIndex = state.pending.firstIndex(where: {
                          $0.id == approvedRequest && $0.clientID == clientID && $0.accountID == accountID &&
                          $0.action == action && $0.grantID == state.grants[index].id &&
                          $0.status == .approved && $0.expiresAt > timestamp
                      }) else { return nil }
                pendingIndex = approvedIndex
            } else {
                guard approvedRequest == nil else { return nil }
                pendingIndex = nil
            }
            // An unavailable host or full run table must not consume credential capacity.
            guard canExecute(account.service) else { throw VaultError.upstreamUnavailable }
            if case .web = account.service.execution { try admitRun(account: accountID) }
            // No actor suspension or credential work occurs inside the transaction.
            // Admission must succeed before spending a single-use approval or budget.
            let reservation = try secretIO.reserveRead(account: account.id)
            if let pendingIndex { state.pending[pendingIndex].status = .consumed }
            // Admitted attempts consume budget even if credential access or the provider fails.
            state.grants[index].callsUsed += 1
            state.record(client: clientID, account: accountID, action: action, outcome: "reserved", at: timestamp)
            return (account, state.grants[index], reservation)
        }
        guard let (account, grant, reservation) = permit else { throw VaultError.denied }
        let binding = RunBinding(client: clientID, account: accountID, action: action,
                                 grant: grant.id, credential: account.credentialID)
        switch account.service.execution {
        case .api(let service):
            return try await executeAPI(service, binding: binding, reservation: reservation)
        case .web(let workflow):
            // `canExecute` admitted this run only with a host configured.
            guard let web else { throw VaultError.upstreamUnavailable }
            // Registered before the first suspension so revocation can always find it.
            let id = BrowserRunID()
            runs[id] = BrowserRun(id: id, binding: binding, grantExpiresAt: grant.expiresAt)
            return try await executeWeb(id, workflow: workflow, binding: binding, web: web, reservation: reservation)
        }
    }

    private func executeAPI(_ service: APIService, binding: RunBinding,
                            reservation: SecretIOExecutor.ReadReservation) async throws -> OperationResult {
        var finishAttempted = false
        do {
            let credential = try await reservation.load(id: binding.credential)
            // Keychain access may block on a human prompt. Recheck before dispatch.
            guard stillAuthorized(binding, in: try state.snapshot(), at: now()) else { throw VaultError.denied }
            let output = try await adapter.execute(service: service, credential: credential)
            // Revocation during an in-flight request also suppresses its response.
            finishAttempted = true
            guard try finish(binding, succeeded: true) else { throw VaultError.denied }
            switch output {
            case .demoReady: return .demoReady
            case .profile(let profile): return .profile(profile)
            }
        } catch {
            if !finishAttempted { _ = try? finish(binding, succeeded: false) }
            throw publicError(error)
        }
    }

    private func executeWeb(_ id: BrowserRunID, workflow: WebWorkflow, binding: RunBinding,
                            web: any WebSessionExecutor,
                            reservation: SecretIOExecutor.ReadReservation) async throws -> OperationResult {
        let loaded: Data
        do { loaded = try await reservation.load(id: binding.credential) }
        catch {
            abandon(id)
            throw publicError(error)
        }
        // A revocation during the load has already removed the run and audited the suppression.
        guard let run = runs[id], run.phase == .loadingCredential else { throw VaultError.denied }
        guard isAuthorized(run) else {
            await apply(id, .authorityLost)
            throw VaultError.denied
        }
        guard let credential = WebLoginCredential(loaded) else {
            abandon(id)
            throw VaultError.secretUnavailable
        }
        // The host needs at least one whole second of context; a clock jump past the grant is a loss of
        // authority, decided before any secret leaves the broker.
        let lifetime = min(LifecycleWindows.hostLifetimeCap, run.grantExpiresAt.timeIntervalSince(now()))
        guard lifetime.isFinite, lifetime >= 1 else {
            await apply(id, .authorityLost)
            throw VaultError.denied
        }
        await apply(id, .credentialLoaded)
        guard let dispatched = runs[id] else { throw VaultError.denied }
        await awaitHost(id, epoch: dispatched.epoch, within: windows.startReply) {
            await web.start(id, workflow: workflow, credential: credential, lifetime: lifetime)
        }
        return try await collect(id)
    }

    /// Waits for one host request at most `window`, whatever the host does. The request itself
    /// keeps running unowned: a late reply still reaches `hostReplied`, which ends any context it
    /// created. The caller disappearing does not stop the deadline either.
    private func awaitHost(_ id: BrowserRunID, epoch: UInt64, within window: TimeInterval,
                           _ request: @escaping @Sendable () async -> WebStep) async {
        let settled = Signal()
        let timer = Task {
            try? await Task.sleep(for: .seconds(window))
            settled.fire()
        }
        Task { [weak self] in
            let step = await request()
            await self?.hostReplied(id, step, epoch: epoch)
            settled.fire()
        }
        await settled.wait()
        timer.cancel()
        await apply(id, .hostReplyOverdue(epoch: epoch))
    }

    public func snapshot() throws -> VaultState { try state.snapshot() }

    public func clientID(for uid: UInt32) throws -> UUID {
        let clients = try state.snapshot().clients.filter { $0.uid == uid && !$0.revoked }
        guard clients.count == 1 else { throw VaultError.denied }
        return clients[0].id
    }

    public func rotate(accountID: UUID, credential: Data) async throws {
        guard !credential.isEmpty, credential.count <= CredentialFormat.transportMaximum else { throw VaultError.invalidInput }
        try beginLifecycle(accountID)
        defer { lifecycleMutations.remove(accountID) }
        let staged = UUID()
        let original: Account = try state.transaction { state in
            guard let i = state.accounts.firstIndex(where: {
                $0.id == accountID && $0.lifecycle == .active && $0.retiredCredentialID == nil
            }) else { throw VaultError.denied }
            guard CredentialFormat.isValid(credential, for: state.accounts[i].service.wire) else { throw VaultError.invalidInput }
            state.accounts[i].lifecycle = .rotating; state.accounts[i].stagedCredentialID = staged
            state.recordAdministration(account: accountID, action: state.accounts[i].service.action,
                                       outcome: "rotation_started", at: now())
            return state.accounts[i]
        }
        // Rotation intent removes the old run's authority even when the write later times out.
        await reconcileRuns()
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
        try state.transaction { state in
            guard let i = state.accounts.firstIndex(where: { $0.id == accountID && $0.stagedCredentialID == staged }) else { throw VaultError.stateUnavailable }
            state.accounts[i].credentialID = staged; state.accounts[i].stagedCredentialID = nil
            state.accounts[i].retiredCredentialID = original.credentialID; state.accounts[i].lifecycle = .active
            for index in state.grants.indices where state.grants[index].accountID == accountID { state.grants[index].revoked = true }
            for index in state.pending.indices where state.pending[index].accountID == accountID { state.pending[index].status = .cancelled }
            state.recordAdministration(account: accountID, action: original.service.action,
                                       outcome: "rotation_committed", at: now())
        }
        // Browser runs bound to the old credential end before it is deleted.
        await reconcileRuns()
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
        await reconcileRuns()
        do { try await removeCredentialItems(account) }
        catch {
            let failure = secretFailure(error)
            recordLifecycleFailure(account: id, action: account.service.action, operation: "deletion", failure: failure)
            throw failure.publicError
        }
        try removeAccountRecord(id, outcome: "deletion_completed")
    }

    // Own admission before draining; an idle-only admission check could starve
    // indefinitely under otherwise authorized read traffic.
    public func recoverInterruptedLifecycle() async throws {
        guard !recoveryInProgress else { throw VaultError.busy }
        recoveryInProgress = true
        defer { recoveryInProgress = false }
        let accountsBeforeDrain = try state.snapshot().accounts
        let auditRecovery = !lifecycleMutations.isEmpty || !secretIO.isIdle || accountsBeforeDrain.contains {
            $0.lifecycle != .active || $0.retiredCredentialID != nil
        }
        if auditRecovery { try state.transaction { $0.recordAdministration(outcome: "recovery_started", at: now()) } }
        let deadline = ContinuousClock.now + recoveryDrainTimeout
        while true {
            try Task.checkCancellation()
            guard ContinuousClock.now < deadline else { throw VaultError.busy }
            if lifecycleMutations.isEmpty && secretIO.isIdle { break }
            try await Task.sleep(for: .milliseconds(5))
        }
        await reconcileRuns()
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
        if auditRecovery { try state.transaction { $0.recordAdministration(outcome: "recovery_completed", at: now()) } }
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

    /// Records the attempt's terminal audit and reports whether its output may be delivered.
    private func finish(_ binding: RunBinding, succeeded: Bool) throws -> Bool {
        try state.transaction { state in
            let timestamp = now()
            let allowed = stillAuthorized(binding, in: state, at: timestamp)
            state.record(client: binding.client, account: binding.account, action: binding.action,
                         outcome: allowed ? (succeeded ? "completed" : "failed") : "response_suppressed",
                         at: timestamp)
            return allowed
        }
    }

    private func publicError(_ error: any Error) -> VaultError {
        (error as? SecretIOFailure)?.publicError ?? (error as? VaultError) ?? VaultError.upstreamUnavailable
    }

    private func canExecute(_ service: Service) -> Bool {
        if case .web = service.execution { return web != nil }
        return true
    }

    private static func permits(_ grant: Grant, client: UUID, account: UUID,
                                action: Action, at timestamp: Date) -> Bool {
        !grant.revoked && grant.clientID == client && grant.accountID == account &&
        grant.action == action && grant.expiresAt > timestamp && grant.callsUsed < grant.callLimit
    }
}

// MARK: - Browser runs. The broker is the only authority; the host only holds browser contexts.

extension Broker {
    /// Metadata for the authenticated human-app transport; never part of the agent read surface.
    public func pendingHumanSteps() async throws -> [PendingHumanStep] {
        await sweep()
        let current = try state.snapshot(), timestamp = now()
        return runs.values.compactMap { run in
            guard stillAuthorized(run.binding, in: current, at: timestamp) else { return nil }
            return run.humanStep
        }
    }

    /// Signed by the human app before this is called. Binds a lease to this connection and to the
    /// run's current human step; a later step or another connection needs a new signed open.
    public func openHumanStep(_ step: HumanStepID, connection: ContinuationConnectionID) async throws -> ContinuationLeaseID {
        await sweep()
        guard let run = runs[step.run], run.humanStep?.id == step else { throw VaultError.denied }
        guard isAuthorized(run) else {
            await apply(run.id, .authorityLost)
            throw VaultError.denied
        }
        let lease = ContinuationLease(id: ContinuationLeaseID(), connection: connection, step: step)
        await apply(run.id, .opened(lease))
        guard runs[run.id]?.lease?.id == lease.id else { throw VaultError.denied }
        return lease.id
    }

    /// The person finished or abandoned the step. The broker, not the page, decides what follows.
    public func concludeHumanStep(_ lease: ContinuationLeaseID, connection: ContinuationConnectionID,
                                  decision: HumanStepDecision) async throws -> HumanStepProgress {
        await sweep()
        guard let run = runs.values.first(where: { $0.lease?.id == lease }),
              run.lease?.connection == connection else { throw VaultError.denied }
        guard isAuthorized(run) else {
            await apply(run.id, .authorityLost)
            throw VaultError.denied
        }
        switch decision {
        case .cancel:
            await apply(run.id, .humanCancelled(lease))
            return .concluded
        case .finished:
            await apply(run.id, .humanFinished(lease))
            guard let web, let classifying = runs[run.id] else { throw VaultError.denied }
            await awaitHost(run.id, epoch: classifying.epoch, within: windows.classifyReply) {
                await web.reclassify(run.id)
            }
            switch runs[run.id]?.phase {
            case .concluded?: return .concluded
            case .awaitingHuman(let kind, _, _)?: return .humanStepRequired(kind)
            default: throw VaultError.denied
            }
        }
    }

    /// The transport lost an authenticated human-app connection. Its leases end; runs keep their pause.
    public func continuationConnectionClosed(_ connection: ContinuationConnectionID) async {
        for id in Array(runs.keys) { await apply(id, .connectionClosed(connection)) }
    }

    fileprivate func collect(_ id: BrowserRunID) async throws -> OperationResult {
        await sweep()
        guard let run = runs[id] else { throw VaultError.denied }
        guard isAuthorized(run) else {
            await apply(id, .authorityLost)
            throw VaultError.denied
        }
        switch run.phase {
        case .awaitingHuman, .classifying: return .humanStepRequired(id)
        case .loadingCredential, .dispatching: throw VaultError.busy
        case .concluded(let conclusion, _):
            // Removed before the audit write: a result is delivered at most once.
            await apply(id, .collected)
            switch conclusion {
            case .profile(let profile):
                guard try finish(run.binding, succeeded: true) else { throw VaultError.denied }
                return .profile(profile)
            case .failed(let failure):
                guard try finish(run.binding, succeeded: false) else { throw VaultError.denied }
                throw failure
            }
        }
    }

    /// Applies a host reply only if the run still waits for the request issued at `epoch` and is
    /// still authorized. A late reply for an ended run ends whatever context the host created.
    fileprivate func hostReplied(_ id: BrowserRunID, _ step: WebStep, epoch: UInt64) async {
        guard let run = runs[id], run.epoch == epoch, run.phase.awaitsHostReply else {
            if runs[id]?.phase.hostMayHoldContext != true { await web?.end(id) }
            return
        }
        guard isAuthorized(run) else {
            await apply(id, .authorityLost)
            return
        }
        await apply(id, .host(step, epoch: epoch))
    }

    fileprivate func admitRun(account: UUID) throws {
        let live = runs.values.filter(\.phase.isLive)
        guard runs.count < Self.maxRuns, live.count < Self.maxLiveRuns,
              !live.contains(where: { $0.binding.account == account }) else { throw VaultError.busy }
    }

    /// Ends every run whose binding lost authority. Unreadable policy state is a loss of authority.
    fileprivate func reconcileRuns() async {
        guard !runs.isEmpty else { return }
        let current = try? state.snapshot(), timestamp = now()
        for (id, run) in runs {
            if let current, stillAuthorized(run.binding, in: current, at: timestamp) { continue }
            await apply(id, .authorityLost)
        }
    }

    fileprivate func isAuthorized(_ run: BrowserRun) -> Bool {
        guard let current = try? state.snapshot() else { return false }
        return stillAuthorized(run.binding, in: current, at: now())
    }

    /// Removes a run that never reached the host and records its terminal audit.
    fileprivate func abandon(_ id: BrowserRunID) {
        guard let run = runs.removeValue(forKey: id) else { return }
        _ = try? finish(run.binding, succeeded: false)
    }

    fileprivate func sweep() async {
        for id in Array(runs.keys) { await apply(id, .clock(now())) }
    }

    /// Ends only the runs bound to the lost connection, so a late loss cannot touch newer runs.
    fileprivate func hostLost(_ lost: Set<BrowserRunID>) async {
        for id in lost { await apply(id, .hostLost) }
    }

    fileprivate func apply(_ id: BrowserRunID, _ event: RunEvent) async {
        guard let run = runs[id] else { return }
        let (next, effects) = run.applying(event, now: now(), windows: windows)
        runs[id] = next
        updateSweep(for: id, deadline: next?.phase.deadline)
        let binding = run.binding
        for effect in effects {
            switch effect {
            case .audit(let outcome):
                try? state.transaction {
                    $0.record(client: binding.client, account: binding.account, action: binding.action,
                              outcome: outcome, at: now())
                }
            case .humanAudit(let outcome):
                try? state.transaction {
                    $0.recordAdministration(client: binding.client, account: binding.account, action: binding.action,
                                            outcome: outcome, at: now())
                }
            case .endHost:
                break
            }
        }
        // Teardown last, after the run table and audit already reflect the decision.
        if effects.contains(.endHost) { await web?.end(id) }
    }

    /// Deadlines also hold when nobody polls: a paused context ends at its deadline.
    private func updateSweep(for id: BrowserRunID, deadline: Date?) {
        if let deadline, sweepTasks[id]?.deadline == deadline { return }
        sweepTasks.removeValue(forKey: id)?.task.cancel()
        guard let date = deadline else { return }
        let delay = max(0, date.timeIntervalSince(now()))
        let task = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(delay)) }
            catch { return }
            await self?.deadlineReached(id, at: date)
        }
        sweepTasks[id] = (date, task)
    }

    private func deadlineReached(_ id: BrowserRunID, at date: Date) async {
        guard sweepTasks[id]?.deadline == date else { return }
        sweepTasks.removeValue(forKey: id)
        await apply(id, .clock(now()))
    }
}

/// Fires once; every waiter, earlier or later, resumes.
private final class Signal: @unchecked Sendable {
    private let lock = NSLock()
    private var fired = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func fire() {
        let waiting = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
            guard !fired else { return [] }
            fired = true
            defer { waiters = [] }
            return waiters
        }
        for waiter in waiting { waiter.resume() }
    }

    func wait() async {
        await withCheckedContinuation { continuation in
            let ready = lock.withLock { () -> Bool in
                if fired { return true }
                waiters.append(continuation)
                return false
            }
            if ready { continuation.resume() }
        }
    }
}
