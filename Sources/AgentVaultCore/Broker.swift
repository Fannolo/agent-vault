import Foundation

public actor Broker {
    private let state: any StateStore
    private let secrets: any SecretStore
    private let adapter: any ServiceAdapter
    private let now: @Sendable () -> Date

    public init(state: any StateStore, secrets: any SecretStore,
                adapter: any ServiceAdapter = FixedServiceAdapter(),
                now: @escaping @Sendable () -> Date = { Date() }) {
        self.state = state; self.secrets = secrets; self.adapter = adapter; self.now = now
    }

    public func enroll(service: Service, credential: Data) throws -> Account {
        guard !credential.isEmpty, credential.count <= 8192 else { throw VaultError.invalidInput }
        if service == .github { try GitHubAdapter.validateCredential(credential) }
        let account = Account(service: service)
        try secrets.save(credential, for: account.id)
        do {
            try state.transaction {
                guard $0.accounts.count < VaultState.maxAccounts else { throw VaultError.stateUnavailable }
                $0.accounts.append(account)
            }
        }
        catch {
            try? secrets.delete(for: account.id)
            throw VaultError.stateUnavailable
        }
        return account
    }

    public func registerClient() throws -> ClientRecord {
        let client = ClientRecord()
        try state.transaction {
            guard $0.clients.count < VaultState.maxClients else { throw VaultError.stateUnavailable }
            $0.clients.append(client)
        }
        return client
    }

    public func grant(clientID: UUID, accountID: UUID, duration: TimeInterval,
                      callLimit: Int) throws -> Grant {
        guard duration > 0, duration <= 86_400, duration.isFinite,
              callLimit > 0, callLimit <= 10_000 else { throw VaultError.invalidInput }
        return try state.transaction { state in
            let timestamp = now()
            guard state.grants.count < VaultState.maxGrants else { throw VaultError.stateUnavailable }
            guard state.clients.contains(where: { $0.id == clientID && !$0.revoked }),
                  let account = state.accounts.first(where: { $0.id == accountID }) else {
                throw VaultError.denied
            }
            let grant = Grant(clientID: clientID, accountID: accountID, action: account.service.action,
                              expiresAt: timestamp.addingTimeInterval(duration), callLimit: callLimit)
            state.grants.append(grant)
            state.record(client: clientID, account: accountID, action: grant.action,
                         outcome: "grant_created", at: timestamp)
            return grant
        }
    }

    public func revokeGrant(_ id: UUID) throws {
        try state.transaction { state in
            let timestamp = now()
            guard let index = state.grants.firstIndex(where: { $0.id == id }) else {
                throw VaultError.invalidInput
            }
            state.grants[index].revoked = true
            let grant = state.grants[index]
            state.record(client: grant.clientID, account: grant.accountID, action: grant.action,
                         outcome: "grant_revoked", at: timestamp)
        }
    }

    public func revokeClient(_ id: UUID) throws {
        try state.transaction { state in
            let timestamp = now()
            guard let index = state.clients.firstIndex(where: { $0.id == id }) else {
                throw VaultError.invalidInput
            }
            state.clients[index].revoked = true
            for i in state.grants.indices where state.grants[i].clientID == id {
                state.grants[i].revoked = true
            }
            state.record(client: id, account: nil, action: nil, outcome: "client_revoked", at: timestamp)
        }
    }

    public func availableAccounts(clientID: UUID) throws -> [Account] {
        let snapshot = try state.snapshot()
        let timestamp = now()
        guard snapshot.clients.contains(where: { $0.id == clientID && !$0.revoked }) else { return [] }
        return snapshot.accounts.filter { account in
            snapshot.grants.contains { grant in
                Self.permits(grant, client: clientID, account: account.id,
                             action: account.service.action, at: timestamp)
            }
        }
    }

    public func run(clientID: UUID, accountID: UUID, action: Action) async throws -> OperationResult {
        let permit: (Account, UUID)? = try state.transaction { state in
            let timestamp = now()
            guard state.clients.contains(where: { $0.id == clientID && !$0.revoked }),
                  let account = state.accounts.first(where: { $0.id == accountID }),
                  account.service.action == action,
                  let index = state.grants.firstIndex(where: {
                      Self.permits($0, client: clientID, account: accountID, action: action, at: timestamp)
                  }) else {
                // Caller-supplied account IDs can be arbitrary; audit only known account IDs.
                state.record(client: clientID, account: state.accounts.first(where: { $0.id == accountID })?.id,
                             action: action, outcome: "denied", at: timestamp)
                return nil
            }
            // Reserve before dispatch; attempted calls consume budget even if the provider fails.
            state.grants[index].callsUsed += 1
            state.record(client: clientID, account: accountID, action: action, outcome: "reserved", at: timestamp)
            return (account, state.grants[index].id)
        }
        guard let (account, grantID) = permit else { throw VaultError.denied }
        do {
            let credential = try secrets.load(for: account.id)
            // Keychain access may block on a human prompt. Recheck before dispatch.
            let current = try state.snapshot()
            guard current.clients.contains(where: { $0.id == clientID && !$0.revoked }),
                  current.grants.contains(where: { $0.id == grantID && !$0.revoked && $0.expiresAt > now() }) else {
                throw VaultError.denied
            }
            let output = try await adapter.execute(service: account.service, credential: credential)
            // Revocation during an in-flight request also suppresses its response.
            let allowed = try finish(client: clientID, account: accountID, action: action,
                                     grant: grantID, succeeded: true)
            guard allowed else { throw VaultError.denied }
            return output
        } catch {
            _ = try? finish(client: clientID, account: accountID, action: action,
                            grant: grantID, succeeded: false)
            throw (error as? VaultError) ?? VaultError.upstreamUnavailable
        }
    }

    private func finish(client: UUID, account: UUID, action: Action, grant: UUID,
                        succeeded: Bool) throws -> Bool {
        return try state.transaction { state in
            let timestamp = now()
            let allowed = state.clients.contains(where: { $0.id == client && !$0.revoked }) &&
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
