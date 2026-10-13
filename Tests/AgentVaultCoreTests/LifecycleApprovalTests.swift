import AgentVaultCore
import AgentVaultContracts
import CryptoKit
import Foundation
import Testing

private final class InterruptedSecrets: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [UUID: Data] = [:]
    private var failSave = false
    private var failDelete = false
    func interruptNextSave() { lock.withLock { failSave = true } }
    func interruptNextDelete() { lock.withLock { failDelete = true } }
    var ids: Set<UUID> { lock.withLock { Set(items.keys) } }
    func save(_ value: Data, for id: UUID) throws {
        try lock.withLock {
            items[id] = value
            if failSave { failSave = false; throw VaultError.secretUnavailable }
        }
    }
    func load(for id: UUID) throws -> Data {
        try lock.withLock {
            guard let value = items[id] else { throw VaultError.secretUnavailable }
            return value
        }
    }
    func delete(for id: UUID) throws {
        try lock.withLock {
            if failDelete { failDelete = false; throw VaultError.secretUnavailable }
            items.removeValue(forKey: id)
        }
    }
}

@Test func interruptedEnrollmentKeepsEvidenceAndRecoveryDeletesOnlyTrackedItem() async throws {
    let state = MemoryState(), secrets = InterruptedSecrets()
    let broker = Broker(state: state, secrets: secrets)
    let unrelated = UUID()
    try secrets.save(Data("SYNTHETIC-unrelated".utf8), for: unrelated)
    secrets.interruptNextSave()
    await #expect(throws: VaultError.secretUnavailable) {
        _ = try await broker.enroll(service: .demo, credential: Data("SYNTHETIC-enrollment".utf8))
    }
    #expect(try state.snapshot().accounts.map(\.lifecycle) == [.enrolling])
    #expect(secrets.ids.count == 2)
    // A replacement broker represents process restart using the same stores.
    try await Broker(state: state, secrets: secrets).recoverInterruptedLifecycle()
    #expect(try state.snapshot().accounts.isEmpty)
    #expect(secrets.ids == [unrelated])
}

@Test func interruptedRotationRestoresOriginalAndSuccessfulRotationRevokesOldGrant() async throws {
    let state = MemoryState(), secrets = InterruptedSecrets()
    let broker = Broker(state: state, secrets: secrets)
    let account = try await broker.enroll(service: .demo, credential: Data("SYNTHETIC-original".utf8))
    let client = try await broker.registerClient()
    let grant = try await broker.grant(clientID: client.id, accountID: account.id, duration: 60, callLimit: 2)
    secrets.interruptNextSave()
    await #expect(throws: VaultError.secretUnavailable) {
        try await broker.rotate(accountID: account.id, credential: Data("SYNTHETIC-replacement".utf8))
    }
    await #expect(throws: VaultError.denied) {
        _ = try await broker.run(clientID: client.id, accountID: account.id, action: .demoStatus)
    }
    let restarted = Broker(state: state, secrets: secrets)
    try await restarted.recoverInterruptedLifecycle()
    #expect(secrets.ids == [account.credentialID])
    #expect(try await restarted.run(clientID: client.id, accountID: account.id, action: .demoStatus) == .demoReady)
    try await restarted.rotate(accountID: account.id, credential: Data("SYNTHETIC-replacement".utf8))
    let current = try state.snapshot()
    #expect(current.accounts[0].id == account.id)
    #expect(current.accounts[0].credentialID != account.credentialID)
    #expect(current.grants.first { $0.id == grant.id }?.revoked == true)
    #expect(secrets.ids == [current.accounts[0].credentialID])
}

@Test func interruptedRetirementAndDeletionRecoverWithoutReactivatingAccess() async throws {
    let state = MemoryState(), secrets = InterruptedSecrets()
    let broker = Broker(state: state, secrets: secrets)
    let account = try await broker.enroll(service: .demo, credential: Data("SYNTHETIC-original".utf8))
    secrets.interruptNextDelete()
    await #expect(throws: VaultError.secretUnavailable) {
        try await broker.rotate(accountID: account.id, credential: Data("SYNTHETIC-new".utf8))
    }
    #expect(try state.snapshot().accounts[0].retiredCredentialID == account.credentialID)
    let restarted = Broker(state: state, secrets: secrets)
    try await restarted.recoverInterruptedLifecycle()
    #expect(secrets.ids.count == 1)
    #expect(try state.snapshot().accounts[0].retiredCredentialID == nil)
    secrets.interruptNextDelete()
    await #expect(throws: VaultError.secretUnavailable) { try await restarted.deleteAccount(account.id) }
    #expect(try state.snapshot().accounts[0].lifecycle == .deleting)
    try await Broker(state: state, secrets: secrets).recoverInterruptedLifecycle()
    #expect(secrets.ids.isEmpty)
    #expect(try state.snapshot().accounts.isEmpty)
}

@Test func approvalBindsFrozenClientAndIsConsumedOnce() async throws {
    let f = try await Fixture.make()
    try await f.broker.revokeGrant(f.grant.id)
    let grant = try await f.broker.grant(clientID: f.client.id, accountID: f.account.id,
        duration: 60, callLimit: 2, requiresApproval: true)
    guard case .approvalRequired(let id) = try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)
    else { Issue.record("Approval-required grant dispatched without approval"); return }
    #expect(f.secrets.reads == 0)
    #expect(try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus) == .approvalRequired(id))
    await #expect(throws: VaultError.denied) { _ = try await f.broker.resume(id, clientID: f.client.id) }
    try await f.broker.approveInvocation(id)
    let other = try await f.broker.registerClient()
    await #expect(throws: VaultError.denied) { _ = try await f.broker.resume(id, clientID: other.id) }
    #expect(try await f.broker.resume(id, clientID: f.client.id) == .demoReady)
    await #expect(throws: VaultError.denied) { _ = try await f.broker.resume(id, clientID: f.client.id) }
    #expect(try f.state.snapshot().grants.first { $0.id == grant.id }?.callsUsed == 1)
}

@Test func revocationAndExpiryCancelApprovalsBeforeSecretRead() async throws {
    let f = try await Fixture.make()
    try await f.broker.revokeGrant(f.grant.id)
    let grant = try await f.broker.grant(clientID: f.client.id, accountID: f.account.id,
        duration: 20, callLimit: 2, requiresApproval: true)
    guard case .approvalRequired(let id) = try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)
    else { Issue.record("Missing approval challenge"); return }
    try await f.broker.approveInvocation(id)
    try await f.broker.revokeGrant(grant.id)
    await #expect(throws: VaultError.denied) { _ = try await f.broker.resume(id, clientID: f.client.id) }
    #expect(f.secrets.reads == 0)
    _ = try await f.broker.grant(clientID: f.client.id, accountID: f.account.id, duration: 10, callLimit: 2, requiresApproval: true)
    guard case .approvalRequired(let second) = try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)
    else { Issue.record("Missing second approval challenge"); return }
    f.clock.advance(11)
    await #expect(throws: VaultError.denied) { try await f.broker.approveInvocation(second) }
    #expect(f.secrets.reads == 0)
}

@Test func adminSignatureCannotBeReplayedOrMovedToAnotherChallenge() async throws {
    let state = MemoryState(), secrets = MemorySecrets(), clock = Clock()
    let broker = Broker(state: state, secrets: secrets)
    let key = P256.Signing.PrivateKey()
    let admin = try Administration(broker: broker, publicKey: key.publicKey.x963Representation, now: { clock.now() })
    var request = AdminRequest(operation: .pairClient); request.uid = 501
    let first = try await admin.begin(request), second = try await admin.begin(request)
    let signature = try key.signature(for: first.payload).derRepresentation
    await #expect(throws: VaultError.denied) { _ = try await admin.authorize(second.id, signature: signature) }
    #expect(try state.snapshot().clients.isEmpty)
    #expect(try await admin.authorize(first.id, signature: signature).status == "completed")
    await #expect(throws: VaultError.denied) { _ = try await admin.authorize(first.id, signature: signature) }
    clock.advance(61)
    let secondSignature = try key.signature(for: second.payload).derRepresentation
    await #expect(throws: VaultError.denied) { _ = try await admin.authorize(second.id, signature: secondSignature) }
    #expect(try state.snapshot().clients.count == 1)
    var extra = request; extra.accountID = UUID()
    await #expect(throws: VaultError.invalidInput) { _ = try await admin.begin(extra) }
}

@Test func readClientIdentityComesFromBoundUIDAndNotRequest() async throws {
    let f = try await Fixture.make()
    let paired = try await f.broker.registerClient(uid: 502)
    _ = try await f.broker.grant(clientID: paired.id, accountID: f.account.id, duration: 60, callLimit: 1)
    let operations = ReadOperations(broker: f.broker)
    await #expect(throws: VaultError.denied) { _ = try await operations.perform(uid: 503, request: .init(operation: .accounts)) }
    #expect(try await operations.perform(uid: 502, request: .init(operation: .accounts)).accounts?.count == 1)
    await #expect(throws: VaultError.invalidInput) {
        _ = try await operations.perform(uid: 502, request: .init(operation: .accounts, accountID: f.account.id))
    }
}

@Test func cancellationAfterDispatchReturnsDeniedInsteadOfClaimingItStoppedWork() async throws {
    let adapter = PausedAdapter()
    let f = try await Fixture.make(adapter: adapter)
    try await f.broker.revokeGrant(f.grant.id)
    _ = try await f.broker.grant(clientID: f.client.id, accountID: f.account.id,
        duration: 60, callLimit: 2, requiresApproval: true)
    guard case .approvalRequired(let id) = try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)
    else { Issue.record("Missing approval challenge"); return }
    try await f.broker.approveInvocation(id)
    let invocation = Task { try await f.broker.resume(id, clientID: f.client.id) }
    await adapter.waitUntilStarted()
    await #expect(throws: VaultError.denied) { try await f.broker.cancelInvocation(id, clientID: f.client.id) }
    await #expect(throws: VaultError.denied) { try await f.broker.rejectInvocation(id) }
    await adapter.release()
    #expect(try await invocation.value == .demoReady)
}
