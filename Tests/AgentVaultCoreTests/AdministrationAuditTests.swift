import AgentVaultCore
import Foundation
import Testing

private func auditBytes(_ events: [AuditEvent]) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    return try encoder.encode(events)
}

@Test func agentDenialFloodCannotEvictAdministrationHistory() async throws {
    let f = try await Fixture.make()
    try await f.broker.revokeGrant(f.grant.id)
    let before = try auditBytes(f.state.snapshot().adminAudit)
    for _ in 0..<1000 {
        await #expect(throws: VaultError.denied) {
            _ = try await f.broker.run(clientID: f.client.id, accountID: UUID(), action: .demoStatus)
        }
    }
    #expect(try f.state.snapshot().audit.isEmpty)
    for _ in 0..<1000 {
        await #expect(throws: VaultError.denied) {
            _ = try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)
        }
    }
    let state = try f.state.snapshot()
    #expect(state.audit.map(\.outcome) == ["denied"])
    #expect(try auditBytes(state.adminAudit) == before)
    #expect(state.adminAudit.contains { $0.outcome == "grant_created" })
    #expect(state.adminAudit.contains { $0.outcome == "grant_revoked" })
    #expect(f.secrets.reads == 0)
}

@Test func agentApprovalCancellationChurnCannotWriteAdministrationHistory() async throws {
    let f = try await Fixture.make()
    try await f.broker.revokeGrant(f.grant.id)
    _ = try await f.broker.grant(clientID: f.client.id, accountID: f.account.id,
        duration: 300, callLimit: 2, requiresApproval: true)
    let before = try auditBytes(f.state.snapshot().adminAudit)
    for _ in 0..<400 {
        guard case .approvalRequired(let id) = try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)
        else { Issue.record("Missing approval request"); return }
        try await f.broker.cancel(id.uuid, clientID: f.client.id)
    }
    let state = try f.state.snapshot()
    #expect(state.audit.map(\.outcome) == ["approval_requested", "approval_cancelled"])
    #expect(try auditBytes(state.adminAudit) == before)
    #expect(f.secrets.reads == 0)
}

@Test func successfulAdministrationMutationsHaveTransactionalLifecycleEvidence() async throws {
    let state = MemoryState(), secrets = MemorySecrets()
    let broker = Broker(state: state, secrets: secrets)
    let account = try await broker.enroll(service: .demo, credential: Data("SYNTHETIC-initial".utf8))
    let client = try await broker.registerClient(uid: 501)
    #expect(try await broker.registerClient(uid: 501).id == client.id)
    let grant = try await broker.grant(clientID: client.id, accountID: account.id,
        duration: 300, callLimit: 10, requiresApproval: true)
    guard case .approvalRequired(let first) = try await broker.run(clientID: client.id, accountID: account.id, action: .demoStatus)
    else { Issue.record("Missing first approval request"); return }
    try await broker.approveInvocation(first)
    #expect(try await broker.resume(first.uuid, clientID: client.id) == .demoReady)
    guard case .approvalRequired(let second) = try await broker.run(clientID: client.id, accountID: account.id, action: .demoStatus)
    else { Issue.record("Missing second approval request"); return }
    try await broker.rejectInvocation(second)
    try await broker.revokeGrant(grant.id)
    try await broker.rotate(accountID: account.id, credential: Data("SYNTHETIC-replacement".utf8))
    try await broker.deleteAccount(account.id)
    try await broker.revokeClient(client.id)
    try await broker.recoverInterruptedLifecycle()
    try await broker.prune()
    let audit = try state.snapshot().adminAudit
    let outcomes = Set(audit.map(\.outcome))
    let expected: Set<String> = ["enrollment_started", "enrollment_completed", "client_paired", "client_pair_reused",
        "grant_created", "invocation_approved", "invocation_rejected", "grant_revoked", "rotation_started",
        "rotation_committed", "rotation_completed", "deletion_started", "deletion_completed", "client_revoked",
        "recovery_started", "recovery_completed", "pruned"]
    #expect(expected.isSubset(of: outcomes))
    for event in audit where event.accountID != nil {
        #expect(event.accountID == account.id)
        #expect(event.action == .demoStatus)
    }
    #expect(audit.first { $0.outcome == "enrollment_completed" }?.clientID == VaultState.administrationPrincipal)
    #expect(audit.first { $0.outcome == "client_paired" }?.clientID == client.id)
    #expect(!String(decoding: try JSONEncoder().encode(state.snapshot()), as: UTF8.self).contains("SYNTHETIC"))
}

@Test func administrationAndInvocationRingsPersistIndependentlyWithin1000Events() throws {
    let root = try privateDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try FileStateStore(directory: root)
    let client = UUID(), timestamp = Date()
    try store.transaction { state in
        state.clients.append(.init(id: client))
        for _ in 0..<300 { state.recordAdministration(client: client, outcome: "client_paired", at: timestamp) }
        for _ in 0..<2000 { state.record(client: client, account: nil, action: nil, outcome: "completed", at: timestamp) }
    }
    let restored = try FileStateStore(directory: root).snapshot()
    #expect(restored.adminAudit.count == VaultState.maxAdministrationAudit)
    #expect(restored.audit.count == VaultState.maxInvocationAudit)
    #expect(restored.adminAudit.count + restored.audit.count == 1000)
    #expect(throws: VaultError.stateUnavailable) { try store.transaction { $0.adminAudit.append($0.adminAudit[0]) } }
    #expect(try store.snapshot().adminAudit.count == VaultState.maxAdministrationAudit)
}

@Test func completedWorkSurvives800ExhaustedGrantDenials() async throws {
    let f = try await Fixture.make(calls: 1)
    #expect(try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus) == .demoReady)
    for _ in 0..<800 {
        await #expect(throws: VaultError.denied) {
            _ = try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus)
        }
    }
    let state = try f.state.snapshot()
    #expect(state.audit.map(\.outcome) == ["reserved", "completed", "denied"])
    #expect(state.grants.first { $0.id == f.grant.id }?.callsUsed == 1)
    #expect(f.secrets.reads == 1)
}

@Test func successfulClientFloodPreservesAnotherClientsSmallHistory() async throws {
    let f = try await Fixture.make(calls: 10_000)
    let victim = try await f.broker.registerClient()
    _ = try await f.broker.grant(clientID: victim.id, accountID: f.account.id, duration: 60, callLimit: 3)
    for _ in 0..<3 {
        #expect(try await f.broker.run(clientID: victim.id, accountID: f.account.id, action: .demoStatus) == .demoReady)
    }
    let victimBefore = try auditBytes(f.state.snapshot().audit.filter { $0.clientID == victim.id })
    let administrationBefore = try auditBytes(f.state.snapshot().adminAudit)
    for _ in 0..<400 {
        #expect(try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus) == .demoReady)
    }
    let state = try f.state.snapshot()
    #expect(state.audit.count == VaultState.maxInvocationAudit)
    #expect(try auditBytes(state.audit.filter { $0.clientID == victim.id }) == victimBefore)
    #expect(try auditBytes(state.adminAudit) == administrationBefore)
    #expect(state.grants.first { $0.id == f.grant.id }?.callsUsed == 400)
}

@Test func invocationRetentionSharesCapacityAcross128RegisteredClients() throws {
    let root = try privateDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try FileStateStore(directory: root), timestamp = Date()
    var before = VaultState()
    before.clients = (0..<VaultState.maxClients).map { _ in .init() }
    for client in before.clients {
        for index in 0..<10 {
            before.record(client: client.id, account: nil, action: nil, outcome: "completed_\(index)", at: timestamp)
        }
    }
    let noisy = before.clients[0].id
    let protectedFloor = VaultState.maxInvocationAudit / VaultState.maxClients
    for client in before.clients {
        let outcomes = before.audit.filter { $0.clientID == client.id }.map(\.outcome)
        #expect(outcomes.count >= protectedFloor)
        #expect(outcomes.last == "completed_9")
    }
    var hammered = before
    for _ in 0..<2000 { hammered.record(client: noisy, account: nil, action: nil, outcome: "completed", at: timestamp) }
    // Unpaired UUIDs do not create retention partitions, even through the data model API.
    for _ in 0..<2000 { hammered.record(client: UUID(), account: nil, action: nil, outcome: "denied", at: timestamp) }
    // Hold the store's global process lock only for persistence, not the synthetic flood.
    try store.transaction { $0 = hammered }
    let after = try FileStateStore(directory: root).snapshot()
    #expect(after.audit.count == VaultState.maxInvocationAudit)
    for client in before.clients where client.id != noisy {
        let protectedHistory = Array(before.audit.filter { $0.clientID == client.id }.suffix(protectedFloor))
        let retained = after.audit.filter { $0.clientID == client.id }
        #expect(retained.count >= protectedFloor)
        #expect(try auditBytes(Array(retained.suffix(protectedFloor))) == auditBytes(protectedHistory))
    }
    #expect(after.audit.allSatisfy { event in after.clients.contains { $0.id == event.clientID } })
}

@Test func prunedClientHistoryCannotCreateUnboundedProtectedPartitions() throws {
    var state = VaultState()
    let timestamp = Date(), current = ClientRecord()
    // Existing history may outlive a revoked client removed by prune, or originate
    // from schema-3 writers that recorded unpaired denials before this policy.
    state.clients = (0..<VaultState.maxClients).map { _ in .init() }
    for client in state.clients {
        for _ in 0..<6 { state.record(client: client.id, account: nil, action: nil, outcome: "completed", at: timestamp) }
    }
    state.clients = [current]
    for _ in 0..<VaultState.maxInvocationAudit {
        state.record(client: current.id, account: nil, action: nil, outcome: "completed", at: timestamp)
    }
    #expect(state.audit.count == VaultState.maxInvocationAudit)
    #expect(state.audit.allSatisfy { $0.clientID == current.id })
}

@Test func unregisteredClientDenialsCannotDisplacePairedClientAudit() async throws {
    let f = try await Fixture.make(calls: 1)
    #expect(try await f.broker.run(clientID: f.client.id, accountID: f.account.id, action: .demoStatus) == .demoReady)
    let before = try auditBytes(f.state.snapshot().audit)
    for _ in 0..<1000 {
        await #expect(throws: VaultError.denied) {
            _ = try await f.broker.run(clientID: UUID(), accountID: f.account.id, action: .demoStatus)
        }
    }
    #expect(try auditBytes(f.state.snapshot().audit) == before)
    #expect(f.secrets.reads == 1)
}

@Test func schemaThreeRequiresAdministrationHistoryAndRefusesVersionTwo() throws {
    let root = try privateDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("state.json")
    let current = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(VaultState())) as? [String: Any])
    var missing = current; missing.removeValue(forKey: "adminAudit")
    var old = current; old["version"] = 2
    for variant in [missing, old] {
        let bytes = try JSONSerialization.data(withJSONObject: variant)
        try bytes.write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        #expect(throws: VaultError.stateUnavailable) { _ = try FileStateStore(directory: root).snapshot() }
        #expect(try Data(contentsOf: path) == bytes)
    }
}
