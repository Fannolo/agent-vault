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
    #expect(state.audit.count == VaultState.maxInvocationAudit)
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
        try await f.broker.cancelInvocation(id, clientID: f.client.id)
    }
    let state = try f.state.snapshot()
    #expect(state.audit.count == VaultState.maxInvocationAudit)
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
    #expect(try await broker.resume(first, clientID: client.id) == .demoReady)
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
        for _ in 0..<2000 { state.record(client: client, account: nil, action: nil, outcome: "denied", at: timestamp) }
    }
    let restored = try FileStateStore(directory: root).snapshot()
    #expect(restored.adminAudit.count == VaultState.maxAdministrationAudit)
    #expect(restored.audit.count == VaultState.maxInvocationAudit)
    #expect(restored.adminAudit.count + restored.audit.count == 1000)
    #expect(throws: VaultError.stateUnavailable) { try store.transaction { $0.adminAudit.append($0.adminAudit[0]) } }
    #expect(try store.snapshot().adminAudit.count == VaultState.maxAdministrationAudit)
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
