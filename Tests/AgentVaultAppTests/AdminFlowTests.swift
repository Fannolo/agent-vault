import AgentVaultContracts
@testable import AgentVaultAppSupport
import CryptoKit
import Foundation
import Testing

@MainActor
struct AdminFlowTests {
    struct Rig {
        let broker: InMemoryBroker
        let signer: SoftwareFixtureSigner
        let model: AppModel
    }

    func rig(features: AppFeatures = .production) async -> Rig {
        let signer = SoftwareFixtureSigner()
        let broker = InMemoryBroker(publicKey: signer.publicKey)
        return Rig(broker: broker, signer: signer, model: AppModel(transport: broker, signer: signer, features: features))
    }

    // MARK: Every operation: challenge, then signature

    @Test func fullLifecycleSignsEveryMutationOnce() async throws {
        let r = await rig()
        #expect(await r.model.enroll(service: .github, secret: "ghp_synthetic_token_123"))
        await r.model.refresh()
        let account = try #require(r.model.snapshot?.accounts.first)
        #expect(await r.model.pair(uid: 501))
        let clientID = try #require(r.model.lastPairedClientID)
        let plan = GrantPlan(clientID: clientID, accountID: account.id, duration: .oneHour, callLimit: 3, alwaysRequireApproval: true)
        #expect(await r.model.grant(plan))
        let grant = try #require(r.model.snapshot?.grants.first)
        #expect(grant.callsRemaining == 3 && grant.requiresApproval && grant.clientID == clientID && grant.accountID == account.id)
        #expect(await r.model.rotate(account: account, secret: "ghp_synthetic_token_456"))
        #expect(await r.model.revoke(grant: grant))
        #expect(r.model.snapshot?.grants.first?.revoked == true)
        let client = try #require(r.model.snapshot?.clients.first)
        #expect(await r.model.revoke(client: client))
        #expect(await r.model.delete(account: account))
        #expect(r.model.snapshot?.accounts.isEmpty == true)

        let applied = await r.broker.appliedOperations
        #expect(applied == [.enroll, .pairClient, .grant, .rotate, .revokeGrant, .revokeClient, .deleteAccount])
        #expect(r.signer.signCount == applied.count, "one fresh approval per mutation")
        #expect(await r.broker.rejectedAuthorizations == 0)
    }

    @Test func pendingApproveAndRejectNeedSignatures() async throws {
        let r = await rig()
        let item = PendingSummary(id: UUID(), clientID: UUID(), accountID: UUID(), action: .demoStatus, expiresAt: .now + 100)
        let other = PendingSummary(id: UUID(), clientID: UUID(), accountID: UUID(), action: .githubProfile, expiresAt: .now + 100)
        await r.broker.seed(pending: [item, other])
        await r.model.refresh()
        #expect(r.model.pendingItems.count == 2 && r.model.pendingItems.allSatisfy { $0.state == .waiting })
        #expect(await r.model.approve(item))
        #expect(await r.model.reject(other))
        #expect(r.model.snapshot?.pending.map(\.status) == ["approved"])
        #expect(r.signer.signCount == 2)
    }

    @Test func approvalPromptNamesTheActionWithoutLeakingTheCredential() async throws {
        let r = await rig()
        _ = await r.model.enroll(service: .demo, secret: "SYNTHETIC-prompt-secret")
        let reasons = r.signer.reasons
        #expect(reasons.count == 1 && reasons[0].hasPrefix("Add a Demo account"))
        #expect(!reasons[0].contains("SYNTHETIC"))
        #expect(await r.broker.credentialsReceived.values.contains(Data("SYNTHETIC-prompt-secret".utf8)),
                "the credential reaches the broker only through the begin request")
    }

    // MARK: Fail closed

    @Test(arguments: [ApprovalSigningError.userCancelled, .unsupported, .keyCreationFailed(-34018), .authenticationFailed])
    func signingFailureAppliesNothingAndNeverAuthorizes(error: ApprovalSigningError) async throws {
        let r = await rig()
        r.signer.failWith = error
        #expect(await r.model.enroll(service: .demo, secret: "synthetic-demo") == false)
        #expect(await r.broker.appliedOperations.isEmpty)
        #expect(r.model.snapshot?.accounts.isEmpty ?? true)
        #expect(r.model.notice?.kind == .failure)
    }

    @Test func unavailableBrokerFailsClosedWithoutSigning() async throws {
        let signer = SoftwareFixtureSigner()
        let model = AppModel(transport: UnavailableTransport(), signer: signer)
        #expect(await model.enroll(service: .demo, secret: "synthetic-demo") == false)
        #expect(signer.signCount == 0)
        await model.refresh()
        #expect(model.brokerReachable == false)
        await model.refreshAudit()
        #expect(model.auditStatus == .unavailable)
    }

    @Test func changedOperationChallengeIsRejectedBeforeSigningOrAuthorization() async throws {
        let signer = SoftwareFixtureSigner()
        let underlying = InMemoryBroker(publicKey: signer.publicKey)
        let transport = AlteredIntentTransport(broker: underlying)
        let model = AppModel(transport: transport, signer: signer)
        #expect(await model.pair(uid: 501) == false)
        #expect(signer.signCount == 0)
        #expect(await transport.authorizationCount == 0)
        #expect(await underlying.appliedOperations.isEmpty)
        #expect(model.notice?.text.contains("did not match") == true)
    }

    @Test func grantPromptIncludesExactScopeAndOnlySupportedDurations() async throws {
        let r = await rig()
        #expect(await r.model.enroll(service: .github, secret: "ghp_synthetic_token_123"))
        #expect(await r.model.pair(uid: 501))
        let account = try #require(r.model.snapshot?.accounts.first)
        let client = try #require(r.model.snapshot?.clients.first)
        #expect(await r.model.grant(GrantPlan(clientID: client.id, accountID: account.id,
            duration: .oneDay, callLimit: 3, alwaysRequireApproval: false)))
        let reason = try #require(r.signer.reasons.last)
        #expect(reason.contains(client.id.uuidString.lowercased()) && reason.contains(account.id.uuidString.lowercased()))
        #expect(reason.contains("UID 501") && reason.contains("GitHub API") && reason.contains("86400 seconds"))
        #expect(reason.contains("3 calls") && reason.contains("without per-call approval"))
        #expect(GrantDuration.allCases.allSatisfy { $0.rawValue > 0 && $0.rawValue <= 86_400 })
    }

    @Test func malformedInputNeverReachesTheBroker() async throws {
        let r = await rig(features: AppFeatures(browserServicesEnabled: true))
        #expect(await r.model.enroll(service: .github, secret: "short") == false)
        #expect(await r.model.enroll(service: .demo, secret: "") == false)
        #expect(await r.model.enroll(service: .githubWeb, secret: "pw", username: "") == false)
        #expect(await r.model.grant(GrantPlan(clientID: UUID(), accountID: UUID(), callLimit: 0)) == false)
        #expect(r.signer.signCount == 0)
        #expect(await r.broker.appliedOperations.isEmpty)
    }

    @Test func browserServicesAreDisabledInProductionBuilds() async throws {
        let production = await rig()
        #expect(AppFeatures.production.enrollableServices == [.demo, .github])
        #expect(await production.model.enroll(service: .githubWeb, secret: "pw", username: "octo") == false)
        #expect(await production.model.enroll(service: .browserDemo, secret: "pw", username: "octo") == false)
        #expect(production.signer.signCount == 0)
        let enabled = await rig(features: AppFeatures(browserServicesEnabled: true))
        #expect(await enabled.model.enroll(service: .githubWeb, secret: "pw", username: "octo"))
        #expect(await enabled.broker.credentialsReceived.values.first == Data("octo\npw".utf8))
    }

    // MARK: Broker-side single use

    @Test func signatureForOneChallengeCannotAuthorizeAnother() async throws {
        let signer = SoftwareFixtureSigner()
        let broker = InMemoryBroker(publicKey: signer.publicKey)
        var request = AdminRequest(operation: .pairClient); request.uid = 501
        let a = try await broker.begin(request)
        let b = try await broker.begin(request)
        let signatureA = try await signer.sign(payload: a.payload, reason: "x")
        let signatureB = try await signer.sign(payload: b.payload, reason: "x")
        #expect(try await broker.authorize(challengeID: b.id, signature: signatureA).status == "signature_invalid")
        #expect(try await broker.authorize(challengeID: b.id, signature: signatureB).status == "challenge_invalid",
                "a challenge is consumed even by a failed attempt")
        #expect(await broker.appliedOperations.isEmpty)
        #expect(try await broker.authorize(challengeID: a.id, signature: signatureA).status == "ok")
        #expect(await broker.appliedOperations == [.pairClient])
    }

    @Test func replayAndExpiryAreRejectedAndServiceDoesNotSignExpiredChallenges() async throws {
        let signer = SoftwareFixtureSigner()
        let broker = InMemoryBroker(publicKey: signer.publicKey)
        var request = AdminRequest(operation: .pairClient); request.uid = 7
        let c = try await broker.begin(request)
        let sig = try await signer.sign(payload: c.payload, reason: "x")
        #expect(try await broker.authorize(challengeID: c.id, signature: sig).status == "ok")
        #expect(try await broker.authorize(challengeID: c.id, signature: sig).status == "challenge_invalid")

        await broker.setChallengeLifetime(0.2)
        let service = AdminAuthorizationService(transport: broker, signer: signer)
        await #expect(throws: AdminFailure.challengeExpired) { _ = try await service.perform(request, summary: "x") }
        #expect(signer.signCount == 1, "no signature was produced for the already-expired challenge")
    }

    @Test func brokerRejectsSignaturesFromAnotherKey() async throws {
        let trusted = SoftwareFixtureSigner()
        let intruder = SoftwareFixtureSigner()
        let broker = InMemoryBroker(publicKey: trusted.publicKey)
        let model = AppModel(transport: broker, signer: intruder)
        #expect(await model.pair(uid: 1) == false)
        #expect(await broker.appliedOperations.isEmpty)
        #expect(model.notice?.text.contains("signature_invalid") == true)
    }

    // MARK: Audit

    @Test func auditExportContainsOnlySafeMetadata() async throws {
        let r = await rig()
        let entry = AuditSummary(timestamp: Date(timeIntervalSince1970: 1_700_000_000), clientID: UUID(), accountID: UUID(),
                                 action: .demoStatus, outcome: "completed")
        await r.broker.seed(audit: [entry])
        await r.model.refreshAudit()
        #expect(r.model.auditStatus == .loaded)
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("agentvault-audit-\(UUID()).json")
        defer { try? FileManager.default.removeItem(at: url) }
        r.model.exportAudit(to: url)
        let rows = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [[String: Any]])
        #expect(rows.count == 1)
        #expect(Set(rows[0].keys) == ["timestamp", "clientID", "accountID", "action", "outcome"])
        let permissions = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
        #expect(permissions == 0o600)
    }

    @Test func approvedRequestCannotBeApprovedOrRejectedAgain() async throws {
        let r = await rig()
        let item = PendingSummary(id: UUID(), clientID: UUID(), accountID: UUID(), action: .demoStatus, expiresAt: .now + 100)
        await r.broker.seed(pending: [item])
        await r.model.refresh()
        #expect(await r.model.approve(item))
        let approved = try #require(r.model.snapshot?.pending.first)
        #expect(approved.status == "approved" && PendingItem(approved).state == .approved)
        #expect(await r.model.approve(approved) == false)
        #expect(await r.model.reject(approved) == false)
        #expect(r.signer.signCount == 1, "no second prompt or signature for an approved request")
        #expect(PendingItem(PendingSummary(id: UUID(), clientID: UUID(), accountID: UUID(), action: .demoStatus,
                                           expiresAt: .now, status: "mystery")).state == .unknown)
    }

    @Test func auditSummaryMapsToSafeEntry() async throws {
        let summary = AuditSummary(timestamp: .now, clientID: UUID(), accountID: nil, action: .githubWebProfile, outcome: "denied")
        let entry = AuditEntry(summary)
        #expect(entry.action == "github.web_profile" && entry.accountID == nil && entry.outcome == "denied")
    }
}

extension InMemoryBroker {
    func setChallengeLifetime(_ value: TimeInterval) { challengeLifetime = value }
}

private actor AlteredIntentTransport: VaultAdminTransport {
    let broker: InMemoryBroker
    private(set) var authorizationCount = 0
    init(broker: InMemoryBroker) { self.broker = broker }
    func snapshot() async throws -> AdminSnapshot { try await broker.snapshot() }
    func begin(_ request: AdminRequest) async throws -> AdminChallenge {
        var altered = request
        altered.uid = 502
        return try await broker.begin(altered)
    }
    func authorize(challengeID: UUID, signature: Data) async throws -> AdminReply {
        authorizationCount += 1
        return try await broker.authorize(challengeID: challengeID, signature: signature)
    }
    func continueHuman(_ request: ContinuationRequest) async throws -> ContinuationReply { try await broker.continueHuman(request) }
}
