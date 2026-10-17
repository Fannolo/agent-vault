import AgentVaultContracts
@testable import AgentVaultCore
import CryptoKit
import Foundation
import Testing

/// The human app's path through the real `Administration` and `ContinuationOperations`: a signed
/// open names one exact step, and every later call is bound to that lease and connection.
private struct Relay {
    let f: WebFixture
    let admin: Administration
    let operations: ContinuationOperations
    let key: P256.Signing.PrivateKey

    static func make(start: [WebStep] = [.humanStep(.mfa)], reclassify: [WebStep] = []) async throws -> (Relay, BrowserRunID) {
        let f = try await WebFixture.make(start: start, reclassify: reclassify)
        let key = P256.Signing.PrivateKey()
        let admin = try Administration(broker: f.broker, publicKey: key.publicKey.x963Representation, now: { f.clock.now() })
        let relay = Relay(f: f, admin: admin, operations: ContinuationOperations(broker: f.broker), key: key)
        return (relay, try await f.startPausedRun())
    }

    init(f: WebFixture, admin: Administration, operations: ContinuationOperations, key: P256.Signing.PrivateKey) {
        self.f = f; self.admin = admin; self.operations = operations; self.key = key
    }

    func step() async throws -> HumanStepSummary { try #require(try await admin.snapshot().humanSteps.first) }

    func openRequest(_ step: HumanStepSummary) -> AdminRequest {
        var request = AdminRequest(operation: .openHumanStep)
        request.requestID = step.runID; request.accountID = step.accountID
        request.stepEpoch = step.epoch; request.humanStepKind = step.kind
        return request
    }

    func sign(_ challenge: AdminChallenge) throws -> Data { try key.signature(for: challenge.payload).derRepresentation }

    func open(_ step: HumanStepSummary, on connection: ContinuationConnectionID) async throws -> UUID {
        let challenge = try await admin.begin(openRequest(step), connection: connection)
        let reply = try await admin.authorize(challenge.id, signature: try sign(challenge), connection: connection)
        return try #require(reply.id)
    }

    func call(_ lease: UUID, _ operation: ContinuationRequest.Operation,
              on connection: ContinuationConnectionID) async -> ContinuationReply {
        await operations.perform(ContinuationRequest(lease: lease, operation: operation), connection: connection)
    }

    /// Polls after the broker's minimum poll interval.
    func poll(_ lease: UUID, after: UInt64 = 0, on connection: ContinuationConnectionID) async -> ContinuationReply {
        try? await Task.sleep(for: .milliseconds(60))
        return await call(lease, .frame(after: after), on: connection)
    }
}

private func frame(_ sequence: UInt64, width: Int = 320, height: Int = 200) -> HumanFrame {
    HumanFrame(sequence: sequence, width: width, height: height, jpeg: Data([0xFF, 0xD8] + Array(repeating: 0, count: 12) + [0xFF, 0xD9]))!
}

private func batch(_ events: HumanInput...) -> HumanInputBatch { HumanInputBatch(events)! }

@Suite(.serialized) struct ContinuationRelayTests {
    @Test func snapshotListsOnlyStepMetadataAndASignedOpenNamesThatExactStep() async throws {
        let (r, run) = try await Relay.make()
        let step = try await r.step()
        #expect(step.runID == run.uuid && step.epoch == 1 && step.kind == .mfa && step.accountID == r.f.account.id)
        #expect(step.service == .githubWeb && step.expiresAt == r.f.clock.now().addingTimeInterval(600))
        let connection = ContinuationConnectionID()

        var wrong: [AdminRequest] = []
        for change in 0..<4 {
            var request = r.openRequest(step)
            switch change {
            case 0: request.stepEpoch = 2
            case 1: request.humanStepKind = .captcha
            case 2: request.accountID = UUID()
            default: request.requestID = UUID()
            }
            wrong.append(request)
        }
        for request in wrong {
            await #expect(throws: VaultError.denied) { _ = try await r.admin.begin(request, connection: connection) }
        }
        await #expect(throws: VaultError.denied) { _ = try await r.admin.begin(r.openRequest(step)) }
        var partial = r.openRequest(step); partial.humanStepKind = nil
        await #expect(throws: VaultError.invalidInput) { _ = try await r.admin.begin(partial, connection: connection) }

        let lease = try await r.open(step, on: connection)
        #expect(r.f.host.shownSteps.map(\.epoch) == [1])
        #expect(await r.call(lease, .frame(after: 0), on: connection) == .noFrame)
        #expect(r.f.callsUsed == 1)
    }

    @Test func aChallengeBegunOnOneConnectionCannotBeAuthorizedOnAnotherAndStaysSingleUse() async throws {
        let (r, _) = try await Relay.make()
        let step = try await r.step()
        let first = ContinuationConnectionID(), other = ContinuationConnectionID()
        let challenge = try await r.admin.begin(r.openRequest(step), connection: first)
        let signature = try r.sign(challenge)
        await #expect(throws: VaultError.denied) { _ = try await r.admin.authorize(challenge.id, signature: signature, connection: other) }
        await #expect(throws: VaultError.denied) { _ = try await r.admin.authorize(challenge.id, signature: signature, connection: first) }
        await #expect(throws: VaultError.denied) { _ = try await r.admin.authorize(challenge.id, signature: signature) }
        #expect(!r.f.humanAudit.contains("continuation_opened"))
        #expect(r.f.host.shownSteps.isEmpty)
    }

    @Test func aStaleSignedOpenCannotAuthorizeTheNextChallengeEvenOfTheSameKind() async throws {
        let (r, run) = try await Relay.make(start: [.humanStep(.mfa)], reclassify: [.humanStep(.mfa)])
        let first = try await r.step()
        let connection = ContinuationConnectionID()
        let delayed = try await r.admin.begin(r.openRequest(first), connection: connection)
        let lease = try await r.open(first, on: connection)
        #expect(await r.call(lease, .finish, on: connection) == .nextStep(.mfa))

        let second = try await r.step()
        #expect(second.runID == run.uuid && second.kind == .mfa && second.epoch == 2)
        await #expect(throws: VaultError.denied) {
            _ = try await r.admin.authorize(delayed.id, signature: try r.sign(delayed), connection: connection)
        }
        await #expect(throws: VaultError.denied) { _ = try await r.admin.begin(r.openRequest(first), connection: connection) }
        #expect(await r.call(lease, .frame(after: 0), on: connection) == .failure(.accessDenied))
        let next = try await r.open(second, on: connection)
        #expect(next != lease)
        #expect(await r.call(next, .cancel, on: connection) == .concluded)
        #expect(r.f.host.openContexts == 0)
    }

    @Test func framesAndInputAreBoundToTheLeaseItsConnectionAndTheLatestFrameServed() async throws {
        let (r, run) = try await Relay.make()
        let connection = ContinuationConnectionID(), stranger = ContinuationConnectionID()
        let lease = try await r.open(try await r.step(), on: connection)

        #expect(await r.call(UUID(), .frame(after: 0), on: connection) == .failure(.accessDenied))
        #expect(await r.call(lease, .frame(after: 0), on: stranger) == .failure(.accessDenied))
        #expect(await r.call(lease, .input(batch: 1, frame: 1, batch(.key(.enter))), on: stranger) == .failure(.accessDenied))
        #expect(await r.call(run.uuid, .cancel, on: connection) == .failure(.accessDenied), "a run ID is not a lease")
        #expect(await r.call(lease, .input(batch: 1, frame: 1, batch(.key(.enter))), on: connection) == .notDelivered,
                "no frame has been seen yet")

        r.f.host.serve(frame(1))
        #expect(await r.poll(lease, on: connection) == .frame(frame(1)))
        #expect(await r.call(lease, .input(batch: 1, frame: 1, batch(.key(.enter))), on: connection) == .notDelivered,
                "batch 1 was consumed by the refused attempt")
        #expect(await r.call(lease, .input(batch: 2, frame: 1, batch(.pointer(.down, x: 10, y: 10))), on: connection) == .delivered)
        #expect(await r.call(lease, .input(batch: 2, frame: 1, batch(.pointer(.up, x: 10, y: 10))), on: connection) == .notDelivered,
                "a replayed batch number")
        #expect(await r.call(lease, .input(batch: 3, frame: 2, batch(.key(.tab))), on: connection) == .notDelivered,
                "a frame this lease never received")
        #expect(await r.call(lease, .input(batch: 4, frame: 1, batch(.pointer(.down, x: 320, y: 0))), on: connection) == .notDelivered,
                "outside the served frame")

        r.f.host.serve(frame(2, width: 640, height: 400))
        #expect(await r.poll(lease, after: 1, on: connection) == .frame(frame(2, width: 640, height: 400)))
        #expect(await r.call(lease, .input(batch: 5, frame: 1, batch(.key(.tab))), on: connection) == .notDelivered, "a stale frame")
        #expect(await r.call(lease, .input(batch: 6, frame: 2, batch(.pointer(.move, x: 500, y: 300))), on: connection) == .delivered)

        let delivered = r.f.host.deliveredInput
        #expect(delivered.map(\.frame) == [1, 2])
        #expect(delivered.map(\.batch.events) == [[.pointer(.down, x: 10, y: 10)], [.pointer(.move, x: 500, y: 300)]])
        #expect(delivered.allSatisfy { $0.step.run == run && $0.step.epoch == 1 })
        #expect(r.f.callsUsed == 1, "relay calls reserve no budget")
    }

    @Test func pollingIsPacedAndOneFrameAndOneInputMayBeInFlightPerLease() async throws {
        let (r, _) = try await Relay.make()
        let connection = ContinuationConnectionID()
        let lease = try await r.open(try await r.step(), on: connection)
        r.f.host.serve(frame(1))
        #expect(await r.poll(lease, on: connection) == .frame(frame(1)))
        #expect(await r.call(lease, .frame(after: 1), on: connection) == .failure(.busy), "polled inside the interval")
        #expect(r.f.host.frameRequests == 1)

        await r.f.host.frameHold.arm()
        try await Task.sleep(for: .milliseconds(60))
        let held = Task { await r.call(lease, .frame(after: 0), on: connection) }
        await r.f.host.frameHold.waitUntilReached()
        try await Task.sleep(for: .milliseconds(60))
        #expect(await r.call(lease, .frame(after: 0), on: connection) == .failure(.busy))
        #expect(await r.call(lease, .input(batch: 1, frame: 1, batch(.key(.enter))), on: connection) == .delivered,
                "input has its own lane")
        await r.f.host.frameHold.open()
        #expect(await held.value == .frame(frame(1)))
        #expect(r.f.host.frameRequests == 2)
    }

    @Test func revocationWhileAFrameIsInFlightDiscardsItAndEndsTheContext() async throws {
        let (r, run) = try await Relay.make()
        let connection = ContinuationConnectionID()
        let lease = try await r.open(try await r.step(), on: connection)
        r.f.host.serve(frame(1))
        await r.f.host.frameHold.arm()
        let held = Task { await r.call(lease, .frame(after: 0), on: connection) }
        await r.f.host.frameHold.waitUntilReached()
        try await r.f.broker.revokeGrant(r.f.grant.id)
        #expect(!r.f.host.contextOpen(run))
        await r.f.host.frameHold.open()
        #expect(await held.value == .failure(.accessDenied), "a frame answered after revocation is not shown")
        #expect(await r.broker.relayCount == 0)
    }

    @Test func hostLossWhileInputIsInFlightLeavesNothingToOperate() async throws {
        let (r, run) = try await Relay.make()
        let connection = ContinuationConnectionID()
        let lease = try await r.open(try await r.step(), on: connection)
        r.f.host.serve(frame(1))
        #expect(await r.poll(lease, on: connection) == .frame(frame(1)))
        await r.f.host.inputHold.arm()
        let held = Task { await r.call(lease, .input(batch: 1, frame: 1, batch(.text("SYNTHETIC-123456"))), on: connection) }
        await r.f.host.inputHold.waitUntilReached()
        r.f.host.lose()
        while try await !r.f.broker.pendingHumanSteps().isEmpty { try await Task.sleep(for: .milliseconds(5)) }
        await r.f.host.inputHold.open()
        #expect(await held.value == .failure(.accessDenied))
        #expect(await r.call(lease, .finish, on: connection) == .failure(.accessDenied))
        await #expect(throws: VaultError.sessionLost) { _ = try await r.f.resume(run) }
    }

    enum Invalidation: CaseIterable { case connection, windowClosed, expiry, revokeGrant, revokeClient, rotate, delete }

    @Test(arguments: Invalidation.allCases)
    func everyLifecycleEventInvalidatesTheLease(_ event: Invalidation) async throws {
        let (r, run) = try await Relay.make()
        let connection = ContinuationConnectionID()
        let lease = try await r.open(try await r.step(), on: connection)
        r.f.host.serve(frame(1))
        #expect(await r.poll(lease, on: connection) == .frame(frame(1)))
        switch event {
        case .connection: await r.f.broker.continuationConnectionClosed(connection)
        case .windowClosed: #expect(await r.call(lease, .close, on: connection) == .closed)
        case .expiry: r.f.clock.advance(601)
        case .revokeGrant: try await r.f.broker.revokeGrant(r.f.grant.id)
        case .revokeClient: try await r.f.broker.revokeClient(r.f.client.id)
        case .rotate:
            try await r.f.broker.rotate(accountID: r.f.account.id, credential: Data("synthetic-user\nSYNTHETIC-rotated".utf8))
        case .delete: try await r.f.broker.deleteAccount(r.f.account.id)
        }
        try await Task.sleep(for: .milliseconds(60))
        for operation: ContinuationRequest.Operation in [.frame(after: 0), .input(batch: 1, frame: 1, batch(.key(.enter))),
                                                         .finish, .cancel, .close] {
            #expect(await r.call(lease, operation, on: connection) == .failure(.accessDenied))
        }
        #expect(r.f.host.deliveredInput.isEmpty)
        #expect(await r.broker.relayCount == 0)
        switch event {
        case .connection, .windowClosed:
            #expect(try await r.f.resume(run) == .humanStepRequired(run), "losing the window keeps the pause")
            let reopened = try await r.open(try await r.step(), on: connection)
            #expect(reopened != lease)
            #expect(r.f.humanAudit.contains("continuation_closed"))
        case .expiry:
            #expect(!r.f.host.contextOpen(run))
            #expect(r.f.audit.contains("human_step_expired"))
        default:
            #expect(!r.f.host.contextOpen(run))
        }
    }

    @Test func aConnectionThatHasClosedCanNeitherOpenNorUseALease() async throws {
        let (r, run) = try await Relay.make()
        let step = try await r.step()
        let liveness = Liveness()
        let closing = ContinuationConnectionID(minted: UUID(), isOpen: { liveness.isOpen })
        let challenge = try await r.admin.begin(r.openRequest(step), connection: closing)
        liveness.close()
        await #expect(throws: VaultError.denied) {
            _ = try await r.admin.authorize(challenge.id, signature: try r.sign(challenge), connection: closing)
        }
        #expect(await r.broker.relayCount == 0 && r.f.host.shownSteps.isEmpty)
        #expect(!r.f.humanAudit.contains("continuation_opened"))

        let other = Liveness()
        let connection = ContinuationConnectionID(minted: UUID(), isOpen: { other.isOpen })
        let lease = try await r.open(step, on: connection)
        other.close()
        #expect(await r.call(lease, .frame(after: 0), on: connection) == .failure(.accessDenied),
                "refused as soon as the transport marks the connection closed")
        #expect(try await r.f.resume(run) == .humanStepRequired(run))
    }

    @Test(arguments: [HumanStepDecision.finished, .cancel])
    func aClosedConnectionCannotConcludeBeforeItsClosedCallback(_ decision: HumanStepDecision) async throws {
        let (r, run) = try await Relay.make()
        let liveness = Liveness()
        let connection = ContinuationConnectionID(minted: UUID(), isOpen: { liveness.isOpen })
        let lease = try await r.open(try await r.step(), on: connection)
        liveness.close()
        await #expect(throws: VaultError.denied) {
            _ = try await r.broker.concludeHumanStep(ContinuationLeaseID(lease), connection: connection, decision: decision)
        }
        #expect(try await r.f.resume(run) == .humanStepRequired(run))
        #expect(r.f.host.contextOpen(run))
        #expect(await r.broker.relayCount == 1, "only the delayed close callback may remove this lease")
        await r.broker.continuationConnectionClosed(connection)
        #expect(await r.broker.relayCount == 0)
    }

    @Test func anOpenThatTheHostCannotShowGrantsNoLeaseAndKeepsThePause() async throws {
        let (r, run) = try await Relay.make()
        r.f.host.refuseToShow()
        let step = try await r.step()
        await #expect(throws: VaultError.upstreamUnavailable) { _ = try await r.open(step, on: ContinuationConnectionID()) }
        #expect(await r.broker.relayCount == 0)
        #expect(try await r.f.resume(run) == .humanStepRequired(run))
    }

    @Test func typedTextReachesOnlyTheHostAndNeverTheAuditOrTheAgent() async throws {
        let secret = "SYNTHETIC-MFA-424242"
        let (r, run) = try await Relay.make()
        let connection = ContinuationConnectionID()
        let lease = try await r.open(try await r.step(), on: connection)
        r.f.host.serve(frame(1))
        #expect(await r.poll(lease, on: connection) == .frame(frame(1)))
        #expect(await r.call(lease, .input(batch: 1, frame: 1, batch(.text(secret), .key(.enter))), on: connection) == .delivered)
        #expect(r.f.host.deliveredInput.first?.batch.events == [.text(secret), .key(.enter)])
        let state = String(decoding: try JSONEncoder().encode(try r.f.state.snapshot()), as: UTF8.self)
        let snapshot = String(decoding: try JSONEncoder().encode(try await r.admin.snapshot()), as: UTF8.self)
        #expect(!state.contains(secret) && !snapshot.contains(secret))
        #expect(try await r.f.resume(run) == .humanStepRequired(run), "the agent sees only the run's status")
    }
}

private extension Relay {
    var broker: Broker { f.broker }
}

private final class Liveness: @unchecked Sendable {
    private let lock = NSLock()
    private var open = true
    var isOpen: Bool { lock.withLock { open } }
    func close() { lock.withLock { open = false } }
}
