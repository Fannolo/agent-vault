import AgentVaultContracts
@testable import AgentVaultCore
import Foundation
import Testing

/// U0: the broker-owned browser run lifecycle, driven through the real Broker by a scripted host.
@Suite struct BrowserRunTests {
    @Test func approvedRunPausesForAPersonThenDeliversProfileOnceOnTheLastPermittedCall() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa)], reclassify: [.profile(syntheticProfile)],
                                          calls: 1, requiresApproval: true)
        guard case .approvalRequired(let approval) = try await f.run() else { Issue.record("no approval"); return }
        try await f.broker.approveInvocation(approval)
        guard case .humanStepRequired(let run) = try await f.broker.resume(approval.uuid, clientID: f.client.id)
        else { Issue.record("no human step"); return }
        #expect(run.uuid != approval.uuid)
        #expect(f.callsUsed == 1 && f.secrets.reads == 1 && f.host.startCount == 1)
        #expect(f.host.startedUsernames == ["synthetic-user"])

        // Polling is free, and the consumed approval's 120 s window does not end the 600 s pause.
        f.clock.advance(300)
        for _ in 0..<3 { #expect(try await f.resume(run) == .humanStepRequired(run)) }
        #expect(f.callsUsed == 1 && f.secrets.reads == 1 && f.host.startCount == 1)
        #expect(try await f.broker.availableAccounts(clientID: f.client.id).isEmpty, "budget exhausted")
        await #expect(throws: VaultError.denied) { _ = try await f.broker.resume(approval.uuid, clientID: f.client.id) }

        let connection = ContinuationConnectionID()
        let lease = try await f.openHumanStep(run, connection: connection)
        #expect(try await f.broker.concludeHumanStep(lease, connection: connection, decision: .finished) == .concluded)
        #expect(f.host.endCount(run) == 1 && f.host.openContexts == 0)

        #expect(try await f.resume(run) == .profile(syntheticProfile))
        await #expect(throws: VaultError.denied) { _ = try await f.resume(run) }
        #expect(f.callsUsed == 1)
        #expect(f.audit == ["approval_requested", "reserved", "human_step_required", "completed"])
        #expect(f.humanAudit.suffix(2) == ["continuation_opened", "human_finished"])
    }

    @Test func profileWithoutAHumanStepIsDeliveredDirectlyThroughReadOperations() async throws {
        let f = try await WebFixture.make(start: [.profile(syntheticProfile)])
        let paired = try await f.broker.registerClient(uid: 501)
        _ = try await f.broker.grant(clientID: paired.id, accountID: f.account.id, duration: 60, callLimit: 1)
        let reply = try await ReadOperations(broker: f.broker).perform(
            uid: 501, request: .init(operation: .run, accountID: f.account.id, action: .githubWebProfile))
        #expect(reply.parsedStatus == .outcome(.completed) && reply.profile == syntheticProfile && reply.isWellFormed)
        #expect(f.host.openContexts == 0 && f.host.startCount == 1)
    }

    @Test func pausedRunReplyCarriesOnlyTheRunIDAndAuditNeverSaysCompleted() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.captcha)])
        let paired = try await f.broker.registerClient(uid: 502)
        _ = try await f.broker.grant(clientID: paired.id, accountID: f.account.id, duration: 60, callLimit: 1)
        let operations = ReadOperations(broker: f.broker)
        let reply = try await operations.perform(uid: 502, request: .init(operation: .run, accountID: f.account.id,
                                                                         action: .githubWebProfile))
        #expect(reply.parsedStatus == .outcome(.humanStepRequired) && reply.isWellFormed)
        #expect(reply.login == nil && reply.userID == nil && reply.accounts == nil)
        let requestID = try #require(reply.requestID)
        let polled = try await operations.perform(uid: 502, request: .init(operation: .resume, requestID: requestID))
        #expect(polled.parsedStatus == .outcome(.humanStepRequired) && polled.requestID == requestID)
        let outcomes = try f.state.snapshot().audit.map(\.outcome)
        #expect(outcomes == ["reserved", "human_step_required"])
    }

    @Test func pauseUsesItsOwnWindowAndARepeatedStepKeepsTheOriginalDeadline() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa)], reclassify: [.humanStep(.captcha)])
        let run = try await f.startPausedRun()
        f.clock.advance(300)
        let connection = ContinuationConnectionID()
        let lease = try await f.openHumanStep(run, connection: connection)
        #expect(try await f.broker.concludeHumanStep(lease, connection: connection, decision: .finished)
                == .humanStepRequired(.captcha))
        // The lease belonged to the previous step; acting on the new one needs a new signed open.
        await #expect(throws: VaultError.denied) {
            _ = try await f.broker.concludeHumanStep(lease, connection: connection, decision: .cancel)
        }
        f.clock.advance(299)
        #expect(try await f.resume(run) == .humanStepRequired(run))
        #expect(f.host.contextOpen(run))
        f.clock.advance(1)
        await #expect(throws: VaultError.humanStepExpired) { _ = try await f.resume(run) }
        #expect(f.host.endCount(run) == 1 && !f.host.contextOpen(run))
        await #expect(throws: VaultError.denied) { _ = try await f.resume(run) }
        #expect(f.audit == ["reserved", "human_step_required", "human_step_required", "human_step_expired", "failed"])
        #expect(f.callsUsed == 1)
    }

    @Test func pauseNeverOutlivesItsGrant() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa)], duration: 100)
        let run = try await f.startPausedRun()
        f.clock.advance(99)
        #expect(try await f.resume(run) == .humanStepRequired(run))
        f.clock.advance(1)
        await #expect(throws: VaultError.denied) { _ = try await f.resume(run) }
        #expect(!f.host.contextOpen(run))
        #expect(f.audit == ["reserved", "human_step_required", "human_step_expired", "response_suppressed"])
    }

    @Test func unpolledPauseEndsItsContextAtTheDeadline() async throws {
        let windows = try LifecycleWindows(approval: 120, humanPause: 0.2, collect: 0.2)
        let f = try await WebFixture.make(start: [.humanStep(.mfa)], windows: windows, realClock: true)
        let run = try await f.startPausedRun()
        #expect(f.host.contextOpen(run))
        for _ in 0..<100 where f.host.contextOpen(run) { try await Task.sleep(for: .milliseconds(20)) }
        #expect(!f.host.contextOpen(run), "the broker must end the context without being polled")
        for _ in 0..<100 where f.audit.last != "result_uncollected" { try await Task.sleep(for: .milliseconds(20)) }
        #expect(f.audit == ["reserved", "human_step_required", "human_step_expired", "result_uncollected"])
        await #expect(throws: VaultError.denied) { _ = try await f.resume(run) }
    }

    @Test func revocationDuringHostStartSuppressesOutputAndEndsTheLateContext() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa)])
        await f.host.startHold.arm()
        let call = Task { try await f.run() }
        await f.host.startHold.waitUntilReached()
        try await f.broker.revokeGrant(f.grant.id)
        await f.host.startHold.open()
        await #expect(throws: VaultError.denied) { _ = try await call.value }
        #expect(f.host.openContexts == 0, "a context created by a late start reply must be ended")
        #expect(f.host.log.all.filter { $0 == "end" }.count == 2)
        #expect(f.audit == ["reserved", "response_suppressed"])
        #expect(f.callsUsed == 1)
    }

    @Test func hungHostStartEndsAtTheBrokerDeadlineAndFreesItsSlots() async throws {
        let windows = try LifecycleWindows(approval: 120, humanPause: 600, collect: 120, startReply: 0.2)
        let f = try await WebFixture.make(start: [.profile(syntheticProfile), .humanStep(.mfa)], windows: windows,
                                          realClock: true)
        await f.host.startHold.arm()
        let began = Date()
        await #expect(throws: VaultError.upstreamUnavailable) { _ = try await f.run() }
        #expect(Date().timeIntervalSince(began) < 1, "the initial call returns at the broker's own deadline")
        #expect(f.audit == ["reserved", "web_timeout", "failed"])
        // The account and live slots are free again; a new attempt is a new paid call.
        await f.host.startHold.open()
        #expect(try await f.startPausedRun() != BrowserRunID())
        #expect(f.callsUsed == 2)
        // The late reply created a context for the first run; it was ended, not delivered.
        for _ in 0..<100 where f.host.openContexts != 1 { try await Task.sleep(for: .milliseconds(10)) }
        #expect(f.host.openContexts == 1, "only the second run's context remains")
    }

    @Test func unansweredStartEndsAtItsDeadlineEvenWithoutAWaiter() async throws {
        let windows = try LifecycleWindows(approval: 120, humanPause: 600, collect: 120, startReply: 60)
        let f = try await WebFixture.make(start: [.humanStep(.mfa)], windows: windows)
        await f.host.startHold.arm()
        let call = Task { try await f.run() }
        await f.host.startHold.waitUntilReached()
        #expect(await f.broker.scheduledDeadlineCount == 1, "an unanswered start has its own deadline task")
        call.cancel()
        f.clock.advance(61)
        _ = try await f.broker.pendingHumanSteps()
        #expect(f.host.log.all.filter { $0 == "end" }.count == 1, "the sweep ends the context without the caller")
        #expect(f.audit == ["reserved", "web_timeout"])
        await f.host.startHold.open()
        await #expect(throws: VaultError.upstreamUnavailable) { _ = try await call.value }
        #expect(f.host.openContexts == 0, "the late context is ended")
        #expect(f.audit == ["reserved", "web_timeout", "failed"])
    }

    @Test func hungReclassificationConcludesAtTheBrokerDeadline() async throws {
        let windows = try LifecycleWindows(approval: 120, humanPause: 600, collect: 120, classifyReply: 0.2)
        let f = try await WebFixture.make(start: [.humanStep(.mfa)], reclassify: [.profile(syntheticProfile)],
                                          windows: windows, realClock: true)
        let run = try await f.startPausedRun()
        let connection = ContinuationConnectionID()
        let lease = try await f.openHumanStep(run, connection: connection)
        await f.host.reclassifyHold.arm()
        let began = Date()
        #expect(try await f.broker.concludeHumanStep(lease, connection: connection, decision: .finished) == .concluded)
        #expect(Date().timeIntervalSince(began) < 1)
        await #expect(throws: VaultError.upstreamUnavailable) { _ = try await f.resume(run) }
        #expect(!f.host.contextOpen(run))
        await f.host.reclassifyHold.open()
        #expect(f.audit == ["reserved", "human_step_required", "web_timeout", "failed"])
        #expect(f.callsUsed == 1, "polling, finishing and collecting reserve nothing")
    }

    @Test func clockJumpLeavingLessThanOneSecondOfGrantNeverDeliversTheSecret() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa)], duration: 3600)
        let started = AsyncStream.makeStream(of: Void.self)
        f.secrets.blockNextLoad { started.continuation.yield() }
        let call = Task { try await f.run() }
        var iterator = started.stream.makeAsyncIterator()
        _ = await iterator.next()
        f.clock.advance(3599.5)
        f.secrets.releaseLoad()
        await #expect(throws: VaultError.denied) { _ = try await call.value }
        #expect(f.host.startCount == 0 && f.host.log.all.isEmpty)
        #expect(f.audit == ["reserved", "response_suppressed"])
    }

    @Test func replyDeadlinesAreEnforcedByTheTransitionItself() throws {
        let windows = try LifecycleWindows(approval: 120, humanPause: 600, collect: 120, startReply: 15, classifyReply: 10)
        let t0 = Date(timeIntervalSince1970: 1_000)
        let binding = RunBinding(client: UUID(), account: UUID(), action: .githubWebProfile, grant: UUID(), credential: UUID())
        let run = BrowserRun(id: BrowserRunID(), binding: binding, grantExpiresAt: t0 + 3600)
        let (dispatching, _) = run.applying(.credentialLoaded, now: t0, windows: windows)
        #expect(dispatching?.phase.deadline == t0 + 15)
        let late = dispatching!.applying(.host(.profile(syntheticProfile), epoch: 1), now: t0 + 15, windows: windows)
        #expect(late.1 == [.audit("web_timeout"), .endHost], "a reply at the deadline is not applied")
        let swept = dispatching!.applying(.clock(t0 + 15), now: t0 + 15, windows: windows)
        #expect(swept.1 == [.audit("web_timeout"), .endHost])
        #expect(dispatching!.applying(.hostReplyOverdue(epoch: 0), now: t0, windows: windows).1.isEmpty,
                "an overdue notice for an older request changes nothing")
    }

    @Test func revocationDuringCredentialLoadNeverReachesTheHost() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa)])
        let started = AsyncStream.makeStream(of: Void.self)
        f.secrets.blockNextLoad { started.continuation.yield() }
        let call = Task { try await f.run() }
        var iterator = started.stream.makeAsyncIterator()
        _ = await iterator.next()
        try await f.broker.revokeGrant(f.grant.id)
        f.secrets.releaseLoad()
        await #expect(throws: VaultError.denied) { _ = try await call.value }
        #expect(f.host.startCount == 0)
        #expect(f.audit == ["reserved", "response_suppressed"])
    }

    @Test func revocationDuringReclassificationEndsTheRunAndIgnoresTheLateReply() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa)], reclassify: [.profile(syntheticProfile)])
        let run = try await f.startPausedRun()
        let connection = ContinuationConnectionID()
        let lease = try await f.openHumanStep(run, connection: connection)
        await f.host.reclassifyHold.arm()
        let finishing = Task { try await f.broker.concludeHumanStep(lease, connection: connection, decision: .finished) }
        await f.host.reclassifyHold.waitUntilReached()
        try await f.broker.revokeClient(f.client.id)
        await f.host.reclassifyHold.open()
        await #expect(throws: VaultError.denied) { _ = try await finishing.value }
        await #expect(throws: VaultError.denied) { _ = try await f.resume(run) }
        #expect(f.host.openContexts == 0)
        #expect(f.audit == ["reserved", "human_step_required", "response_suppressed"])
    }

    @Test func grantExpiryDuringReclassificationEndsTheContextWithoutWaitingForAPoll() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa)], reclassify: [.humanStep(.captcha)], duration: 100)
        let run = try await f.startPausedRun()
        let connection = ContinuationConnectionID()
        let lease = try await f.openHumanStep(run, connection: connection)
        await f.host.reclassifyHold.arm()
        let finishing = Task { try await f.broker.concludeHumanStep(lease, connection: connection, decision: .finished) }
        await f.host.reclassifyHold.waitUntilReached()
        f.clock.advance(100)
        await f.host.reclassifyHold.open()
        await #expect(throws: VaultError.denied) { _ = try await finishing.value }
        #expect(!f.host.contextOpen(run))
        #expect(f.audit == ["reserved", "human_step_required", "response_suppressed"])
    }

    @Test(arguments: [WebStep.profile(syntheticProfile), .humanStep(.captcha)], [1.0, 2.0])
    func lateClassificationCannotExtendTheHumanDeadline(reply: WebStep, delay: TimeInterval) async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa)], reclassify: [reply], calls: 1)
        let run = try await f.startPausedRun()
        f.clock.advance(599)
        let connection = ContinuationConnectionID()
        let lease = try await f.openHumanStep(run, connection: connection)
        await f.host.reclassifyHold.arm()
        let finishing = Task { try await f.broker.concludeHumanStep(lease, connection: connection, decision: .finished) }
        await f.host.reclassifyHold.waitUntilReached()
        f.clock.advance(delay)
        await f.host.reclassifyHold.open()
        #expect(try await finishing.value == .concluded)
        await #expect(throws: VaultError.humanStepExpired) { _ = try await f.resume(run) }
        #expect(f.host.openContexts == 0)
        #expect(f.audit == ["reserved", "human_step_required", "human_step_expired", "failed"])
        #expect(f.callsUsed == 1)
    }

    @Test func collectedResultsAndCancelledRunsReleaseTheirDeadlineTasks() async throws {
        let f = try await WebFixture.make(start: Array(repeating: .profile(syntheticProfile), count: 200)
                                          + [.humanStep(.mfa)], calls: 201)
        for _ in 0..<200 {
            #expect(try await f.run() == .profile(syntheticProfile))
            #expect(await f.broker.scheduledDeadlineCount == 0)
        }
        let run = try await f.startPausedRun()
        #expect(await f.broker.scheduledDeadlineCount == 1)
        try await f.broker.cancel(run.uuid, clientID: f.client.id)
        #expect(await f.broker.scheduledDeadlineCount == 0)
        #expect(f.host.openContexts == 0)
    }

    @Test func repeatedHumanStepsKeepOneDeadlineTask() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa)], reclassify: Array(repeating: .humanStep(.captcha), count: 3))
        let run = try await f.startPausedRun()
        let connection = ContinuationConnectionID()
        for _ in 0..<3 {
            f.clock.advance(100)
            let lease = try await f.openHumanStep(run, connection: connection)
            #expect(try await f.broker.concludeHumanStep(lease, connection: connection, decision: .finished)
                    == .humanStepRequired(.captcha))
            #expect(await f.broker.scheduledDeadlineCount == 1)
        }
        try await f.broker.cancel(run.uuid, clientID: f.client.id)
        #expect(await f.broker.scheduledDeadlineCount == 0)
    }

    @Test func rotationDuringHostStartEndsTheLateContext() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa)])
        await f.host.startHold.arm()
        let call = Task { try await f.run() }
        await f.host.startHold.waitUntilReached()
        try await f.broker.rotate(accountID: f.account.id, credential: Data("synthetic-user\nSYNTHETIC-next".utf8))
        await f.host.startHold.open()
        await #expect(throws: VaultError.denied) { _ = try await call.value }
        #expect(f.host.openContexts == 0)
        #expect(f.audit == ["reserved", "response_suppressed"])
        #expect(f.callsUsed == 1)
    }

    @Test func rotationEndsOnlyThatAccountsRunBeforeDeletingTheOldCredential() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa), .humanStep(.mfa)])
        let other = try await f.broker.enroll(service: .githubWeb, credential: syntheticWebCredential)
        _ = try await f.broker.grant(clientID: f.client.id, accountID: other.id, duration: 3600, callLimit: 1)
        let run = try await f.startPausedRun()
        guard case .humanStepRequired(let otherRun) = try await f.broker.run(
            clientID: f.client.id, accountID: other.id, action: .githubWebProfile) else { Issue.record("no run"); return }
        try await f.broker.rotate(accountID: f.account.id, credential: Data("synthetic-user\nSYNTHETIC-next".utf8))
        let log = f.host.log.all
        let end = try #require(log.firstIndex(of: "end")), deletion = try #require(log.firstIndex(of: "secret_deleted"))
        #expect(end < deletion, "the session ends before its credential is deleted")
        #expect(!f.host.contextOpen(run) && f.host.contextOpen(otherRun))
        await #expect(throws: VaultError.denied) { _ = try await f.resume(run) }
        #expect(try await f.broker.resume(otherRun.uuid, clientID: f.client.id) == .humanStepRequired(otherRun))
        try await f.broker.deleteAccount(other.id)
        #expect(f.host.openContexts == 0)
        await #expect(throws: VaultError.denied) { _ = try await f.broker.resume(otherRun.uuid, clientID: f.client.id) }
    }

    @Test func hostLossConcludesLiveRunsAsSessionLostWithoutRefund() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa)])
        let run = try await f.startPausedRun()
        f.host.lose()
        var failure: (any Error)?
        for _ in 0..<200 where failure == nil {
            do { _ = try await f.resume(run); try await Task.sleep(for: .milliseconds(5)) }
            catch { failure = error }
        }
        #expect(failure as? VaultError == .sessionLost)
        #expect(f.callsUsed == 1)
        #expect(f.audit == ["reserved", "human_step_required", "session_lost", "failed"])
    }

    @Test func lateLossOfAnOldConnectionEndsOnlyTheRunsItCarried() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa), .humanStep(.captcha)])
        let other = try await f.broker.enroll(service: .githubWeb, credential: syntheticWebCredential)
        _ = try await f.broker.grant(clientID: f.client.id, accountID: other.id, duration: 3600, callLimit: 1)
        let old = try await f.startPausedRun()
        // The old connection died; a new run starts on its replacement before the notice arrives.
        guard case .humanStepRequired(let new) = try await f.broker.run(
            clientID: f.client.id, accountID: other.id, action: .githubWebProfile) else { Issue.record("no run"); return }
        f.host.deliverLoss(of: [old])
        var failure: (any Error)?
        for _ in 0..<200 where failure == nil {
            do { _ = try await f.resume(old); try await Task.sleep(for: .milliseconds(5)) }
            catch { failure = error }
        }
        #expect(failure as? VaultError == .sessionLost)
        #expect(try await f.broker.resume(new.uuid, clientID: f.client.id) == .humanStepRequired(new))
        #expect(f.host.contextOpen(new))
        #expect(try await f.broker.pendingHumanSteps().map(\.id.run) == [new])
    }

    @Test func brokerRestartForgetsRunsAndDoesNotRefund() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa)])
        let run = try await f.startPausedRun()
        let restarted = Broker(state: f.state, secrets: f.secrets, webSessions: ScriptedWebHost(start: []),
                               now: { f.clock.now() })
        await #expect(throws: VaultError.denied) { _ = try await restarted.resume(run.uuid, clientID: f.client.id) }
        #expect(f.callsUsed == 1)
    }

    @Test func agentAndHumanCancellationEndTheContext() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa), .humanStep(.captcha)])
        let first = try await f.startPausedRun()
        try await f.broker.cancel(first.uuid, clientID: f.client.id)
        #expect(!f.host.contextOpen(first))
        await #expect(throws: VaultError.denied) { _ = try await f.resume(first) }

        let second = try await f.startPausedRun()
        let connection = ContinuationConnectionID()
        let lease = try await f.openHumanStep(second, connection: connection)
        #expect(try await f.broker.concludeHumanStep(lease, connection: connection, decision: .cancel) == .concluded)
        #expect(!f.host.contextOpen(second))
        await #expect(throws: VaultError.humanCancelled) { _ = try await f.resume(second) }
        #expect(f.audit == ["reserved", "human_step_required", "run_cancelled",
                            "reserved", "human_step_required", "failed"])
        #expect(f.humanAudit.suffix(2) == ["continuation_opened", "human_cancelled"])
    }

    @Test func leasesAreBoundToTheirConnectionAndAreNotAgentRequestIDs() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa)])
        let run = try await f.startPausedRun()
        let connection = ContinuationConnectionID()
        let lease = try await f.openHumanStep(run, connection: connection)
        await #expect(throws: VaultError.denied) {
            _ = try await f.broker.concludeHumanStep(lease, connection: ContinuationConnectionID(), decision: .cancel)
        }
        // The agent cannot use a lease, and another client cannot use the run.
        await #expect(throws: VaultError.denied) { _ = try await f.broker.resume(lease.uuid, clientID: f.client.id) }
        await #expect(throws: VaultError.denied) { try await f.broker.cancel(lease.uuid, clientID: f.client.id) }
        let other = try await f.broker.registerClient()
        await #expect(throws: VaultError.denied) { _ = try await f.broker.resume(run.uuid, clientID: other.id) }
        await #expect(throws: VaultError.denied) { try await f.broker.cancel(run.uuid, clientID: other.id) }

        await f.broker.continuationConnectionClosed(connection)
        await #expect(throws: VaultError.denied) {
            _ = try await f.broker.concludeHumanStep(lease, connection: connection, decision: .cancel)
        }
        #expect(try await f.resume(run) == .humanStepRequired(run), "losing the app keeps the pause")
        #expect(f.humanAudit.suffix(2) == ["continuation_opened", "continuation_closed"])
    }

    @Test func delayedSignedOpenCannotAuthorizeADifferentHumanStep() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa)], reclassify: [.humanStep(.captcha)])
        let run = try await f.startPausedRun()
        let first = try #require(try await f.broker.pendingHumanSteps().first)
        let connection = ContinuationConnectionID()
        let lease = try await f.broker.openHumanStep(first.id, connection: connection)
        #expect(try await f.broker.concludeHumanStep(lease, connection: connection, decision: .finished)
                == .humanStepRequired(.captcha))
        let second = try #require(try await f.broker.pendingHumanSteps().first)
        #expect(first.id.run == run && second.id.run == run)
        #expect(first.kind == .mfa && second.kind == .captcha && first.id != second.id)
        await #expect(throws: VaultError.denied) {
            _ = try await f.broker.openHumanStep(first.id, connection: ContinuationConnectionID())
        }
        let currentLease = try await f.broker.openHumanStep(second.id, connection: connection)
        #expect(try await f.broker.concludeHumanStep(currentLease, connection: connection, decision: .cancel) == .concluded)
        #expect(f.host.openContexts == 0)
    }

    @Test func busyAndUnavailableHostAreRefusedBeforeBudgetIsReserved() async throws {
        let f = try await WebFixture.make(start: [.humanStep(.mfa)])
        _ = try await f.startPausedRun()
        await #expect(throws: VaultError.busy) { _ = try await f.run() }
        #expect(f.callsUsed == 1 && f.host.startCount == 1)

        let state = MemoryState(), secrets = MemorySecrets()
        let disabled = Broker(state: state, secrets: secrets)
        let account = try await disabled.enroll(service: .githubWeb, credential: syntheticWebCredential)
        let client = try await disabled.registerClient()
        let grant = try await disabled.grant(clientID: client.id, accountID: account.id, duration: 60, callLimit: 1,
                                             requiresApproval: true)
        await #expect(throws: VaultError.upstreamUnavailable) {
            _ = try await disabled.run(clientID: client.id, accountID: account.id, action: .githubWebProfile)
        }
        let snapshot = try state.snapshot()
        #expect(snapshot.grants.first { $0.id == grant.id }?.callsUsed == 0)
        #expect(snapshot.pending.isEmpty && secrets.reads == 0)
    }

    @Test func liveRunsAreBoundedAcrossAccounts() async throws {
        let f = try await WebFixture.make(start: Array(repeating: .humanStep(.mfa), count: 5))
        _ = try await f.startPausedRun()
        var accounts: [Account] = []
        for _ in 0..<4 {
            let account = try await f.broker.enroll(service: .githubWeb, credential: syntheticWebCredential)
            _ = try await f.broker.grant(clientID: f.client.id, accountID: account.id, duration: 60, callLimit: 1)
            accounts.append(account)
        }
        for account in accounts.prefix(3) {
            _ = try await f.broker.run(clientID: f.client.id, accountID: account.id, action: .githubWebProfile)
        }
        await #expect(throws: VaultError.busy) {
            _ = try await f.broker.run(clientID: f.client.id, accountID: accounts[3].id, action: .githubWebProfile)
        }
        #expect(try f.state.snapshot().grants.first { $0.accountID == accounts[3].id }?.callsUsed == 0)
        #expect(f.host.startCount == 4)
    }

    @Test(arguments: WebFailure.allCases)
    func hostFailuresReachTheAgentOnlyAsClosedStatuses(failure: WebFailure) async throws {
        let f = try await WebFixture.make(start: [.failed(failure)])
        do {
            _ = try await f.run()
            Issue.record("failure delivered as success")
        } catch let error as VaultError {
            #expect(error != .denied)
            #expect(ReadFailureStatus.allCases.contains(error.readFailure))
        }
        #expect(f.audit == ["reserved", "web_" + failure.rawValue, "failed"])
        #expect(f.host.openContexts == 0)
    }

    @Test func webCredentialGrammarIsEnforcedBeforeAnyKeychainWrite() async throws {
        let state = MemoryState(), secrets = MemorySecrets()
        let broker = Broker(state: state, secrets: secrets)
        for bad in ["no-newline", "\nempty-user", "user\n", "user\nbad\u{7}control",
                    String(repeating: "u", count: 256) + "\npassword", "user\n" + String(repeating: "p", count: 4092)] {
            await #expect(throws: VaultError.invalidInput) {
                _ = try await broker.enroll(service: .githubWeb, credential: Data(bad.utf8))
            }
        }
        #expect(try state.snapshot().accounts.isEmpty && state.snapshot().adminAudit.isEmpty)
        let account = try await broker.enroll(service: .githubWeb, credential: syntheticWebCredential)
        await #expect(throws: VaultError.invalidInput) {
            try await broker.rotate(accountID: account.id, credential: Data("SYNTHETIC-token-without-username".utf8))
        }
        #expect(try state.snapshot().accounts.first?.lifecycle == .active)
    }
}
