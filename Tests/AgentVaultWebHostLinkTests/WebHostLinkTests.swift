@testable import AgentVaultCore
@testable import AgentVaultWebHostLink
@testable import AgentVaultWebHostProtocol
import AgentVaultContracts
import Foundation
import Testing

@Suite(.serialized) struct WebHostLinkTests {
    // MARK: Authentication before credentials

    @Test func genuineHostRunsTheFullVocabulary() async throws {
        let host = TestHost(handler: pausingHost)
        let link = link { host.endpoint }
        let run = BrowserRunID()
        #expect(await link.start(run, workflow: .githubWebProfile, credential: credential, authority: authority(600)) == .humanStep(.mfa))
        #expect(await link.showHuman(step(run)))
        let frame = await link.frame(step(run), after: 0)
        #expect(frame?.sequence == 1 && frame?.width == 4)
        #expect(await link.input(step(run), frame: 1, HumanInputBatch([.text("123456"), .key(.enter)])!))
        #expect(await link.reclassify(run) == .profile(profile))
        await link.end(run)
        guard case .start(let started, .githubWebProfile, let sent, 600) = host.commands.all.first else {
            Issue.record("start not first"); return
        }
        #expect(started == run.uuid && sent == credential)
        #expect(host.commands.all.count == 6 && host.count(where: isEnd) == 1)
    }

    @Test func probeIsTheFirstPayloadAndCredentialFollowsOnlyAfterIt() async throws {
        let raw = RawHost { _ in errorEnvelope(.invalidRequest) }
        let link = link { raw.endpoint }
        let run = BrowserRunID()
        _ = await link.start(run, workflow: .browserDemo, credential: credential, authority: authority(60))
        let received = raw.received.all
        #expect(received.count == 2 && received.first == Data())
        guard received.count == 2, case .start(let started, _, let sent, _)? = try? HostWire.decodeRequest(received[1]).command else {
            Issue.record("second payload was not the start"); return
        }
        #expect(started == run.uuid && sent == credential)
    }

    @Test func impostorFailingTheHostRequirementReceivesOnlyTheEmptyProbe() async {
        let impostor = RawHost { _ in errorEnvelope(.invalidRequest) }
        let link = link({ impostor.endpoint }, configuration: developmentConfiguration(host: "cdhash H\"\(wrongCDHash)\""))
        let run = BrowserRunID()
        #expect(await link.start(run, workflow: .githubWebProfile, credential: credential, authority: authority(60)) == .failed(.hostUnavailable))
        #expect(impostor.received.all == [Data()])
        #expect(await link.reclassify(run) == .failed(.hostLost))
        #expect(impostor.received.all == [Data()])
    }

    @Test func hostWithAnotherKernelUIDReceivesOnlyTheEmptyProbe() async {
        let impostor = RawHost { _ in errorEnvelope(.invalidRequest) }
        let link = link({ impostor.endpoint }, configuration: developmentConfiguration(hostUID: me + 1))
        #expect(await link.start(BrowserRunID(), workflow: .githubWebProfile, credential: credential, authority: authority(60))
                == .failed(.hostUnavailable))
        #expect(impostor.received.all == [Data()])
    }

    @Test func probeAnsweredWithAnythingButTheFixedRefusalSendsNothingElse() async {
        let impostor = RawHost { _ in
            try? HostWire.encode(HostResponse(request: 1, run: UUID(), reply: .ended))
        }
        let link = link { impostor.endpoint }
        #expect(await link.start(BrowserRunID(), workflow: .githubWebProfile, credential: credential, authority: authority(60))
                == .failed(.hostUnavailable))
        #expect(impostor.received.all == [Data()])
    }

    // MARK: Host listener identity and bounds

    @Test func hostRefusesBrokerFailingItsRequirementOrUID() async {
        for configuration in [developmentConfiguration(broker: "cdhash H\"\(wrongCDHash)\""),
                              developmentConfiguration(brokerUID: me + 1)] {
            let host = TestHost(configuration: configuration, handler: pausingHost)
            let link = link { host.endpoint }
            #expect(await link.start(BrowserRunID(), workflow: .githubWebProfile, credential: credential, authority: authority(60))
                    == .failed(.hostUnavailable))
            #expect(host.commands.all.isEmpty)
        }
    }

    @Test func hostServesOnePeerAndAnswersRawPayloadsWithFixedCodes() async throws {
        let host = TestHost(handler: pausingHost)
        let first = RawClient(host.endpoint)
        #expect(await first.send(Data()) == errorEnvelope(.invalidRequest))
        #expect(await first.send(Data("{\"op\":\"evaluate\"}".utf8)) == errorEnvelope(.invalidRequest))
        #expect(await first.send(Data(repeating: 0x20, count: HostWire.maximumCommandBytes + 1)) == errorEnvelope(.requestTooLarge))
        let end = try HostWire.encode(HostRequest(id: 1, command: .end(run: UUID())))
        let reply = await first.send(end).flatMap { try? HostWire.decodeReply($0) }
        guard case .response(let response)? = reply else { Issue.record("no reply"); return }
        #expect(response.reply == .ended)
        #expect(host.commands.all.count == 1, "probe and malformed payloads never reach the handler")
        // A second concurrent peer is refused while the first is connected.
        let second = RawClient(host.endpoint)
        #expect(await second.send(Data()) == nil)
        // Losing the peer is terminal: teardown runs and no later broker connection is served.
        first.connection.invalidate()
        #expect(await eventually { host.peerLosses.all.count == 1 })
        #expect(host.server.isTerminated)
        let third = RawClient(host.endpoint)
        #expect(await third.send(Data()) == nil)
    }

    @Test func peerLossCancelsRunningHandlersAndDropsTheirResults() async {
        let cancelled = Log<Bool>()
        let host = TestHost { command in
            if case .start = command {
                await withTaskCancellationHandler { try? await Task.sleep(for: .seconds(5)) }
                    onCancel: { cancelled.append(true) }
                return .humanStep(.mfa)
            }
            return .ended
        }
        let client = RawClient(host.endpoint)
        #expect(await client.send(Data()) == errorEnvelope(.invalidRequest))
        let start = try! HostWire.encode(HostRequest(id: 1, command: .start(run: UUID(), workflow: .browserDemo,
                                                                            credential: credential, lifetime: 60)))
        let pending = Task { await client.send(start, timeout: 3) }
        #expect(await eventually { host.count(where: isStart) == 1 })
        client.connection.invalidate()
        #expect(await eventually { cancelled.all == [true] }, "the old peer's handler is cancelled at loss")
        #expect(await pending.value == nil)
        #expect(host.server.isTerminated)
    }

    @Test func hostReplyWithAnotherRunIsAViolationThatDropsTheConnection() async {
        let raw = RawHost { data in
            guard let request = try? HostWire.decodeRequest(data) else { return errorEnvelope(.invalidRequest) }
            return try? HostWire.encode(HostResponse(request: request.id, run: UUID(), reply: .humanStep(.mfa)))
        }
        let link = link { raw.endpoint }
        #expect(await link.start(BrowserRunID(), workflow: .githubWebProfile, credential: credential, authority: authority(60))
                == .failed(.rendererUnavailable))
        #expect(await eventually { raw.invalidations.all.count == 1 })
    }

    // MARK: Deadlines

    @Test func stalledStartTimesOutWithinItsBudgetAndIsEnded() async {
        let never = Latch()
        let host = TestHost { command in
            if case .start = command { await never.wait() }
            return .ended
        }
        let link = link { host.endpoint }
        let run = BrowserRunID()
        let began = Date()
        #expect(await link.start(run, workflow: .githubWebProfile, credential: credential, authority: authority(60)) == .failed(.timeout))
        let elapsed = Date().timeIntervalSince(began)
        #expect(elapsed >= fastBudgets.start && elapsed < fastBudgets.start + fastBudgets.end + 0.5)
        #expect(host.commands.all.last == .end(run: run.uuid), "a timed-out start is ended before returning")
        await never.open()
    }

    @Test func lateStartReplyAfterTheDeadlineIsIgnored() async {
        let host = TestHost { command in
            if case .start = command { try? await Task.sleep(for: .seconds(1)) }
            return command == .end(run: command.run) ? .ended : .profile(profile)
        }
        let link = link { host.endpoint }
        let run = BrowserRunID()
        #expect(await link.start(run, workflow: .githubWebProfile, credential: credential, authority: authority(60)) == .failed(.timeout))
        try? await Task.sleep(for: .seconds(1))
        #expect(await link.reclassify(run) == .failed(.hostLost), "the timed-out run is no longer bound")
        #expect(host.count(where: isEnd) == 1)
    }

    @Test func stalledProbeTimesOutAndSendsNothing() async {
        let silent = RawHost { _ in nil }
        let link = link { silent.endpoint }
        let began = Date()
        #expect(await link.start(BrowserRunID(), workflow: .githubWebProfile, credential: credential, authority: authority(60))
                == .failed(.timeout))
        #expect(Date().timeIntervalSince(began) < fastBudgets.start + 0.5)
        #expect(silent.received.all == [Data()])
    }

    @Test func stalledClassifyAndUnconfirmedEndDropTheHostAndReportOnlyItsRuns() async {
        let never = Latch()
        let host = TestHost { command in
            switch command {
            case .start: return .humanStep(.mfa)
            case .classify, .end: await never.wait(); return .ended
            default: return .accepted
            }
        }
        let link = link { host.endpoint }
        let losses = Losses(link)
        let stuck = BrowserRunID(), other = BrowserRunID()
        #expect(await link.start(stuck, workflow: .githubWebProfile, credential: credential, authority: authority(60)) == .humanStep(.mfa))
        #expect(await link.start(other, workflow: .browserDemo, credential: credential, authority: authority(60)) == .humanStep(.mfa))
        let began = Date()
        #expect(await link.reclassify(stuck) == .failed(.timeout))
        #expect(Date().timeIntervalSince(began) < fastBudgets.classify + 0.5)
        // The host cannot confirm teardown, so it loses its broker and with it every context.
        await link.end(stuck)
        #expect(await eventually { host.peerLosses.all.count == 1 })
        #expect(await eventually { losses.all == [[other]] }, "the ended run is not reported lost")
        await never.open()
    }

    // MARK: Generations and loss scoping

    @Test func lossNamesOnlyRunsOfTheDeadConnectionAndNewRunsUseAFreshAuthenticatedOne() async {
        let first = TestHost(handler: pausingHost)
        let current = Box(first.endpoint)
        let link = link { current.value }
        let losses = Losses(link)
        let old = BrowserRunID()
        #expect(await link.start(old, workflow: .githubWebProfile, credential: credential, authority: authority(60)) == .humanStep(.mfa))
        // The host dies; launchd would start a new one under the same name.
        let second = TestHost(handler: pausingHost)
        current.value = second.endpoint
        first.server.invalidate()
        #expect(await eventually { losses.all == [[old]] })
        let new = BrowserRunID()
        #expect(await link.start(new, workflow: .githubWebProfile, credential: credential, authority: authority(60)) == .humanStep(.mfa))
        // Commands for the old run never reach the new host, and teardown of it is a no-op.
        #expect(await link.reclassify(old) == .failed(.hostLost))
        #expect(!(await link.showHuman(step(old))))
        await link.end(old)
        #expect(second.runs == [new.uuid])
        // Losing the new host later reports only the new run.
        second.server.invalidate()
        #expect(await eventually { losses.all == [[old], [new]] })
    }

    @Test func pendingStartFailsAtOnceWhenItsConnectionDies() async {
        let hold = Latch()
        let host = TestHost { command in
            if case .start = command { await hold.wait() }
            return .ended
        }
        let link = link({ host.endpoint }, budgets: .standard)
        let losses = Losses(link)
        let run = BrowserRunID()
        let call = Task { await link.start(run, workflow: .githubWebProfile, credential: credential, authority: authority(60)) }
        #expect(await eventually { host.count(where: isStart) == 1 })
        let began = Date()
        host.server.invalidate()
        #expect(await call.value == .failed(.hostLost))
        #expect(Date().timeIntervalSince(began) < 2, "abandoned starts fail at once, not at the 15 s budget")
        #expect(await eventually { losses.all == [[run]] })
        await hold.open()
    }

    @Test func startAfterEndIsRefusedWithoutReachingTheHost() async {
        let host = TestHost(handler: pausingHost)
        let link = link { host.endpoint }
        let run = BrowserRunID()
        await link.end(run)
        #expect(await link.start(run, workflow: .githubWebProfile, credential: credential, authority: authority(60)) == .failed(.unknownRun))
        let twice = BrowserRunID()
        #expect(await link.start(twice, workflow: .githubWebProfile, credential: credential, authority: authority(60)) == .humanStep(.mfa))
        #expect(await link.start(twice, workflow: .githubWebProfile, credential: credential, authority: authority(60)) == .failed(.unknownRun))
        #expect(host.runs == [twice.uuid])
    }

    @Test func endedRunsDoNotAccumulateOnALongLivedConnection() async {
        let host = TestHost(handler: pausingHost)
        let link = link { host.endpoint }
        for _ in 0..<200 {
            let run = BrowserRunID()
            #expect(await link.start(run, workflow: .githubWebProfile, credential: credential, authority: authority(600))
                    == .humanStep(.mfa))
            await link.end(run)
        }
        let counts = link.retainedRunCounts
        #expect(counts.bound == 0 && counts.generation == 0)
        #expect(host.peerLosses.all.isEmpty, "one connection served all 200 runs")
    }

    @Test func withdrawnAuthorityAfterTheProbeSendsNoCredential() async {
        let raw = RawHost { _ in errorEnvelope(.invalidRequest) }
        let link = link { raw.endpoint }
        let run = BrowserRunID()
        #expect(await link.start(run, workflow: .githubWebProfile, credential: credential,
                                 authority: WebStartAuthority { nil }) == .failed(.unknownRun))
        #expect(raw.received.all == [Data()], "authenticated, then nothing: authority was gone")
        // Teardown racing the authority answer: the run is tombstoned before it could bind.
        let raced = BrowserRunID()
        #expect(await link.start(raced, workflow: .githubWebProfile, credential: credential,
                                 authority: WebStartAuthority { await link.end(raced); return 60 }) == .failed(.unknownRun))
        #expect(raw.received.all == [Data()])
    }

    // MARK: Bounded concurrency and teardown priority

    @Test func excessControlRequestsFailFastAndFramesNeverBlockTeardown() async {
        let hold = Latch()
        let host = TestHost { command in
            switch command {
            case .start(let run, _, _, _) where run.uuidString.hasPrefix("0"): await hold.wait(); return .humanStep(.mfa)
            case .frame: await hold.wait(); return .noFrame(step: 1)
            case .end: return .ended
            default: return .humanStep(.mfa)
            }
        }
        let limits = WebHostLink.Limits(control: 2, frame: 1, teardown: 4)
        let link = link({ host.endpoint }, budgets: .standard, limits: limits)
        let paused = BrowserRunID()
        #expect(await link.start(paused, workflow: .githubWebProfile, credential: credential, authority: authority(60)) == .humanStep(.mfa))
        let slow = (0..<2).map { BrowserRunID(UUID(uuidString: "0000000\($0)-0000-4000-8000-000000000000")!) }
        let calls = slow.map { run in Task { await link.start(run, workflow: .githubWebProfile, credential: credential, authority: authority(60)) } }
        let frame = Task { await link.frame(step(paused), after: 0) }
        #expect(await eventually { host.count(where: isStart) == 3 && host.commands.all.contains { if case .frame = $0 { true } else { false } } })
        #expect(await link.start(BrowserRunID(), workflow: .githubWebProfile, credential: credential, authority: authority(60)) == .failed(.busy))
        #expect(await link.frame(step(paused), after: 0) == nil, "frame lane full")
        let began = Date()
        await link.end(paused)
        #expect(Date().timeIntervalSince(began) < 1, "teardown is not queued behind frames or control work")
        #expect(host.commands.all.contains(.end(run: paused.uuid)), "teardown reached the host")
        #expect(host.peerLosses.all.isEmpty, "a confirmed teardown keeps the connection")
        #expect(host.count(where: isStart) == 3)
        await hold.open()
        for call in calls { _ = await call.value }
        _ = await frame.value
    }

    @Test func hostSideLanesReportBusyAndKeepTeardownCapacity() async throws {
        let hold = Latch()
        let host = TestHost(limits: WebHostServer.Limits(control: 1, frame: 1, teardown: 1)) { command in
            if case .classify = command { await hold.wait() }
            return await pausingHost(command)
        }
        let link = link({ host.endpoint }, budgets: .standard)
        let a = BrowserRunID(), b = BrowserRunID()
        #expect(await link.start(a, workflow: .githubWebProfile, credential: credential, authority: authority(60)) == .humanStep(.mfa))
        #expect(await link.start(b, workflow: .githubWebProfile, credential: credential, authority: authority(60)) == .humanStep(.mfa))
        let stuck = Task { await link.reclassify(a) }
        #expect(await eventually { host.commands.all.contains(.classify(run: a.uuid)) })
        #expect(await link.reclassify(b) == .failed(.busy))
        await link.end(b)
        #expect(host.commands.all.last == .end(run: b.uuid))
        await hold.open()
        _ = await stuck.value
    }
}

final class Box<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Value
    init(_ value: Value) { stored = value }
    var value: Value {
        get { lock.withLock { stored } }
        set { lock.withLock { stored = newValue } }
    }
}
