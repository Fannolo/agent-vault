import AgentVaultBrowserFixture
import AgentVaultContracts
@testable import AgentVaultAppSupport
@testable import AgentVaultCore
@testable import AgentVaultWebHost
import Foundation
import Testing

@MainActor
@Suite(.serialized, .enabled(if: fixtureChromium != nil, "set AGENT_VAULT_TEST_CHROMIUM to the designated synthetic headless shell"))
struct HeadlessContinuationE2ETests {
    @Test(arguments: [("mfa-user", HumanStepKind.mfa), ("captcha-user", .captcha)])
    func realPixelsAndTypedHumanInputCompleteTheAuthenticatedWorkflow(user: String, kind: HumanStepKind) async throws {
        try await HeadlessStack.using(user: user) { stack in
            let run = try await stack.pause(), model = stack.app()
            await model.refresh()
            let step = try #require(model.humanSteps.first)
            #expect(step.runID == run && step.epoch == 1 && step.kind == kind)
            #expect(stack.posts.map(\.path) == ["/session"], "the host has not submitted the challenge")
            #expect(await model.openHumanStep(step))
            let window = try #require(model.humanStep)
            #expect(await eventually { window.phase == .live })
            let image = try #require(window.frame)
            #expect(image.image.width == image.width && image.image.height == image.height)
            #expect(image.width < 1280 && image.height < 200, "ImageIO decoded the challenge crop, not a full page")
            let size = CGSize(width: image.width, height: image.height)
            window.pointer(.down, at: CGPoint(x: 4, y: 4), in: size)
            window.pointer(.up, at: CGPoint(x: 4, y: 4), in: size)
            if kind == .mfa { window.type("123456") } else { window.key(.tab) }
            window.key(.enter)
            #expect(await eventually { stack.posts.contains { $0.path == "/step" } }, "only typed human input submits the step")
            #expect(await eventually { stack.site.trusted.requests.filter { $0.path == "/home" }.count >= 1 })
            await window.finish()
            #expect(window.phase == .ended(.concluded))
            let result = try await stack.collect(run)
            #expect(result.parsedStatus == .outcome(.completed))
            #expect(result.login == FixtureSite.loginName && result.userID == FixtureSite.userID)
            #expect(try await stack.collect(run).parsedStatus == .failure(.accessDenied))
            #expect(try stack.state.snapshot().grants[0].callsUsed == 1)
            #expect(await stack.host.liveRuns == 0)
            #expect(stack.signer.signCount == 1 && stack.commands.count("start") == 1)
            #expect(stack.site.elsewhereRequests.isEmpty)
            let resultBytes = String(decoding: try JSONEncoder().encode(result), as: UTF8.self)
            let stateBytes = String(decoding: try JSONEncoder().encode(stack.state.snapshot()), as: UTF8.self)
            for forbidden in [FixtureSite.password, "<html", "sid=", "127.0.0.1", "/mfa", "jpeg"] {
                #expect(!resultBytes.lowercased().contains(forbidden.lowercased()))
                #expect(!stateBytes.lowercased().contains(forbidden.lowercased()))
            }
        }
    }

    @Test func staleEpochFrameBatchAndClosedLeaseNeverDeliverInput() async throws {
        try await HeadlessStack.using { stack in
            let run = try await stack.pause(), model = stack.app()
            await model.refresh()
            let step = try #require(model.humanSteps.first)
            let wrong = HumanStepSummary(runID: run, epoch: step.epoch + 1, kind: step.kind,
                accountID: step.accountID, service: step.service, expiresAt: step.expiresAt)
            #expect(await model.openHumanStep(wrong) == false)
            #expect(stack.signer.signCount == 0 && stack.commands.count("show") == 0)
            let (transport, _) = stack.transport()
            let lease = try await stack.open(transport, step: step)
            let frame = try await stack.frame(transport, lease: lease)
            let tab = try #require(HumanInputBatch([.key(.tab)]))
            let before = stack.commands.count("input")
            #expect(try await transport.continueHuman(.init(lease: lease,
                operation: .input(batch: 1, frame: frame.sequence + 1, tab))) == .notDelivered)
            #expect(try await transport.continueHuman(.init(lease: lease,
                operation: .input(batch: 1, frame: frame.sequence, tab))) == .notDelivered, "the refused batch cannot be replayed")
            #expect(stack.commands.count("input") == before)
            #expect(try await transport.continueHuman(.init(lease: lease,
                operation: .input(batch: 2, frame: frame.sequence, tab))) == .delivered)
            #expect(stack.commands.count("input") == before + 1)
            let newer = try await stack.frame(transport, lease: lease, after: frame.sequence)
            #expect(newer.sequence > frame.sequence)
            #expect(try await transport.continueHuman(.init(lease: lease,
                operation: .input(batch: 3, frame: frame.sequence, tab))) == .notDelivered)
            #expect(stack.commands.count("input") == before + 1)
            #expect(try await transport.continueHuman(.init(lease: lease, operation: .close)) == .closed)
            #expect(try await transport.continueHuman(.init(lease: lease, operation: .finish)) == .failure(.accessDenied))
            #expect(try await stack.collect(run).parsedStatus == .outcome(.humanStepRequired))
            #expect(await stack.host.liveRuns == 1, "close keeps the paused context")
            #expect(stack.posts.map(\.path) == ["/session"])
            let reopened = try await stack.open(transport, step: step)
            #expect(reopened != lease)
            let reopenedFrame = try await stack.frame(transport, lease: reopened)
            #expect(try await transport.continueHuman(.init(lease: lease,
                operation: .input(batch: 4, frame: reopenedFrame.sequence, tab))) == .failure(.accessDenied))
            #expect(stack.commands.count("input") == before + 1, "a new lease never revives old-lease input")
            #expect(try await transport.continueHuman(.init(lease: reopened, operation: .cancel)) == .concluded)
            #expect(await stack.host.liveRuns == 0)
        }
    }

    @Test func disconnectDropsTheLeaseWithoutDiscardingThePause() async throws {
        try await HeadlessStack.using { stack in
            let run = try await stack.pause()
            let (first, client) = stack.transport(), (second, _) = stack.transport()
            let step = try #require(try await first.snapshot().humanSteps.first)
            let lease = try await stack.open(first, step: step)
            _ = try await stack.frame(first, lease: lease)
            #expect(try await second.continueHuman(.init(lease: lease, operation: .cancel)) == .failure(.accessDenied))
            client.invalidate()
            #expect(await eventually { await stack.broker.relayCount == 0 })
            #expect(try await first.continueHuman(.init(lease: lease, operation: .finish)) == .failure(.accessDenied))
            #expect(try await stack.collect(run).parsedStatus == .outcome(.humanStepRequired))
            #expect(await stack.host.liveRuns == 1)
            let reopened = try await stack.open(second, step: step)
            _ = try await stack.frame(second, lease: reopened)
            #expect(try await second.continueHuman(.init(lease: reopened, operation: .cancel)) == .concluded)
            #expect(await stack.host.liveRuns == 0)
        }
    }

    @Test func unfinishedRealChallengeRequiresANewSignedEpoch() async throws {
        try await HeadlessStack.using { stack in
            let run = try await stack.pause(), (transport, _) = stack.transport()
            let old = try #require(try await transport.snapshot().humanSteps.first)
            let lease = try await stack.open(transport, step: old)
            _ = try await stack.frame(transport, lease: lease)
            #expect(try await transport.continueHuman(.init(lease: lease, operation: .finish)) == .nextStep(.mfa))
            let next = try #require(try await transport.snapshot().humanSteps.first)
            #expect(next.runID == run && next.epoch > old.epoch && next.expiresAt == old.expiresAt)
            #expect(stack.posts.map(\.path) == ["/session"], "Finish never submits the unfinished challenge")
            #expect(try await transport.continueHuman(.init(lease: lease, operation: .cancel)) == .failure(.accessDenied))
            let before = stack.signer.signCount
            await #expect(throws: (any Error).self) { _ = try await stack.open(transport, step: old) }
            #expect(stack.signer.signCount == before)
            let reopened = try await stack.open(transport, step: next)
            #expect(HumanFrameImage(try await stack.frame(transport, lease: reopened)) != nil)
            #expect(try await transport.continueHuman(.init(lease: reopened, operation: .cancel)) == .concluded)
            #expect(await stack.host.liveRuns == 0)
        }
    }

    @Test func revocationEndsTheLiveModelAndHostContext() async throws {
        try await HeadlessStack.using { stack in
            let run = try await stack.pause(), model = stack.app()
            await model.refresh()
            #expect(await model.openHumanStep(try #require(model.humanSteps.first)))
            let window = try #require(model.humanStep)
            #expect(await eventually { window.phase == .live })
            try await stack.broker.revokeGrant(stack.grant.id)
            #expect(await eventually { window.phase == .ended(.unavailable) })
            #expect(await stack.host.liveRuns == 0)
            #expect(try await stack.collect(run).parsedStatus == .failure(.accessDenied))
            let inputCount = stack.commands.count("input")
            window.type("SYNTHETIC-after-revoke"); await window.finish()
            #expect(stack.commands.count("input") == inputCount)
            #expect(stack.posts.map(\.path) == ["/session"])
        }
    }

    @Test func anUnpolledPauseExpiresAndCannotBeReopened() async throws {
        let windows = try LifecycleWindows(approval: 120, humanPause: 1.2, collect: 30)
        try await HeadlessStack.using(windows: windows) { stack in
            let run = try await stack.pause(), (transport, _) = stack.transport()
            let step = try #require(try await transport.snapshot().humanSteps.first)
            #expect(await eventually { await stack.host.liveRuns == 0 }, "the broker sweep ends an unpolled real context")
            #expect(try await stack.collect(run).parsedStatus == .failure(.humanStepExpired))
            await #expect(throws: (any Error).self) { _ = try await stack.open(transport, step: step) }
            #expect(stack.signer.signCount == 0)
            #expect(try stack.state.snapshot().grants[0].callsUsed == 1)
        }
    }

    @Test func hostConnectionLossEndsTheContextAndSuppressesTheRun() async throws {
        try await HeadlessStack.using { stack in
            let run = try await stack.pause(), model = stack.app()
            await model.refresh()
            #expect(await model.openHumanStep(try #require(model.humanSteps.first)))
            let window = try #require(model.humanStep)
            #expect(await eventually { window.phase == .live })
            stack.hostServer.invalidate()
            #expect(await eventually { await stack.host.terminal && stack.hostServer.isTerminated })
            #expect(await eventually { await stack.host.liveRuns == 0 })
            #expect(await eventually { window.phase == .ended(.unavailable) })
            #expect(try await stack.collect(run).parsedStatus == .failure(.sessionLost))
            #expect(stack.posts.map(\.path) == ["/session"])
        }
    }
}
