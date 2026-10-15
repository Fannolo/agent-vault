import AgentVaultContracts
@testable import AgentVaultAppSupport
import CoreGraphics
import Foundation
import ImageIO
import Testing
import UniformTypeIdentifiers

/// Answers continuation calls from a script and records every request. Input replies can be held
/// to interleave a new frame with an in-flight batch.
private actor ScriptedContinuation: VaultAdminTransport {
    var frameReplies: [ContinuationReply] = []
    var inputReply: ContinuationReply = .delivered
    var finishReply: ContinuationReply = .concluded
    var failAll = false
    private(set) var requests: [ContinuationRequest] = []
    private var holdInput = false
    private var held: [CheckedContinuation<Void, Never>] = []
    private var holdOthers: Set<String> = []
    private var heldOthers: [String: [CheckedContinuation<Void, Never>]] = [:]
    /// Parks frame or finish calls ("frame", "finish") until released.
    func hold(_ kind: String) { holdOthers.insert(kind) }
    func release(_ kind: String) { holdOthers.remove(kind); heldOthers.removeValue(forKey: kind)?.forEach { $0.resume() } }
    func heldCount(_ kind: String) -> Int { heldOthers[kind]?.count ?? 0 }
    private func park(_ kind: String) async {
        guard holdOthers.contains(kind) else { return }
        await withCheckedContinuation { heldOthers[kind, default: []].append($0) }
    }

    func script(frames: [ContinuationReply]) { frameReplies += frames }
    func set(input: ContinuationReply) { inputReply = input }
    func set(finish: ContinuationReply) { finishReply = finish }
    func fail() { failAll = true }
    func holdInputs() { holdInput = true }
    func releaseInputs() { holdInput = false; held.forEach { $0.resume() }; held = [] }
    var heldCount: Int { held.count }

    var inputs: [(batch: UInt64, frame: UInt64, events: [HumanInput])] {
        requests.compactMap {
            if case .input(let batch, let frame, let events) = $0.operation { (batch, frame, events.events) } else { nil }
        }
    }
    var frameRequests: Int { requests.filter { if case .frame = $0.operation { true } else { false } }.count }
    var last: ContinuationRequest.Operation? { requests.last?.operation }
    var finished: Bool { requests.contains { $0.operation == .finish } }
    /// Request kinds in order, without payloads.
    var order: [String] {
        requests.compactMap {
            switch $0.operation {
            case .input: "input"
            case .finish: "finish"
            default: nil
            }
        }
    }

    func snapshot() async throws -> AdminSnapshot { AdminSnapshot(accounts: [], clients: [], grants: [], pending: []) }
    func begin(_ request: AdminRequest) async throws -> AdminChallenge { throw AdminTransportError.unsupported }
    func authorize(challengeID: UUID, signature: Data) async throws -> AdminReply { throw AdminTransportError.unsupported }

    func continueHuman(_ request: ContinuationRequest) async throws -> ContinuationReply {
        requests.append(request)
        if failAll { throw AdminTransportError.unavailable }
        switch request.operation {
        case .frame:
            await park("frame")
            return frameReplies.isEmpty ? .noFrame : frameReplies.removeFirst()
        case .input:
            if holdInput { await withCheckedContinuation { held.append($0) } }
            return inputReply
        case .finish:
            await park("finish")
            return finishReply
        case .cancel: return .concluded
        case .close: return .closed
        }
    }
}

private let step = HumanStepSummary(runID: UUID(), epoch: 2, kind: .mfa, accountID: UUID(), service: .githubWeb,
                                    expiresAt: Date().addingTimeInterval(300))

@MainActor
private func eventually(_ condition: @MainActor () async -> Bool) async -> Bool {
    for _ in 0..<300 {
        if await condition() { return true }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return false
}

@MainActor
private func liveModel(_ transport: ScriptedContinuation, frame: HumanFrame = SyntheticFrames.frame(1),
                       now: @escaping @Sendable () -> Date = Date.init) async -> HumanStepModel {
    await transport.script(frames: [.frame(frame)])
    let model = HumanStepModel(step: step, lease: UUID(), transport: transport, now: now, pollInterval: .milliseconds(10))
    model.start()
    _ = await eventually { model.phase == .live }
    return model
}

private func jpeg(width: Int, height: Int, type: UTType = .jpeg, orientation: Int? = nil) -> Data {
    let context = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
                            space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)!
    let data = NSMutableData()
    let destination = CGImageDestinationCreateWithData(data, type.identifier as CFString, 1, nil)!
    let properties = orientation.map { [kCGImagePropertyOrientation: $0] as CFDictionary }
    CGImageDestinationAddImage(destination, context.makeImage()!, properties)
    CGImageDestinationFinalize(destination)
    return data as Data
}

@MainActor @Suite(.serialized)
struct HumanStepTests {
    // MARK: Opening through the app model

    @Test func openingSignsTheExactListedStepThenShowsItsValidatedFrame() async throws {
        let signer = SoftwareFixtureSigner()
        let broker = InMemoryBroker(publicKey: signer.publicKey)
        let listed = HumanStepSummary(runID: UUID(), epoch: 3, kind: .captcha, accountID: UUID(), service: .githubWeb,
                                      expiresAt: Date().addingTimeInterval(300))
        await broker.seed(accounts: [AccountSummary(id: listed.accountID, service: .githubWeb)], humanSteps: [listed])
        let model = AppModel(transport: broker, signer: signer)
        await model.refresh()
        #expect(model.humanSteps == [listed])
        #expect(await model.openHumanStep(listed))
        #expect(await broker.appliedOperations == [.openHumanStep])
        let reason = try #require(signer.reasons.last)
        #expect(reason.contains("CAPTCHA step 3") && reason.contains(listed.runID.uuidString.lowercased())
                && reason.contains(listed.accountID.uuidString.lowercased()) && reason.contains("GitHub web profile"))
        let window = try #require(model.humanStep)
        #expect(await eventually { window.frame?.sequence == 1 && window.phase == .live })
        #expect(window.frame?.width == 640 && window.frame?.height == 420)
        #expect(await model.openHumanStep(listed) == false, "one window at a time")

        await model.dismissHumanStep()
        #expect(model.humanStep == nil && window.phase == .ended(.closed))
        let calls = await broker.continuationCalls
        try await Task.sleep(for: .milliseconds(300))
        #expect(await broker.continuationCalls == calls, "a closed window sends nothing more")
    }

    @Test func aStepTheBrokerDoesNotListOrThatExpiredIsNotOpened() async throws {
        let signer = SoftwareFixtureSigner()
        let broker = InMemoryBroker(publicKey: signer.publicKey)
        await broker.seed(humanSteps: [step])
        let model = AppModel(transport: broker, signer: signer)
        await model.refresh()
        let stale = HumanStepSummary(runID: step.runID, epoch: step.epoch - 1, kind: step.kind, accountID: step.accountID,
                                     service: step.service, expiresAt: step.expiresAt)
        #expect(await model.openHumanStep(stale) == false)
        #expect(model.humanStep == nil && model.notice?.kind == .failure && signer.signCount == 0)
        let expired = HumanStepSummary(runID: UUID(), epoch: 1, kind: .mfa, accountID: UUID(), service: .githubWeb,
                                       expiresAt: Date().addingTimeInterval(-1))
        #expect(await model.openHumanStep(expired) == false)
        #expect(signer.signCount == 0)
        #expect(await broker.appliedOperations.isEmpty)
    }

    // MARK: Untrusted frames

    @Test func framesWhoseActualRasterDoesNotMatchTheirDeclarationAreNeverShown() async throws {
        let png = jpeg(width: 64, height: 48, type: .png)
        let candidates: [HumanFrame?] = [
            HumanFrame(sequence: 1, width: 640, height: 420, jpeg: jpeg(width: 320, height: 210)),
            HumanFrame(sequence: 1, width: 64, height: 48, jpeg: Data([0xFF, 0xD8]) + Data(repeating: 0x41, count: 64) + Data([0xFF, 0xD9])),
            HumanFrame(sequence: 1, width: 64, height: 48, jpeg: Data([0xFF, 0xD8]) + png.dropFirst(2).dropLast(2) + Data([0xFF, 0xD9])),
            HumanFrame(sequence: 1, width: 64, height: 48, jpeg: jpeg(width: 64, height: 48, orientation: 6)),
            HumanFrame(sequence: 1, width: 48, height: 64, jpeg: jpeg(width: 64, height: 48))
        ]
        for candidate in candidates {
            let frame = try #require(candidate)
            #expect(HumanFrameImage(frame) == nil)
        }
        #expect(HumanFrameImage(HumanFrame(sequence: 1, width: 64, height: 48, jpeg: jpeg(width: 64, height: 48))!) != nil)

        let transport = ScriptedContinuation()
        await transport.script(frames: candidates.compactMap { $0.map(ContinuationReply.frame) } + [.frame(SyntheticFrames.frame(4))])
        let model = HumanStepModel(step: step, lease: UUID(), transport: transport, pollInterval: .milliseconds(5))
        model.start()
        #expect(await eventually { model.frame?.sequence == 4 })
        #expect(model.rejectedFrames == candidates.count)
        await model.close()
    }

    @Test func aFrameThatIsNotNewerThanTheOneShownIsIgnored() async throws {
        let transport = ScriptedContinuation()
        let model = await liveModel(transport, frame: SyntheticFrames.frame(5))
        await transport.script(frames: [.frame(SyntheticFrames.frame(5)), .frame(SyntheticFrames.frame(3))])
        #expect(await eventually { model.rejectedFrames == 2 })
        #expect(model.frame?.sequence == 5)
        await model.close()
    }

    // MARK: Coordinates

    @Test func viewPointsMapIntoTheAspectFitFrameAndNothingOutsideIsSent() {
        let geometry = FrameGeometry(frameWidth: 640, frameHeight: 420, viewSize: CGSize(width: 1280, height: 420))
        #expect(geometry.imageRect == CGRect(x: 320, y: 0, width: 640, height: 420))
        #expect(geometry.pixel(at: CGPoint(x: 320, y: 0))! == (0, 0))
        #expect(geometry.pixel(at: CGPoint(x: 959.9, y: 419.9))! == (639, 419))
        #expect(geometry.pixel(at: CGPoint(x: 319, y: 10)) == nil)
        #expect(geometry.pixel(at: CGPoint(x: 1000, y: 500)) == nil)
        #expect(geometry.pixel(at: CGPoint(x: 1000, y: 500), clamped: true)! == (639, 419))
        #expect(geometry.pixel(at: CGPoint(x: CGFloat.nan, y: 1), clamped: true) == nil)
        let scaled = FrameGeometry(frameWidth: 640, frameHeight: 420, viewSize: CGSize(width: 1280, height: 1000))
        #expect(scaled.imageRect == CGRect(x: 0, y: 80, width: 1280, height: 840))
        #expect(scaled.pixel(at: CGPoint(x: 640, y: 500))! == (320, 210))
        #expect(FrameGeometry(frameWidth: 640, frameHeight: 420, viewSize: .zero).pixel(at: .zero, clamped: true) == nil)
    }

    // MARK: Input

    @Test func inputCarriesTheLatestFrameStrictlyIncreasingBatchesAndFramePixels() async throws {
        let transport = ScriptedContinuation()
        let model = await liveModel(transport)
        let view = CGSize(width: 1280, height: 840)
        model.pointer(.down, at: CGPoint(x: 200, y: 100), in: view)
        #expect(await eventually { await transport.inputs.count == 1 })
        model.pointer(.up, at: CGPoint(x: 5000, y: 5000), in: view)
        model.pointer(.down, at: CGPoint(x: -5, y: 10), in: view)
        model.key(.enter)
        model.wheel(dx: 0, dy: 1e9)
        model.wheel(dx: 0.2, dy: -0.3)
        #expect(await eventually { await transport.inputs.flatMap(\.events).count == 4 })
        let inputs = await transport.inputs
        #expect(inputs.flatMap(\.events) == [.pointer(.down, x: 100, y: 50), .pointer(.up, x: 639, y: 419), .key(.enter),
                                             .wheel(dx: 0, dy: 2000)])
        #expect(inputs.allSatisfy { $0.frame == 1 })
        #expect(zip(inputs, inputs.dropFirst()).allSatisfy { $0.batch < $1.batch })
        await model.close()
    }

    @Test func queuedInputAimedAtAnEarlierFrameIsDroppedWhenANewFrameArrives() async throws {
        let transport = ScriptedContinuation()
        let model = await liveModel(transport)
        await transport.holdInputs()
        model.key(.tab)
        #expect(await eventually { await transport.heldCount == 1 })
        model.key(.enter)
        await transport.script(frames: [.frame(SyntheticFrames.frame(2, width: 320, height: 200))])
        #expect(await eventually { model.frame?.sequence == 2 })
        await transport.releaseInputs()
        model.key(.escape)
        #expect(await eventually { await transport.inputs.count == 2 })
        try await Task.sleep(for: .milliseconds(100))
        let inputs = await transport.inputs
        #expect(inputs.map(\.frame) == [1, 2])
        #expect(inputs.map(\.events) == [[.key(.tab)], [.key(.escape)]], "enter was aimed at frame 1 and never sent")
        await model.close()
    }

    @Test func typedTextIsChunkedBoundedAndKeptOutOfPublishedState() async throws {
        let secret = "SYNTHETIC-MFA-" + String(repeating: "7", count: 70)
        let transport = ScriptedContinuation()
        let model = await liveModel(transport)
        model.type("bad\ntext")
        model.type(secret)
        #expect(await eventually { await transport.inputs.flatMap(\.events).count == 2 })
        let texts = await transport.inputs.flatMap(\.events).compactMap { if case .text(let text) = $0 { text } else { nil } }
        #expect(texts.joined() == secret && texts.allSatisfy { $0.utf8.count <= 64 })
        let published = [String(describing: model.phase), String(describing: model.frame?.sequence),
                         String(describing: model.declinedBatches), String(describing: model.rejectedFrames)]
        #expect(!published.joined().contains("SYNTHETIC-MFA"))
        await model.close()
    }

    // MARK: Endings

    @Test func closingStopsPollingAndDiscardsLaterInput() async throws {
        let transport = ScriptedContinuation()
        let model = await liveModel(transport)
        await model.close()
        #expect(model.phase == .ended(.closed) && model.frame == nil)
        #expect(await transport.last == .close)
        let count = await transport.requests.count
        model.key(.enter); model.type("late"); model.pointer(.down, at: .zero, in: CGSize(width: 10, height: 10))
        await model.finish()
        try await Task.sleep(for: .milliseconds(100))
        #expect(await transport.requests.count == count)
    }

    @Test func theDeadlineEndsTheWindowAndClosesTheLease() async throws {
        let clock = TestClock()
        let transport = ScriptedContinuation()
        let model = await liveModel(transport, now: { clock.now })
        clock.now = step.expiresAt
        #expect(await eventually { model.phase == .ended(.expired) })
        #expect(await transport.last == .close)
        #expect(model.remaining(at: step.expiresAt) == 0)
    }

    @Test(arguments: [ContinuationFailure.accessDenied, .upstreamUnavailable, .invalidInput])
    func aBrokerRefusalEndsTheWindow(failure: ContinuationFailure) async throws {
        let transport = ScriptedContinuation()
        let model = await liveModel(transport)
        await transport.script(frames: [.failure(failure)])
        #expect(await eventually { model.phase == .ended(.unavailable) })
    }

    @Test func aLostConnectionEndsTheWindowBecauseTheLeaseWasBoundToIt() async throws {
        let transport = ScriptedContinuation()
        let model = await liveModel(transport)
        await transport.fail()
        #expect(await eventually { model.phase == .ended(.connectionLost) })
    }

    @Test func finishAndCancelAreExplicitAndReportWhatFollows() async throws {
        let transport = ScriptedContinuation()
        await transport.set(finish: .nextStep(.captcha))
        let model = await liveModel(transport)
        await model.finish()
        #expect(model.phase == .ended(.nextStep(.captcha)))
        let other = ScriptedContinuation()
        let cancelled = await liveModel(other)
        await cancelled.cancel()
        #expect(cancelled.phase == .ended(.cancelled))
        #expect(await other.last == .cancel)
    }

    @Test func finishDeliversQueuedInputInOrderBeforeAskingTheBroker() async throws {
        let transport = ScriptedContinuation()
        let model = await liveModel(transport)
        await transport.holdInputs()
        model.type("A")
        #expect(await eventually { await transport.heldCount == 1 })
        model.type("B")
        let finishing = Task { await model.finish() }
        try await Task.sleep(for: .milliseconds(100))
        #expect(await transport.finished == false, "finish waits for the batch in flight")
        model.type("C")
        await transport.releaseInputs()
        await finishing.value
        let texts = await transport.inputs.flatMap(\.events)
        #expect(texts == [.text("A"), .text("B")], "queued input is delivered; input typed while finishing is refused")
        #expect(await transport.order == ["input", "input", "finish"])
        #expect(model.phase == .ended(.concluded))
    }

    @Test func undeliveredInputBlocksFinishExplicitlyAndTheWindowStaysLive() async throws {
        let transport = ScriptedContinuation()
        let model = await liveModel(transport)
        await transport.set(input: .notDelivered)
        model.type("A")
        await model.finish()
        #expect(await transport.finished == false)
        #expect(model.phase == .live && model.finishBlockedByUndeliveredInput)
        #expect(await eventually { await transport.frameRequests >= 3 }, "polling resumes")
        await transport.set(input: .delivered)
        await model.finish()
        #expect(model.phase == .ended(.concluded) && !model.finishBlockedByUndeliveredInput)
    }

    @Test func aPollReplyArrivingDuringFinishDoesNotDecideTheEnding() async throws {
        let transport = ScriptedContinuation()
        let model = await liveModel(transport)
        await transport.hold("frame")
        #expect(await eventually { await transport.heldCount("frame") == 1 }, "a poll is in flight")
        await transport.hold("finish")
        let finishing = Task { await model.finish() }
        #expect(await eventually { await transport.heldCount("finish") == 1 })
        // The broker has already invalidated the lease for polling; that reply arrives now.
        await transport.script(frames: [.failure(.accessDenied)])
        await transport.release("frame")
        try await Task.sleep(for: .milliseconds(100))
        #expect(model.phase == .finishing)
        await transport.release("finish")
        await finishing.value
        #expect(model.phase == .ended(.concluded))
    }

    @Test func pollingIsPaced() async throws {
        let transport = ScriptedContinuation()
        let model = HumanStepModel(step: step, lease: UUID(), transport: transport)
        model.start()
        try await Task.sleep(for: .milliseconds(450))
        await model.close()
        #expect((3...6).contains(await transport.frameRequests))
    }
}

private final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value = Date()
    var now: Date {
        get { lock.withLock { value } }
        set { lock.withLock { value = newValue } }
    }
}
