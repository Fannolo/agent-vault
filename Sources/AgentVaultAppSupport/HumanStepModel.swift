import AgentVaultContracts
import CoreGraphics
import Foundation
import Observation

/// One opened human step: the latest validated frame in, bounded input out, until the person
/// finishes, cancels or closes it, or the broker ends the lease. A model never outlives its lease:
/// after it ends it sends nothing more, so no input aimed at an old frame or run can arrive late.
///
/// Typed text exists only in the outgoing queue. It is never stored in published state,
/// notices or errors.
@MainActor @Observable
public final class HumanStepModel: Identifiable {
    public enum Phase: Equatable, Sendable {
        case connecting, live, finishing
        case ended(Ending)
    }

    public enum Ending: Equatable, Sendable {
        case concluded
        /// The page asks for another step; it needs a new signed open from Requests.
        case nextStep(HumanStepKind)
        case cancelled, closed, expired
        /// The broker no longer recognizes this lease: revoked, lost, concluded elsewhere or expired.
        case unavailable
        /// The authenticated connection failed. The lease was bound to it and is gone.
        case connectionLost
    }

    public let id = UUID()
    public let step: HumanStepSummary
    public private(set) var phase = Phase.connecting
    public private(set) var frame: HumanFrameImage?
    /// Frames the broker sent that failed validation and were not shown.
    public private(set) var rejectedFrames = 0
    /// Input batches the broker declined because the page had moved on.
    public private(set) var declinedBatches = 0
    /// The last finish was not sent because earlier input was not delivered. The window is live
    /// again so the person can check the picture before finishing.
    public private(set) var finishBlockedByUndeliveredInput = false

    public static let pollInterval: Duration = .milliseconds(100)
    static let busyBackoff: Duration = .milliseconds(250)
    static let inputInterval: Duration = .milliseconds(30)

    private let lease: UUID
    private let transport: VaultAdminTransport
    private let now: @Sendable () -> Date
    private let pollInterval: Duration
    private var poller: Task<Void, Never>?
    private var queue: [(frame: UInt64, input: HumanInput)] = []
    private var sending = false
    private var batch: UInt64 = 0
    private var drainWaiters: [CheckedContinuation<Void, Never>] = []

    public init(step: HumanStepSummary, lease: UUID, transport: VaultAdminTransport,
                now: @escaping @Sendable () -> Date = Date.init, pollInterval: Duration = HumanStepModel.pollInterval) {
        self.step = step; self.lease = lease; self.transport = transport; self.now = now; self.pollInterval = pollInterval
    }

    public var isEnded: Bool { if case .ended = phase { true } else { false } }

    public func remaining(at date: Date) -> TimeInterval { max(0, step.expiresAt.timeIntervalSince(date)) }

    public func start() {
        guard poller == nil, !isEnded else { return }
        poller = Task { [weak self] in await self?.poll() }
    }

    // MARK: Input. Coordinates are in the view showing `frame`, origin at the top left.

    public func pointer(_ phase: PointerPhase, at point: CGPoint, in viewSize: CGSize) {
        guard let frame else { return }
        let geometry = FrameGeometry(frameWidth: frame.width, frameHeight: frame.height, viewSize: viewSize)
        // A release outside the frame still releases, at the nearest edge.
        guard let pixel = geometry.pixel(at: point, clamped: phase == .up) else { return }
        enqueue(.pointer(phase, x: pixel.x, y: pixel.y))
    }

    public func wheel(dx: Double, dy: Double) {
        let limit = Double(HumanInput.maximumWheelDelta)
        guard dx.isFinite, dy.isFinite else { return }
        let x = Int(min(max(dx, -limit), limit).rounded()), y = Int(min(max(dy, -limit), limit).rounded())
        guard x != 0 || y != 0 else { return }
        enqueue(.wheel(dx: x, dy: y))
    }

    public func key(_ key: NamedKey) { enqueue(.key(key)) }

    /// Printable text only; anything with a control character is dropped whole.
    public func type(_ text: String) {
        guard !text.isEmpty, !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return }
        var chunk = ""
        for character in text {
            if chunk.utf8.count + String(character).utf8.count > HumanInput.maximumTextBytes {
                enqueue(.text(chunk)); chunk = ""
            }
            chunk.append(character)
        }
        if !chunk.isEmpty { enqueue(.text(chunk)) }
    }

    // MARK: Endings. Each is explicit; none retries.

    /// Delivers every queued event in order, then asks the broker to reclassify. Polling and new
    /// input stop first: the finish reply alone decides how the window ends.
    public func finish() async {
        guard phase == .live || phase == .connecting else { return }
        phase = .finishing
        poller?.cancel(); poller = nil
        let declined = declinedBatches
        flush()
        await drained()
        guard phase == .finishing else { return }
        guard declinedBatches == declined, queue.isEmpty else {
            queue.removeAll()
            finishBlockedByUndeliveredInput = true
            phase = frame == nil ? .connecting : .live
            start()
            return
        }
        finishBlockedByUndeliveredInput = false
        switch try? await transport.continueHuman(ContinuationRequest(lease: lease, operation: .finish)) {
        case .concluded?: end(.concluded)
        case .nextStep(let kind)?: end(.nextStep(kind))
        case .failure?: end(.unavailable)
        case nil: end(.connectionLost)
        default: end(.unavailable)
        }
    }

    public func cancel() async {
        guard !isEnded else { return }
        end(.cancelled)
        _ = try? await transport.continueHuman(ContinuationRequest(lease: lease, operation: .cancel))
    }

    /// The window is going away. The broker keeps the pause; a person can open it again.
    public func close() async {
        guard !isEnded else { return }
        end(.closed)
        _ = try? await transport.continueHuman(ContinuationRequest(lease: lease, operation: .close))
    }

    private func end(_ ending: Ending) {
        guard !isEnded else { return }
        phase = .ended(ending)
        poller?.cancel(); poller = nil
        queue.removeAll()
        frame = nil
    }

    // MARK: Plumbing

    private func poll() async {
        while !isEnded && !Task.isCancelled {
            if now() >= step.expiresAt {
                await expire()
                return
            }
            let after = frame?.sequence ?? 0
            let reply: ContinuationReply
            do { reply = try await transport.continueHuman(ContinuationRequest(lease: lease, operation: .frame(after: after))) }
            catch {
                if !Task.isCancelled { end(.connectionLost) }
                return
            }
            // A finish stops polling; a reply that arrives afterwards must not decide the ending.
            guard !isEnded, !Task.isCancelled else { return }
            var pause = pollInterval
            switch reply {
            case .frame(let candidate):
                accept(candidate, after: after)
            case .failure(.busy):
                pause = Self.busyBackoff
            case .failure:
                end(.unavailable); return
            case .noFrame:
                break
            default:
                end(.unavailable); return
            }
            try? await Task.sleep(for: pause)
        }
    }

    private func expire() async {
        end(.expired)
        _ = try? await transport.continueHuman(ContinuationRequest(lease: lease, operation: .close))
    }

    private func accept(_ candidate: HumanFrame, after: UInt64) {
        guard candidate.sequence > after, let image = HumanFrameImage(candidate) else {
            rejectedFrames += 1
            return
        }
        frame = image
        if phase == .connecting { phase = .live }
    }

    private func enqueue(_ input: HumanInput) {
        guard phase == .live, let frame, input.fits(width: frame.width, height: frame.height) else { return }
        if let last = queue.last, last.frame == frame.sequence {
            switch (last.input, input) {
            case (.pointer(.move, _, _), .pointer(.move, _, _)):
                queue[queue.count - 1].input = input
                return
            case (.text(let previous), .text(let next)) where (previous + next).utf8.count <= HumanInput.maximumTextBytes:
                queue[queue.count - 1].input = .text(previous + next)
                return
            default: break
            }
        }
        queue.append((frame.sequence, input))
        flush()
    }

    private func flush() {
        guard !sending, !queue.isEmpty else { return }
        sending = true
        Task { [weak self] in await self?.send() }
    }

    /// Returns once nothing is queued or in flight.
    private func drained() async {
        guard sending || !queue.isEmpty else { return }
        await withCheckedContinuation { drainWaiters.append($0) }
    }

    private func send() async {
        defer {
            sending = false
            let waiters = drainWaiters
            drainWaiters = []
            waiters.forEach { $0.resume() }
        }
        while phase == .live || phase == .finishing, let frame, !queue.isEmpty {
            // Events aimed at an earlier frame are never sent against this one.
            queue.removeAll { $0.frame != frame.sequence }
            let events = queue.prefix(HumanInputBatch.maximumEvents).map(\.input)
            queue.removeFirst(events.count)
            guard let bounded = HumanInputBatch(events, width: frame.width, height: frame.height) else { continue }
            batch += 1
            let request = ContinuationRequest(lease: lease, operation: .input(batch: batch, frame: frame.sequence, bounded))
            let reply = try? await transport.continueHuman(request)
            guard !isEnded else { return }
            switch reply {
            case .delivered?: break
            case .notDelivered?, .failure(.busy)?:
                declinedBatches += 1
                // While finishing, a declined batch stops the drain; finish reports it.
                if phase == .finishing { return }
            case nil: end(.connectionLost); return
            default: end(.unavailable); return
            }
            try? await Task.sleep(for: Self.inputInterval)
        }
    }
}
