import AgentVaultContracts
import AgentVaultWebHostProtocol
import Darwin
import Foundation

/// Serial owner of the single browser process and every run in it.
///
/// It decides nothing about authority: the broker does. It only keeps each run inside its fixed
/// workflow, bounds its lifetime, and makes teardown final. After `teardown`, or after the
/// browser dies or stops confirming a disposal, the service is terminal: no context is created
/// again, and `onFatal` lets the process end so the broker sees the loss of every run at once.
actor HostService {
    static let maximumRuns = 4
    static let tombstoneCapacity = 4096

    private let policy: HostPolicy
    private let binary: URL
    private let runDirectory: URL
    private let timing: WebRun.Timing
    private let onFatal: @Sendable () -> Void
    private let router = EventRouter()
    private var pipe: ChromiumPipe?
    private var runs: [UUID: WebRun] = [:]
    private var lifetimes: [UUID: Task<Void, Never>] = [:]
    private var tombstones: Set<UUID> = []
    private var tombstoneOrder: [UUID] = []
    private(set) var terminal = false

    init(policy: HostPolicy, binary: URL, runDirectory: URL, timing: WebRun.Timing = .standard,
         onFatal: @escaping @Sendable () -> Void) {
        self.policy = policy; self.binary = binary; self.runDirectory = runDirectory
        self.timing = timing; self.onFatal = onFatal
    }

    func perform(_ command: HostCommand) async -> HostReply {
        switch command {
        case .start(let run, let workflow, let credential, let lifetime):
            return await start(run, workflow: workflow, credential: credential, lifetime: lifetime)
        case .classify(let run):
            guard let web = runs[run] else { return .rejected(.unknownRun) }
            return await settle(run, await web.reclassify())
        case .end(let run):
            await end(run)
            return .ended
        case .showHuman(let run, let step):
            guard let web = runs[run] else { return .rejected(.unknownRun) }
            return await web.showHuman(step: step)
        case .frame(let run, let step, let after):
            guard let web = runs[run] else { return .rejected(.unknownRun) }
            return await web.frame(step: step, after: after)
        case .input(let run, let step, let frame, let batch):
            guard let web = runs[run] else { return .rejected(.unknownRun) }
            return await web.input(step: step, frame: frame, batch)
        }
    }

    private func start(_ id: UUID, workflow: HostWorkflow, credential: WebLoginCredential, lifetime: Int) async -> HostReply {
        guard admissible(id) else { return .rejected(.unknownRun) }
        guard runs[id] == nil else { return .rejected(.duplicateRun) }
        guard let definition = policy.workflows[workflow] else { return .rejected(.unsupportedWorkflow) }
        guard runs.count < Self.maximumRuns else { return .rejected(.busy) }
        guard let pipe = await browser() else { return .failed(.rendererUnavailable) }
        // Launching the browser suspended: everything checked above may have changed.
        guard admissible(id), runs[id] == nil else { return .rejected(.unknownRun) }
        guard runs.count < Self.maximumRuns else { return .rejected(.busy) }
        // Registered before the first suspension, so `end` and teardown can always find it.
        let web = WebRun(id: id, pipe: pipe, router: router, gate: RequestGate(policy: policy, workflow: definition),
                         timing: timing)
        runs[id] = web
        lifetimes[id] = Task { [weak self] in
            try? await Task.sleep(for: .seconds(lifetime))
            await self?.end(id)
        }
        let reply = await web.start(credential)
        return await settle(id, reply)
    }

    /// Keeps a run only while a person must act on it; anything else disposes it now.
    private func settle(_ id: UUID, _ reply: HostReply) async -> HostReply {
        guard !terminal, runs[id] != nil else { return .rejected(.unknownRun) }
        if case .humanStep = reply { return reply }
        await end(id, tombstone: false)
        return reply
    }

    /// Idempotent. A later `start` for this run is refused.
    func end(_ id: UUID, tombstone: Bool = true) async {
        if tombstone { bury(id) }
        lifetimes.removeValue(forKey: id)?.cancel()
        guard let web = runs.removeValue(forKey: id) else { return }
        guard await web.dispose() else {
            // The browser no longer confirms teardown: end all of it.
            await fail()
            return
        }
    }

    /// The broker is gone. Final: every context and the browser end, and nothing starts again.
    func teardown() async {
        terminal = true
        for task in lifetimes.values { task.cancel() }
        lifetimes = [:]
        let ended = runs
        runs = [:]
        for web in ended.values { _ = await web.dispose() }
        pipe?.terminate()
        pipe = nil
    }

    /// The one rule for creating a context: never after teardown, never for an ended run.
    private func admissible(_ id: UUID) -> Bool { !terminal && !tombstones.contains(id) }

    var liveRuns: Int { runs.count }
    var refusedRequests: Int { router.refusedRequests }
    var browserProcessGroup: pid_t? { pipe?.processGroup }

    private func fail() async {
        await teardown()
        onFatal()
    }

    private func browser() async -> ChromiumPipe? {
        if let pipe { return pipe.isClosed ? nil : pipe }   // a dead browser is fatal, never replaced
        let router = router
        guard let created = try? ChromiumPipe(binary: binary, runDirectory: runDirectory,
                                              onEvent: { router.handle($0) },
                                              onExit: { [weak self] in Task { await self?.browserExited() } }) else {
            terminal = true
            return nil
        }
        router.pipe = created
        pipe = created
        // Every new target, ours included, starts paused and attached, so nothing runs ungated.
        guard (try? await created.call(.targetSetAutoAttach, ["autoAttach": true, "waitForDebuggerOnStart": true,
                                                               "flatten": true])) != nil, !terminal else {
            await fail()
            return nil
        }
        return created
    }

    private func browserExited() async {
        guard !terminal else { return }
        await fail()
    }

    private func bury(_ id: UUID) {
        guard tombstones.insert(id).inserted else { return }
        tombstoneOrder.append(id)
        if tombstoneOrder.count > Self.tombstoneCapacity { tombstones.remove(tombstoneOrder.removeFirst()) }
    }
}
