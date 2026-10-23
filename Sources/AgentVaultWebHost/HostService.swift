import AgentVaultCredentials
import AgentVaultContracts
import AgentVaultWebHostProtocol
import Darwin
import Foundation

/// Serial owner of the single browser process and every run and continuing-site session in it.
///
/// It decides nothing about authority: the broker does. It only keeps each run inside its fixed
/// workflow and each session inside its site policy, bounds their lifetimes, and makes teardown
/// final. Runs and sessions share one ID namespace, capacity and tombstone set. After `teardown`, or after the
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
    /// The one launch every run waits for: no run creates a target before every new target is
    /// guaranteed to start paused under auto-attach.
    private var launch: Task<ChromiumPipe?, Never>?
    /// The browser this service started, kept after teardown so its owner can confirm it is gone.
    private(set) var launched: ChromiumPipe?
    private var runs: [UUID: WebRun] = [:]
    private var sessions: [UUID: SiteSession] = [:]
    private let epochs = DocumentEpochs()
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
        case .openSite(let id, let site, let lifetime):
            return await openSite(id, site: site, lifetime: lifetime)
        case .siteObserve(let id): return await site(id) { await $0.observe() }
        case .siteLogin(let id, let operation, let account, let credential):
            return await site(id) { await $0.login(operation, account, credential) }
        case .siteOperate(let id, let operation, let command): return await site(id) { await $0.operate(operation, command) }
        case .siteTakeover(let id): return await site(id) { await $0.takeover() }
        case .siteRelease(let id): return await site(id) { await $0.release() }
        }
    }

    /// Runs a command on a live session. A session that ended itself, because it could not hand its
    /// page to a person, is then ended like any other: its context is disposed, or the host fails.
    private func site(_ id: UUID, _ command: (SiteSession) async -> HostReply) async -> HostReply {
        guard let site = sessions[id] else { return .rejected(.unknownRun) }
        let reply = await command(site)
        if await site.isEnded { await end(id) }
        return reply
    }

    private func start(_ id: UUID, workflow: HostWorkflow, credential: WebLoginCredential, lifetime: Int) async -> HostReply {
        guard admissible(id) else { return .rejected(.unknownRun) }
        guard !live(id) else { return .rejected(.duplicateRun) }
        guard let definition = policy.workflows[workflow] else { return .rejected(.unsupportedWorkflow) }
        guard live < Self.maximumRuns else { return .rejected(.busy) }
        guard let pipe = await browser() else { return .failed(.rendererUnavailable) }
        // Launching the browser suspended: everything checked above may have changed.
        guard admissible(id), !live(id) else { return .rejected(.unknownRun) }
        guard live < Self.maximumRuns else { return .rejected(.busy) }
        // Registered before the first suspension, so `end` and teardown can always find it.
        let web = WebRun(id: id, pipe: pipe, router: router, gate: RequestGate(policy: policy, workflow: definition),
                         timing: timing)
        runs[id] = web
        expire(id, after: lifetime)
        let reply = await web.start(credential)
        return await settle(id, reply)
    }

    /// A session stays open after login until `end`, its lifetime, teardown or a fatal browser loss.
    private func openSite(_ id: UUID, site: HostSite, lifetime: Int) async -> HostReply {
        guard admissible(id) else { return .rejected(.unknownRun) }
        guard !live(id) else { return .rejected(.duplicateRun) }
        guard let sitePolicy = policy.sites[site] else { return .rejected(.unsupportedSite) }
        guard live < Self.maximumRuns else { return .rejected(.busy) }
        guard let pipe = await browser() else { return .failed(.rendererUnavailable) }
        guard admissible(id), !live(id) else { return .rejected(.unknownRun) }
        guard live < Self.maximumRuns else { return .rejected(.busy) }
        let session = SiteSession(id: id, pipe: pipe, router: router, policy: sitePolicy, epochs: epochs, timing: timing)
        sessions[id] = session
        expire(id, after: lifetime)
        let reply = await session.open()
        guard !terminal, sessions[id] != nil else { return .rejected(.unknownRun) }
        if case .site = reply { return reply }
        await end(id)
        return reply
    }

    private func expire(_ id: UUID, after lifetime: Int) {
        lifetimes[id] = Task { [weak self] in
            try? await Task.sleep(for: .seconds(lifetime))
            await self?.end(id)
        }
    }

    private func live(_ id: UUID) -> Bool { runs[id] != nil || sessions[id] != nil }
    private var live: Int { runs.count + sessions.count }

    /// Keeps a run only while a person must act on it; anything else disposes it now. Either way
    /// a run ID is used once: a concluded run can never be started again.
    private func settle(_ id: UUID, _ reply: HostReply) async -> HostReply {
        guard !terminal, runs[id] != nil else { return .rejected(.unknownRun) }
        if case .humanStep = reply { return reply }
        await end(id)
        return reply
    }

    /// Idempotent. A later `start` for this run is refused.
    func end(_ id: UUID) async {
        bury(id)
        lifetimes.removeValue(forKey: id)?.cancel()
        let disposed: Bool
        if let web = runs.removeValue(forKey: id) {
            disposed = await web.dispose()
        } else if let site = sessions.removeValue(forKey: id) {
            disposed = await site.dispose()
        } else {
            return
        }
        guard disposed else {
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
        let ended = runs, closed = sessions
        runs = [:]; sessions = [:]
        for web in ended.values { _ = await web.dispose() }
        for site in closed.values { _ = await site.dispose() }
        pipe?.terminate()
        pipe = nil
    }

    /// The one rule for creating a context: never after teardown, never for an ended run.
    private func admissible(_ id: UUID) -> Bool { !terminal && !tombstones.contains(id) }

    var liveRuns: Int { runs.count }
    var liveSessions: Int { sessions.count }
    var refusedRequests: Int { router.refusedRequests }
    var browserProcessGroup: pid_t? { pipe?.processGroup }

    private func fail() async {
        await teardown()
        onFatal()
    }

    private func browser() async -> ChromiumPipe? {
        if launch == nil { launch = Task { await self.launchBrowser() } }
        guard let ready = await launch?.value, !ready.isClosed, !terminal else { return nil }
        return ready   // a dead browser is fatal, never replaced
    }

    private func launchBrowser() async -> ChromiumPipe? {
        let router = router
        guard let created = try? ChromiumPipe(binary: binary, runDirectory: runDirectory,
                                              onEvent: { router.handle($0) },
                                              onExit: { [weak self] in Task { await self?.browserExited() } }) else {
            terminal = true
            return nil
        }
        router.pipe = created
        pipe = created
        launched = created
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
