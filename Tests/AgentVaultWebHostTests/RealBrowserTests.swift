@testable import AgentVaultWebHost
import AgentVaultBrowserFixture
import AgentVaultContracts
import AgentVaultWebHostProtocol
import Darwin
import Foundation
import ImageIO
import Testing

/// Path to a Chrome for Testing `chrome-headless-shell`. These tests run only when it is set.
private let chromium: URL? = ProcessInfo.processInfo.environment["AGENT_VAULT_TEST_CHROMIUM"].map(URL.init(fileURLWithPath:))

private final class Flag: @unchecked Sendable {
    private let lock = NSLock(); private var value = false
    func set() { lock.withLock { value = true } }
    var isSet: Bool { lock.withLock { value } }
}

/// The real host service, the real headless shell with its sandbox on, and the synthetic site.
private struct Host {
    let site: FixtureSite
    let service: HostService
    let runDirectory: URL
    let fatal: Flag

    static func make(timing: WebRun.Timing = .standard) async throws -> Host {
        let site = FixtureSite()
        try await site.start()
        var template = Array(FileManager.default.temporaryDirectory.appendingPathComponent("avwebhost-XXXXXX").path.utf8CString)
        guard let created = mkdtemp(&template) else { throw CDPError.closed }
        let runDirectory = URL(fileURLWithPath: String(cString: created))
        let fatal = Flag()
        let service = HostService(policy: HostPolicy.fixture(primary: site.origin)!, binary: chromium!,
                                  runDirectory: runDirectory, timing: timing, onFatal: { fatal.set() })
        return Host(site: site, service: service, runDirectory: runDirectory, fatal: fatal)
    }

    func start(user: String = FixtureSite.loginName, password: String = FixtureSite.password,
               workflow: HostWorkflow = .browserDemo, lifetime: Int = 120) async -> (UUID, HostReply) {
        let run = UUID()
        let credential = WebLoginCredential(FixtureSite.credential(user: user, password: password))!
        return (run, await service.perform(.start(run: run, workflow: workflow, credential: credential, lifetime: lifetime)))
    }

    var posts: [FixtureRequest] { site.trusted.requests.filter { $0.method == "POST" } }

    func finish() async {
        await service.teardown()
        site.stop()
        try? FileManager.default.removeItem(at: runDirectory)
    }
}

private let fixtureProfile = HostReply.profile(AccountProfile(login: FixtureSite.loginName, userID: FixtureSite.userID)!)

/// Waits until `condition` holds, for at most `seconds`.
private func eventually(_ seconds: Double = 5, _ condition: @Sendable () async -> Bool) async -> Bool {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
        if await condition() { return true }
        try? await Task.sleep(for: .milliseconds(50))
    }
    return await condition()
}

private func groupExists(_ group: pid_t) -> Bool {
    kill(-group, 0) == 0 || errno == EPERM
}

@Suite(.serialized, .enabled(if: chromium != nil, "set AGENT_VAULT_TEST_CHROMIUM to a chrome-headless-shell"))
struct RealBrowserTests {
    @Test func fixedWorkflowReturnsOnlyTheTypedProfileAndDisposesTheContext() async throws {
        let h = try await Host.make(); defer { Task { await h.finish() } }
        let (run, reply) = await h.start()
        #expect(reply == fixtureProfile)
        #expect(await h.service.liveRuns == 0)
        let paths = h.site.trusted.requests.map(\.path)
        #expect(paths.contains("/pixel") && paths.contains("/script.js"), "same-origin subresources load")
        #expect(h.site.elsewhereRequests.isEmpty)
        // Nothing but typed fields leaves the host.
        let wire = String(decoding: try HostWire.encode(HostResponse(request: 1, run: run, reply: reply)), as: UTF8.self)
        for forbidden in [FixtureSite.password, "<html", "sid=", "cookie", "127.0.0.1", "/login"] {
            #expect(!wire.lowercased().contains(forbidden.lowercased()), "\(forbidden)")
        }
        #expect(await h.service.perform(.classify(run: run)) == .rejected(.unknownRun), "the context is gone")
        let credential = WebLoginCredential(FixtureSite.credential())!
        #expect(await h.service.perform(.start(run: run, workflow: .browserDemo, credential: credential, lifetime: 60))
                == .rejected(.unknownRun), "a concluded run ID is never started again")
        #expect(await h.service.perform(.start(run: UUID(), workflow: .browserDemo, credential: credential, lifetime: 60))
                == fixtureProfile, "a fresh run on the same browser still works")
    }

    @Test func rejectedPasswordAndUnsupportedWorkflow() async throws {
        let h = try await Host.make(); defer { Task { await h.finish() } }
        #expect(await h.start(password: "wrong").1 == .failed(.loginRejected))
        let before = h.site.trusted.requests.count
        #expect(await h.start(workflow: .githubWebProfile).1 == .rejected(.unsupportedWorkflow))
        #expect(h.site.trusted.requests.count == before, "an unsupported workflow never loads a page")
    }

    @Test(arguments: [FixtureSite.LoginPage.redirectToElsewhere, .redirectToSameHostOtherName,
                      .metaRefreshToElsewhere, .scriptNavigationToElsewhere])
    func offOriginNavigationFailsBeforeTheCredentialIsUsed(_ page: FixtureSite.LoginPage) async throws {
        let h = try await Host.make(); defer { Task { await h.finish() } }
        h.site.loginPage = page
        #expect(await h.start().1 == .failed(.originMismatch))
        #expect(h.site.elsewhereRequests.isEmpty, "the browser never reaches another origin")
        #expect(h.posts.isEmpty, "no credential is submitted from a hostile page")
        #expect(await h.service.liveRuns == 0)
    }

    @Test(arguments: [FixtureSite.LoginPage.subresourcesFromElsewhere, .frameFromElsewhere, .openPopup,
                      .webSockets, .serviceWorker, .workerAndBeacon])
    func backgroundChannelsNeverLeaveTheReviewedOrigin(_ page: FixtureSite.LoginPage) async throws {
        let h = try await Host.make(); defer { Task { await h.finish() } }
        h.site.loginPage = page
        let outcome = await h.start().1
        #expect(outcome == fixtureProfile, "blocked side channels do not break the fixed workflow: \(outcome) \(h.site.trusted.requests.map { $0.method + " " + $0.path })")
        try await Task.sleep(for: .milliseconds(300))
        #expect(h.site.elsewhereRequests.isEmpty, "\(h.site.elsewhereRequests.map(\.path))")
        let trusted = h.site.trusted.requests
        #expect(!trusted.contains { $0.headers["upgrade"] != nil }, "no WebSocket handshake, even same-origin")
        #expect(!trusted.contains { ["/sw.js", "/worker.js"].contains($0.path) }, "no worker script is fetched")
        if page == .subresourcesFromElsewhere {
            // Chrome's Local Network Access also denies cross-port loopback subresources, so the
            // server log alone cannot show the gate worked: the gate's own refusals must.
            #expect(await h.service.refusedRequests >= 2, "the gate refused the off-origin script and image")
        }
    }

    @Test func formPostingElsewhereAndAmbiguousFieldsGetNoCredential() async throws {
        let h = try await Host.make(); defer { Task { await h.finish() } }
        h.site.loginPage = .formPostsToElsewhere
        #expect(await h.start().1 == .failed(.unexpectedPage))
        h.site.loginPage = .duplicateLoginFields
        #expect(await h.start().1 == .failed(.unexpectedPage))
        #expect(h.posts.isEmpty && h.site.elsewhereRequests.isEmpty)
    }

    @Test func reflectedProfileFieldsAreRejectedOrIgnored() async throws {
        let h = try await Host.make(); defer { Task { await h.finish() } }
        h.site.profile = .reflectedMetaInHead
        #expect(await h.start().1 == .failed(.invalidProfile))
        h.site.profile = .invalidLogin
        #expect(await h.start().1 == .failed(.invalidProfile))
        for profile in [FixtureSite.Profile.reflectedMetaInBody, .reflectedEscapedText] {
            h.site.profile = profile
            #expect(await h.start().1 == fixtureProfile)
        }
    }

    @Test(arguments: [("mfa-user", HumanStepKind.mfa), ("captcha-user", .captcha)])
    func humanStepIsShownAsABoundCropAndCompletedOnlyByThePerson(user: String, kind: HumanStepKind) async throws {
        let h = try await Host.make(); defer { Task { await h.finish() } }
        let (run, reply) = await h.start(user: user)
        #expect(reply == .humanStep(kind))
        #expect(h.posts.count == 1, "only the login post; the step is never submitted by the host")
        // Early "finished": the same step again, never a profile.
        #expect(await h.service.perform(.classify(run: run)) == .humanStep(kind))
        // Frames and input exist only for the step the broker named.
        #expect(await h.service.perform(.frame(run: run, step: 1, after: 0)) == .rejected(.staleStep))
        #expect(await h.service.perform(.showHuman(run: run, step: 1)) == .accepted)
        #expect(await h.service.perform(.showHuman(run: run, step: 1)) == .rejected(.staleStep), "epochs only move forward")
        guard case .frame(1, let frame) = await h.service.perform(.frame(run: run, step: 1, after: 0)) else {
            Issue.record("no frame"); return
        }
        #expect(frame.sequence == 1 && frame.jpeg.prefix(2) == Data([0xFF, 0xD8]))
        #expect(frame.width < WebRun.viewport.width && frame.height < 200, "a crop of the step form, not the page")
        let pixels = try #require(decodedSize(frame.jpeg))
        #expect(pixels.width == frame.width && pixels.height == frame.height, "the JPEG itself is only the crop")
        let tab = HumanInputBatch([.key(.tab)])!
        #expect(await h.service.perform(.input(run: run, step: 1, frame: 2, batch: tab)) == .rejected(.staleStep))
        #expect(await h.service.perform(.input(run: run, step: 2, frame: 1, batch: tab)) == .rejected(.staleStep))
        let outside = HumanInputBatch([.pointer(.down, x: frame.width, y: 0)])!
        #expect(await h.service.perform(.input(run: run, step: 1, frame: 1, batch: outside)) == .rejected(.staleStep))
        // The person acts: focus the first control in the crop, then answer and submit.
        let answer: [HumanInput] = kind == .mfa
            ? [.pointer(.down, x: 4, y: 4), .pointer(.up, x: 4, y: 4), .text("123456"), .key(.enter)]
            : [.pointer(.down, x: 2, y: 2), .pointer(.up, x: 2, y: 2), .key(.tab), .key(.enter)]
        #expect(await h.service.perform(.input(run: run, step: 1, frame: 1, batch: HumanInputBatch(answer)!)) == .accepted)
        #expect(await eventually { h.posts.contains { $0.path == "/step" } }, "the person's own submission")
        try await Task.sleep(for: .milliseconds(400))
        #expect(await h.service.perform(.frame(run: run, step: 1, after: 1)) == .rejected(.captureUnavailable),
                "nothing is shown once the page left the step")
        #expect(await h.service.perform(.classify(run: run)) == fixtureProfile)
        #expect(await h.service.liveRuns == 0)
        #expect(h.site.elsewhereRequests.isEmpty)
    }

    @Test func lifetimeAndEndDisposeTheContextAndRefuseALateStart() async throws {
        let h = try await Host.make(); defer { Task { await h.finish() } }
        let (run, reply) = await h.start(user: "mfa-user", lifetime: 2)
        #expect(reply == .humanStep(.mfa))
        #expect(await eventually(4) { await h.service.liveRuns == 0 }, "the host's own lifetime cap ends the context")
        #expect(await h.service.perform(.showHuman(run: run, step: 1)) == .rejected(.unknownRun))
        #expect(await h.service.perform(.end(run: run)) == .ended)
        let credential = WebLoginCredential(FixtureSite.credential())!
        #expect(await h.service.perform(.start(run: run, workflow: .browserDemo, credential: credential, lifetime: 60))
                == .rejected(.unknownRun), "a start after end is refused")
    }

    @Test func endDuringAStalledLoginReturnsAtOnceWithoutSubmitting() async throws {
        let h = try await Host.make(); defer { Task { await h.finish() } }
        h.site.loginPage = .stall
        let run = UUID()
        let credential = WebLoginCredential(FixtureSite.credential())!
        let call = Task { await h.service.perform(.start(run: run, workflow: .browserDemo, credential: credential, lifetime: 60)) }
        try await Task.sleep(for: .milliseconds(600))
        let began = Date()
        #expect(await h.service.perform(.end(run: run)) == .ended)
        #expect(Date().timeIntervalSince(began) < 3)
        let outcome = await call.value
        #expect(outcome == .rejected(.unknownRun) || outcome == .failed(.loadFailed), "\(outcome)")
        let live = await h.service.liveRuns
        #expect(h.posts.isEmpty && live == 0)
    }

    @Test func rendererProcessesRunInsideChromiumsOwnSandbox() async throws {
        let h = try await Host.make(); defer { Task { await h.finish() } }
        #expect(await h.start(user: "mfa-user").1 == .humanStep(.mfa))
        let group = try #require(await h.service.browserProcessGroup)
        let processes = ownedProcesses(group)
        let renderers = processes.filter { $0.arguments.contains("--type=renderer") }
        #expect(!renderers.isEmpty)
        #expect(processes.allSatisfy { !$0.arguments.contains("--no-sandbox") })
        #expect(processes.allSatisfy { !$0.arguments.contains { $0.hasPrefix("--remote-debugging-port") } })
        for renderer in renderers { #expect(renderer.sandboxed, "renderer \(renderer.pid) is not sandboxed") }
        let record = processes.map { "\($0.pid) sandboxed=\($0.sandboxed) \($0.arguments.first { $0.hasPrefix("--type=") } ?? "browser")" }
        print("SANDBOX-EVIDENCE " + record.joined(separator: "; "))
    }

    @Test func peerLossIsTerminalAndEndsTheBrowserTree() async throws {
        let h = try await Host.make(); defer { Task { await h.finish() } }
        #expect(await h.start(user: "mfa-user").1 == .humanStep(.mfa))
        let group = try #require(await h.service.browserProcessGroup)
        await h.service.teardown()
        #expect(await eventually { !groupExists(group) }, "every browser process is gone")
        #expect(await h.start().1 == .rejected(.unknownRun), "no context is created after teardown")
        #expect(await h.service.browserProcessGroup == nil)
    }

    @Test func browserThatStopsAnsweringIsKilledAndReportedFatal() async throws {
        let h = try await Host.make(); defer { Task { await h.finish() } }
        let (run, reply) = await h.start(user: "mfa-user")
        #expect(reply == .humanStep(.mfa))
        let group = try #require(await h.service.browserProcessGroup)
        // Freeze only the browser group this test's host spawned; CDP now never replies.
        #expect(kill(-group, SIGSTOP) == 0)
        let began = Date()
        #expect(await h.service.perform(.end(run: run)) == .ended)
        #expect(Date().timeIntervalSince(began) < 4, "teardown is bounded without CDP")
        #expect(h.fatal.isSet, "the host reports itself fatal so its broker sees every run lost")
        #expect(await eventually { !groupExists(group) })
        #expect(await h.service.terminal)
    }
}

/// Pixel size decoded independently of the host, with ImageIO.
private func decodedSize(_ jpeg: Data) -> (width: Int, height: Int)? {
    guard let source = CGImageSourceCreateWithData(jpeg as CFData, nil),
          let image = CGImageSourceCreateImageAtIndex(source, 0, nil) else { return nil }
    return (image.width, image.height)
}

// MARK: Test-only inspection of the browser's own process group (never searched by name)

private struct OwnedProcess {
    let pid: pid_t
    let arguments: [String]
    let sandboxed: Bool
}

private typealias SandboxCheck = @convention(c) (pid_t, UnsafePointer<CChar>?, Int32) -> Int32
private let sandboxCheck: SandboxCheck? = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "sandbox_check")
    .map { unsafeBitCast($0, to: SandboxCheck.self) }

private func ownedProcesses(_ group: pid_t) -> [OwnedProcess] {
    var pids = [pid_t](repeating: 0, count: 256)
    // Returns the number of process IDs written (measured on macOS 15), not bytes.
    let count = max(0, min(pids.count, Int(proc_listpgrppids(group, &pids, Int32(pids.count * MemoryLayout<pid_t>.size)))))
    return pids.prefix(count).filter { $0 > 0 }.map { pid in
        OwnedProcess(pid: pid, arguments: arguments(of: pid), sandboxed: (sandboxCheck?(pid, nil, 0) ?? 0) == 1)
    }
}

private func arguments(of pid: pid_t) -> [String] {
    var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
    var size = 0
    guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else { return [] }
    var buffer = [UInt8](repeating: 0, count: size)
    guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0 else { return [] }
    let argc = Int(buffer.withUnsafeBytes { $0.load(as: Int32.self) })
    var parts: [String] = [], current: [UInt8] = []
    var index = 4
    // Executable path, padding NULs, then argc NUL-terminated arguments.
    while index < size, buffer[index] != 0 { index += 1 }
    while index < size, buffer[index] == 0 { index += 1 }
    while index < size, parts.count < argc + 1 {
        if buffer[index] == 0 { parts.append(String(decoding: current, as: UTF8.self)); current = [] }
        else { current.append(buffer[index]) }
        index += 1
    }
    return parts
}
