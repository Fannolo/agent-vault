@testable import AgentVaultWebHost
import AgentVaultContracts
import AgentVaultWebHostProtocol
import Darwin
import Foundation
import Testing

/// A stand-in "browser" this test owns: it inherits the CDP pipes and never reads its commands,
/// so a large command fills the pipe and the writer stalls. It exits on its own after 20 s.
private struct StalledReader {
    let directory: URL
    let binary: URL

    init(script: String = "exec /bin/sleep 20") throws {
        var template = Array(FileManager.default.temporaryDirectory.appendingPathComponent("avpipe-XXXXXX").path.utf8CString)
        guard let created = mkdtemp(&template) else { throw CDPError.closed }
        directory = URL(fileURLWithPath: String(cString: created))
        binary = directory.appendingPathComponent("stalled-reader")
        try "#!/bin/sh\n\(script)\n".write(to: binary, atomically: true, encoding: .utf8)
        chmod(binary.path, 0o755)
    }

    func pipe() throws -> ChromiumPipe {
        try ChromiumPipe(binary: binary, runDirectory: directory, onEvent: { _ in }, onExit: {})
    }

    func remove() { try? FileManager.default.removeItem(at: directory) }
}

/// Runs `work` on its own thread; `true` if it returned within `seconds`.
private func returns(within seconds: Double, _ work: @escaping @Sendable () -> Void) -> Bool {
    let done = DispatchSemaphore(value: 0)
    Thread { work(); done.signal() }.start()
    return done.wait(timeout: .now() + seconds) == .success
}

private func groupGone(_ group: pid_t, within seconds: Double = 3) -> Bool {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
        if kill(-group, 0) != 0 && errno == ESRCH { return true }
        usleep(20_000)
    }
    return false
}

@Suite(.serialized) struct PipeStallTests {
    static let large = String(repeating: "A", count: 8 << 20)

    @Test func teardownIsBoundedWhileALargeWriteIsStalled() async throws {
        let reader = try StalledReader(); defer { reader.remove() }
        let pipe = try reader.pipe()
        let group = pipe.processGroup
        let began = Date()
        let stalled = Task { try? await pipe.call(.fetchFulfillRequest, ["requestId": "r", "body": Self.large], timeout: 30) }
        try await Task.sleep(for: .milliseconds(300))
        // Teardown must not wait for the writer: it kills the owned group and returns.
        #expect(returns(within: 1) { pipe.terminate() }, "terminate waited on a stalled pipe write")
        #expect(groupGone(group), "the owned browser group is gone")
        _ = await stalled.value
        #expect(Date().timeIntervalSince(began) < 5, "the stalled call ends with the pipe, not at its 30 s timeout")
    }

    @Test func stalledWriteEndsAtItsOwnDeadlineAndBreaksThePipe() async throws {
        let reader = try StalledReader(); defer { reader.remove() }
        let pipe = try reader.pipe()
        let group = pipe.processGroup
        let began = Date()
        let result: Result<JSONValue, CDPError>
        do { result = .success(try await pipe.call(.fetchFulfillRequest, ["requestId": "r", "body": Self.large], timeout: 1)) }
        catch { result = .failure(error) }
        #expect(result == .failure(.timeout) || result == .failure(.closed))
        #expect(Date().timeIntervalSince(began) < 3, "a write cannot outlive its call's deadline")
        // A half-written message would corrupt the framing: the whole browser goes.
        #expect(groupGone(group) && pipe.isClosed)
    }

    @Test func callsQueuedBehindAStalledWriteKeepTheirOwnDeadlines() async throws {
        let reader = try StalledReader(); defer { reader.remove() }
        let pipe = try reader.pipe()
        let stalled = Task { try? await pipe.call(.fetchFulfillRequest, ["requestId": "r", "body": Self.large], timeout: 10) }
        try await Task.sleep(for: .milliseconds(300))
        let began = Date()
        let small: Result<JSONValue, CDPError>
        do { small = .success(try await pipe.call(.browserGetVersion, timeout: 0.5)) } catch { small = .failure(error) }
        #expect(small == .failure(.timeout) || small == .failure(.closed))
        #expect(Date().timeIntervalSince(began) < 2, "a queued call is not held past its deadline by another's write")
        pipe.terminate()
        _ = await stalled.value
    }
}

@Suite(.serialized) struct LaunchBarrierTests {
    /// The fake browser records every command and never answers, so auto-attach is never confirmed.
    @Test func concurrentColdStartsCreateNoTargetBeforeAutoAttachIsConfirmed() async throws {
        let reader = try StalledReader(script: "exec /bin/cat <&3 > \"$HOME/cdp-commands.log\"")
        defer { reader.remove() }
        let fatal = Log()
        let service = HostService(policy: HostPolicy.fixture(primary: URL(string: "http://127.0.0.1:9")!)!,
                                  binary: reader.binary, runDirectory: reader.directory, onFatal: { fatal.mark() })
        let credential = WebLoginCredential(Data("synthetic-user\nSYNTHETIC-only".utf8))!
        let first = Task { await service.perform(.start(run: UUID(), workflow: .browserDemo, credential: credential, lifetime: 60)) }
        // Second start arrives once the browser exists and its auto-attach is still unconfirmed.
        let log = reader.directory.appendingPathComponent("cdp-commands.log")
        for _ in 0..<200 where !((try? String(contentsOf: log, encoding: .utf8))?.contains("Target.setAutoAttach") ?? false) {
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(await service.browserProcessGroup != nil)
        let second = Task { await service.perform(.start(run: UUID(), workflow: .browserDemo, credential: credential, lifetime: 60)) }
        let replies = [await first.value, await second.value]
        for reply in replies { #expect(reply == .failed(.rendererUnavailable) || reply == .rejected(.unknownRun), "\(reply)") }
        let recorded = (try? String(contentsOf: log, encoding: .utf8)) ?? ""
        #expect(recorded.contains("Target.setAutoAttach"))
        #expect(!recorded.contains("Target.createBrowserContext") && !recorded.contains("Target.createTarget"),
                "no run may create a target before every new target starts paused")
        let terminal = await service.terminal
        #expect(fatal.marked && terminal, "an unconfirmed auto-attach is fatal")
        await service.teardown()
    }
}

private final class Log: @unchecked Sendable {
    private let lock = NSLock(); private var value = false
    func mark() { lock.withLock { value = true } }
    var marked: Bool { lock.withLock { value } }
}
