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

    func pipe(makeGroup: @Sendable (pid_t) -> OwnedGroup = { OwnedGroup($0) }) throws -> ChromiumPipe {
        try ChromiumPipe(binary: binary, runDirectory: directory, onEvent: { _ in }, onExit: {}, makeGroup: makeGroup)
    }

    func remove() { try? FileManager.default.removeItem(at: directory) }

    /// Ends the fake through its owned group handle and waits until its leader is reaped.
    static func release(_ pipe: ChromiumPipe?) {
        guard let pipe else { return }
        pipe.killGroup()
        let deadline = Date().addingTimeInterval(5)
        while !pipe.isReaped && Date() < deadline { usleep(20_000) }
        #expect(pipe.isReaped, "owned group \(pipe.processGroup) was not reaped")
    }
}

/// Runs `work` on its own thread; `true` if it returned within `seconds`.
private func returns(within seconds: Double, _ work: @escaping @Sendable () -> Void) -> Bool {
    let done = DispatchSemaphore(value: 0)
    Thread { work(); done.signal() }.start()
    return done.wait(timeout: .now() + seconds) == .success
}

/// The owned group's leader has been reaped, after every member was ended.
private func reaped(_ pipe: ChromiumPipe, within seconds: Double = 3) -> Bool {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline && !pipe.isReaped { usleep(20_000) }
    return pipe.isReaped
}

@Suite(.serialized) struct PipeStallTests {
    static let large = String(repeating: "A", count: 8 << 20)

    @Test func teardownIsBoundedWhileALargeWriteIsStalled() async throws {
        let reader = try StalledReader(); defer { reader.remove() }
        let pipe = try reader.pipe(); defer { StalledReader.release(pipe) }
        let began = Date()
        let stalled = Task { try? await pipe.call(.fetchFulfillRequest, ["requestId": "r", "body": Self.large], timeout: 30) }
        try await Task.sleep(for: .milliseconds(300))
        // Teardown must not wait for the writer: it kills the owned group and returns.
        #expect(returns(within: 1) { pipe.terminate() }, "terminate waited on a stalled pipe write")
        #expect(reaped(pipe), "the owned browser group is gone")
        _ = await stalled.value
        #expect(Date().timeIntervalSince(began) < 5, "the stalled call ends with the pipe, not at its 30 s timeout")
    }

    @Test func stalledWriteEndsAtItsOwnDeadlineAndBreaksThePipe() async throws {
        let reader = try StalledReader(); defer { reader.remove() }
        let pipe = try reader.pipe(); defer { StalledReader.release(pipe) }
        let began = Date()
        let result: Result<JSONValue, CDPError>
        do { result = .success(try await pipe.call(.fetchFulfillRequest, ["requestId": "r", "body": Self.large], timeout: 1)) }
        catch { result = .failure(error) }
        #expect(result == .failure(.timeout) || result == .failure(.closed))
        #expect(Date().timeIntervalSince(began) < 3, "a write cannot outlive its call's deadline")
        // A half-written message would corrupt the framing: the whole browser goes.
        #expect(reaped(pipe) && pipe.isClosed)
    }

    @Test func callsQueuedBehindAStalledWriteKeepTheirOwnDeadlines() async throws {
        let reader = try StalledReader(); defer { reader.remove() }
        let pipe = try reader.pipe(); defer { StalledReader.release(pipe) }
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

@Suite(.serialized) struct OwnedGroupTests {
    @Test func failedExitObservationKillsAndReapsTheOwnedChild() throws {
        let reader = try StalledReader(); defer { reader.remove() }
        let pipe = try reader.pipe { OwnedGroup($0, observeExit: { _ in false }) }
        defer { StalledReader.release(pipe) }
        #expect(reaped(pipe), "observer failure must end the child without waiting for its 20 s lifetime")
        #expect(!pipe.signalGroup(SIGKILL))
        let observation = pipe.withOwnedChild { _ in true }
        #expect(observation == nil, "observation is refused after confirmed reap")
    }

    @Test func interruptedWaitRetriesBeforeReportingTheChildReaped() throws {
        let reader = try StalledReader(); defer { reader.remove() }
        let calls = ReapCalls()
        let pipe = try reader.pipe { OwnedGroup($0, observeExit: { _ in false }, reap: { id in
            if calls.next() == 1 { return .interrupted }
            return OwnedGroup.waitForChild(id)
        }) }
        defer { StalledReader.release(pipe) }
        #expect(reaped(pipe))
        #expect(calls.count == 2, "EINTR cannot count as a completed wait")
        #expect(!pipe.signalGroup(SIGKILL))
    }

    @Test(arguments: [OwnedGroup.ReapResult.noChild, .failed])
    func anUnconfirmedWaitNeitherClaimsReapedNorSignalsAgain(_ failure: OwnedGroup.ReapResult) throws {
        let reader = try StalledReader(); defer { reader.remove() }
        let calls = ReapCalls()
        let pipe = try reader.pipe { OwnedGroup($0, observeExit: { _ in false }, reap: { id in
            // Actually reap our child so fault injection cannot leak it. Report uncertainty
            // to the handle to check its fail-closed state independently of that cleanup.
            guard case .reaped = OwnedGroup.waitForChild(id) else { return .failed }
            _ = calls.next()
            return failure
        }) }
        let deadline = Date().addingTimeInterval(3)
        while calls.count == 0 && Date() < deadline { usleep(20_000) }
        #expect(calls.count == 1)
        #expect(!pipe.signalGroup(SIGKILL), "ownership cannot be assumed after ECHILD or a failed wait")
        #expect(!pipe.isReaped, "only a confirmed wait may report successful cleanup")
        let observation = pipe.withOwnedChild { _ in true }
        #expect(observation == nil, "observation is refused when ownership becomes uncertain")
    }

    @Test func aStoppedBrowserIsNeitherExitedNorReapedUntilItIsKilled() async throws {
        let reader = try StalledReader(); defer { reader.remove() }
        let pipe = try reader.pipe(); defer { StalledReader.release(pipe) }
        #expect(pipe.signalGroup(SIGSTOP))
        try await Task.sleep(for: .milliseconds(500))
        #expect(!pipe.isReaped, "a stop is not an exit: the group ID must stay pinned")
        #expect(pipe.signalGroup(SIGCONT))
        pipe.killGroup()
        #expect(reaped(pipe), "killed through the owned handle, then reaped")
        #expect(!pipe.signalGroup(SIGKILL), "after reaping, the handle never signals again")
    }
}

private final class ReapCalls: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func next() -> Int { lock.withLock { value += 1; return value } }
    var count: Int { lock.withLock { value } }
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
        StalledReader.release(await service.launched)
    }
}

private final class Log: @unchecked Sendable {
    private let lock = NSLock(); private var value = false
    func mark() { lock.withLock { value = true } }
    var marked: Bool { lock.withLock { value } }
}
