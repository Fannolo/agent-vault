import Darwin
import Foundation

/// The only CDP methods the host can send. Callers never name a method: every call site in this
/// target uses one of these cases with parameters built in code. There is deliberately no generic
/// expression evaluation, no cookie or storage reader and no remote-debugging listener.
enum CDPMethod: String, CaseIterable, Sendable {
    case browserGetVersion = "Browser.getVersion"
    case browserSetDownloadBehavior = "Browser.setDownloadBehavior"
    case targetSetAutoAttach = "Target.setAutoAttach"
    case targetCreateBrowserContext = "Target.createBrowserContext"
    case targetDisposeBrowserContext = "Target.disposeBrowserContext"
    case targetCreateTarget = "Target.createTarget"
    case targetCloseTarget = "Target.closeTarget"
    case runtimeRunIfWaitingForDebugger = "Runtime.runIfWaitingForDebugger"
    case fetchEnable = "Fetch.enable"
    case fetchContinueRequest = "Fetch.continueRequest"
    case fetchFailRequest = "Fetch.failRequest"
    case fetchGetResponseBody = "Fetch.getResponseBody"
    case fetchFulfillRequest = "Fetch.fulfillRequest"
    case networkEnable = "Network.enable"
    case pageEnable = "Page.enable"
    case pageNavigate = "Page.navigate"
    case pageGetFrameTree = "Page.getFrameTree"
    case pageCreateIsolatedWorld = "Page.createIsolatedWorld"
    case pageCaptureScreenshot = "Page.captureScreenshot"
    case runtimeCallFunctionOn = "Runtime.callFunctionOn"
    case emulationSetDeviceMetricsOverride = "Emulation.setDeviceMetricsOverride"
    case inputDispatchMouseEvent = "Input.dispatchMouseEvent"
    case inputDispatchKeyEvent = "Input.dispatchKeyEvent"
    case inputInsertText = "Input.insertText"
    case browserClose = "Browser.close"
}

/// A JSON value crossing the pipe.
enum JSONValue: Sendable, Equatable {
    case null, bool(Bool), number(Double), string(String), array([JSONValue]), object([String: JSONValue])

    init?(any value: Any) {
        switch value {
        case is NSNull: self = .null
        case let number as NSNumber:
            self = CFGetTypeID(number) == CFBooleanGetTypeID() ? .bool(number.boolValue) : .number(number.doubleValue)
        case let string as String: self = .string(string)
        case let array as [Any]:
            var items: [JSONValue] = []
            for item in array { guard let value = JSONValue(any: item) else { return nil }; items.append(value) }
            self = .array(items)
        case let object as [String: Any]:
            var fields: [String: JSONValue] = [:]
            for (key, item) in object { guard let value = JSONValue(any: item) else { return nil }; fields[key] = value }
            self = .object(fields)
        default: return nil
        }
    }

    var any: Any {
        switch self {
        case .null: NSNull()
        case .bool(let value): value
        case .number(let value): value
        case .string(let value): value
        case .array(let items): items.map(\.any)
        case .object(let fields): fields.mapValues(\.any)
        }
    }

    subscript(key: String) -> JSONValue? { if case .object(let fields) = self { fields[key] } else { nil } }
    var string: String? { if case .string(let value) = self { value } else { nil } }
    var double: Double? { if case .number(let value) = self { value } else { nil } }
    var bool: Bool? { if case .bool(let value) = self { value } else { nil } }
    var array: [JSONValue]? { if case .array(let value) = self { value } else { nil } }
}

/// Immutable JSON-compatible parameters, built in code and serialized as soon as they are sent.
struct CDPParameters: @unchecked Sendable, ExpressibleByDictionaryLiteral {
    let fields: [String: Any]
    init(_ fields: [String: Any]) { self.fields = fields }
    init(dictionaryLiteral elements: (String, Any)...) { fields = Dictionary(uniqueKeysWithValues: elements) }
}

struct CDPEvent: Sendable {
    let method: String
    let params: JSONValue
    let session: String?
}

enum CDPError: Error, Equatable { case closed, timeout, protocolError, tooLarge }

/// Chromium driven over two inherited private pipes: commands on fd 3, replies on fd 4.
/// No TCP debugging port exists. The child runs in its own process group so teardown can end
/// the whole browser tree with one signal, even if CDP has stopped answering.
final class ChromiumPipe: @unchecked Sendable {
    /// Constant. No caller contributes a switch.
    static let arguments: [String] = [
        "--remote-debugging-pipe", "--use-mock-keychain", "--password-store=basic", "--no-first-run",
        "--no-default-browser-check", "--disable-extensions", "--disable-sync", "--disable-background-networking",
        "--disable-component-update", "--disable-default-apps", "--no-pings", "--disable-domain-reliability",
        "--dns-prefetch-disable", "--disable-breakpad", "--disable-client-side-phishing-detection",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--metrics-recording-only",
        "--disable-features=Translate,OptimizationHints,MediaRouter,DialMediaRouteProvider,AutofillServerCommunication",
        // window.open and target=_blank create nothing; paused auto-attach remains a second layer.
        "--block-new-web-contents", "--window-size=1280,900", "about:blank",
    ]
    static let maximumMessageBytes = 8 << 20

    let processGroup: pid_t
    private let commands: Int32
    private let replies: Int32
    private let lock = NSLock()
    private let owned: OwnedGroup
    /// Writes happen only here, one message at a time, never under `lock`; it alone closes `commands`.
    private let writer = DispatchQueue(label: "agentvault.cdp.writer")
    private var commandsOpen = true
    private var nextID = 0
    private var pending: [Int: CheckedContinuation<Result<JSONValue, CDPError>, Never>] = [:]
    private var closed = false
    private let onEvent: @Sendable (CDPEvent) -> Void
    private let onExit: @Sendable () -> Void

    /// Starts `binary` with a private user data directory under `runDirectory`, which must be a
    /// 0700 directory owned by this user. HOME and TMPDIR also point inside it.
    init(binary: URL, runDirectory: URL, onEvent: @escaping @Sendable (CDPEvent) -> Void,
         onExit: @escaping @Sendable () -> Void,
         makeGroup: @Sendable (pid_t) -> OwnedGroup = { OwnedGroup($0) }) throws {
        self.onEvent = onEvent; self.onExit = onExit
        var info = stat()
        guard lstat(runDirectory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, info.st_uid == geteuid(),
              info.st_mode & 0o077 == 0 else { throw CDPError.closed }
        let profile = runDirectory.appendingPathComponent("profile-\(UUID().uuidString)")
        guard mkdir(profile.path, 0o700) == 0 else { throw CDPError.closed }

        var toChild: [Int32] = [0, 0], fromChild: [Int32] = [0, 0]
        guard pipe(&toChild) == 0 else { throw CDPError.closed }
        guard pipe(&fromChild) == 0 else { close(toChild[0]); close(toChild[1]); throw CDPError.closed }
        for fd in [toChild[1], fromChild[0]] { _ = fcntl(fd, F_SETFD, FD_CLOEXEC) }

        var actions: posix_spawn_file_actions_t? = nil
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY, 0)
        posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0)
        posix_spawn_file_actions_adddup2(&actions, toChild[0], 3)
        posix_spawn_file_actions_adddup2(&actions, fromChild[1], 4)
        var attributes: posix_spawnattr_t? = nil
        posix_spawnattr_init(&attributes)
        defer { posix_spawnattr_destroy(&attributes) }
        // Own process group, and no descriptor beyond 0-4 is inherited.
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT))
        posix_spawnattr_setpgroup(&attributes, 0)

        let argv = [binary.path, "--user-data-dir=\(profile.path)"] + Self.arguments
        let environment = ["HOME=\(runDirectory.path)", "TMPDIR=\(runDirectory.path)/", "PATH=/usr/bin:/bin"]
        var pid: pid_t = 0
        let status = withCStrings(argv) { argvPointers in
            withCStrings(environment) { envPointers in
                posix_spawn(&pid, binary.path, &actions, &attributes, argvPointers, envPointers)
            }
        }
        close(toChild[0]); close(fromChild[1])
        guard status == 0 else { close(toChild[1]); close(fromChild[0]); throw CDPError.closed }
        processGroup = pid; commands = toChild[1]; replies = fromChild[0]
        owned = makeGroup(pid)
        // A browser that stops reading must never block a writer past its deadline.
        _ = fcntl(commands, F_SETFL, fcntl(commands, F_GETFL) | O_NONBLOCK)
        signal(SIGPIPE, SIG_IGN)
        let thread = Thread { [weak self] in self?.readLoop() }
        thread.stackSize = 1 << 20
        thread.start()
        owned.startReaper()
    }

    deinit {
        terminate()
        // No write can be running: an in-flight write holds a strong reference to this pipe.
        if commandsOpen { close(commands) }
    }

    /// Sends one command and waits at most `timeout` for its reply.
    func call(_ method: CDPMethod, _ params: CDPParameters = [:], session: String? = nil,
              timeout: TimeInterval = 10) async throws(CDPError) -> JSONValue {
        let result = await withCheckedContinuation { (continuation: CheckedContinuation<Result<JSONValue, CDPError>, Never>) in
            let id: Int? = lock.withLock {
                guard !closed else { return nil }
                nextID += 1
                pending[nextID] = continuation
                return nextID
            }
            guard let id else { return continuation.resume(returning: .failure(.closed)) }
            var message: [String: Any] = ["id": id, "method": method.rawValue, "params": params.fields]
            if let session { message["sessionId"] = session }
            guard var data = try? JSONSerialization.data(withJSONObject: message) else {
                return finish(id, .failure(.protocolError))
            }
            data.append(0)
            let deadline = Date().addingTimeInterval(timeout)
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak self] in self?.finish(id, .failure(.timeout)) }
            writer.async { [weak self] in self?.send(data, id: id, until: deadline) }
        }
        return try result.get()
    }

    /// Ends the browser tree: closes the pipes and kills the whole process group, then reaps it.
    /// Bounded: it does not depend on CDP answering.
    func terminate() {
        let (waiting, alreadyClosed) = lock.withLock { () -> ([CheckedContinuation<Result<JSONValue, CDPError>, Never>], Bool) in
            defer { closed = true; pending = [:] }
            return (Array(pending.values), closed)
        }
        for continuation in waiting { continuation.resume(returning: .failure(.closed)) }
        guard !alreadyClosed else { return }
        // Never waits for a writer: kill first; the writer notices within one poll slice.
        killGroup()
        writer.async { [weak self] in self?.closeCommandsIfShut() }
    }

    /// SIGKILLs every process of the owned group, but only while its leader is unreaped: the group
    /// ID is then still ours. After reaping there is nothing left to signal, and nothing is.
    func killGroup() { owned.signal() }

    /// Sends `signal` to the owned group only while it is still pinned; `false` otherwise.
    @discardableResult
    func signalGroup(_ signal: Int32) -> Bool { owned.signal(signal) }

    /// True once the leader has been reaped, after every member of its group was ended.
    var isReaped: Bool { owned.isReaped }

    var isClosed: Bool { lock.withLock { closed } }

    private func finish(_ id: Int, _ result: Result<JSONValue, CDPError>) {
        let continuation = lock.withLock { pending.removeValue(forKey: id) }
        continuation?.resume(returning: result)
    }

    /// Writer queue only. A message whose call already ended is skipped whole, so framing stays
    /// intact; a message cut short by its deadline or a dead pipe breaks the framing, so the
    /// browser is ended.
    private func send(_ data: Data, id: Int, until deadline: Date) {
        defer { closeCommandsIfShut() }
        guard lock.withLock({ !closed && pending[id] != nil }) else { return }
        if !writeAll(data, until: deadline) { terminate() }
    }

    private func writeAll(_ data: Data, until deadline: Date) -> Bool {
        data.withUnsafeBytes { buffer -> Bool in
            var offset = 0
            while offset < buffer.count {
                let remaining = deadline.timeIntervalSinceNow
                guard remaining > 0, !isClosed else { return false }
                var descriptor = pollfd(fd: commands, events: Int16(POLLOUT), revents: 0)
                let ready = poll(&descriptor, 1, Int32(max(1, min(50, remaining * 1000))))
                if ready < 0 { if errno == EINTR { continue }; return false }
                if ready == 0 { continue }
                if descriptor.revents & Int16(POLLERR | POLLHUP | POLLNVAL) != 0 { return false }
                let written = Darwin.write(commands, buffer.baseAddress! + offset, buffer.count - offset)
                if written < 0 { if errno == EINTR || errno == EAGAIN { continue }; return false }
                offset += written
            }
            return true
        }
    }

    private func closeCommandsIfShut() {
        guard isClosed, commandsOpen else { return }
        commandsOpen = false
        close(commands)
    }

    private func readLoop() {
        var buffer = Data()
        var chunk = [UInt8](repeating: 0, count: 65_536)
        while true {
            let count = read(replies, &chunk, chunk.count)
            if count < 0 && errno == EINTR { continue }
            if count <= 0 { break }
            buffer.append(contentsOf: chunk[0..<count])
            while let end = buffer.firstIndex(of: 0) {
                let message = buffer[buffer.startIndex..<end]
                buffer.removeSubrange(buffer.startIndex...end)
                dispatch(message)
            }
            // A message larger than the cap means a misbehaving browser: end it.
            if buffer.count > Self.maximumMessageBytes { break }
        }
        close(replies)
        terminate()
        onExit()
    }

    private func dispatch(_ data: Data) {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let message = JSONValue(any: object) else { return }
        if let id = message["id"]?.double {
            if message["error"] != nil { finish(Int(id), .failure(.protocolError)) }
            else { finish(Int(id), .success(message["result"] ?? .object([:]))) }
        } else if let method = message["method"]?.string {
            onEvent(CDPEvent(method: method, params: message["params"] ?? .object([:]), session: message["sessionId"]?.string))
        }
    }
}

/// The browser's process group, owned from spawn until its leader is reaped.
///
/// The leader is a child of this process, so its PID, and with it the group ID, cannot be reused
/// until it is reaped, and it is reaped only here, under `lock`. Signalling under the same lock
/// while ownership is pinned therefore can only reach this browser's processes.
final class OwnedGroup: @unchecked Sendable {
    enum ReapResult: Sendable { case reaped, interrupted, noChild, failed }
    private enum Ownership { case pinned, reaped, unavailable }
    let id: pid_t
    private let lock = NSLock()
    private var ownership = Ownership.pinned
    private let observeExit: @Sendable (pid_t) -> Bool
    private let reap: @Sendable (pid_t) -> ReapResult

    init(_ leader: pid_t, observeExit: (@Sendable (pid_t) -> Bool)? = nil,
         reap: (@Sendable (pid_t) -> ReapResult)? = nil) {
        id = leader
        self.observeExit = observeExit ?? Self.waitForExit
        self.reap = reap ?? Self.waitForChild
    }

    /// Returns `false` once the leader is reaped: the group ID may then belong to someone else.
    @discardableResult
    func signal(_ signal: Int32 = SIGKILL) -> Bool {
        lock.withLock {
            guard ownership == .pinned else { return false }
            return Darwin.kill(-id, signal) == 0
        }
    }

    var isReaped: Bool { lock.withLock { ownership == .reaped } }

    /// Waits for the leader to exit without reaping it, ends any member it left behind while the
    /// group ID is still pinned, then reaps it. Holds itself alive until then.
    func startReaper() {
        let reaper = Thread { [self] in
            // Not `waitid(WEXITED | WNOWAIT)`: measured on macOS 15, it also returns for a stopped
            // child. A kqueue exit event fires only on exit and does not reap.
            // A failed watcher also tears down the owned group; it cannot abandon the child.
            _ = observeExit(id)
            lock.withLock {
                _ = Darwin.kill(-id, SIGKILL)
                while true {
                    switch reap(id) {
                    case .interrupted: continue
                    case .reaped: ownership = .reaped
                    // ECHILD means ownership can no longer be proved. Never signal again or
                    // claim a successful reap; an unexpected wait failure is equally uncertain.
                    case .noChild, .failed: ownership = .unavailable
                    }
                    return
                }
            }
        }
        reaper.stackSize = 1 << 16
        reaper.start()
    }

    static func waitForChild(_ id: pid_t) -> ReapResult {
        var status: Int32 = 0
        if waitpid(id, &status, 0) == id { return .reaped }
        switch errno {
        case EINTR: return .interrupted
        case ECHILD: return .noChild
        default: return .failed
        }
    }

    /// Blocks until exit; a failed observer makes the caller kill and reap instead.
    private static func waitForExit(_ id: pid_t) -> Bool {
        let queue = kqueue()
        guard queue >= 0 else { return false }
        defer { close(queue) }
        var change = kevent(ident: UInt(id), filter: Int16(EVFILT_PROC), flags: UInt16(EV_ADD | EV_ONESHOT),
                            fflags: NOTE_EXIT, data: 0, udata: nil)
        var event = kevent()
        while true {
            let count = kevent(queue, &change, 1, &event, 1, nil)
            if count > 0 {
                // An exited but unreaped leader cannot be registered: that is an exit too.
                if event.flags & UInt16(EV_ERROR) != 0 { return event.data == Int(ESRCH) }
                return event.fflags & NOTE_EXIT != 0
            }
            if count < 0 && errno == EINTR { continue }
            return count < 0 && errno == ESRCH
        }
    }
}

private func withCStrings<R>(_ strings: [String], _ body: (UnsafePointer<UnsafeMutablePointer<CChar>?>) -> R) -> R {
    let pointers: [UnsafeMutablePointer<CChar>?] = strings.map { strdup($0) } + [nil]
    defer { for pointer in pointers { free(pointer) } }
    return pointers.withUnsafeBufferPointer { body($0.baseAddress!) }
}
