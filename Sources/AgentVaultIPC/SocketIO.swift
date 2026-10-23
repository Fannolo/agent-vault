#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import CAgentVaultSocket
import Dispatch
import Foundation

/// An absolute point on the monotonic clock. Every wait recomputes its remainder from it, so
/// interrupted and partial I/O can never extend an operation.
struct Deadline: Sendable {
    private let nanoseconds: UInt64?

    static let never = Deadline(nanoseconds: nil)

    static func after(_ seconds: TimeInterval) -> Deadline {
        let span = seconds.isFinite && seconds > 0 ? UInt64(min(seconds, 86_400) * 1_000_000_000) : 0
        return Deadline(nanoseconds: DispatchTime.now().uptimeNanoseconds + span)
    }

    /// Milliseconds left for `poll`, rounded up; -1 waits indefinitely; nil once expired.
    var pollTimeout: Int32? {
        guard let nanoseconds else { return -1 }
        let now = DispatchTime.now().uptimeNanoseconds
        guard nanoseconds > now else { return nil }
        return Int32(min((nanoseconds - now + 999_999) / 1_000_000, UInt64(Int32.max)))
    }

    var dispatchTime: DispatchTime? { nanoseconds.map { DispatchTime(uptimeNanoseconds: $0) } }
}

/// Time bounds of the socket transport. A frame, once its first byte arrives, must complete by
/// `frame`; one reply write must complete by `write`.
struct SocketTimeouts: Sendable {
    var frame: TimeInterval
    var write: TimeInterval
    static let standard = SocketTimeouts(frame: 5, write: 5)
}

/// Wire framing. A request is `length:u32be | id:u32be | opcode:u8 | body`; a reply is
/// `length:u32be | id:u32be | body`, where `length` counts the body only. The ID only matches
/// a reply to its request; it carries no authority.
enum SocketFrame {
    static let requestHeader = 9
    static let replyHeader = 8

    enum Opcode: UInt8, Sendable {
        case read = 0x01
        case snapshot = 0x11, begin = 0x12, authorize = 0x13, continuation = 0x14
    }

    static func request(id: UInt32, opcode: Opcode, body: Data) -> Data {
        var data = Data(capacity: requestHeader + body.count)
        append(UInt32(body.count), to: &data); append(id, to: &data)
        data.append(opcode.rawValue); data.append(body)
        return data
    }

    static func reply(id: UInt32, body: Data) -> Data {
        var data = Data(capacity: replyHeader + body.count)
        append(UInt32(body.count), to: &data); append(id, to: &data)
        data.append(body)
        return data
    }

    static func number(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        bytes[offset..<offset + 4].reduce(0) { $0 << 8 | UInt32($1) }
    }

    private static func append(_ value: UInt32, to data: inout Data) {
        data.append(contentsOf: [UInt8(value >> 24), UInt8(value >> 16 & 0xff), UInt8(value >> 8 & 0xff), UInt8(value & 0xff)])
    }
}

/// Blocking frame I/O on one nonblocking descriptor. The owner guarantees the descriptor stays
/// open for the duration of each call; these functions never close it.
enum SocketIO {
    enum End: Error, Equatable {
        /// Orderly close before any byte of a frame.
        case closed
        /// Close, error or deadline inside a frame.
        case broken
        /// The wake descriptor fired.
        case stopped
    }

    enum Frame {
        case complete(header: [UInt8], body: [UInt8])
        /// The declared body exceeds the limit; `header` is intact and nothing more was read.
        case oversized(header: [UInt8])
    }

    /// Waits indefinitely for a frame to start, then requires it to finish within `timeout`.
    static func readFrame(_ fd: Int32, wake: Int32, headerSize: Int, maxBody: Int,
                          timeout: TimeInterval) -> Result<Frame, End> {
        var header = [UInt8](repeating: 0, count: headerSize)
        var deadline = Deadline.never
        var filled = 0
        while filled < headerSize {
            switch receive(fd, wake: wake, into: &header, from: filled, deadline: deadline) {
            case .success(let count):
                if filled == 0 { deadline = .after(timeout) }
                filled += count
            case .failure(let end):
                return .failure(filled == 0 ? end : (end == .stopped ? .stopped : .broken))
            }
        }
        let length = Int(SocketFrame.number(header, at: 0))
        guard length <= maxBody else { return .success(.oversized(header: header)) }
        var body = [UInt8](repeating: 0, count: length)
        filled = 0
        while filled < length {
            switch receive(fd, wake: wake, into: &body, from: filled, deadline: deadline) {
            case .success(let count): filled += count
            case .failure(let end): return .failure(end == .stopped ? .stopped : .broken)
            }
        }
        return .success(.complete(header: header, body: body))
    }

    /// Every attempt first checks the wake descriptor and the deadline, so a peer that always has
    /// bytes ready cannot outlast either.
    private static func receive(_ fd: Int32, wake: Int32, into buffer: inout [UInt8], from offset: Int,
                                deadline: Deadline) -> Result<Int, End> {
        while true {
            switch wait(fd, wake: wake, events: Int32(AV_WAIT_READ), deadline: deadline) {
            case .ready: break
            case .woken: return .failure(.stopped)
            case .expired, .failed: return .failure(.broken)
            }
            let count = buffer.withUnsafeMutableBytes {
                av_socket_recv(fd, $0.baseAddress! + offset, $0.count - offset)
            }
            if count > 0 { return .success(count) }
            if count == 0 { return .failure(.closed) }
            let failure = errno
            guard failure == EINTR || failure == EAGAIN || failure == EWOULDBLOCK else { return .failure(.broken) }
        }
    }

    /// Writes every byte by `deadline`, checking the wake descriptor and the deadline before each
    /// attempt. A `false` result leaves the stream unusable unless no byte was sent.
    static func writeAll(_ fd: Int32, wake: Int32, _ data: Data, deadline: Deadline) -> Bool {
        data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                guard case .ready = wait(fd, wake: wake, events: Int32(AV_WAIT_WRITE), deadline: deadline) else { return false }
                let count = av_socket_send(fd, bytes.baseAddress! + offset, bytes.count - offset)
                if count > 0 { offset += count; continue }
                let failure = errno
                guard count < 0, failure == EINTR || failure == EAGAIN || failure == EWOULDBLOCK else { return false }
            }
            return true
        }
    }

    enum Wait { case ready, woken, expired, failed }

    static func wait(_ fd: Int32, wake: Int32, events: Int32, deadline: Deadline) -> Wait {
        while true {
            guard let timeout = deadline.pollTimeout else { return .expired }
            switch av_socket_wait(fd, wake, events, timeout) {
            case Int32(AV_WAIT_READY): return .ready
            case Int32(AV_WAIT_WOKEN): return .woken
            case Int32(AV_WAIT_TIMEOUT): continue   // the next pass observes expiry
            default: if errno == EINTR { continue }; return .failed
            }
        }
    }

    /// Connects and authenticates the broker before the caller can send a byte.
    static func connect(path: String, brokerUID: UInt32, deadline: Deadline) -> Result<Int32, IPCError> {
        var inProgress: Int32 = 0
        let fd = av_socket_connect(path, &inProgress)
        guard fd >= 0 else { return .failure(.connectionFailed) }
        if inProgress != 0 {
            switch wait(fd, wake: -1, events: Int32(AV_WAIT_WRITE), deadline: deadline) {
            case .ready where av_socket_connect_result(fd) == 0: break
            case .expired: close(fd); return .failure(.timeout)
            default: close(fd); return .failure(.connectionFailed)
            }
        }
        var uid: UInt32 = 0
        guard av_socket_peer_uid(fd, &uid) == 0 else { close(fd); return .failure(.connectionFailed) }
        guard uid == brokerUID, uid != 0 else { close(fd); return .failure(.brokerRejected) }
        return .success(fd)
    }
}

/// A one-shot event any number of tasks can await.
final class Completion: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func signal() {
        let pending = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
            done = true
            defer { waiters = [] }
            return waiters
        }
        for waiter in pending { waiter.resume() }
    }

    var isSignalled: Bool { lock.withLock { done } }

    func wait() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let ready = lock.withLock { () -> Bool in
                if !done { waiters.append(continuation) }
                return done
            }
            if ready { continuation.resume() }
        }
    }
}

/// Counts handler tasks so a stopping server can await every one it started.
final class WorkTracker: @unchecked Sendable {
    private let lock = NSLock()
    private var running = 0
    private var idle: [CheckedContinuation<Void, Never>] = []

    func enter() { lock.withLock { running += 1 } }

    func leave() {
        let pending = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
            running -= 1
            guard running == 0 else { return [] }
            defer { idle = [] }
            return idle
        }
        for waiter in pending { waiter.resume() }
    }

    var count: Int { lock.withLock { running } }

    func drained() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let ready = lock.withLock { () -> Bool in
                if running > 0 { idle.append(continuation) }
                return running == 0
            }
            if ready { continuation.resume() }
        }
    }
}

/// `close(2)` for types that declare their own `close()`.
func closeDescriptor(_ fd: Int32) { _ = close(fd) }

/// Starts a dedicated thread for blocking descriptor work, keeping it off the concurrency pool.
func startThread(_ name: String, _ body: @escaping @Sendable () -> Void) {
    let thread = Thread(block: body)
    thread.name = name
    thread.start()
}
