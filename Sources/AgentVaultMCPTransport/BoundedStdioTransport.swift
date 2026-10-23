#if canImport(Darwin)
import Darwin
#else
import Glibc
import CAgentVaultStdio
#endif
import Dispatch
import Foundation
import Logging
import MCP

public enum StdioTransportError: String, Error, Sendable {
    case invalidConfiguration = "invalid_transport_configuration"
    case disconnected = "transport_disconnected"
    case ioFailure = "transport_io_failure"
    case lineTooLong = "transport_input_too_large"
    case outputTooLong = "transport_output_too_large"
    case invalidJSON = "transport_invalid_json"
    case tooDeep = "transport_json_too_deep"
    case duplicateKey = "transport_duplicate_json_key"
    case invalidRequestID = "transport_invalid_request_id"
    case duplicateRequestID = "transport_duplicate_request_id"
    case notificationTooLong = "transport_notification_too_large"
    case backpressure = "transport_backpressure"
    case writeTimeout = "transport_write_timeout"
    case truncatedInput = "transport_truncated_input"
}

/// A one-shot transport for a tools-only MCP server that emits no client requests.
/// Requires exclusive descriptor use and sets shared file descriptions nonblocking.
/// Owns duplicates and never closes the caller's descriptors.
public actor BoundedStdioTransport: Transport {
    public static let maxIncomingBytes = 65_536
    public static let maxOutgoingBytes = 1_048_576
    public static let maxBufferedMessages = 16
    public static let maxRequestIDBytes = 128
    public static let maxNotificationBytes = 8_192
    public nonisolated let logger = Logger(label: "agent-vault.transport", factory: { _ in SwiftLogNoOpLogHandler() })
    private enum State { case idle, connected, closed }
    private var state = State.idle
    private var pendingWrites = 0
    private let stream: AsyncThrowingStream<Data, any Error>
    private let channel: StdioChannel

    public init(input: Int32 = STDIN_FILENO, output: Int32 = STDOUT_FILENO, writeTimeout: TimeInterval = 5) {
        let (stream, continuation) = AsyncThrowingStream<Data, any Error>.makeStream(bufferingPolicy: .bufferingOldest(Self.maxBufferedMessages))
        self.stream = stream
        self.channel = StdioChannel(input: input, output: output, timeout: writeTimeout, continuation: continuation)
        continuation.onTermination = { [weak channel] _ in channel?.stop() }
    }

    deinit { channel.stop() }

    public func connect() async throws {
        if state == .connected, channel.isRunning { return }
        guard state == .idle else { throw StdioTransportError.disconnected }
        do { try channel.start(); state = .connected }
        catch {
            state = .closed
            channel.stop(error: (error as? StdioTransportError) ?? .ioFailure)
            throw error
        }
    }

    public func disconnect() async {
        state = .closed
        channel.stop()
        await channel.waitForClosure()
    }

    public func receive() -> AsyncThrowingStream<Data, any Error> { stream }

    public func send(_ data: Data) async throws {
        guard state == .connected, channel.isRunning else { throw StdioTransportError.disconnected }
        guard data.count <= Self.maxOutgoingBytes else {
            channel.stop(error: .outputTooLong)
            throw StdioTransportError.outputTooLong
        }
        guard !data.isEmpty, !data.contains(0x0A) else {
            channel.stop(error: .invalidJSON)
            throw StdioTransportError.invalidJSON
        }
        guard pendingWrites < Self.maxBufferedMessages else {
            channel.stop(error: .backpressure)
            throw StdioTransportError.backpressure
        }
        pendingWrites += 1
        defer { pendingWrites -= 1 }
        do {
            try await withCheckedThrowingContinuation { continuation in
                channel.write(data) { result in continuation.resume(with: result) }
            }
        } catch {
            channel.stop(error: (error as? StdioTransportError) ?? .ioFailure)
            throw error
        }
    }
}

private final class StdioChannel: @unchecked Sendable {
    private let lock = NSLock()
    private let originalInput: Int32
    private let originalOutput: Int32
    private let timeout: TimeInterval
    private let continuation: AsyncThrowingStream<Data, any Error>.Continuation
    private let readQueue = DispatchQueue(label: "agent-vault.stdin", qos: .utility)
    private let writeQueue = DispatchQueue(label: "agent-vault.stdout", qos: .utility)
    private let closure = DispatchGroup()
    private var started = false
    private var closed = false
    private var input: Int32 = -1
    private var output: Int32 = -1
    private var outstanding = Set<ID>()
    private var notificationTokens: Double = 16
    private var lastRefill = DispatchTime.now().uptimeNanoseconds

    init(input: Int32, output: Int32, timeout: TimeInterval, continuation: AsyncThrowingStream<Data, any Error>.Continuation) {
        originalInput = input; originalOutput = output; self.timeout = timeout; self.continuation = continuation
    }

    var isRunning: Bool { lock.withLock { started && !closed } }

    func start() throws {
        try lock.withLock {
            guard !started, !closed, timeout > 0, timeout <= 60, timeout.isFinite else {
                throw StdioTransportError.invalidConfiguration
            }
            input = fcntl(originalInput, F_DUPFD_CLOEXEC, 3)
            guard input >= 0 else { throw StdioTransportError.ioFailure }
            output = fcntl(originalOutput, F_DUPFD_CLOEXEC, 3)
            do {
                guard output >= 0 else { throw StdioTransportError.ioFailure }
                try nonblocking(input); try nonblocking(output)
                #if canImport(Darwin)
                guard fcntl(output, F_SETNOSIGPIPE, 1) == 0 else { throw StdioTransportError.ioFailure }
                #endif
            } catch {
                close(input); if output >= 0 { close(output) }
                input = -1; output = -1
                throw error
            }
            started = true
            closure.enter(); closure.enter()
            let descriptor = input
            readQueue.async { [self] in
                defer { close(descriptor); closure.leave() }
                readLoop(descriptor)
            }
        }
    }

    private func nonblocking(_ descriptor: Int32) throws {
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else { throw StdioTransportError.ioFailure }
    }

    func stop(error: StdioTransportError? = nil) {
        let descriptor: Int32? = lock.withLock {
            guard !closed else { return nil }
            closed = true
            outstanding.removeAll()
            return started ? output : -1
        }
        guard let descriptor else { return }
        if let error { continuation.finish(throwing: error) } else { continuation.finish() }
        if descriptor >= 0 {
            writeQueue.async { [self] in close(descriptor); closure.leave() }
        }
    }

    func waitForClosure() async {
        await withCheckedContinuation { continuation in
            closure.notify(queue: .global(qos: .utility)) { continuation.resume() }
        }
    }

    private func readLoop(_ descriptor: Int32) {
        var pending = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while isRunning {
            var event = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            let ready = poll(&event, 1, 50)
            if ready < 0 { if errno == EINTR { continue }; stop(error: .ioFailure); return }
            if ready == 0 { continue }
            if event.revents & Int16(POLLERR | POLLNVAL) != 0 { stop(error: .ioFailure); return }
            let count = read(descriptor, &buffer, buffer.count)
            if count < 0 { if errno == EINTR || errno == EAGAIN { continue }; stop(error: .ioFailure); return }
            if count == 0 { stop(error: pending.isEmpty ? nil : .truncatedInput); return }
            for byte in buffer.prefix(count) {
                guard isRunning else { return }
                if byte == 0x0A {
                    if pending.isEmpty { continue }
                    do {
                        try JSONMessageValidator.validate(pending)
                        try admit(try JSONDecoder().decode(RPCEnvelope.self, from: pending), byteCount: pending.count)
                    }
                    catch { stop(error: (error as? StdioTransportError) ?? .invalidJSON); return }
                    switch continuation.yield(pending) {
                    case .enqueued: pending.removeAll(keepingCapacity: true)
                    case .dropped: stop(error: .backpressure); return
                    case .terminated: stop(); return
                    @unknown default: stop(error: .backpressure); return
                    }
                } else {
                    guard pending.count < BoundedStdioTransport.maxIncomingBytes else { stop(error: .lineTooLong); return }
                    pending.append(byte)
                }
            }
        }
    }

    func write(_ data: Data, completion: @escaping @Sendable (Result<Void, any Error>) -> Void) {
        let deadline = DispatchTime.now().uptimeNanoseconds + UInt64(timeout * 1_000_000_000)
        let descriptor = lock.withLock { output }
        writeQueue.async { [self] in
            do {
                let envelope: RPCEnvelope
                do { envelope = try JSONDecoder().decode(RPCEnvelope.self, from: data) }
                catch { throw (error as? StdioTransportError) ?? StdioTransportError.invalidJSON }
                var framed = data; framed.append(0x0A)
                try writeAll(framed, descriptor: descriptor, deadline: deadline)
                if let response = envelope.responseID { _ = lock.withLock { outstanding.remove(response) } }
                completion(.success(()))
            } catch {
                stop(error: (error as? StdioTransportError) ?? .ioFailure)
                completion(.failure(error))
            }
        }
    }

    private func admit(_ envelope: RPCEnvelope, byteCount: Int) throws {
        try envelope.validateIncoming()
        try lock.withLock {
            guard !closed else { throw StdioTransportError.disconnected }
            if let id = envelope.requestID {
                guard !outstanding.contains(id) else { throw StdioTransportError.duplicateRequestID }
                guard outstanding.count < BoundedStdioTransport.maxBufferedMessages else { throw StdioTransportError.backpressure }
                outstanding.insert(id)
            } else if envelope.isNotification {
                guard byteCount <= BoundedStdioTransport.maxNotificationBytes else { throw StdioTransportError.notificationTooLong }
                let now = DispatchTime.now().uptimeNanoseconds
                notificationTokens = min(16, notificationTokens + Double(now - lastRefill) / 1_000_000_000 * 64)
                lastRefill = now
                guard notificationTokens >= 1 else { throw StdioTransportError.backpressure }
                notificationTokens -= 1
            }
        }
    }

    private func writeAll(_ data: Data, descriptor: Int32, deadline: UInt64) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                guard isRunning else { throw StdioTransportError.disconnected }
                let now = DispatchTime.now().uptimeNanoseconds
                guard now < deadline else { throw StdioTransportError.writeTimeout }
                let remainingMS = max(1, min(50, Int((deadline - now) / 1_000_000)))
                var event = pollfd(fd: descriptor, events: Int16(POLLOUT), revents: 0)
                let ready = poll(&event, 1, Int32(remainingMS))
                if ready < 0 { if errno == EINTR { continue }; throw StdioTransportError.ioFailure }
                if ready == 0 { continue }
                guard event.revents & Int16(POLLERR | POLLHUP | POLLNVAL) == 0 else { throw StdioTransportError.ioFailure }
                #if canImport(Darwin)
                let count = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                #else
                let count = av_stdio_write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                #endif
                if count < 0 { if errno == EINTR || errno == EAGAIN { continue }; throw StdioTransportError.ioFailure }
                guard count > 0 else { throw StdioTransportError.ioFailure }
                offset += count
            }
        }
    }
}

private struct RPCEnvelope: Decodable {
    let requestID: ID?
    let responseID: ID?
    let isNotification: Bool
    private let method: String?
    private let version: String?
    private let keys: Set<String>
    private enum CodingKeys: String, CodingKey { case id, method, jsonrpc, params, result, error }
    private struct ObjectKey: CodingKey {
        let stringValue: String
        let intValue: Int? = nil
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }

    func validateIncoming() throws {
        guard version == "2.0", method != nil,
              keys.isSubset(of: ["jsonrpc", "method", "id", "params"]) else { throw StdioTransportError.invalidJSON }
    }

    init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        method = try values.decodeIfPresent(String.self, forKey: .method)
        version = try values.decodeIfPresent(String.self, forKey: .jsonrpc)
        keys = Set(try decoder.container(keyedBy: ObjectKey.self).allKeys.map(\.stringValue))
        if let method, method.isEmpty || method.utf8.count > 128 { throw StdioTransportError.invalidJSON }
        if values.contains(.params) {
            guard try !values.decodeNil(forKey: .params) else { throw StdioTransportError.invalidJSON }
            _ = try values.nestedContainer(keyedBy: ObjectKey.self, forKey: .params)
        }
        let id: ID?
        if values.contains(.id) {
            guard try !values.decodeNil(forKey: .id) else { throw StdioTransportError.invalidRequestID }
            do { id = try values.decode(ID.self, forKey: .id) }
            catch { throw StdioTransportError.invalidRequestID }
            if let id, case .string(let string) = id, string.utf8.count > BoundedStdioTransport.maxRequestIDBytes {
                throw StdioTransportError.invalidRequestID
            }
        } else { id = nil }
        requestID = method == nil ? nil : id
        isNotification = method != nil && id == nil
        let hasResult = values.contains(.result), hasError = values.contains(.error)
        if method == nil, hasResult != hasError, version == "2.0" {
            if hasError { _ = try values.decode(MCPError.self, forKey: .error) }
            responseID = id
        }
        else { responseID = nil }
    }
}
