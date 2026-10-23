import AgentVaultMCPTransport
#if canImport(Darwin)
import Darwin
#else
import Glibc
import CAgentVaultStdio
#endif
import Dispatch
import Foundation
import Testing

private final class Pipes: @unchecked Sendable {
    let input: Int32
    let inputWriter: Int32
    let output: Int32
    let outputReader: Int32
    private let lock = NSLock()
    private var writerClosed = false

    init() throws {
        var incoming: [Int32] = [-1, -1], outgoing: [Int32] = [-1, -1]
        guard pipe(&incoming) == 0 else { throw StdioTransportError.ioFailure }
        guard pipe(&outgoing) == 0 else {
            close(incoming[0]); close(incoming[1]); throw StdioTransportError.ioFailure
        }
        input = incoming[0]; inputWriter = incoming[1]
        outputReader = outgoing[0]; output = outgoing[1]
        for descriptor in [inputWriter, outputReader] {
            let flags = fcntl(descriptor, F_GETFL)
            guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else { throw StdioTransportError.ioFailure }
            #if canImport(Darwin)
            guard fcntl(descriptor, F_SETNOSIGPIPE, 1) == 0 else { throw StdioTransportError.ioFailure }
            #endif
        }
    }

    deinit {
        close(input); close(output); close(outputReader)
        if !writerClosed { close(inputWriter) }
    }

    func endInput() {
        lock.withLock { if !writerClosed { close(inputWriter); writerClosed = true } }
    }

    func feed(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            DispatchQueue.global(qos: .utility).async { [self] in
                do {
                    let deadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
                    try data.withUnsafeBytes { bytes in
                        var offset = 0
                        while offset < bytes.count {
                            guard DispatchTime.now().uptimeNanoseconds < deadline else { throw StdioTransportError.writeTimeout }
                            var event = pollfd(fd: inputWriter, events: Int16(POLLOUT), revents: 0)
                            let ready = poll(&event, 1, 25)
                            if ready < 0 { if errno == EINTR { continue }; throw StdioTransportError.ioFailure }
                            if ready == 0 { continue }
                            #if canImport(Darwin)
                            let count = Darwin.write(inputWriter, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                            #else
                            let count = av_stdio_write(inputWriter, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                            #endif
                            if count < 0 { if errno == EINTR || errno == EAGAIN { continue }; throw StdioTransportError.ioFailure }
                            guard count > 0 else { throw StdioTransportError.ioFailure }
                            offset += count
                        }
                    }
                    continuation.resume()
                } catch { continuation.resume(throwing: error) }
            }
        }
    }

    func readOutputLine() async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .utility).async { [self] in
                do {
                    let deadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
                    var result = Data(), byte: UInt8 = 0
                    while true {
                        guard DispatchTime.now().uptimeNanoseconds < deadline else { throw StdioTransportError.writeTimeout }
                        var event = pollfd(fd: outputReader, events: Int16(POLLIN), revents: 0)
                        let ready = poll(&event, 1, 25)
                        if ready < 0 { if errno == EINTR { continue }; throw StdioTransportError.ioFailure }
                        if ready == 0 { continue }
                        let count = read(outputReader, &byte, 1)
                        if count < 0 { if errno == EINTR || errno == EAGAIN { continue }; throw StdioTransportError.ioFailure }
                        guard count == 1 else { throw StdioTransportError.ioFailure }
                        if byte == 0x0A { break }
                        result.append(byte)
                    }
                    continuation.resume(returning: result)
                } catch { continuation.resume(throwing: error) }
            }
        }
    }
}

private func rejected(_ bytes: Data, as expected: StdioTransportError) async throws {
    let pipes = try Pipes()
    let transport = BoundedStdioTransport(input: pipes.input, output: pipes.output)
    try await transport.connect()
    let stream = await transport.receive()
    try await pipes.feed(bytes)
    await #expect(throws: expected) {
        for try await _ in stream {}
    }
    await #expect(throws: StdioTransportError.disconnected) { try await transport.send(Data("{}".utf8)) }
    await transport.disconnect()
}

@Test func requestAndResponseAreNewlineFramedAndDescriptorsRemainOwnedByCaller() async throws {
    let pipes = try Pipes()
    let transport = BoundedStdioTransport(input: pipes.input, output: pipes.output)
    try await transport.connect()
    let request = Data(#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.utf8)
    try await pipes.feed(request + Data([0x0A]))
    var iterator = await transport.receive().makeAsyncIterator()
    #expect(try await iterator.next() == request)
    let response = Data(#"{"jsonrpc":"2.0","id":1,"result":{}}"#.utf8)
    try await transport.send(response)
    #expect(try await pipes.readOutputLine() == response)
    await transport.disconnect()
    #expect(fcntl(pipes.input, F_GETFD) >= 0)
    #expect(fcntl(pipes.output, F_GETFD) >= 0)
}

@Test func oversizedUnterminatedInputIsRejectedBeforeWaitingForNewline() async throws {
    try await rejected(Data(repeating: 0x20, count: BoundedStdioTransport.maxIncomingBytes + 1), as: .lineTooLong)
}

@Test func exactInputLimitIsAcceptedWithoutGrowingAnUnterminatedBuffer() async throws {
    let pipes = try Pipes()
    let transport = BoundedStdioTransport(input: pipes.input, output: pipes.output)
    try await transport.connect()
    let base = #"{"jsonrpc":"2.0","id":1,"method":"ping"}"#
    let message = Data((base + String(repeating: " ", count: BoundedStdioTransport.maxIncomingBytes - base.utf8.count)).utf8)
    try await pipes.feed(message + Data([0x0A]))
    var iterator = await transport.receive().makeAsyncIterator()
    #expect(try await iterator.next() == message)
    await transport.disconnect()
}

@Test func excessiveNestingBatchesAndDuplicateEscapedKeysAreRejected() async throws {
    let deep = "{\"x\":" + String(repeating: "[", count: 64) + "0" + String(repeating: "]", count: 64) + "}\n"
    try await rejected(Data(deep.utf8), as: .tooDeep)
    try await rejected(Data("[{\"jsonrpc\":\"2.0\"}]\n".utf8), as: .invalidJSON)
    try await rejected(Data(#"{"method":"ping","\u006dethod":"other"}"#.utf8) + Data([0x0A]), as: .duplicateKey)
    try await rejected(Data(#"{"x":{"a":1,"a":2}}"#.utf8) + Data([0x0A]), as: .duplicateKey)
}

@Test func validNestedJSONUnicodeAndNumberGrammarPassBeforeSDKDecode() async throws {
    let pipes = try Pipes(), transport = BoundedStdioTransport(input: -1, output: -1)
    await #expect(throws: StdioTransportError.ioFailure) { try await transport.connect() }
    await transport.disconnect()
    let valid = BoundedStdioTransport(input: pipes.input, output: pipes.output)
    try await valid.connect()
    let message = Data(#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"nested":[null,true,false,-12.3e+2,{"escaped":"\"\\\uD83D\uDE00"}]}}"#.utf8)
    try await pipes.feed(message + Data([0x0A]))
    var iterator = await valid.receive().makeAsyncIterator()
    #expect(try await iterator.next() == message)
    await valid.disconnect()
}

@Test func queueFloodTerminatesInsteadOfSilentlyDroppingRequests() async throws {
    let pipes = try Pipes()
    let transport = BoundedStdioTransport(input: pipes.input, output: pipes.output)
    try await transport.connect()
    let flood = (0..<17).map { "{\"jsonrpc\":\"2.0\",\"id\":\($0),\"method\":\"ping\"}\n" }.joined()
    try await pipes.feed(Data(flood.utf8))
    // Observe closure without consuming input; send checks the I/O channel state.
    let deadline = ContinuousClock.now + .seconds(2)
    while ContinuousClock.now < deadline {
        do { try await transport.send(Data("{}".utf8)); try await Task.sleep(for: .milliseconds(1)) }
        catch StdioTransportError.disconnected { break }
    }
    var count = 0
    await #expect(throws: StdioTransportError.backpressure) {
        for try await _ in await transport.receive() { count += 1 }
    }
    #expect(count <= BoundedStdioTransport.maxBufferedMessages)
    await transport.disconnect()
}

@Test func eofEndsNormallyButUnframedTailFailsClosed() async throws {
    let pipes = try Pipes()
    let transport = BoundedStdioTransport(input: pipes.input, output: pipes.output)
    try await transport.connect(); pipes.endInput()
    var iterator = await transport.receive().makeAsyncIterator()
    #expect(try await iterator.next() == nil)
    await transport.disconnect()
    let second = try Pipes()
    let truncated = BoundedStdioTransport(input: second.input, output: second.output)
    try await truncated.connect()
    try await second.feed(Data("{}".utf8)); second.endInput()
    await #expect(throws: StdioTransportError.truncatedInput) {
        for try await _ in await truncated.receive() {}
    }
    await truncated.disconnect()
}

@Test func oversizedOutputAndUnresponsiveReadersFailClosed() async throws {
    let pipes = try Pipes()
    let transport = BoundedStdioTransport(input: pipes.input, output: pipes.output)
    try await transport.connect()
    await #expect(throws: StdioTransportError.outputTooLong) {
        try await transport.send(Data(repeating: 0x20, count: BoundedStdioTransport.maxOutgoingBytes + 1))
    }
    await transport.disconnect()
    let stalled = try Pipes()
    let writer = BoundedStdioTransport(input: stalled.input, output: stalled.output, writeTimeout: 0.05)
    try await writer.connect()
    let message = Data(("{\"padding\":\"" + String(repeating: "x", count: 262_144) + "\"}").utf8)
    await #expect(throws: StdioTransportError.writeTimeout) { try await writer.send(message) }
    await #expect(throws: StdioTransportError.disconnected) { try await writer.send(Data("{}".utf8)) }
    await writer.disconnect()
}

@Test func outstandingRequestsAreBoundBeforeSDKConsumptionAndResponsesReleaseIDs() async throws {
    let pipes = try Pipes()
    let transport = BoundedStdioTransport(input: pipes.input, output: pipes.output)
    try await transport.connect()
    var iterator = await transport.receive().makeAsyncIterator()
    for id in 0..<16 {
        let request = Data("{\"jsonrpc\":\"2.0\",\"id\":\(id),\"method\":\"ping\"}".utf8)
        try await pipes.feed(request + Data([0x0A]))
        #expect(try await iterator.next() == request)
    }
    try await transport.send(Data(#"{"jsonrpc":"2.0","id":0,"result":{}}"#.utf8))
    _ = try await pipes.readOutputLine()
    let extra = Data(#"{"jsonrpc":"2.0","id":16,"method":"ping"}"#.utf8)
    try await pipes.feed(extra + Data([0x0A]))
    #expect(try await iterator.next() == extra)
    try await pipes.feed(Data(#"{"jsonrpc":"2.0","id":17,"method":"ping"}"#.utf8) + Data([0x0A]))
    await #expect(throws: StdioTransportError.backpressure) { _ = try await iterator.next() }
    await transport.disconnect()
}

@Test func duplicateOversizedAndInvalidRequestIDsFailClosed() async throws {
    try await rejected(Data("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n".utf8), as: .duplicateRequestID)
    try await rejected(Data(("{\"jsonrpc\":\"2.0\",\"id\":\"" + String(repeating: "x", count: 129) + "\",\"method\":\"ping\"}\n").utf8), as: .invalidRequestID)
    try await rejected(Data("{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"ping\"}\n".utf8), as: .invalidRequestID)
    try await rejected(Data("{\"jsonrpc\":\"2.0\",\"id\":true,\"method\":\"ping\"}\n".utf8), as: .invalidRequestID)
    try await rejected(Data("{\"jsonrpc\":\"2.0\",\"id\":1.2,\"method\":\"ping\"}\n".utf8), as: .invalidRequestID)
    try await rejected(Data("{\"jsonrpc\":\"2.0\",\"id\":1.0,\"method\":\"ping\"}\n".utf8), as: .invalidRequestID)
    try await rejected(Data("{\"jsonrpc\":\"2.0\",\"id\":1e0,\"method\":\"ping\"}\n".utf8), as: .invalidRequestID)
}

@Test func notificationsHaveSizeAndBurstBounds() async throws {
    let oversized = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"x\":\"" + String(repeating: "x", count: 8_192) + "\"}}\n"
    try await rejected(Data(oversized.utf8), as: .notificationTooLong)
    try await rejected(Data(String(repeating: "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n", count: 40).utf8), as: .backpressure)
}

@Test func malformedAndResponseShapedMessagesCannotReleaseAnActiveRequestID() async throws {
    let malformed = [
        #"{"jsonrpc":"2.0","id":1}"#,
        #"{"jsonrpc":"2.0","id":1,"method":null}"#,
        #"{"jsonrpc":"2.0","id":1,"result":{}}"#
    ]
    for message in malformed {
        let pipes = try Pipes()
        let transport = BoundedStdioTransport(input: pipes.input, output: pipes.output)
        try await transport.connect()
        var iterator = await transport.receive().makeAsyncIterator()
        let request = Data(#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.utf8)
        try await pipes.feed(request + Data([0x0A]))
        #expect(try await iterator.next() == request)
        try await pipes.feed(Data(message.utf8) + Data([0x0A]))
        await #expect(throws: StdioTransportError.invalidJSON) { _ = try await iterator.next() }
        await #expect(throws: StdioTransportError.disconnected) {
            try await transport.send(Data(#"{"jsonrpc":"2.0","id":1,"error":{"code":-32700,"message":"Invalid message"}}"#.utf8))
        }
        await transport.disconnect()
    }
}

@Test func serverEnvelopeRequiresVersionMethodAndObjectParameters() async throws {
    let invalid = [
        #"{"method":"ping"}"#,
        #"{"jsonrpc":"1.0","method":"ping"}"#,
        #"{"jsonrpc":"2.0","method":""}"#,
        #"{"jsonrpc":"2.0","method":"ping","params":[]}"#,
        #"{"jsonrpc":"2.0","method":"ping","params":null}"#,
        #"{"jsonrpc":"2.0","method":"ping","extra":1}"#
    ]
    for message in invalid { try await rejected(Data(message.utf8) + Data([0x0A]), as: .invalidJSON) }
}
