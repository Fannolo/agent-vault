import Foundation
import Network

public struct FixtureRequest: Sendable {
    public let method: String
    public let target: String
    public let headers: [String: String]
    public let body: Data
    public var path: String { target.split(separator: "?", maxSplits: 1).first.map(String.init) ?? target }
    public var query: String { target.split(separator: "?", maxSplits: 1).dropFirst().first.map(String.init) ?? "" }
}

public struct FixtureResponse: Sendable {
    public var status: Int
    public var headers: [String: String]
    public var body: Data

    public init(status: Int = 200, headers: [String: String] = [:], body: Data = Data()) {
        self.status = status; self.headers = headers; self.body = body
    }

    public static func html(_ text: String, status: Int = 200, headers: [String: String] = [:]) -> FixtureResponse {
        var all = headers
        all["Content-Type"] = "text/html; charset=utf-8"
        return FixtureResponse(status: status, headers: all, body: Data(text.utf8))
    }

    public static func redirect(to location: String, headers: [String: String] = [:]) -> FixtureResponse {
        var all = headers
        all["Location"] = location
        return FixtureResponse(status: 302, headers: all)
    }
}

/// Minimal loopback HTTP/1.1 server (127.0.0.1, ephemeral port, one request per connection).
/// Synthetic verification only; it records every request it receives.
public final class FixtureHTTPServer: @unchecked Sendable {
    public typealias Handler = @Sendable (FixtureRequest) -> FixtureResponse

    private let handler: Handler
    private let queue = DispatchQueue(label: "agentvault.fixture.http")
    private let lock = NSLock()
    private var listener: NWListener?
    private var received: [FixtureRequest] = []
    public private(set) var port: UInt16 = 0

    public init(handler: @escaping Handler) { self.handler = handler }

    public var origin: String { "http://127.0.0.1:\(port)" }
    public var requests: [FixtureRequest] { lock.withLock { received } }

    public func start() async throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        listener.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
        self.listener = listener
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let once = OnceBox()
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: if once.take() { continuation.resume() }
                case .failed(let error): if once.take() { continuation.resume(throwing: error) }
                default: break
                }
            }
            listener.start(queue: queue)
        }
        port = listener.port?.rawValue ?? 0
    }

    public func stop() {
        listener?.cancel()
        listener = nil
    }

    private func accept(_ connection: NWConnection) {
        connection.start(queue: queue)
        read(connection, buffer: Data())
    }

    private func read(_ connection: NWConnection, buffer: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard let self else { connection.cancel(); return }
            var buffer = buffer
            if let data { buffer.append(data) }
            if buffer.count > 262_144 || error != nil { connection.cancel(); return }
            if let request = Self.parse(buffer) {
                lock.withLock { received.append(request) }
                send(handler(request), on: connection)
            } else if isComplete {
                connection.cancel()
            } else {
                read(connection, buffer: buffer)
            }
        }
    }

    private static func parse(_ data: Data) -> FixtureRequest? {
        guard let split = data.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let head = String(decoding: data[data.startIndex..<split.lowerBound], as: UTF8.self)
        var lines = head.components(separatedBy: "\r\n")
        let start = lines.removeFirst().split(separator: " ")
        guard start.count >= 2 else { return nil }
        var headers: [String: String] = [:]
        for line in lines {
            guard let colon = line.firstIndex(of: ":") else { continue }
            headers[line[..<colon].lowercased()] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        let length = headers["content-length"].flatMap(Int.init) ?? 0
        let body = data[split.upperBound...]
        guard body.count >= length else { return nil }
        return FixtureRequest(method: String(start[0]), target: String(start[1]), headers: headers,
                              body: Data(body.prefix(length)))
    }

    private func send(_ response: FixtureResponse, on connection: NWConnection) {
        var head = "HTTP/1.1 \(response.status) \(response.status == 302 ? "Found" : "OK")\r\n"
        var headers = response.headers
        headers["Content-Length"] = String(response.body.count)
        headers["Connection"] = "close"
        for (key, value) in headers.sorted(by: { $0.key < $1.key }) { head += "\(key): \(value)\r\n" }
        head += "\r\n"
        connection.send(content: Data(head.utf8) + response.body, completion: .contentProcessed { _ in
            connection.cancel()
        })
    }
}

private final class OnceBox: @unchecked Sendable {
    private let lock = NSLock()
    private var taken = false
    func take() -> Bool { lock.withLock { defer { taken = true }; return !taken } }
}
