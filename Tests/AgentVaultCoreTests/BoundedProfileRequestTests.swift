@testable import AgentVaultCore
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing

private let endpoint = URL(string: "https://profile.example.invalid/user")!

private struct ResponseFixture: Sendable {
    var status = 200
    var responseURL = endpoint
    var declaredLength: Int?
    var chunks: [Data] = []
    var stalled: AsyncStream<Void>.Continuation?
}

private final class Fixtures: @unchecked Sendable {
    static let shared = Fixtures()
    private let lock = NSLock()
    private var values: [String: ResponseFixture] = [:]
    func put(_ fixture: ResponseFixture) -> String {
        lock.withLock { let id = UUID().uuidString; values[id] = fixture; return id }
    }
    func get(_ id: String) -> ResponseFixture? { lock.withLock { values[id] } }
    func remove(_ id: String) { _ = lock.withLock { values.removeValue(forKey: id) } }
}

private final class ProfileProtocol: URLProtocol, @unchecked Sendable {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        guard let id = request.value(forHTTPHeaderField: "X-Fixture-ID"),
              let fixture = Fixtures.shared.get(id) else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }
        if let stalled = fixture.stalled { stalled.yield(); return }
        let headers = fixture.declaredLength.map { ["Content-Length": String($0)] }
        guard let response = HTTPURLResponse(url: fixture.responseURL, statusCode: fixture.status,
                                            httpVersion: nil, headerFields: headers) else { return }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        for chunk in fixture.chunks { client?.urlProtocol(self, didLoad: chunk) }
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

private func load(_ fixture: ResponseFixture) async throws -> Data {
    let id = Fixtures.shared.put(fixture)
    defer { Fixtures.shared.remove(id) }
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [ProfileProtocol.self]
    var request = URLRequest(url: endpoint)
    request.setValue(id, forHTTPHeaderField: "X-Fixture-ID")
    return try await BoundedProfileRequest.load(request, expectedURL: endpoint, configuration: configuration)
}

@Test func profileStreamingAcceptsExactLimitAcrossChunks() async throws {
    let body = try await load(.init(chunks: [Data(repeating: 0x41, count: 32_768),
                                          Data(repeating: 0x42, count: 32_768)]))
    let correct = body.count == 65_536 && body.first == 0x41 && body.last == 0x42
    #expect(correct)
}

@Test func profileStreamingRejectsAnOversizedUnknownLengthBody() async {
    await #expect(throws: VaultError.invalidResponse) {
        _ = try await load(.init(chunks: [Data(repeating: 0x41, count: 65_536), Data([0x42])]))
    }
}

@Test func profileStreamingRejectsOversizedDeclaredLengthBeforeReadingBody() async {
    await #expect(throws: VaultError.invalidResponse) {
        _ = try await load(.init(declaredLength: 65_537))
    }
}

@Test func profileStreamingRejectsStatusOrResponseDestinationMismatch() async {
    for fixture in [ResponseFixture(status: 302), ResponseFixture(status: 401),
                    ResponseFixture(responseURL: URL(string: "https://elsewhere.example.invalid/user")!)] {
        await #expect(throws: VaultError.upstreamUnavailable) { _ = try await load(fixture) }
    }
}

@Test func profileStreamingCanBeCancelledAfterConnectionStarts() async {
    let (started, signal) = AsyncStream<Void>.makeStream()
    let request = Task { try await load(.init(stalled: signal)) }
    var iterator = started.makeAsyncIterator()
    _ = await iterator.next()
    request.cancel()
    await #expect(throws: VaultError.upstreamUnavailable) { _ = try await request.value }
    signal.finish()
}

@Test func cancelledProfileRequestNeverStartsAConnection() async {
    let (started, signal) = AsyncStream<Void>.makeStream()
    let request = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        return try await load(.init(stalled: signal))
    }
    await #expect(throws: VaultError.upstreamUnavailable) { _ = try await request.value }
    signal.finish()
    var iterator = started.makeAsyncIterator()
    let didStart: Bool
    switch await iterator.next() {
    case .some: didStart = true
    case .none: didStart = false
    }
    #expect(!didStart)
}
