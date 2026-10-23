import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing
import AgentVaultCredentials
@testable import AgentVaultCloud

private final class Fixture: @unchecked Sendable {
    typealias Handler = @Sendable (URLRequest) -> Response
    struct Response: Sendable {
        var status = 200
        var data = Data()
        var headers: [String: String] = [:]
        var error = false
        var held = false
        var chunks: [Data]? = nil
    }
    let host = UUID().uuidString.lowercased() + ".invalid"
    let handler: Handler
    private let lock = NSLock()
    private var continuation: (@Sendable () -> Void)?
    private var started = false
    init(_ handler: @escaping Handler) { self.handler = handler; Stub.add(self) }
    func close() { Stub.remove(host) }
    func hold(_ work: @escaping @Sendable () -> Void) { lock.withLock { started = true; continuation = work } }
    func release() { let work = lock.withLock { let value = continuation; continuation = nil; return value }; work?() }
    func waitUntilStarted() async throws {
        for _ in 0..<200 {
            if lock.withLock({ started }) { return }
            try await Task.sleep(for: .milliseconds(5))
        }
        throw CloudError.unavailable
    }
    func client() throws -> SupabaseTransport {
        let endpoint = try CloudEndpoint(origin: URL(string: "https://" + host)!, publishableKey: "sb_publishable_fixture")
        let token = CloudAccessToken(Data("synthetic.cloud.access".utf8))!
        let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [Stub.self]
        return SupabaseTransport(endpoint: endpoint, accessToken: token, configuration: config)
    }
}

private final class Stub: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var fixtures: [String: Fixture] = [:]
    private let state = NSLock()
    private var stopped = false
    static func add(_ fixture: Fixture) { lock.withLock { fixtures[fixture.host] = fixture } }
    static func remove(_ host: String) { _ = lock.withLock { fixtures.removeValue(forKey: host) } }
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        guard let host = request.url?.host, let fixture = Self.lock.withLock({ Self.fixtures[host] }) else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL)); return
        }
        let response = fixture.handler(request)
        let finish: @Sendable () -> Void = { [self] in
            guard !state.withLock({ stopped }) else { return }
            if response.error { client?.urlProtocol(self, didFailWithError: URLError(.networkConnectionLost)); return }
            client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: response.status,
                httpVersion: "HTTP/1.1", headerFields: response.headers)!, cacheStoragePolicy: .notAllowed)
            for data in response.chunks ?? [response.data] { client?.urlProtocol(self, didLoad: data) }
            client?.urlProtocolDidFinishLoading(self)
        }
        if response.held { fixture.hold(finish) } else { finish() }
    }
    override func stopLoading() { state.withLock { stopped = true } }
}

private func json(_ value: Any) -> Data { try! JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed]) }
private func hex(_ value: Data) -> String { "\\x" + value.map { String(format: "%02x", $0) }.joined() }
private func row(_ object: CloudObject, vault: UUID, seq: Int64) -> [String: Any] {
    ["vault_id": vault.uuidString, "body": hex(object.bytes), "digest": hex(object.digest.bytes), "seq": seq]
}
private func fails(_ expected: CloudError, _ work: () async throws -> Void) async {
    do { try await work(); Issue.record("expected cloud refusal") }
    catch { #expect((error as? CloudError) == expected) }
}

@Test func endpointAndTokenAreStrictAndRedacted() throws {
    for origin in ["http://cloud.invalid", "https://user@cloud.invalid", "https://cloud.invalid/path", "https://cloud.invalid?x=1", "https://cloud.invalid/#x"] {
        #expect(throws: CloudError.invalidConfiguration) {
            _ = try CloudEndpoint(origin: URL(string: origin)!, publishableKey: "sb_publishable_fixture")
        }
    }
    #expect(throws: CloudError.invalidConfiguration) {
        _ = try CloudEndpoint(origin: URL(string: "https://cloud.invalid")!, publishableKey: "service_role_not_allowed")
    }
    #expect(CloudAccessToken(Data("bad\r\nheader".utf8)) == nil)
    let token = CloudAccessToken(Data("synthetic.cloud.access".utf8))!
    var output = ""; dump(token, to: &output)
    #expect(!output.contains("synthetic.cloud.access"))
    #expect(String(reflecting: token) == "CloudAccessToken(redacted)")
}

@Test func fixedPutRouteUsesOnlyTrustedHeadersAndImmutableRetry() async throws {
    let vault = UUID(), object = try CloudObject(Data([1, 2, 3]))
    let fixture = Fixture { request in
        #expect(request.url?.path == "/rest/v1/objects")
        #expect(request.httpMethod == "POST")
        #expect(request.value(forHTTPHeaderField: "Content-Profile") == "vault")
        #expect(request.value(forHTTPHeaderField: "Prefer") == "return=minimal,resolution=ignore-duplicates")
        let authorizationMatches = request.value(forHTTPHeaderField: "Authorization") == "Bearer synthetic.cloud.access"
        #expect(authorizationMatches)
        #expect(URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?.queryItems == [.init(name: "on_conflict", value: "vault_id,digest")])
        return .init(status: 201)
    }
    defer { fixture.close() }
    try await fixture.client().put(object, vault: vault)
}

@Test func changesVerifyDigestAndCursorBeforeReturningCiphertext() async throws {
    let vault = UUID(), object = try CloudObject(Data([4, 5]))
    let data = json([row(object, vault: vault, seq: 7)])
    let fixture = Fixture { request in
        let query = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!.queryItems!
        #expect(query.contains(.init(name: "seq", value: "gt.6")))
        #expect(query.contains(.init(name: "limit", value: "3")))
        #expect(request.value(forHTTPHeaderField: "Accept-Profile") == "vault")
        return .init(data: data)
    }
    defer { fixture.close() }
    let changes = try await fixture.client().changes(vault: vault, after: 6)
    #expect(changes.count == 1)
    #expect(changes.first?.object.digest == object.digest)
    #expect(changes.first?.sequence == 7)
}

@Test func hostileChangeSetsAreRefused() async throws {
    let vault = UUID(), object = try CloudObject(Data([5])), other = try CloudObject(Data([6]))
    var wrongDigest = row(object, vault: vault, seq: 1); wrongDigest["digest"] = hex(other.digest.bytes)
    var wrongHex = row(object, vault: vault, seq: 1); wrongHex["body"] = "\\x0z"
    let cases = [json([wrongDigest]), json([wrongHex]), json([row(object, vault: UUID(), seq: 1)]),
                 json([row(object, vault: vault, seq: 0)]), json([row(object, vault: vault, seq: 2), row(other, vault: vault, seq: 1)]),
                 json([row(object, vault: vault, seq: 1), row(object, vault: vault, seq: 2)]),
                 json((1...4).map { row(object, vault: vault, seq: Int64($0)) }), Data("null".utf8)]
    for data in cases {
        let fixture = Fixture { _ in .init(data: data) }; defer { fixture.close() }
        let client = try fixture.client()
        await fails(.invalidResponse) { _ = try await client.changes(vault: vault, after: 0) }
    }
}

@Test func headIsScopedAndConditionalWriteNeverRetries() async throws {
    let vault = UUID(), object = try CloudObject(Data([8]))
    let validHead = json([["vault_id": vault.uuidString, "head": hex(object.digest.bytes), "revision": 2]])
    let fixture = Fixture { request in .init(data: request.httpMethod == "GET" ? validHead : Data("3".utf8)) }
    defer { fixture.close() }
    let client = try fixture.client()
    let head = try await client.head(vault: vault)
    #expect(head?.revision == 2)
    #expect(head?.digest == object.digest)
    #expect(try await client.compareAndSwap(vault: vault, expected: nil, new: object.digest) == 3)
    for (status, expected) in [(401, CloudError.unauthorized), (409, .conflict), (500, .writeUnconfirmed)] {
        let refusal = Fixture { _ in .init(status: status) }; defer { refusal.close() }
        let refused = try refusal.client()
        await fails(expected) { _ = try await refused.compareAndSwap(vault: vault, expected: nil, new: object.digest) }
    }
}

@Test func networkLossAndMalformedWriteReplyStayUnconfirmed() async throws {
    let vault = UUID(), object = try CloudObject(Data([9]))
    for response in [Fixture.Response(error: true), .init(data: Data("null".utf8))] {
        let fixture = Fixture { _ in response }; defer { fixture.close() }
        let client = try fixture.client()
        await fails(.writeUnconfirmed) { _ = try await client.compareAndSwap(vault: vault, expected: nil, new: object.digest) }
    }
}

@Test func responseBoundsApplyToDeclaredAndChunkedBodies() async throws {
    let cases = [Fixture.Response(headers: ["Content-Length": String(CloudHTTPRequest.maximumBytes + 1)]),
                 Fixture.Response(chunks: [Data(repeating: 32, count: CloudHTTPRequest.maximumBytes), Data([32])])]
    for response in cases {
        let fixture = Fixture { _ in response }; defer { fixture.close() }
        let client = try fixture.client()
        await fails(.unavailable) { _ = try await client.head(vault: UUID()) }
    }
}

@Test func invalidationFencesInFlightResponseAndNewRequests() async throws {
    let fixture = Fixture { _ in .init(data: Data("[]".utf8), held: true) }
    defer { fixture.release(); fixture.close() }
    let client = try fixture.client()
    let pending = Task { try await client.head(vault: UUID()) }
    try await fixture.waitUntilStarted()
    await client.invalidate()
    fixture.release()
    await fails(.unauthorized) { _ = try await pending.value }
    await fails(.unauthorized) { _ = try await client.head(vault: UUID()) }
}

@Test func cancellationEndsAStalledRequest() async throws {
    let fixture = Fixture { _ in .init(held: true) }
    defer { fixture.release(); fixture.close() }
    let client = try fixture.client()
    let pending = Task { try await client.head(vault: UUID()) }
    try await fixture.waitUntilStarted()
    pending.cancel()
    await fails(.unavailable) { _ = try await pending.value }
}
