import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing
import AgentVaultCredentials
@testable import AgentVaultCloud

/// Request as the URL loading system delivered it. Handlers only route; every assertion runs on
/// the test's own task after the call, so a failed expectation is attributed to that test.
private struct Captured: Sendable {
    let method: String?
    let url: URL?
    let headers: [String: String]
    let body: Data?
    var path: String? { url?.path }
    var query: [URLQueryItem]? { url.flatMap { URLComponents(url: $0, resolvingAgainstBaseURL: false)?.queryItems } }
    func header(_ name: String) -> String? { headers.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value }
    func json() -> [String: Any]? { body.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } }

    init(_ request: URLRequest) {
        method = request.httpMethod; url = request.url; headers = request.allHTTPHeaderFields ?? [:]
        // Inside URLProtocol the body normally arrives as a stream, not `httpBody`.
        if let stream = request.httpBodyStream {
            var data = Data(), buffer = [UInt8](repeating: 0, count: 4096)
            stream.open(); defer { stream.close() }
            while true {
                let count = stream.read(&buffer, maxLength: buffer.count)
                if count <= 0 { break }
                data.append(buffer, count: count)
            }
            body = data
        } else { body = request.httpBody }
    }
}

private final class Fixture: @unchecked Sendable {
    typealias Handler = @Sendable (Captured) -> Response
    struct Response: Sendable {
        var status = 200
        var data = Data()
        var headers: [String: String] = [:]
        var error = false
        var held = false
        var chunks: [Data]? = nil
        /// Response URL different from the request URL (a loader-side destination change).
        var url: URL? = nil
        /// Darwin only: report a redirect through URLProtocolClient.
        var redirect: URL? = nil
    }
    let host = UUID().uuidString.lowercased() + ".invalid"
    let handler: Handler
    private let lock = NSLock()
    private var continuation: Delivery?
    private var started = false
    private var captured: [Captured] = []
    init(_ handler: @escaping Handler) { self.handler = handler; Stub.add(self) }
    var requests: [Captured] { lock.withLock { captured } }
    func record(_ request: Captured) { lock.withLock { captured.append(request) } }
    func close() { Stub.remove(host) }
    func hold(_ work: Delivery) { lock.withLock { started = true; continuation = work } }
    func release() { let work = lock.withLock { let value = continuation; continuation = nil; return value }; work?.finish() }
    func waitUntilStarted() async throws {
        for _ in 0..<200 {
            if lock.withLock({ started }) { return }
            try await Task.sleep(for: .milliseconds(5))
        }
        throw CloudError.unavailable
    }
    func client(origin: String? = nil) throws -> SupabaseTransport {
        let endpoint = try CloudEndpoint(origin: URL(string: origin ?? "https://" + host)!, publishableKey: "sb_publishable_fixture")
        let token = CloudAccessToken(Data("synthetic.cloud.access".utf8))!
        let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [Stub.self]
        return SupabaseTransport(endpoint: endpoint, accessToken: token, configuration: config)
    }
}

/// Transfers only a one-shot response capability. URLProtocol itself is non-Sendable on
/// Linux; this private holder serializes access and never exposes the underlying instance.
private final class Delivery: @unchecked Sendable {
    private let lock = NSLock()
    private var instance: Stub?
    private let response: Fixture.Response
    init(_ instance: Stub, _ response: Fixture.Response) { self.instance = instance; self.response = response }
    func finish() {
        let target = lock.withLock { let value = instance; instance = nil; return value }
        target?.complete(response)
    }
}

private final class Stub: URLProtocol {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var fixtures: [String: Fixture] = [:]
    private let state = NSRecursiveLock()
    private var stopped = false
    static func add(_ fixture: Fixture) { lock.withLock { fixtures[fixture.host] = fixture } }
    static func remove(_ host: String) { _ = lock.withLock { fixtures.removeValue(forKey: host) } }
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        guard let host = request.url?.host, let fixture = Self.lock.withLock({ Self.fixtures[host] }) else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL)); return
        }
        let captured = Captured(request)
        fixture.record(captured)
        let response = fixture.handler(captured)
        if response.held { fixture.hold(Delivery(self, response)) } else { complete(response) }
    }
    func complete(_ response: Fixture.Response) {
        state.withLock {
            guard !stopped else { return }
            if response.error { client?.urlProtocol(self, didFailWithError: URLError(.networkConnectionLost)); return }
            #if !canImport(FoundationNetworking)
            if let target = response.redirect {
                // FoundationNetworking traps on protocol-reported redirects; Linux covers the delegate below.
                client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: target), redirectResponse: HTTPURLResponse(
                    url: request.url!, statusCode: 307, httpVersion: "HTTP/1.1", headerFields: ["Location": target.absoluteString])!)
                return
            }
            #endif
            client?.urlProtocol(self, didReceive: HTTPURLResponse(url: response.url ?? request.url!, statusCode: response.status,
                httpVersion: "HTTP/1.1", headerFields: response.headers)!, cacheStoragePolicy: .notAllowed)
            for data in response.chunks ?? [response.data] { client?.urlProtocol(self, didLoad: data) }
            client?.urlProtocolDidFinishLoading(self)
        }
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
    for origin in ["http://cloud.invalid", "https://user@cloud.invalid", "https://cloud.invalid/path", "https://cloud.invalid?x=1",
                   "https://cloud.invalid/#x", "https://clo_ud.invalid", "https://-cloud.invalid", "https://cloud..invalid",
                   "https://cloud.invalid.", "https://cl%6Fud.invalid", "https://[::1]", "https://cloud.invalid:0"] {
        guard let url = URL(string: origin) else { continue }
        #expect(throws: CloudError.invalidConfiguration) {
            _ = try CloudEndpoint(origin: url, publishableKey: "sb_publishable_fixture")
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

@Test func endpointIsCanonicalSoExactResponseURLsMatch() async throws {
    let canonical = try CloudEndpoint(origin: URL(string: "https://ABC-1.Supabase.CO:443/")!, publishableKey: "sb_publishable_fixture")
    #expect(canonical.origin.absoluteString == "https://abc-1.supabase.co")
    let custom = try CloudEndpoint(origin: URL(string: "https://Vault.Example:8443")!, publishableKey: "sb_publishable_fixture")
    #expect(custom.origin.absoluteString == "https://vault.example:8443")
    // A real macOS loader reports the lowercase host for an uppercase request host
    // (verification-logs/cloud-client/v2/url-probe.log); requests must already use that form.
    let vault = UUID()
    let fixture = Fixture { _ in .init(data: Data("[]".utf8)) }
    defer { fixture.close() }
    let head = try await fixture.client(origin: "https://" + fixture.host.uppercased() + ":443/").head(vault: vault)
    #expect(head == nil)
    let request = try #require(fixture.requests.first)
    #expect(request.url?.absoluteString == "https://\(fixture.host)/rest/v1/heads?select=vault_id,head,revision&vault_id=eq.\(vault.uuidString.lowercased())&limit=1")
}

@Test func fixedPutRouteUsesOnlyTrustedHeadersAndImmutableRetry() async throws {
    let vault = UUID(), object = try CloudObject(Data([1, 2, 0xab]))
    let fixture = Fixture { _ in .init(status: 201) }
    defer { fixture.close() }
    try await fixture.client().put(object, vault: vault)
    #expect(fixture.requests.count == 1)
    let request = try #require(fixture.requests.first)
    #expect(request.method == "POST")
    #expect(request.path == "/rest/v1/objects")
    #expect(request.query == [.init(name: "on_conflict", value: "vault_id,digest")])
    #expect(request.header("Content-Profile") == "vault")
    #expect(request.header("Accept-Profile") == nil)
    #expect(request.header("Prefer") == "return=minimal,resolution=ignore-duplicates")
    #expect(request.header("apikey") == "sb_publishable_fixture")
    let authorizationMatches = request.header("Authorization") == "Bearer synthetic.cloud.access"
    #expect(authorizationMatches)
    // Without the `\x` prefix PostgreSQL would store the ASCII hex text and hash that instead.
    let body = try #require(request.json())
    #expect(Set(body.keys) == ["vault_id", "body"])
    #expect(body["vault_id"] as? String == vault.uuidString.lowercased())
    #expect(body["body"] as? String == "\\x0102ab")
}

@Test func conditionalHeadBodiesUseNullOrPrefixedDigests() async throws {
    let vault = UUID(), first = try CloudObject(Data([8])), second = try CloudObject(Data([9]))
    let fixture = Fixture { _ in .init(data: Data("4".utf8)) }
    defer { fixture.close() }
    let client = try fixture.client()
    #expect(try await client.compareAndSwap(vault: vault, expected: nil, new: first.digest) == 4)
    #expect(try await client.compareAndSwap(vault: vault, expected: first.digest, new: second.digest) == 4)
    let requests = fixture.requests
    #expect(requests.count == 2)
    for request in requests {
        #expect(request.method == "POST")
        #expect(request.path == "/rest/v1/rpc/cas_head")
        #expect(request.query == nil)
        #expect(request.header("Content-Profile") == "vault")
        #expect(request.header("Prefer") == nil)
    }
    let initial = try #require(requests.first?.json())
    #expect(Set(initial.keys) == ["p_vault", "p_expected", "p_new"])
    #expect(initial["p_vault"] as? String == vault.uuidString.lowercased())
    #expect(initial["p_expected"] is NSNull)
    #expect(initial["p_new"] as? String == hex(first.digest.bytes))
    let next = try #require(requests.last?.json())
    #expect(next["p_expected"] as? String == hex(first.digest.bytes))
    #expect(next["p_new"] as? String == hex(second.digest.bytes))
}

@Test func createVaultConfirmsOwnershipOfAnExistingId() async throws {
    let vault = UUID()
    // Mirrors the native SQL result: ON CONFLICT DO NOTHING inserts 0 rows without error (201),
    // a plain insert of an existing id fails 23505 (409), and RLS hides other owners' rows.
    func server(owned: Bool, exists: Bool) -> Fixture {
        Fixture { request in
            switch (request.method, request.path) {
            case ("POST", "/rest/v1/vaults"):
                if !exists { return .init(status: 201) }
                return .init(status: request.header("Prefer")?.contains("ignore-duplicates") == true ? 201 : 409)
            case ("GET", "/rest/v1/vaults"):
                return .init(data: json(owned ? [["id": vault.uuidString.lowercased()]] : []))
            default: return .init(status: 404)
            }
        }
    }
    let fresh = server(owned: true, exists: false); defer { fresh.close() }
    try await fresh.client().createVault(vault)
    #expect(fresh.requests.count == 1)
    let create = try #require(fresh.requests.first)
    #expect(create.header("Prefer") == "return=minimal")
    #expect(create.header("Content-Profile") == "vault")
    let body = try #require(create.json())
    #expect(Set(body.keys) == ["id"])
    #expect(body["id"] as? String == vault.uuidString.lowercased())

    let retry = server(owned: true, exists: true); defer { retry.close() }
    try await retry.client().createVault(vault)
    #expect(retry.requests.map(\.method) == ["POST", "GET"])
    let confirm = try #require(retry.requests.last)
    #expect(confirm.header("Accept-Profile") == "vault")
    #expect(confirm.query == [.init(name: "select", value: "id"), .init(name: "id", value: "eq." + vault.uuidString.lowercased()),
                              .init(name: "limit", value: "1")])

    let foreign = server(owned: false, exists: true); defer { foreign.close() }
    let client = try foreign.client()
    await fails(.conflict) { try await client.createVault(vault) }

    let mismatched = Fixture { request in
        request.method == "POST" ? .init(status: 409) : .init(data: json([["id": UUID().uuidString]]))
    }
    defer { mismatched.close() }
    let other = try mismatched.client()
    await fails(.invalidResponse) { try await other.createVault(vault) }
}

@Test func changesVerifyDigestAndCursorBeforeReturningCiphertext() async throws {
    let vault = UUID(), object = try CloudObject(Data([4, 5]))
    let data = json([row(object, vault: vault, seq: 7)])
    let fixture = Fixture { _ in .init(data: data) }
    defer { fixture.close() }
    let changes = try await fixture.client().changes(vault: vault, after: 6)
    #expect(changes.count == 1)
    #expect(changes.first?.object.digest == object.digest)
    #expect(changes.first?.sequence == 7)
    let request = try #require(fixture.requests.first)
    #expect(request.method == "GET")
    #expect(request.path == "/rest/v1/objects")
    #expect(request.body == nil || request.body?.isEmpty == true)
    #expect(request.query == [.init(name: "select", value: "vault_id,body,digest,seq"),
                              .init(name: "vault_id", value: "eq." + vault.uuidString.lowercased()),
                              .init(name: "seq", value: "gt.6"), .init(name: "order", value: "seq"), .init(name: "limit", value: "3")])
    #expect(request.header("Accept-Profile") == "vault")
    #expect(request.header("Content-Profile") == nil)
    #expect(request.header("apikey") == "sb_publishable_fixture")
    let authorizationMatches = request.header("Authorization") == "Bearer synthetic.cloud.access"
    #expect(authorizationMatches)
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
    let fixture = Fixture { request in .init(data: request.method == "GET" ? validHead : Data("3".utf8)) }
    defer { fixture.close() }
    let client = try fixture.client()
    let head = try await client.head(vault: vault)
    #expect(head?.revision == 2)
    #expect(head?.digest == object.digest)
    #expect(try await client.compareAndSwap(vault: vault, expected: nil, new: object.digest) == 3)
    // 409 is the documented PostgREST status for a PT409-coded head conflict (server change pending
    // integration). The current 40001 raise arrives as 500 and must stay unconfirmed, never a conflict.
    for (status, expected) in [(401, CloudError.unauthorized), (403, .denied), (409, .conflict), (500, .writeUnconfirmed),
                               (400, .writeUnconfirmed)] {
        let refusal = Fixture { _ in .init(status: status) }; defer { refusal.close() }
        let refused = try refusal.client()
        await fails(expected) { _ = try await refused.compareAndSwap(vault: vault, expected: nil, new: object.digest) }
        #expect(refusal.requests.count == 1)
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
        await fails(.invalidResponse) { _ = try await client.head(vault: UUID()) }
    }
}

@Test func responseFromAnotherDestinationIsRefused() async throws {
    let vault = UUID(), object = try CloudObject(Data([3]))
    for moved in ["https://elsewhere.invalid/rest/v1/heads", "https://HOST/rest/v1/heads", "https://HOST/rest/v1/objects"] {
        let fixture = Fixture { request in
            .init(data: Data("[]".utf8), url: URL(string: moved.replacingOccurrences(of: "HOST", with: request.url!.host!)))
        }
        defer { fixture.close() }
        let client = try fixture.client()
        await fails(.invalidResponse) { _ = try await client.head(vault: vault) }
        await fails(.writeUnconfirmed) { try await client.put(object, vault: vault) }
    }
}

/// The delegate is reached through the protocol, as URLSession reaches it. A signature that stops
/// being a witness would run the default implementation, which follows the redirect.
@Test func redirectDelegateWitnessRefusesTheNewRequest() throws {
    final class Outcome: @unchecked Sendable {
        let lock = NSLock(); var calls: [URLRequest?] = []
        func add(_ value: URLRequest?) { lock.withLock { calls.append(value) } }
        var values: [URLRequest?] { lock.withLock { calls } }
    }
    let url = URL(string: "https://cloud.invalid/rest/v1/heads")!, outcome = Outcome()
    let delegate: any URLSessionTaskDelegate = CloudHTTPRequest(url: url)
    let session = URLSession(configuration: .ephemeral); defer { session.invalidateAndCancel() }
    let task = session.dataTask(with: url)
    let response = HTTPURLResponse(url: url, statusCode: 307, httpVersion: "HTTP/1.1", headerFields: ["Location": "https://elsewhere.invalid/"])!
    let next = URLRequest(url: URL(string: "https://elsewhere.invalid/")!)
    #if canImport(FoundationNetworking)
    delegate.urlSession(session, task: task, willPerformHTTPRedirection: response, newRequest: next) { outcome.add($0) }
    #else
    delegate.urlSession?(session, task: task, willPerformHTTPRedirection: response, newRequest: next) { outcome.add($0) }
    #endif
    #expect(outcome.values.count == 1)
    #expect(outcome.values.first == .some(nil))
}

#if !canImport(FoundationNetworking)
@Test func redirectIsRefusedBeforeTheNewHostReceivesCredentials() async throws {
    let vault = UUID(), object = try CloudObject(Data([2]))
    let target = Fixture { _ in .init(status: 201, data: Data("[]".utf8)) }
    defer { target.close() }
    let origin = Fixture { _ in .init(redirect: URL(string: "https://\(target.host)/rest/v1/heads")!) }
    defer { origin.close() }
    let client = try origin.client()
    await fails(.invalidResponse) { _ = try await client.head(vault: vault) }
    await fails(.writeUnconfirmed) { try await client.put(object, vault: vault) }
    #expect(origin.requests.count == 2)
    #expect(target.requests.isEmpty)
}
#endif

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
