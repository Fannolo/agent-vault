import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@_spi(CredentialUse) import AgentVaultCredentials

/// Broker-owned ciphertext client. No refresh token, admin key or password belongs here.
/// A separate trusted authentication/custody owner supplies and rotates its access token.
public actor SupabaseTransport: CloudTransport {
    private let endpoint: CloudEndpoint
    private let configuration: URLSessionConfiguration
    private var token: CloudAccessToken?
    private var generation: UInt64 = 0

    public init(endpoint: CloudEndpoint, accessToken: CloudAccessToken) {
        self.endpoint = endpoint; token = accessToken; configuration = .ephemeral
    }

    // Tests supply URLProtocol fixtures; production never accepts a caller-owned browser/session.
    init(endpoint: CloudEndpoint, accessToken: CloudAccessToken, configuration: URLSessionConfiguration) {
        self.endpoint = endpoint; token = accessToken; self.configuration = configuration
    }

    public func replaceAccessToken(_ accessToken: CloudAccessToken) {
        token = accessToken; generation &+= 1
    }

    public func invalidate() { token = nil; generation &+= 1 }

    public func createVault(_ vault: UUID) async throws {
        let body = try JSONSerialization.data(withJSONObject: ["id": vault.uuidString.lowercased()])
        _ = try await request("vaults", method: "POST", query: [], body: body,
                              prefer: "return=minimal,resolution=ignore-duplicates", success: [201, 200, 204])
    }

    public func put(_ object: CloudObject, vault: UUID) async throws {
        let body = try JSONSerialization.data(withJSONObject: ["vault_id": vault.uuidString.lowercased(), "body": "\\x" + object.bytes.hex])
        _ = try await request("objects", method: "POST", query: [.init(name: "on_conflict", value: "vault_id,digest")],
                              body: body, prefer: "return=minimal,resolution=ignore-duplicates", success: [201, 200, 204])
    }

    public func changes(vault: UUID, after cursor: Int64) async throws -> [CloudChange] {
        guard cursor >= 0 else { throw CloudError.invalidObject }
        let data = try await request("objects", method: "GET", query: [
            .init(name: "select", value: "vault_id,body,digest,seq"),
            .init(name: "vault_id", value: "eq." + vault.uuidString.lowercased()),
            .init(name: "seq", value: "gt.\(cursor)"), .init(name: "order", value: "seq"), .init(name: "limit", value: "3")], success: [200])
        guard let rows = try? JSONDecoder().decode([ObjectRow].self, from: data), rows.count <= 3 else { throw CloudError.invalidResponse }
        var previous = cursor, seen: Set<CloudDigest> = [], result: [CloudChange] = []
        for row in rows {
            guard row.vault_id == vault, row.seq > previous, let bytes = Data(postgresHex: row.body),
                  let digestBytes = Data(postgresHex: row.digest), let digest = try? CloudDigest(digestBytes),
                  let object = try? CloudObject(bytes), object.digest == digest, seen.insert(digest).inserted
            else { throw CloudError.invalidResponse }
            previous = row.seq
            result.append(try .init(sequence: row.seq, object: object))
        }
        return result
    }

    public func head(vault: UUID) async throws -> CloudHead? {
        let data = try await request("heads", method: "GET", query: [
            .init(name: "select", value: "vault_id,head,revision"),
            .init(name: "vault_id", value: "eq." + vault.uuidString.lowercased()), .init(name: "limit", value: "1")], success: [200])
        guard let rows = try? JSONDecoder().decode([HeadRow].self, from: data), rows.count <= 1 else { throw CloudError.invalidResponse }
        guard let row = rows.first else { return nil }
        guard row.vault_id == vault, row.revision > 0, let bytes = Data(postgresHex: row.head),
              let digest = try? CloudDigest(bytes) else { throw CloudError.invalidResponse }
        return try .init(digest: digest, revision: row.revision)
    }

    public func compareAndSwap(vault: UUID, expected: CloudDigest?, new: CloudDigest) async throws -> Int64 {
        var value: [String: Any] = ["p_vault": vault.uuidString.lowercased(), "p_expected": NSNull(), "p_new": "\\x" + new.hex]
        if let expected { value["p_expected"] = "\\x" + expected.hex }
        let body = try JSONSerialization.data(withJSONObject: value)
        let data = try await request("rpc/cas_head", method: "POST", query: [], body: body, success: [200])
        guard let revision = try? JSONDecoder().decode(Int64.self, from: data), revision > 0 else { throw CloudError.writeUnconfirmed }
        return revision
    }

    private func request(_ route: String, method: String, query: [URLQueryItem], body: Data? = nil,
                         prefer: String? = nil, success: Set<Int>) async throws -> Data {
        guard let token else { throw CloudError.unauthorized }
        let admittedGeneration = generation
        var parts = URLComponents(url: endpoint.origin, resolvingAgainstBaseURL: false)!
        parts.path = "/rest/v1/" + route; parts.queryItems = query.isEmpty ? nil : query
        guard let url = parts.url else { throw CloudError.invalidConfiguration }
        var request = URLRequest(url: url)
        request.httpMethod = method; request.httpBody = body
        request.setValue(endpoint.publishableKey, forHTTPHeaderField: "apikey")
        request.setValue("vault", forHTTPHeaderField: method == "GET" ? "Accept-Profile" : "Content-Profile")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(prefer, forHTTPHeaderField: "Prefer")
        token.withTokenBytes { bytes in
            request.setValue("Bearer " + String(decoding: bytes, as: UTF8.self), forHTTPHeaderField: "Authorization")
        }
        guard let copy = configuration.copy() as? URLSessionConfiguration else { throw CloudError.invalidConfiguration }
        let response: CloudHTTPResponse
        do { response = try await CloudHTTPRequest.load(request, configuration: copy) }
        catch { throw method == "GET" ? CloudError.unavailable : CloudError.writeUnconfirmed }
        guard tokenIsCurrent(admittedGeneration) else { throw method == "GET" ? CloudError.unauthorized : CloudError.writeUnconfirmed }
        if response.status == 401 || response.status == 403 { throw CloudError.unauthorized }
        if response.status == 409 { throw CloudError.conflict }
        guard success.contains(response.status) else { throw method == "GET" ? CloudError.invalidResponse : CloudError.writeUnconfirmed }
        return response.body
    }

    private func tokenIsCurrent(_ value: UInt64) -> Bool { token != nil && generation == value }
    private struct ObjectRow: Decodable { let vault_id: UUID; let body: String; let digest: String; let seq: Int64 }
    private struct HeadRow: Decodable { let vault_id: UUID; let head: String; let revision: Int64 }
}

private extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
    init?(postgresHex text: String) {
        guard (2...(CloudObject.maximumBytes * 2 + 2)).contains(text.utf8.count) else { return nil }
        let bytes = Array(text.utf8)
        guard bytes.count >= 2,
              bytes[0] == 92, bytes[1] == 120, bytes.count % 2 == 0 else { return nil }
        var result = Data(capacity: (bytes.count - 2) / 2)
        func digit(_ byte: UInt8) -> UInt8? {
            if (48...57).contains(byte) { return byte - 48 }
            if (97...102).contains(byte) { return byte - 87 }
            return nil
        }
        for index in stride(from: 2, to: bytes.count, by: 2) {
            guard let a = digit(bytes[index]), let b = digit(bytes[index + 1]) else { return nil }
            result.append(a * 16 + b)
        }
        self = result
    }
}
