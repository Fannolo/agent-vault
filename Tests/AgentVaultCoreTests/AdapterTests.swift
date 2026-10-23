import AgentVaultContracts
import AgentVaultCore
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing

@Test func githubOutputDropsUnknownSensitiveFields() throws {
    let data = Data(#"{"login":"synthetic-user","id":42,"token":"SYNTHETIC-only-token","email":"private@example.invalid"}"#.utf8)
    let profile = try GitHubAdapter.decodeProfile(data)
    #expect(profile == AccountProfile(login: "synthetic-user", userID: 42))
    let serialized = String(decoding: try JSONEncoder().encode(profile), as: UTF8.self)
    #expect(!serialized.contains("token"))
    #expect(!serialized.contains("email"))
}

@Test func githubRejectsUnsafeOutputAndOversizedBody() throws {
    for value in [#"{"login":"<script>","id":42}"#, #"{"login":"valid","id":0}"#, #"{"login":42,"id":3}"#] {
        #expect(throws: VaultError.invalidResponse) { try GitHubAdapter.decodeProfile(Data(value.utf8)) }
    }
    #expect(throws: VaultError.invalidResponse) { try GitHubAdapter.decodeProfile(Data(repeating: 0, count: 65_537)) }
}

@Test func credentialCannotInjectHeaders() async throws {
    for value in ["short", "valid-token\r\nInjected: yes", "valid-token with-space"] {
        #expect(!CredentialFormat.isValid(Data(value.utf8), for: .github))
        await #expect(throws: VaultError.invalidInput) { _ = try await GitHubAdapter().profile(credential: Data(value.utf8)) }
    }
}

@Test func redirectsAreNeverFollowed() async throws {
    let response = HTTPURLResponse(url: GitHubAdapter.endpoint, statusCode: 302,
                                   httpVersion: nil, headerFields: ["Location": "https://elsewhere.invalid"])!
    let result: URLRequest? = await withCheckedContinuation { continuation in
        RejectRedirects().urlSession(URLSession.shared, task: URLSession.shared.dataTask(with: GitHubAdapter.endpoint),
                                     willPerformHTTPRedirection: response,
                                     newRequest: URLRequest(url: URL(string: "https://elsewhere.invalid")!)) {
            continuation.resume(returning: $0)
        }
    }
    #expect(result == nil)
}

@Test func githubRejectsInvalidSyntheticTokenAtFixedLiveEndpoint() async throws {
    guard ProcessInfo.processInfo.environment["AGENT_VAULT_NETWORK_TEST"] == "1" else { return }
    await #expect(throws: VaultError.upstreamUnavailable) {
        _ = try await GitHubAdapter().profile(credential: Data("SYNTHETIC-invalid-not-a-real-token".utf8))
    }
}
