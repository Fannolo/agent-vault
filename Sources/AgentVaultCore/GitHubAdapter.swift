import Foundation
import AgentVaultJSON

public struct FixedServiceAdapter: ServiceAdapter {
    public init() {}
    public func execute(service: Service, credential: Data) async throws -> OperationResult {
        switch service {
        case .demo:
            guard !credential.isEmpty else { throw VaultError.secretUnavailable }
            return .demoReady
        case .github:
            return .githubProfile(try await GitHubAdapter().profile(credential: credential))
        case .browserDemo, .githubWeb:
            // A broker-linked browser adapter must be configured explicitly.
            throw VaultError.upstreamUnavailable
        }
    }
}

public final class RejectRedirects: NSObject, URLSessionTaskDelegate, Sendable {
    public func urlSession(_ session: URLSession, task: URLSessionTask,
                           willPerformHTTPRedirection response: HTTPURLResponse,
                           newRequest request: URLRequest,
                           completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

public struct GitHubAdapter: Sendable {
    public static let endpoint = URL(string: "https://api.github.com/user")!
    private let session: URLSession

    public init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 20
        session = URLSession(configuration: configuration, delegate: RejectRedirects(), delegateQueue: nil)
    }

    public static func validateCredential(_ data: Data) throws {
        guard data.count >= 10, data.count <= 8192,
              data.allSatisfy({ (0x21...0x7E).contains($0) }) else { throw VaultError.invalidInput }
    }

    public func profile(credential: Data) async throws -> GitHubProfile {
        // The adapter owns this single-operation delegated session.
        defer { session.invalidateAndCancel() }
        try Self.validateCredential(credential)
        guard let token = String(data: credential, encoding: .utf8) else { throw VaultError.invalidInput }
        var request = URLRequest(url: Self.endpoint)
        request.httpMethod = "GET"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        request.setValue("AgentVault/0.1.0", forHTTPHeaderField: "User-Agent")
        do {
            let (bytes, response) = try await session.bytes(for: request)
            guard let response = response as? HTTPURLResponse, response.url == Self.endpoint,
                  response.statusCode == 200 else { throw VaultError.upstreamUnavailable }
            var body = Data()
            for try await byte in bytes {
                guard body.count < 65_536 else { throw VaultError.invalidResponse }
                body.append(byte)
            }
            let profile = try Self.decodeProfile(body)
            guard !profile.login.contains(token) else { throw VaultError.invalidResponse }
            return profile
        } catch { throw (error as? VaultError) ?? VaultError.upstreamUnavailable }
    }

    public static func decodeProfile(_ body: Data) throws -> GitHubProfile {
        guard body.count <= 65_536 else { throw VaultError.invalidResponse }
        do {
            try JSONObjectGuard.validate(body)
            let value = try JSONDecoder().decode(GitHubProfile.self, from: body)
            guard value.id > 0, value.login.range(of: "^[A-Za-z0-9][A-Za-z0-9-]{0,38}$",
                                                  options: .regularExpression) != nil else {
                throw VaultError.invalidResponse
            }
            return value
        } catch { throw VaultError.invalidResponse }
    }
}
