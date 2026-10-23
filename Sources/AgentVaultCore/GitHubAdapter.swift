import AgentVaultContracts
import AgentVaultJSON
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public struct FixedServiceAdapter: ServiceAdapter {
    public init() {}
    public func execute(service: APIService, credential: Data) async throws -> ServiceOutput {
        switch service {
        case .demo:
            guard !credential.isEmpty else { throw VaultError.secretUnavailable }
            return .demoReady
        case .github:
            return .profile(try await GitHubAdapter().profile(credential: credential))
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
    public init() {}

    public func profile(credential: Data) async throws -> AccountProfile {
        guard CredentialFormat.isValid(credential, for: .github),
              let token = String(data: credential, encoding: .utf8) else { throw VaultError.invalidInput }
        var request = URLRequest(url: Self.endpoint)
        request.httpMethod = "GET"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        request.setValue("AgentVault/0.1.0", forHTTPHeaderField: "User-Agent")
        do {
            let body = try await BoundedProfileRequest.load(request, expectedURL: Self.endpoint)
            let profile = try Self.decodeProfile(body)
            guard !profile.login.contains(token) else { throw VaultError.invalidResponse }
            return profile
        } catch { throw (error as? VaultError) ?? VaultError.upstreamUnavailable }
    }

    private struct Body: Decodable { let login: String; let id: Int }

    public static func decodeProfile(_ body: Data) throws -> AccountProfile {
        guard body.count <= 65_536 else { throw VaultError.invalidResponse }
        do {
            try JSONObjectGuard.validate(body)
            let value = try JSONDecoder().decode(Body.self, from: body)
            guard let profile = AccountProfile(login: value.login, userID: value.id) else { throw VaultError.invalidResponse }
            return profile
        } catch { throw VaultError.invalidResponse }
    }
}
