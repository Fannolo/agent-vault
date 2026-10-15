import AgentVaultContracts
import AgentVaultIPC
import Foundation

public final class XPCAdminTransport: VaultAdminTransport, Sendable {
    private let client: VaultAdminClient
    public init(configuration: IPCConfiguration) throws { client = try VaultAdminClient(configuration: configuration) }
    init(client: VaultAdminClient) { self.client = client }
    public func snapshot() async throws -> AdminSnapshot {
        do { return try await client.snapshot() }
        catch { throw AdminTransportError.unavailable }
    }
    public func begin(_ request: AdminRequest) async throws -> AdminChallenge {
        do {
            switch try await client.begin(request) {
            case .challenge(let challenge): return challenge
            case .rejected(let reply): throw AdminTransportError.rejected(reply.status)
            }
        } catch let error as AdminTransportError { throw error }
        catch { throw AdminTransportError.unavailable }
    }
    public func authorize(challengeID: UUID, signature: Data) async throws -> AdminReply {
        do { return try await client.authorize(id: challengeID, signature: signature) }
        catch { throw AdminTransportError.unavailable }
    }
    public func continueHuman(_ request: ContinuationRequest) async throws -> ContinuationReply {
        do { return try await client.continueHuman(request) }
        catch { throw AdminTransportError.unavailable }
    }
}
