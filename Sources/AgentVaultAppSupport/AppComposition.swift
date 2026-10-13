import AgentVaultContracts
import AgentVaultRuntime
import Foundation

/// The single place where the app's transport and signer are chosen.
///
/// Production uses the hardware-protected signer and, until the authenticated admin channel is
/// linked here, a transport that fails closed. DEBUG builds can opt into an in-memory preview
/// broker with a software key; that code is compiled out of release builds.
public enum AppComposition {
    /// Replace `UnavailableTransport` with the admin XPC transport when the IPC module lands.
    @MainActor public static func makeModel(environment: [String: String] = ProcessInfo.processInfo.environment) -> AppModel {
        #if DEBUG
        if environment["AGENT_VAULT_UI_PREVIEW"] == "1" { return previewModel() }
        #endif
        let transport: any VaultAdminTransport
        if let config = try? DeploymentConfiguration.load(for: .adminClient),
           let installed = try? XPCAdminTransport(configuration: config.ipc) {
            transport = installed
        } else { transport = UnavailableTransport() }
        return AppModel(transport: transport, signer: HumanApprovalSigner(), features: .production)
    }

    #if DEBUG
    @MainActor static func previewModel() -> AppModel {
        let signer = SoftwareFixtureSigner()
        let broker = InMemoryBroker(publicKey: signer.publicKey)
        let account = AccountSummary(id: UUID(), service: .github)
        let demo = AccountSummary(id: UUID(), service: .demo)
        let client = ClientSummary(id: UUID(), uid: 502, revoked: false)
        let now = Date()
        Task {
            await broker.seed(
                accounts: [account, demo], clients: [client],
                pending: [PendingSummary(id: UUID(), clientID: client.id, accountID: account.id,
                                         action: .githubProfile, expiresAt: now.addingTimeInterval(240))],
                grants: [GrantSummary(id: UUID(), clientID: client.id, accountID: demo.id,
                                      expiresAt: now.addingTimeInterval(3600), callsRemaining: 8,
                                      requiresApproval: true, revoked: false)],
                audit: [AuditSummary(timestamp: now.addingTimeInterval(-300), clientID: client.id, accountID: demo.id,
                                     action: .demoStatus, outcome: "completed"),
                        AuditSummary(timestamp: now.addingTimeInterval(-120), clientID: client.id, accountID: account.id,
                                     action: .githubProfile, outcome: "denied")])
        }
        return AppModel(transport: broker, signer: signer, features: AppFeatures(browserServicesEnabled: true))
    }
    #endif
}
