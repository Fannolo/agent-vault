#if os(macOS)
import AgentVaultContracts
import AgentVaultCore
import AgentVaultIPC
import AgentVaultRuntime
import Darwin
import Foundation

@main
enum BrokerMain {
    @MainActor private static var running: (BrokerLease, VaultXPCServer)?

    static func main() {
        // All paths and identities come from the protected installed configuration.
        guard CommandLine.arguments.count == 1 else { fail() }
        Task { @MainActor in
            do {
                let config = try DeploymentConfiguration.load(for: .broker)
                let root = URL(fileURLWithPath: DeploymentConfiguration.dataPath, isDirectory: true)
                let lease = try BrokerLease(directory: root)
                let material = try config.brokerMaterial()
                let state = try FileStateStore(directory: root.appendingPathComponent("state"), integrityKey: material.integrityKey)
                let secrets = try PrivateKeychainStore(path: root.appendingPathComponent("broker.keychain-db"), password: material.password)
                let broker = Broker(state: state, secrets: secrets)
                try await broker.recoverInterruptedLifecycle()
                let admin = try Administration(broker: broker, publicKey: config.approvalPublicKey,
                    allowedServices: [.demo, .github], allowedClientUID: config.ipc.allowedUID)
                let server = try VaultXPCServer(configuration: config.ipc,
                                                handlers: BrokerComposition.handlers(broker: broker, administration: admin))
                running = (lease, server)
                server.activate()
            } catch { fail() }
        }
        dispatchMain()
    }

    private static func fail() -> Never {
        FileHandle.standardError.write(Data("Agent Vault broker: invalid_installation\n".utf8))
        exit(1)
    }
}
#endif
